import logging
import os
import json
import mimetypes
from datetime import datetime
from flask import Flask, jsonify, render_template, request, Response

import database
import sniffer
import notifier
import wifi_manager
import telegram_agent
import blocker
import agent_manager

# Ensure correct MIME types on all hosting environments
mimetypes.add_type('text/css', '.css')
mimetypes.add_type('application/javascript', '.js')

logger = logging.getLogger("App")
logging.getLogger("werkzeug").setLevel(logging.ERROR)

app = Flask(__name__, template_folder="templates", static_folder="static")

_app_config = {}
_packet_queue_ref = None

def set_app_config(config_dict, packet_queue):
    global _app_config, _packet_queue_ref
    _app_config = config_dict
    _packet_queue_ref = packet_queue

def _save_config():
    """Persist _app_config back to config.json."""
    try:
        with open("config.json", "w") as f:
            json.dump(_app_config, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving config: {e}")

def get_memory_usage():
    try:
        import psutil
        return round(psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024, 1)
    except ImportError:
        pass
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return round(int(line.split()[1]) / 1024, 1)
    except Exception:
        pass
    return 0.0

# ─────────────────────────────────────────
# Pages
# ─────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# ─────────────────────────────────────────
# WiFi API
# ─────────────────────────────────────────

@app.route("/api/wifi/status")
def wifi_status():
    return jsonify(wifi_manager.get_network_status())

@app.route("/api/wifi/networks")
def wifi_networks():
    return jsonify({"networks": wifi_manager.list_wifi_networks()})

@app.route("/api/wifi/connect", methods=["POST"])
def wifi_connect():
    data = request.json or {}
    ssid = data.get("ssid", "").strip()
    password = data.get("password", "").strip()
    if not ssid:
        return jsonify({"success": False, "message": "SSID is required."}), 400
    result = wifi_manager.connect_to_wifi(ssid, password)
    if result["success"] and _packet_queue_ref:
        sniffer.trigger_arp_scan(_packet_queue_ref)
    return jsonify(result)

# ─────────────────────────────────────────
# System Status
# ─────────────────────────────────────────

@app.route("/api/status")
def status():
    q_size = _packet_queue_ref.qsize() if _packet_queue_ref else 0
    devices  = database.execute_read("SELECT count(*) as c FROM devices")[0]["c"]
    logs     = database.execute_read("SELECT count(*) as c FROM traffic_logs")[0]["c"]
    alerts_a = database.execute_read("SELECT count(*) as c FROM alerts WHERE is_resolved=0")[0]["c"]
    alerts_t = database.execute_read("SELECT count(*) as c FROM alerts")[0]["c"]
    blocked  = database.execute_read("SELECT count(*) as c FROM blocked_devices WHERE is_active=1")[0]["c"]
    pending  = len(agent_manager.get_pending_approvals())

    db_mb = 0
    if os.path.exists("nids.db"):
        db_mb = round(os.path.getsize("nids.db") / 1024 / 1024, 3)

    net = wifi_manager.get_network_status()

    return jsonify({
        "status": "online",
        "elevated": sniffer.is_elevated(),
        "packet_queue_size": q_size,
        "memory_usage_mb": get_memory_usage(),
        "db_size_mb": db_mb,
        "network": net,
        "webhook_url": _app_config.get("webhook_url", ""),
        "agent_configured": False,
        "telegram_configured": telegram_agent.is_configured(),
        "root_user": _app_config.get("root_user", {"name": "", "phone": ""}),
        "counts": {
            "devices": devices,
            "traffic_logs": logs,
            "alerts_active": alerts_a,
            "alerts_total": alerts_t,
            "blocked": blocked,
            "pending_approval": pending
        }
    })

# ─────────────────────────────────────────
# Root User (Admin) API
# ─────────────────────────────────────────

@app.route("/api/root-user", methods=["GET"])
def get_root_user():
    return jsonify(_app_config.get("root_user", {"name": "", "phone": ""}))

@app.route("/api/root-user/setup", methods=["POST"])
def setup_root_user():
    data = request.json or {}
    name  = data.get("name", "").strip()
    phone = data.get("phone", "").strip()
    if not name or not phone:
        return jsonify({"success": False, "message": "Name and phone number are required."}), 400

    _app_config.setdefault("root_user", {})
    _app_config["root_user"]["name"]  = name
    _app_config["root_user"]["phone"] = phone
    _save_config()

    return jsonify({"success": True, "message": f"Root user '{name}' configured.", "root_user": _app_config["root_user"]})

# ─────────────────────────────────────────
# Agent (Telegram Bot) Config API
# ─────────────────────────────────────────

@app.route("/api/telegram/config", methods=["GET"])
def get_telegram_config():
    cfg = _app_config.get("telegram", {})
    token = cfg.get("bot_token", "")
    masked = token[:4] + "****" + token[-4:] if len(token) > 8 else ("****" if token else "")
    return jsonify({
        "bot_token_masked": masked,
        "chat_id": cfg.get("chat_id", ""),
        "configured": telegram_agent.is_configured()
    })

@app.route("/api/telegram/config", methods=["POST"])
def save_telegram_config():
    data = request.json or {}
    _app_config.setdefault("telegram", {})

    for field in ["bot_token", "chat_id"]:
        val = data.get(field, "").strip()
        if val:
            _app_config["telegram"][field] = val

    _save_config()
    telegram_agent.update_config(_app_config)
    return jsonify({"success": True, "message": "Telegram Bot settings saved.", "configured": telegram_agent.is_configured()})

@app.route("/api/telegram/test", methods=["POST"])
def test_telegram():
    if not telegram_agent.is_configured():
        return jsonify({"success": False, "message": "Telegram agent not configured."}), 400
    telegram_agent.send_text(
        f"✅ *Network Scanner test alert.*\nYour guard is active and monitoring your network.\n— Sent at {datetime.now().strftime('%H:%M:%S')}"
    )
    return jsonify({"success": True, "message": "Test Telegram message dispatched."})



# ─────────────────────────────────────────
# Pending Approvals API
# ─────────────────────────────────────────

@app.route("/api/pending")
def get_pending():
    # Retrieve pending approvals from agent_manager
    return jsonify(agent_manager.get_pending_approvals())

# ─────────────────────────────────────────
# Devices API
# ─────────────────────────────────────────

@app.route("/api/devices")
def devices():
    net = wifi_manager.get_network_status()
    subnet = net.get("subnet", "")
    prefix = ""
    if subnet and "/" in subnet:
        prefix = subnet.split("/")[0].rsplit(".", 1)[0] + "."

    if prefix:
        # Filter to only return devices currently matching the active subnet prefix
        rows = database.execute_read(
            "SELECT mac_address, last_known_ip, hostname, custom_name, is_approved, device_type, first_seen, last_seen FROM devices WHERE last_known_ip LIKE ? ORDER BY last_seen DESC",
            (f"{prefix}%",)
        )
    else:
        rows = database.execute_read(
            "SELECT mac_address, last_known_ip, hostname, custom_name, is_approved, device_type, first_seen, last_seen FROM devices ORDER BY last_seen DESC"
        )

    # Enrich with blocked status
    blocked_ips = {r["ip"] for r in database.execute_read("SELECT ip FROM blocked_devices WHERE is_active=1")}
    for row in rows:
        row["is_blocked"] = row["last_known_ip"] in blocked_ips
    return jsonify(rows)

@app.route("/api/devices/<mac>/type", methods=["POST"])
def update_device_type(mac):
    data = request.json or {}
    dev_type = data.get("type", "").strip().lower()
    if dev_type not in ["phone", "pc", "tv", "printer", "router", "iot", "unknown"]:
        return jsonify({"success": False, "message": "Invalid device type."}), 400
    mac = mac.lower()
    database.execute_write_sync("UPDATE devices SET device_type = ? WHERE mac_address = ?", (dev_type, mac))
    return jsonify({"success": True, "message": f"Device type updated to '{dev_type}'."})

@app.route("/api/devices/<mac>/rename", methods=["POST"])
def rename_device(mac):
    data = request.json or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"success": False, "message": "Name cannot be empty."}), 400
    mac = mac.lower()
    database.execute_write_sync("UPDATE devices SET custom_name=? WHERE mac_address=?", (name, mac))
    return jsonify({"success": True, "message": f"Device renamed to '{name}'."})

@app.route("/api/devices/<mac>/block", methods=["POST"])
def block_device_endpoint(mac):
    mac = mac.lower()
    row = database.execute_read("SELECT last_known_ip, hostname, custom_name FROM devices WHERE mac_address=?", (mac,))
    if not row:
        return jsonify({"success": False, "message": "Device not found."}), 404
    ip       = row[0]["last_known_ip"]
    hostname = row[0].get("custom_name") or row[0].get("hostname", "Unknown")
    result   = _do_block_device(mac, ip, hostname)
    return jsonify(result)

@app.route("/api/devices/<mac>/allow", methods=["POST"])
def allow_device(mac):
    mac = mac.lower()
    database.execute_write_sync("UPDATE devices SET is_approved=1 WHERE mac_address=?", (mac,))
    agent_manager.remove_pending(mac)
    return jsonify({"success": True, "message": "Device approved."})

@app.route("/api/devices/<mac>/unblock", methods=["POST"])
def unblock_device_endpoint(mac):
    mac = mac.lower()
    rows = database.execute_read("SELECT ip FROM blocked_devices WHERE mac=? AND is_active=1", (mac,))
    if not rows:
        return jsonify({"success": False, "message": "No active block found for this device."}), 404
    ip = rows[0]["ip"]
    result = blocker.unblock_device(ip)
    if result["success"]:
        database.execute_write_sync("UPDATE blocked_devices SET is_active=0 WHERE mac=? AND is_active=1", (mac,))
        database.execute_write_async("UPDATE devices SET is_approved=0 WHERE mac_address=?", (mac,))
    return jsonify(result)

@app.route("/api/devices/<mac>/delete", methods=["POST"])
def delete_device(mac):
    mac = mac.lower()
    database.execute_write_sync("DELETE FROM devices WHERE mac_address=?", (mac,))
    return jsonify({"success": True})

def _do_block_device(mac, ip, hostname="Unknown"):
    result = blocker.block_device(ip, mac)
    if result["success"]:
        database.execute_write_async(
            "INSERT INTO blocked_devices (ip, mac, hostname, blocked_by) VALUES (?,?,?,'admin')",
            (ip, mac, hostname)
        )
        database.execute_write_async("UPDATE devices SET is_approved=-1 WHERE mac_address=?", (mac,))
        agent_manager.remove_pending(mac)
    return result

# ─────────────────────────────────────────
# Blocked Devices API
# ─────────────────────────────────────────

@app.route("/api/blocked")
def blocked_devices():
    rows = database.execute_read("SELECT * FROM blocked_devices WHERE is_active=1 ORDER BY blocked_at DESC")
    return jsonify(rows)

# ─────────────────────────────────────────
# Traffic Logs API
# ─────────────────────────────────────────

@app.route("/api/traffic_logs")
def traffic_logs():
    sort  = request.args.get("sort", "last_active")
    limit = request.args.get("limit", 150, type=int)
    order = "packet_count DESC" if sort == "packet_count" else "last_active DESC"
    rows  = database.execute_read(f"SELECT * FROM traffic_logs ORDER BY {order} LIMIT ?", (limit,))
    return jsonify(rows)

# ─────────────────────────────────────────
# Alerts API
# ─────────────────────────────────────────

@app.route("/api/alerts")
def alerts():
    show_resolved = request.args.get("show_resolved", "0")
    if show_resolved == "1":
        rows = database.execute_read("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200")
    else:
        rows = database.execute_read("SELECT * FROM alerts WHERE is_resolved=0 ORDER BY timestamp DESC LIMIT 200")
    return jsonify(rows)

@app.route("/api/alerts/resolve/<int:alert_id>", methods=["POST"])
def resolve_alert(alert_id):
    database.execute_write_sync("UPDATE alerts SET is_resolved=1 WHERE id=?", (alert_id,))
    return jsonify({"success": True})

@app.route("/api/alerts/resolve-all", methods=["POST"])
def resolve_all():
    database.execute_write_sync("UPDATE alerts SET is_resolved=1 WHERE is_resolved=0")
    return jsonify({"success": True})

# ─────────────────────────────────────────
# Control Actions
# ─────────────────────────────────────────

@app.route("/api/scan/trigger", methods=["POST"])
def trigger_scan():
    if _packet_queue_ref:
        sniffer.trigger_arp_scan(_packet_queue_ref)
        return jsonify({"success": True, "message": "ARP scan triggered."})
    return jsonify({"success": False, "message": "Scanner not initialized."}), 500

@app.route("/api/purge", methods=["POST"])
def purge():
    days = _app_config.get("traffic_retention_days", 7)
    res  = database.execute_write_sync(
        "DELETE FROM traffic_logs WHERE last_active < DATETIME('now', ?)", (f"-{days} days",)
    )
    return jsonify({"success": True, "message": f"Purged {res.get('rowcount', 0)} old flow logs."})

@app.route("/api/config/update", methods=["POST"])
def update_config():
    data = request.json or {}
    webhook_url = data.get("webhook_url", "").strip()
    _app_config["webhook_url"] = webhook_url
    notifier.update_webhook_url(webhook_url)
    _save_config()
    return jsonify({"success": True})

@app.route("/api/webhook/test", methods=["POST"])
def test_webhook():
    if not _app_config.get("webhook_url"):
        return jsonify({"success": False, "message": "No webhook URL configured."}), 400
    ts = datetime.now().isoformat()
    database.execute_write_async(
        "INSERT INTO alerts (timestamp, alert_type, description, severity, is_resolved) VALUES (?,?,?,?,0)",
        (ts, "TEST_ALERT", "Webhook test from Network Scanner.", "LOW")
    )
    notifier.queue_alert("TEST_ALERT", "Webhook test notification.", "LOW", ts)
    return jsonify({"success": True, "message": "Test alert dispatched."})
