"""
backend_api/routes/health.py — Health & diagnostics endpoints.

GET  /api/health          — Simple liveness probe
GET  /api/v1/health       — Detailed component health (dashboard status panel)
GET  /api/diagnostics     — Full diagnostics (legacy compat)
GET  /api/v1/diagnostics  — Full diagnostics

OWASP ASVS V14.4: Health endpoints must not expose secrets.
"""

from __future__ import annotations

import os
import socket

from flask import Blueprint, jsonify, request

import database
import sniffer
import wifi_manager
from common.constants import APP_NAME, APP_VERSION

health_bp = Blueprint("health", __name__)


def _check_internet() -> bool:
    """Quick TCP probe to 8.8.8.8:53 to verify internet connectivity."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("8.8.8.8", 53))
        sock.close()
        return True
    except Exception:
        return False


def _check_database() -> bool:
    try:
        database.execute_read("SELECT 1")
        return True
    except Exception:
        return False


def _db_size_mb() -> float:
    db_path = "nids.db"
    if os.path.exists(db_path):
        return round(os.path.getsize(db_path) / 1024 / 1024, 3)
    return 0.0


@health_bp.route("/api/health")
def liveness():
    """Kubernetes / Render liveness probe — returns 200 if process is alive."""
    return jsonify({"status": "ok", "app": APP_NAME, "version": APP_VERSION})


@health_bp.route("/api/v1/health")
@health_bp.route("/api/diagnostics")
@health_bp.route("/api/v1/diagnostics")
def diagnostics():
    """
    Full component health status used by the dashboard status panel.
    Returns green/yellow/red for each component.
    """
    from shared.config import get_config

    cfg = get_config()

    diag = sniffer.get_diagnostics()
    internet_ok = _check_internet()
    db_ok = _check_database()

    # Telegram status
    telegram_ok = (
        bool(cfg.telegram.bot_token) and len(database.execute_read("SELECT chat_id FROM telegram_subscribers")) > 0
    )
    webhook_ok = bool(cfg.webhook_url)
    net = wifi_manager.get_network_status()

    def _status(ok: bool, warn: bool = False) -> str:
        if ok:
            return "ok"
        return "warn" if warn else "error"

    health = {
        "npcap": {
            "status": _status(diag["npcap_installed"]),
            "detail": ("Npcap detected" if diag["npcap_installed"] else "Npcap not installed — install from npcap.com"),
        },
        "scapy": {
            "status": _status(sniffer.scapy_available),
            "detail": ("Scapy ready" if sniffer.scapy_available else "Scapy not installed"),
        },
        "database": {
            "status": _status(db_ok),
            "detail": "Connected" if db_ok else "Database unreachable",
        },
        "internet": {
            "status": _status(internet_ok, warn=True),
            "detail": "Reachable" if internet_ok else "No internet connectivity",
        },
        "telegram": {
            "status": _status(telegram_ok, warn=True),
            "detail": "Configured & subscribed" if telegram_ok else "Not configured",
        },
        "webhook": {
            "status": _status(webhook_ok, warn=True),
            "detail": "Configured" if webhook_ok else "Not configured",
        },
        "discovery": {
            "status": _status(diag["passive_discovery_active"] or diag["active_arp_active"]),
            "detail": sniffer.get_scan_mode(),
        },
        "interface": {
            "status": ("ok" if diag["current_interface"] not in ("Unknown", "Auto-detected") else "warn"),
            "detail": diag["current_interface"],
        },
        "gateway": {
            "status": ("ok" if diag["gateway"] and diag["gateway"] != "Unknown" else "warn"),
            "detail": diag["gateway"] or "Unknown",
        },
        "backend": {
            "status": "ok",
            "detail": f"{APP_NAME} v{APP_VERSION} online",
        },
    }

    scan_info = {
        "mode": sniffer.get_scan_mode(),
        "npcap_installed": diag["npcap_installed"],
        "packet_capture": diag["packet_capture_active"],
        "passive_discovery": diag["passive_discovery_active"],
        "active_arp": diag["active_arp_active"],
        "active_arp_reason": diag["active_arp_disabled_reason"],
        "current_interface": diag["current_interface"],
        "subnet": diag["subnet"],
        "gateway": diag["gateway"],
        "packet_count": diag["packet_count"],
        "arp_requests_sent": diag["arp_requests_sent"],
        "packets_captured": diag["packets_captured"],
        "devices_discovered": diag["devices_discovered"],
        "last_scan_time": diag["last_scan_time"],
    }

    return jsonify(
        {
            "health": health,
            "scan": scan_info,
            "network": net,
            "db_size_mb": _db_size_mb(),
        }
    )


@health_bp.route("/api/status")
@health_bp.route("/api/v1/status")
def status():
    """Legacy status endpoint — kept for backward compatibility."""
    from shared.config import get_config

    cfg = get_config()
    net = wifi_manager.get_network_status()

    # Device count (current subnet scope)
    subnet = net.get("subnet", "")
    prefix = ""
    if subnet and "/" in subnet:
        prefix = subnet.split("/")[0].rsplit(".", 1)[0] + "."

    scope = request.args.get("scope", "current")
    if scope == "current" and prefix:
        device_count = database.execute_read(
            "SELECT count(*) as c FROM devices WHERE last_known_ip LIKE ? AND deleted_at IS NULL",
            (f"{prefix}%",),
        )[0]["c"]
    else:
        device_count = database.execute_read("SELECT count(*) as c FROM devices WHERE deleted_at IS NULL")[0]["c"]

    from sniffer import get_scan_mode, is_elevated

    try:
        import psutil

        mem_mb = round(psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024, 1)
    except Exception:
        mem_mb = 0.0

    # Injected externally; placeholder
    logs = database.execute_read("SELECT count(*) as c FROM traffic_logs")[0]["c"]
    alerts_a = database.execute_read("SELECT count(*) as c FROM alerts WHERE is_resolved=0")[0]["c"]
    alerts_t = database.execute_read("SELECT count(*) as c FROM alerts")[0]["c"]
    tg_subs = len(database.execute_read("SELECT chat_id FROM telegram_subscribers")) > 0
    tg_cfg = bool(cfg.telegram.bot_token)

    return jsonify(
        {
            "status": "online",
            "version": APP_VERSION,
            "elevated": is_elevated(),
            "scan_mode": get_scan_mode(),
            "subnet_warning": wifi_manager.has_subnet_mismatch(),
            "memory_usage_mb": mem_mb,
            "db_size_mb": _db_size_mb(),
            "network": net,
            "webhook_url": cfg.webhook_url,
            "agent_configured": False,
            "telegram_configured": tg_cfg and tg_subs,
            "root_user": cfg.root_user,
            "counts": {
                "devices": device_count,
                "traffic_logs": logs,
                "alerts_active": alerts_a,
                "alerts_total": alerts_t,
            },
        }
    )


@health_bp.route("/api/metrics")
@health_bp.route("/api/v1/metrics")
def prometheus_metrics():
    """
    Basic Prometheus-compatible metrics endpoint.
    Returns text/plain in exposition format.
    """
    device_count = database.execute_read("SELECT count(*) as c FROM devices WHERE deleted_at IS NULL")[0]["c"]
    alert_count = database.execute_read("SELECT count(*) as c FROM alerts WHERE is_resolved=0")[0]["c"]
    traffic_rows = database.execute_read("SELECT count(*) as c FROM traffic_logs")[0]["c"]
    diag = sniffer.get_diagnostics()

    lines = [
        "# HELP nids_devices_total Total discovered devices",
        "# TYPE nids_devices_total gauge",
        f"nids_devices_total {device_count}",
        "# HELP nids_alerts_active Active (unresolved) alerts",
        "# TYPE nids_alerts_active gauge",
        f"nids_alerts_active {alert_count}",
        "# HELP nids_packets_captured Total packets captured",
        "# TYPE nids_packets_captured counter",
        f"nids_packets_captured {diag['packets_captured']}",
        "# HELP nids_traffic_flows Total traffic flow records",
        "# TYPE nids_traffic_flows gauge",
        f"nids_traffic_flows {traffic_rows}",
        "",
    ]

    from flask import Response

    return Response("\n".join(lines), mimetype="text/plain; version=0.0.4")
