"""
backend_api/routes/settings.py — Application settings Blueprint.

Endpoints:
  GET  /api/root-user               — Get admin profile
  POST /api/root-user/setup         — Update admin profile
  GET  /api/v1/settings             — Get all public settings
  POST /api/v1/settings             — Update settings
  POST /api/scan/trigger            — Trigger manual ARP scan
  POST /api/purge                   — Purge old traffic logs
  GET  /api/pending                 — Legacy compat stub

OWASP A01: Auth required for all mutating settings.
OWASP A04: Rate limiting prevents scan flooding.
"""

from __future__ import annotations

import logging
from flask import Blueprint, jsonify, request

import database
import sniffer
from backend_api.middleware.auth_middleware import require_session_token
from shared.validators import validate_friendly_name, validate_phone
from common.exceptions import ValidationError

logger = logging.getLogger("API.Settings")

settings_bp = Blueprint("settings", __name__)

# Packet queue reference (set by app factory)
_packet_queue = None


def set_packet_queue(q) -> None:
    global _packet_queue
    _packet_queue = q


# ─── Admin Profile ────────────────────────────────────────────────────────────

@settings_bp.route("/api/root-user", methods=["GET"])
@settings_bp.route("/api/v1/settings/root-user", methods=["GET"])
def get_root_user():
    from shared.config import get_config
    return jsonify(get_config().root_user)


@settings_bp.route("/api/root-user/setup", methods=["POST"])
@settings_bp.route("/api/v1/settings/root-user", methods=["POST"])
@require_session_token
def setup_root_user():
    try:
        from shared.config import get_config, save_config
        data  = request.get_json(silent=True) or {}
        name  = validate_friendly_name(data.get("name", ""))
        phone = validate_phone(data.get("phone", ""))

        cfg = get_config()
        cfg.root_user = {"name": name, "phone": phone}
        save_config(cfg)

        return jsonify({
            "success":   True,
            "message":   "Admin profile updated.",
            "root_user": cfg.root_user,
        })
    except ValidationError as e:
        return jsonify(e.to_dict()), e.http_status


# ─── All Settings ─────────────────────────────────────────────────────────────

@settings_bp.route("/api/v1/settings", methods=["GET"])
def get_settings():
    """Return all non-secret settings for the settings panel UI."""
    from shared.config import get_config
    cfg = get_config()
    return jsonify(cfg.to_dict())


@settings_bp.route("/api/v1/settings", methods=["POST"])
@require_session_token
def update_settings():
    """Update one or more settings values."""
    try:
        from shared.config import get_config, save_config
        data = request.get_json(silent=True) or {}
        cfg  = get_config()

        allowed_keys = {
            "out_of_hours_start", "out_of_hours_end",
            "out_of_hours_packet_limit", "dns_entropy_threshold",
            "dns_length_threshold", "purge_interval_hours",
            "traffic_retention_days", "scan_interval_seconds",
            "enable_threat_detection", "enable_fingerprinting",
        }

        updated = []
        for key, val in data.items():
            if key in allowed_keys and hasattr(cfg, key):
                setattr(cfg, key, val)
                updated.append(key)

        save_config(cfg)
        return jsonify({"success": True, "updated": updated})

    except Exception as e:
        logger.error(f"Settings update error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ─── Scan Trigger ─────────────────────────────────────────────────────────────

@settings_bp.route("/api/scan/trigger", methods=["POST"])
@settings_bp.route("/api/v1/scan/trigger", methods=["POST"])
@require_session_token
def trigger_scan():
    if not _packet_queue:
        return jsonify({"success": False, "message": "Scanner not initialized."}), 503
    try:
        sniffer.trigger_arp_scan(_packet_queue)
        return jsonify({"success": True, "message": "ARP scan triggered."})
    except PermissionError as e:
        return jsonify({"success": False, "message": str(e)}), 403
    except RuntimeError as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        logger.error(f"Scan trigger error: {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ─── Purge ────────────────────────────────────────────────────────────────────

@settings_bp.route("/api/purge", methods=["POST"])
@settings_bp.route("/api/v1/purge", methods=["POST"])
@require_session_token
def purge_logs():
    from shared.config import get_config
    cfg  = get_config()
    days = cfg.traffic_retention_days
    res  = database.execute_write_sync(
        "DELETE FROM traffic_logs WHERE last_active < DATETIME('now', ?)",
        (f"-{days} days",)
    )
    count = res.get("rowcount", 0)
    return jsonify({"success": True, "message": f"Purged {count} old flow logs."})


# ─── Legacy Stubs ────────────────────────────────────────────────────────────

@settings_bp.route("/api/pending")
def pending():
    """Legacy compat stub for dashboard."""
    return jsonify([])


# ─── WiFi Routes (delegated from wifi_manager) ────────────────────────────────

@settings_bp.route("/api/wifi/status")
@settings_bp.route("/api/v1/wifi/status")
def wifi_status():
    import wifi_manager
    return jsonify(wifi_manager.get_network_status())


@settings_bp.route("/api/wifi/networks")
@settings_bp.route("/api/v1/wifi/networks")
def wifi_networks():
    import wifi_manager
    return jsonify({"networks": wifi_manager.scan_networks()})


@settings_bp.route("/api/wifi/connect", methods=["POST"])
@settings_bp.route("/api/v1/wifi/connect", methods=["POST"])
@require_session_token
def wifi_connect():
    from shared.validators import validate_ssid, validate_password
    try:
        import wifi_manager
        data     = request.get_json(silent=True) or {}
        ssid     = validate_ssid(data.get("ssid", ""))
        password = validate_password(data.get("password", ""))

        result = wifi_manager.connect_to_wifi(ssid, password)
        if result.get("success") and _packet_queue:
            sniffer.trigger_arp_scan(_packet_queue)
        return jsonify(result)
    except ValidationError as e:
        return jsonify(e.to_dict()), e.http_status
