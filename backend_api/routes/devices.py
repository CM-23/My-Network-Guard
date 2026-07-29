"""
backend_api/routes/devices.py — Device management API Blueprint.

Endpoints:
  GET    /api/devices              — List devices (scope, filter, sort, paginate)
  GET    /api/v1/devices           — Same (versioned)
  GET    /api/devices/<mac>        — Device detail
  GET    /api/v1/devices/<mac>     — Device detail (versioned)
  PATCH  /api/devices/<mac>        — Update friendly name
  POST   /api/devices/<mac>/rename — Rename (legacy alias)
  POST   /api/devices/<mac>/delete — Soft delete device
  POST   /api/v1/devices/<mac>/whitelist  — Whitelist device
  POST   /api/v1/devices/<mac>/blacklist  — Blacklist device
  GET    /api/v1/devices/<mac>/history    — IP/hostname change history
  GET    /api/v1/devices/<mac>/alerts     — Alerts for device

OWASP A01: All mutating endpoints require session/JWT auth.
OWASP A03: All queries are parameterized.
OWASP A04: Input length limits enforced.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

import database
from backend_api.middleware.auth_middleware import require_session_token
from common.exceptions import NotFoundError, ValidationError
from shared.validators import validate_friendly_name, validate_mac, validate_notes

logger = logging.getLogger("API.Devices")

devices_bp = Blueprint("devices", __name__)


def _get_device_or_404(mac: str) -> dict:
    """Fetch a device by MAC or raise NotFoundError."""
    mac_clean = mac.lower()
    rows = database.execute_read("SELECT * FROM devices WHERE mac_address = ? AND deleted_at IS NULL", (mac_clean,))
    if not rows:
        raise NotFoundError(f"Device '{mac}' not found.")
    return rows[0]


def _network_hint(ip: str) -> str:
    if ip and "." in ip:
        parts = ip.split(".")
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
    return "Unknown Subnet"


# ─── List Devices ─────────────────────────────────────────────────────────────


@devices_bp.route("/api/devices")
@devices_bp.route("/api/v1/devices")
def list_devices():
    """
    List all discovered devices.

    Query params:
      scope      = "current" | "all"     (default: current)
      online     = "1" | "0"             (filter by online status)
      type       = "pc" | "phone" | ...  (filter by device_type)
      sort       = "last_seen" | "risk_score" | "hostname"
      order      = "asc" | "desc"
      page       = int (default: 1)
      per_page   = int (default: 100, max: 500)
    """
    import wifi_manager

    scope = request.args.get("scope", "current")
    online_f = request.args.get("online", "")
    type_f = request.args.get("type", "").strip().lower()
    sort_col = request.args.get("sort", "last_seen")
    order = request.args.get("order", "desc").lower()
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(500, max(1, int(request.args.get("per_page", 200))))

    # Validate sort column (whitelist to prevent SQL injection)
    allowed_sorts = {"last_seen", "first_seen", "hostname", "last_known_ip", "risk_score", "vendor", "device_type"}
    if sort_col not in allowed_sorts:
        sort_col = "last_seen"
    order = "DESC" if order == "desc" else "ASC"

    # Build WHERE clause
    conditions = ["deleted_at IS NULL"]
    params: list = []

    if scope == "current":
        net = wifi_manager.get_network_status()
        subnet = net.get("subnet", "")
        if subnet and "/" in subnet:
            prefix = subnet.split("/")[0].rsplit(".", 1)[0] + "."
            conditions.append("(last_known_ip LIKE ? OR last_known_ip = '0.0.0.0' OR last_known_ip = '')")
            params.append(f"{prefix}%")

    if online_f in ("0", "1"):
        conditions.append("is_online = ?")
        params.append(int(online_f))

    if type_f:
        conditions.append("device_type = ?")
        params.append(type_f)

    where = " AND ".join(conditions)
    offset = (page - 1) * per_page

    rows = database.execute_read(
        f"""SELECT mac_address, last_known_ip, hostname, friendly_name, vendor,
                   is_online, device_type, operating_system, confidence_score,
                   risk_score, is_whitelisted, is_blacklisted, first_seen, last_seen
            FROM devices
            WHERE {where}
            ORDER BY {sort_col} {order}
            LIMIT ? OFFSET ?""",
        tuple(params) + (per_page, offset),
    )

    # Total count for pagination
    total = database.execute_read(f"SELECT count(*) as c FROM devices WHERE {where}", tuple(params))[0]["c"]

    for row in rows:
        row["network_hint"] = _network_hint(row.get("last_known_ip", ""))
        row["display_name"] = row.get("friendly_name") or row.get("hostname") or row["mac_address"]

    if request.path == "/api/devices":
        return jsonify(rows)

    return jsonify(
        {
            "devices": rows,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page,
            },
        }
    )


# ─── Get Device Detail ────────────────────────────────────────────────────────


@devices_bp.route("/api/devices/<mac>")
@devices_bp.route("/api/v1/devices/<mac>")
def get_device(mac: str):
    try:
        row = _get_device_or_404(mac)
        row["display_name"] = row.get("friendly_name") or row.get("hostname") or row["mac_address"]
        row["network_hint"] = _network_hint(row.get("last_known_ip", ""))
        return jsonify(row)
    except NotFoundError as e:
        return jsonify(e.to_dict()), 404


# ─── Update Friendly Name ─────────────────────────────────────────────────────


@devices_bp.route("/api/devices/<mac>", methods=["PATCH"])
@devices_bp.route("/api/v1/devices/<mac>", methods=["PATCH"])
@require_session_token
def patch_device(mac: str):
    try:
        mac_clean = validate_mac(mac)
        data = request.get_json(silent=True) or {}
        friendly_name = validate_friendly_name(data.get("friendly_name", ""))

        _get_device_or_404(mac_clean)

        database.execute_write_sync(
            "UPDATE devices SET friendly_name = ? WHERE mac_address = ?", (friendly_name, mac_clean)
        )
        database.record_audit(
            action="RENAME_DEVICE",
            entity="devices",
            entity_id=mac_clean,
            new_value=friendly_name,
            actor="user",
            ip_address=request.remote_addr or "",
        )
        return jsonify({"success": True, "message": f"Device renamed to '{friendly_name}'."})

    except (ValidationError, NotFoundError) as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Rename Alias (legacy) ────────────────────────────────────────────────────


@devices_bp.route("/api/devices/<mac>/rename", methods=["POST"])
@require_session_token
def rename_device(mac: str):
    try:
        mac_clean = validate_mac(mac)
        data = request.get_json(silent=True) or {}
        name = validate_friendly_name(data.get("name", ""))

        _get_device_or_404(mac_clean)
        database.execute_write_sync("UPDATE devices SET friendly_name = ? WHERE mac_address = ?", (name, mac_clean))
        database.record_audit(
            action="RENAME_DEVICE",
            entity="devices",
            entity_id=mac_clean,
            new_value=name,
            actor="user",
            ip_address=request.remote_addr or "",
        )
        return jsonify({"success": True, "message": f"Device renamed to '{name}'."})

    except (ValidationError, NotFoundError) as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Soft Delete ──────────────────────────────────────────────────────────────


@devices_bp.route("/api/devices/<mac>/delete", methods=["POST"])
@devices_bp.route("/api/v1/devices/<mac>", methods=["DELETE"])
@require_session_token
def delete_device(mac: str):
    try:
        mac_clean = validate_mac(mac)
        _get_device_or_404(mac_clean)

        # Soft delete — preserve history
        database.execute_write_sync(
            "UPDATE devices SET deleted_at = CURRENT_TIMESTAMP WHERE mac_address = ?", (mac_clean,)
        )
        database.record_audit(
            action="DELETE_DEVICE",
            entity="devices",
            entity_id=mac_clean,
            actor="user",
            ip_address=request.remote_addr or "",
        )
        return jsonify({"success": True, "message": "Device removed."})

    except (ValidationError, NotFoundError) as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Whitelist / Blacklist ────────────────────────────────────────────────────


@devices_bp.route("/api/v1/devices/<mac>/whitelist", methods=["POST"])
@require_session_token
def whitelist_device(mac: str):
    try:
        mac_clean = validate_mac(mac)
        _get_device_or_404(mac_clean)
        database.execute_write_sync(
            "UPDATE devices SET is_whitelisted=1, is_blacklisted=0 WHERE mac_address=?", (mac_clean,)
        )
        return jsonify({"success": True, "message": "Device whitelisted."})
    except (ValidationError, NotFoundError) as e:
        return jsonify(e.to_dict()), e.http_status


@devices_bp.route("/api/v1/devices/<mac>/blacklist", methods=["POST"])
@require_session_token
def blacklist_device(mac: str):
    try:
        mac_clean = validate_mac(mac)
        _get_device_or_404(mac_clean)
        database.execute_write_sync(
            "UPDATE devices SET is_blacklisted=1, is_whitelisted=0 WHERE mac_address=?", (mac_clean,)
        )
        return jsonify({"success": True, "message": "Device blacklisted."})
    except (ValidationError, NotFoundError) as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Notes ───────────────────────────────────────────────────────────────────


@devices_bp.route("/api/v1/devices/<mac>/notes", methods=["POST"])
@require_session_token
def update_notes(mac: str):
    try:
        mac_clean = validate_mac(mac)
        data = request.get_json(silent=True) or {}
        notes = validate_notes(data.get("notes", ""))
        _get_device_or_404(mac_clean)
        database.execute_write_sync("UPDATE devices SET notes=? WHERE mac_address=?", (notes, mac_clean))
        return jsonify({"success": True})
    except (ValidationError, NotFoundError) as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Device History ───────────────────────────────────────────────────────────


@devices_bp.route("/api/v1/devices/<mac>/history")
def device_history(mac: str):
    try:
        mac_clean = validate_mac(mac)
        rows = database.execute_read(
            "SELECT * FROM device_history WHERE mac_address = ? ORDER BY timestamp DESC LIMIT 100", (mac_clean,)
        )
        return jsonify(rows)
    except ValidationError as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Device Alerts ────────────────────────────────────────────────────────────


@devices_bp.route("/api/v1/devices/<mac>/alerts")
def device_alerts(mac: str):
    try:
        mac_clean = validate_mac(mac)
        rows = database.execute_read(
            """SELECT id, timestamp, alert_type, description, severity,
                      confidence, mitre_attack, cwe_id, is_resolved
               FROM alerts
               WHERE affected_mac = ?
               ORDER BY timestamp DESC
               LIMIT 50""",
            (mac_clean,),
        )
        return jsonify(rows)
    except ValidationError as e:
        return jsonify(e.to_dict()), e.http_status
