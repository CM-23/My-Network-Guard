"""
backend_api/routes/alerts.py — Alert management API Blueprint.

Endpoints:
  GET  /api/alerts                    — List alerts (filter, paginate, sort)
  GET  /api/v1/alerts                 — Same (versioned)
  GET  /api/v1/alerts/<id>            — Alert detail (with evidence)
  POST /api/alerts/<id>/resolve       — Resolve specific alert
  POST /api/v1/alerts/<id>/resolve    — Resolve (versioned)
  POST /api/alerts/resolve-all        — Resolve all active alerts
  GET  /api/v1/alerts/stats           — Alert statistics

OWASP A01: All mutating endpoints require session/JWT auth.
OWASP A03: Parameterized queries only.
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

import database
from backend_api.middleware.auth_middleware import require_session_token
from common.exceptions import NotFoundError, ValidationError
from shared.validators import validate_severity

logger = logging.getLogger("API.Alerts")

alerts_bp = Blueprint("alerts", __name__)


# ─── List Alerts ──────────────────────────────────────────────────────────────


@alerts_bp.route("/api/alerts")
@alerts_bp.route("/api/v1/alerts")
def list_alerts():
    """
    List alerts with filtering, pagination, and sorting.

    Query params:
      show_resolved = "1" | "0"         (default: 0)
      severity      = LOW|MEDIUM|HIGH|CRITICAL
      type          = alert_type string
      mac           = affected MAC address
      page          = int (default: 1)
      per_page      = int (default: 50, max: 200)
      sort          = "timestamp" | "severity" | "confidence"
      order         = "asc" | "desc"
    """
    show_resolved = request.args.get("show_resolved", "0")
    severity_f = request.args.get("severity", "").strip().upper()
    type_f = request.args.get("type", "").strip()
    mac_f = request.args.get("mac", "").strip().lower()
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    sort_col = request.args.get("sort", "timestamp")
    order = request.args.get("order", "desc").lower()

    # Whitelist sort columns
    allowed_sorts = {"timestamp", "severity", "confidence", "alert_type"}
    if sort_col not in allowed_sorts:
        sort_col = "timestamp"
    order = "DESC" if order == "desc" else "ASC"

    conditions: list[str] = []
    params: list = []

    if show_resolved != "1":
        conditions.append("is_resolved = 0")

    if severity_f:
        try:
            validated_sev = validate_severity(severity_f)
            if validated_sev:
                conditions.append("severity = ?")
                params.append(validated_sev)
        except ValidationError:
            pass

    if type_f:
        conditions.append("alert_type = ?")
        params.append(type_f)

    if mac_f:
        conditions.append("affected_mac = ?")
        params.append(mac_f)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    offset = (page - 1) * per_page

    rows = database.execute_read(  # nosec B608
        f"""SELECT id, timestamp, alert_type, description, severity,  # nosec B608
                   confidence, affected_mac, mitre_attack, cwe_id,
                   recommended_action, cvss_score, is_resolved
            FROM alerts
            {where}
            ORDER BY {sort_col} {order}
            LIMIT ? OFFSET ?""",  # nosec B608
        tuple(params) + (per_page, offset),
    )

    total = database.execute_read(f"SELECT count(*) as c FROM alerts {where}", tuple(params))[0]["c"]  # nosec B608

    if request.path == "/api/alerts":
        return jsonify(rows)

    return jsonify(
        {
            "alerts": rows,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page,
            },
        }
    )


# ─── Alert Detail ─────────────────────────────────────────────────────────────


@alerts_bp.route("/api/v1/alerts/<int:alert_id>")
def get_alert(alert_id: int):
    """Return full alert detail including evidence JSON."""
    rows = database.execute_read("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not rows:
        err = NotFoundError(f"Alert {alert_id} not found.")
        return jsonify(err.to_dict()), 404

    row = rows[0]
    # Attempt to parse evidence JSON for richer display
    import json

    try:
        row["evidence_parsed"] = json.loads(row.get("evidence", "{}") or "{}")
    except (json.JSONDecodeError, TypeError):
        row["evidence_parsed"] = {}

    return jsonify(row)


# ─── Resolve Single Alert ─────────────────────────────────────────────────────


@alerts_bp.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@alerts_bp.route("/api/v1/alerts/<int:alert_id>/resolve", methods=["POST"])
@alerts_bp.route("/api/alerts/resolve/<int:alert_id>", methods=["POST"])  # legacy alias
@require_session_token
def resolve_alert(alert_id: int):
    rows = database.execute_read("SELECT id FROM alerts WHERE id = ?", (alert_id,))
    if not rows:
        err = NotFoundError(f"Alert {alert_id} not found.")
        return jsonify(err.to_dict()), 404

    database.execute_write_sync("UPDATE alerts SET is_resolved = 1 WHERE id = ?", (alert_id,))
    database.record_audit(
        action="RESOLVE_ALERT",
        entity="alerts",
        entity_id=str(alert_id),
        actor="user",
        ip_address=request.remote_addr or "",
    )
    return jsonify({"success": True, "message": f"Alert {alert_id} resolved."})


# ─── Resolve All ──────────────────────────────────────────────────────────────


@alerts_bp.route("/api/alerts/resolve-all", methods=["POST"])
@alerts_bp.route("/api/v1/alerts/resolve-all", methods=["POST"])
@require_session_token
def resolve_all_alerts():
    result = database.execute_write_sync("UPDATE alerts SET is_resolved = 1 WHERE is_resolved = 0")
    count = result.get("rowcount", 0)
    database.record_audit(
        action="RESOLVE_ALL_ALERTS",
        entity="alerts",
        new_value=str(count),
        actor="user",
        ip_address=request.remote_addr or "",
    )
    return jsonify({"success": True, "message": f"Resolved {count} alerts."})


# ─── Alert Statistics ─────────────────────────────────────────────────────────


@alerts_bp.route("/api/v1/alerts/stats")
def alert_stats():
    """Aggregated alert statistics for dashboard charts."""
    severity_dist = database.execute_read(
        "SELECT severity, count(*) as count FROM alerts WHERE is_resolved=0 GROUP BY severity"
    )
    type_dist = database.execute_read("""SELECT alert_type, count(*) as count
           FROM alerts
           WHERE is_resolved=0
           GROUP BY alert_type
           ORDER BY count DESC
           LIMIT 10""")
    daily_trend = database.execute_read("""SELECT date(timestamp) as day, count(*) as count
           FROM alerts
           WHERE timestamp >= datetime('now', '-7 days')
           GROUP BY day
           ORDER BY day ASC""")
    top_affected = database.execute_read("""SELECT affected_mac, count(*) as count
           FROM alerts
           WHERE affected_mac IS NOT NULL AND is_resolved=0
           GROUP BY affected_mac
           ORDER BY count DESC
           LIMIT 5""")

    return jsonify(
        {
            "severity_distribution": severity_dist,
            "type_distribution": type_dist,
            "daily_trend": daily_trend,
            "top_affected_devices": top_affected,
        }
    )
