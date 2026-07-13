"""
backend_api/routes/statistics.py — Network statistics & traffic Blueprint.

Endpoints:
  GET /api/v1/stats              — Aggregated network stats for dashboard
  GET /api/traffic               — Traffic log list (legacy)
  GET /api/v1/traffic            — Traffic log list (paginated)
  GET /api/v1/stats/top-talkers  — Top source IPs by packet count
  GET /api/v1/stats/protocols    — Protocol distribution
"""

from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

import database

logger = logging.getLogger("API.Statistics")

stats_bp = Blueprint("statistics", __name__)


@stats_bp.route("/api/v1/stats")
def network_stats():
    """Aggregated statistics for the dashboard overview cards."""
    device_count = database.execute_read("SELECT count(*) as c FROM devices WHERE deleted_at IS NULL")[0]["c"]
    online_count = database.execute_read("SELECT count(*) as c FROM devices WHERE is_online=1 AND deleted_at IS NULL")[
        0
    ]["c"]
    alert_total = database.execute_read("SELECT count(*) as c FROM alerts")[0]["c"]
    alert_active = database.execute_read("SELECT count(*) as c FROM alerts WHERE is_resolved=0")[0]["c"]
    traffic_flows = database.execute_read("SELECT count(*) as c FROM traffic_logs")[0]["c"]
    severity_dist = database.execute_read("""SELECT severity, count(*) as count
           FROM alerts WHERE is_resolved=0
           GROUP BY severity""")
    device_types = database.execute_read("""SELECT device_type, count(*) as count
           FROM devices WHERE deleted_at IS NULL
           GROUP BY device_type
           ORDER BY count DESC""")
    recent_alerts = database.execute_read("""SELECT id, timestamp, alert_type, severity, description, is_resolved
           FROM alerts
           ORDER BY timestamp DESC
           LIMIT 5""")

    return jsonify(
        {
            "devices": {
                "total": device_count,
                "online": online_count,
                "offline": device_count - online_count,
            },
            "alerts": {
                "total": alert_total,
                "active": alert_active,
                "resolved": alert_total - alert_active,
                "severity_distribution": severity_dist,
            },
            "traffic_flows": traffic_flows,
            "device_types": device_types,
            "recent_alerts": recent_alerts,
        }
    )


@stats_bp.route("/api/traffic")
@stats_bp.route("/api/v1/traffic")
def traffic_logs():
    """
    Paginated traffic flow log list.
    Query params: page, per_page, src_ip
    """
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(200, max(1, int(request.args.get("per_page", 50))))
    src_ip = request.args.get("src_ip", "").strip()
    offset = (page - 1) * per_page

    conditions = []
    params: list = []
    if src_ip:
        conditions.append("source_ip = ?")
        params.append(src_ip)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    rows = database.execute_read(
        f"""SELECT source_ip, dest_ip, dest_port, protocol, packet_count, last_active
            FROM traffic_logs
            {where}
            ORDER BY packet_count DESC
            LIMIT ? OFFSET ?""",
        tuple(params) + (per_page, offset),
    )

    total = database.execute_read(f"SELECT count(*) as c FROM traffic_logs {where}", tuple(params))[0]["c"]

    return jsonify(
        {
            "traffic": rows,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) // per_page,
            },
        }
    )


@stats_bp.route("/api/v1/stats/top-talkers")
def top_talkers():
    """Top 10 source IPs by total packet count."""
    rows = database.execute_read("""SELECT source_ip, SUM(packet_count) as total_packets
           FROM traffic_logs
           GROUP BY source_ip
           ORDER BY total_packets DESC
           LIMIT 10""")
    return jsonify(rows)


@stats_bp.route("/api/v1/stats/protocols")
def protocol_distribution():
    """Protocol usage distribution."""
    rows = database.execute_read("""SELECT protocol, SUM(packet_count) as total_packets, count(*) as flows
           FROM traffic_logs
           GROUP BY protocol
           ORDER BY total_packets DESC""")
    return jsonify(rows)


@stats_bp.route("/api/v1/stats/timeline")
def alert_timeline():
    """Hourly alert count over last 24 hours."""
    rows = database.execute_read("""SELECT strftime('%Y-%m-%dT%H:00', timestamp) as hour,
                  count(*) as count,
                  severity
           FROM alerts
           WHERE timestamp >= datetime('now', '-24 hours')
           GROUP BY hour, severity
           ORDER BY hour ASC""")
    return jsonify(rows)
