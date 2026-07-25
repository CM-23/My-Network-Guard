"""
app.py — Flask Application Factory.

Creates and configures the Flask application:
  1. Secure session & secret key
  2. Registers all Blueprint route modules
  3. Applies security headers middleware
  4. Applies rate limiting middleware
  5. Configures auth middleware
  6. Registers the SSE stream endpoint
  7. Maintains full backward compatibility with all existing /api/ routes

OWASP ASVS V14.4: Security headers on all responses.
OWASP ASVS V13.2.6: Rate limiting on APIs.
OWASP ASVS V4.1: Auth enforced on all mutating operations.
"""

import mimetypes
import os
import secrets
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, session

import database
from backend_api.middleware.auth_middleware import configure_auth
from backend_api.middleware.rate_limiter import apply_rate_limiting
from backend_api.middleware.security_headers import apply_security_headers
from backend_api.routes.alerts import alerts_bp
from backend_api.routes.devices import devices_bp
from backend_api.routes.health import health_bp
from backend_api.routes.notifications import notifications_bp, set_notifications_config
from backend_api.routes.settings import set_packet_queue, settings_bp
from backend_api.routes.statistics import stats_bp
from common.logging_config import get_logger

# Ensure correct MIME types on all hosting environments
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("application/javascript", ".js")

logger = get_logger("App")

# ─── Module State ─────────────────────────────────────────────────────────────

_app_config: dict = {}
_packet_queue_ref = None


def set_app_config(config_dict: dict, packet_queue) -> None:
    """
    Called from main.py to inject config and packet queue reference into this module.
    Preserved for backward compatibility with existing test_security.py tests.
    """
    global _app_config, _packet_queue_ref
    _app_config = config_dict
    _packet_queue_ref = packet_queue

    # Forward references to blueprint modules
    set_packet_queue(packet_queue)
    set_notifications_config(config_dict)

    # Configure auth middleware from injected config
    from shared.config import get_config

    cfg = get_config()
    configure_auth(cfg.require_auth, cfg.jwt_secret)


# ─── App Factory ──────────────────────────────────────────────────────────────


def create_app() -> Flask:
    """
    Create and configure the Flask application.
    Returns the configured app instance.
    """
    app = Flask(__name__, template_folder="templates", static_folder="static")

    # ── Secret Key (OWASP ASVS V2.10: never hardcode) ─────────────────────────
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

    # ── Secure Session Cookies (OWASP ASVS V3.4.1 / A07) ─────────────────────
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
        PERMANENT_SESSION_LIFETIME=86400,  # 24 hours
    )

    # ── Register Blueprints ───────────────────────────────────────────────────
    app.register_blueprint(health_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(notifications_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(stats_bp)

    # ── Middleware ────────────────────────────────────────────────────────────
    apply_security_headers(app)
    apply_rate_limiting(app)

    # ── Main page ─────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        if "session_token" not in session:
            session["session_token"] = secrets.token_hex(16)
        return render_template("index.html", session_token=session["session_token"])

    # ── SSE Stream ────────────────────────────────────────────────────────────
    @app.route("/api/stream")
    @app.route("/api/v1/stream")
    def sse_stream():
        """
        Server-Sent Events endpoint for real-time dashboard updates.
        Yields a merged stream of new_device, alert, and status_update events.
        """

        def _event_generator():
            import json
            import time

            last_device_ts = ""
            last_alert_id = 0
            heartbeat_count = 0

            # Initialise last_alert_id to current max to avoid re-sending old alerts
            rows = database.execute_read("SELECT MAX(id) as m FROM alerts")
            if rows and rows[0]["m"]:
                last_alert_id = rows[0]["m"]

            rows = database.execute_read("SELECT MAX(last_seen) as m FROM devices")
            if rows and rows[0]["m"]:
                last_device_ts = rows[0]["m"] or ""

            while True:
                try:
                    sent_something = False

                    # ── New / Updated Devices ─────────────────────────────────
                    new_devs = database.execute_read(
                        """SELECT mac_address, last_known_ip, hostname, friendly_name,
                                  vendor, is_online, device_type, last_seen
                           FROM devices
                           WHERE last_seen > ? AND deleted_at IS NULL
                           ORDER BY last_seen ASC
                           LIMIT 20""",
                        (last_device_ts,),
                    )
                    for dev in new_devs:
                        last_device_ts = max(last_device_ts, dev["last_seen"])
                        event_data = json.dumps(
                            {
                                "type": "new_device",
                                "device": dev,
                            }
                        )
                        yield f"data: {event_data}\n\n"
                        sent_something = True

                    # ── New Alerts ────────────────────────────────────────────
                    new_alerts = database.execute_read(
                        """SELECT id, timestamp, alert_type, description, severity,
                                  confidence, affected_mac, mitre_attack, is_resolved
                           FROM alerts
                           WHERE id > ?
                           ORDER BY id ASC
                           LIMIT 10""",
                        (last_alert_id,),
                    )
                    for alert in new_alerts:
                        last_alert_id = max(last_alert_id, alert["id"])
                        event_data = json.dumps(
                            {
                                "type": "alert",
                                "alert": alert,
                            }
                        )
                        yield f"data: {event_data}\n\n"
                        sent_something = True

                    # ── Heartbeat (every 15 poll cycles = ~30s) ───────────────
                    heartbeat_count += 1
                    if heartbeat_count >= 15 or not sent_something:
                        heartbeat_count = 0
                        hb = json.dumps(
                            {
                                "type": "heartbeat",
                                "timestamp": datetime.utcnow().isoformat(),
                            }
                        )
                        yield f"data: {hb}\n\n"

                    time.sleep(2)

                except GeneratorExit:
                    break
                except Exception as e:
                    logger.error(f"SSE error: {e}")
                    time.sleep(2)

        return Response(
            _event_generator(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # ── Error Handlers ────────────────────────────────────────────────────────

    @app.errorhandler(404)
    def not_found(e):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "NOT_FOUND",
                    "message": "Resource not found.",
                }
            ),
            404,
        )

    @app.errorhandler(405)
    def method_not_allowed(e):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "METHOD_NOT_ALLOWED",
                    "message": "Method not allowed.",
                }
            ),
            405,
        )

    @app.errorhandler(429)
    def rate_limited(e):
        return (
            jsonify(
                {
                    "success": False,
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests.",
                }
            ),
            429,
        )

    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Internal server error: {e}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": "INTERNAL_ERROR",
                    "message": "An internal error occurred.",
                }
            ),
            500,
        )

    return app


# ─── Module-level app instance ────────────────────────────────────────────────
# Created at import time so existing code that does `import app; app.app` works.

app = create_app()
