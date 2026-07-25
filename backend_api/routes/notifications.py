"""
backend_api/routes/notifications.py — Notification configuration Blueprint.

Endpoints:
  POST /api/notify/telegram/subscribe  — Subscribe a chat_id
  POST /api/notify/telegram/test       — Send test alert
  GET  /api/telegram/config            — Get telegram config (masked)
  POST /api/telegram/config            — Save telegram bot token
  POST /api/notify/webhook             — Update webhook URL
  POST /api/webhook/test               — Send test webhook
  POST /api/v1/notify/telegram/subscribe
  ...

OWASP A10: SSRF protection on webhook URLs.
OWASP A03: Input validation on all fields.
"""

from __future__ import annotations

import logging
from datetime import datetime

from flask import Blueprint, jsonify, request

import database
import notifier
import telegram_agent
from backend_api.middleware.auth_middleware import require_session_token
from common.exceptions import SSRFAttemptError, ValidationError
from shared.validators import validate_bot_token, validate_chat_id, validate_webhook_url

logger = logging.getLogger("API.Notifications")

notifications_bp = Blueprint("notifications", __name__)

# Reference to live app config (set via set_app_config)
_app_config: dict = {}


def set_notifications_config(config: dict) -> None:
    global _app_config
    _app_config = config


# ─── Telegram Subscribe ───────────────────────────────────────────────────────


@notifications_bp.route("/api/notify/telegram/subscribe", methods=["POST"])
@notifications_bp.route("/api/v1/notify/telegram/subscribe", methods=["POST"])
@require_session_token
def telegram_subscribe():
    try:
        data = request.get_json(silent=True) or {}
        chat_id = validate_chat_id(str(data.get("chat_id", "")).strip())

        database.execute_write_sync(
            "INSERT OR IGNORE INTO telegram_subscribers (chat_id) VALUES (?)",
            (chat_id,),
        )
        return jsonify({"success": True, "message": f"Chat ID '{chat_id}' registered."})
    except ValidationError as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Telegram Test ────────────────────────────────────────────────────────────


@notifications_bp.route("/api/notify/telegram/test", methods=["POST"])
@notifications_bp.route("/api/telegram/test", methods=["POST"])
@require_session_token
def telegram_test():
    rows = database.execute_read("SELECT chat_id FROM telegram_subscribers")
    if not rows:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "No Telegram subscribers registered. Subscribe first.",
                }
            ),
            400,
        )

    ts = datetime.now().isoformat()
    database.execute_write_async(
        "INSERT INTO alerts (timestamp, alert_type, description, severity, is_resolved) VALUES (?,?,?,?,0)",
        (ts, "TEST_ALERT", "Test notification from dashboard.", "LOW"),
    )
    notifier.queue_alert("TEST_ALERT", "Test notification from dashboard.", "LOW", ts)
    return jsonify({"success": True, "message": "Test alert dispatched."})


# ─── Telegram Config ──────────────────────────────────────────────────────────


@notifications_bp.route("/api/telegram/config", methods=["GET"])
@notifications_bp.route("/api/v1/telegram/config", methods=["GET"])
def get_telegram_config():
    from shared.config import get_config

    cfg = get_config()
    token = cfg.telegram.bot_token or ""
    masked = (token[:4] + "****" + token[-4:]) if len(token) > 8 else ("****" if token else "")
    subs = len(database.execute_read("SELECT chat_id FROM telegram_subscribers")) > 0
    return jsonify(
        {
            "bot_token_masked": masked,
            "configured": bool(token) and subs,
            "subscriber_count": len(database.execute_read("SELECT chat_id FROM telegram_subscribers")),
        }
    )


@notifications_bp.route("/api/telegram/config", methods=["POST"])
@notifications_bp.route("/api/v1/telegram/config", methods=["POST"])
@require_session_token
def save_telegram_config():
    try:
        from shared.config import get_config, save_config

        data = request.get_json(silent=True) or {}
        raw_token = str(data.get("bot_token", "")).strip()

        if not raw_token:
            return jsonify({"success": False, "message": "bot_token is required."}), 400

        bot_token = validate_bot_token(raw_token)
        cfg = get_config()
        cfg.telegram.bot_token = bot_token

        telegram_agent.update_config({"telegram": {"bot_token": bot_token, "chat_id": cfg.telegram.chat_id}})
        save_config(cfg)
        return jsonify({"success": True, "message": "Bot token saved.", "configured": True})

    except ValidationError as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Webhook URL ──────────────────────────────────────────────────────────────


@notifications_bp.route("/api/notify/webhook", methods=["POST"])
@notifications_bp.route("/api/v1/notify/webhook", methods=["POST"])
@require_session_token
def update_webhook():
    try:
        from shared.config import get_config, save_config

        data = request.get_json(silent=True) or {}
        url = str(data.get("url", "")).strip()

        if url:
            validated_url = validate_webhook_url(url)
        else:
            validated_url = ""

        cfg = get_config()
        cfg.webhook_url = validated_url
        notifier.update_webhook_url(validated_url)
        save_config(cfg)

        return jsonify({"success": True, "message": "Webhook URL updated."})

    except (ValidationError, SSRFAttemptError) as e:
        return jsonify(e.to_dict()), e.http_status


# ─── Webhook Test ─────────────────────────────────────────────────────────────


@notifications_bp.route("/api/webhook/test", methods=["POST"])
@notifications_bp.route("/api/v1/webhook/test", methods=["POST"])
@require_session_token
def test_webhook():
    from shared.config import get_config

    cfg = get_config()
    if not cfg.webhook_url:
        return jsonify({"success": False, "message": "No webhook URL configured."}), 400

    try:
        import requests as _requests

        test_payload = {
            "username": "My Network Guard",
            "embeds": [
                {
                    "title": "✅ Webhook Test",
                    "description": "Your webhook is working correctly.",
                    "color": 3066993,
                }
            ],
        }
        resp = _requests.post(cfg.webhook_url, json=test_payload, timeout=5)
        if resp.status_code < 400:
            return jsonify({"success": True, "message": f"Test sent. HTTP {resp.status_code}"})
        return (
            jsonify({"success": False, "message": f"Webhook returned {resp.status_code}"}),
            400,
        )
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
