"""
telegram_agent.py
Handles sending network alerts to Telegram.
Uses standard requests library to avoid external dependencies.
"""

import logging
import threading
import time

import requests

import database

logger = logging.getLogger("TelegramAgent")

_bot_token = ""
_chat_id = ""
_polling_thread = None
_shutdown_event = threading.Event()
_last_update_id = 0


def start_agent(config: dict):
    """Start the Telegram agent background worker."""
    global _bot_token, _chat_id, _polling_thread
    tg_cfg = config.get("telegram", {})
    _bot_token = tg_cfg.get("bot_token", "").strip()
    _chat_id = tg_cfg.get("chat_id", "").strip()

    if not _bot_token or not _chat_id:
        logger.info("Telegram Bot token or Chat ID not configured. Telegram alerts disabled.")
        return

    _shutdown_event.clear()
    _polling_thread = threading.Thread(target=_polling_worker, name="TelegramPollingThread", daemon=True)
    _polling_thread.start()
    logger.info("Telegram Agent polling thread started.")


def stop_agent():
    global _polling_thread
    if _polling_thread:
        _shutdown_event.set()
        _polling_thread.join(timeout=3.0)
        _polling_thread = None
    logger.info("Telegram Agent stopped.")


def update_config(config: dict):
    """Hot-reload configuration."""
    global _bot_token, _chat_id
    tg_cfg = config.get("telegram", {})
    new_token = tg_cfg.get("bot_token", "").strip()
    new_chat = tg_cfg.get("chat_id", "").strip()

    if new_token != _bot_token or new_chat != _chat_id:
        _bot_token = new_token
        _chat_id = new_chat
        stop_agent()
        start_agent(config)


def is_configured() -> bool:
    return bool(_bot_token and _chat_id)


# ─────────────────────────────────────────
# Sending Messages
# ─────────────────────────────────────────


def alert_new_device(device: dict):
    """Send alert text notification."""
    if not is_configured():
        return

    mac = device.get("mac_address", "Unknown")
    ip = device.get("last_known_ip", "Unknown")
    name = device.get("hostname") or device.get("friendly_name") or f"Device-{mac[-5:].replace(':', '')}"

    text = (
        f"⚠️ *New Device Detected on Your Network!*\n\n"
        f"📱 *Name:* {name}\n"
        f"🌐 *IP Address:* `{ip}`\n"
        f"🔌 *MAC Address:* `{mac}`"
    )

    _send_request("sendMessage", {"chat_id": _chat_id, "text": text, "parse_mode": "Markdown"})


def send_text(text: str):
    """Send plain text notification."""
    if not is_configured():
        return
    _send_request("sendMessage", {"chat_id": _chat_id, "text": text, "parse_mode": "Markdown"})


# ─────────────────────────────────────────
# Long Polling Worker
# ─────────────────────────────────────────


def _polling_worker():
    """Background worker that queries Telegram updates to handle user commands."""
    global _last_update_id
    logger.info("Telegram polling loop active.")

    # Fast initial fetch
    _fetch_latest_update_id()

    while not _shutdown_event.is_set():
        try:
            url = f"https://api.telegram.org/bot{_bot_token}/getUpdates"
            params = {"offset": _last_update_id + 1, "timeout": 5}
            r = requests.get(url, params=params, timeout=10)

            if r.status_code == 200:
                data = r.json()
                if data.get("ok"):
                    for update in data.get("result", []):
                        _last_update_id = update["update_id"]
                        _handle_update(update)
            elif r.status_code == 401:
                logger.error("Unauthorized: Invalid Telegram bot token.")
                time.sleep(15)  # Back off
            else:
                time.sleep(5)
        except requests.exceptions.RequestException:
            # Network issue, wait briefly
            time.sleep(5)
        except Exception as e:
            logger.error(f"Telegram polling error: {e}")
            time.sleep(5)


def _fetch_latest_update_id():
    """Fetch updates once to skip old message events on start."""
    global _last_update_id
    try:
        url = f"https://api.telegram.org/bot{_bot_token}/getUpdates"
        r = requests.get(url, params={"limit": 1}, timeout=5)
        if r.status_code == 200 and r.json().get("ok"):
            res = r.json().get("result", [])
            if res:
                _last_update_id = res[0]["update_id"]
    except Exception:
        pass


def _handle_update(update):
    """Parse incoming event. Specifically looking for /start message."""
    if "message" in update:
        msg = update["message"]
        text = msg.get("text", "").strip()
        chat_id = msg.get("chat", {}).get("id")

        if text.startswith("/start") and chat_id:
            logger.info(f"Auto-subscribing chat ID via Telegram /start: {chat_id}")
            database.execute_write_sync(
                "INSERT OR IGNORE INTO telegram_subscribers (chat_id) VALUES (?)", (str(chat_id),)
            )

            _send_request(
                "sendMessage",
                {
                    "chat_id": chat_id,
                    "text": (
                        "🛡️ *Network Visibility Guard - Subscription Activated!*\n\n"
                        "You have successfully subscribed to real-time network visibility alerts. "
                        "You will receive notifications when new devices join."
                    ),
                    "parse_mode": "Markdown",
                },
            )
            return


# ─────────────────────────────────────────
# HTTP Helper
# ─────────────────────────────────────────


def _send_request(method: str, payload: dict):
    if not _bot_token:
        return None
    try:
        url = f"https://api.telegram.org/bot{_bot_token}/{method}"
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code != 200:
            logger.error(f"Telegram API {method} failed: {r.text}")
        return r.json()
    except Exception as e:
        logger.error(f"Error sending request to Telegram ({method}): {e}")
        return None
