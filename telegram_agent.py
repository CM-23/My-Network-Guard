"""
telegram_agent.py
Handles sending network alerts to Telegram and listening for callback query buttons (BLOCK / ALLOW).
Uses standard requests library to avoid external dependencies.
"""
import os
import logging
import threading
import time
import requests
import database
import blocker
import agent_manager

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
# Sending Messages with Buttons
# ─────────────────────────────────────────

def alert_new_device(device: dict):
    """Send alert with Block/Allow inline buttons."""
    if not is_configured():
        return

    mac  = device.get("mac_address", "Unknown")
    ip   = device.get("last_known_ip", "Unknown")
    name = device.get("hostname") or device.get("custom_name") or f"Device-{mac[-5:].replace(':','')}"

    # Queue in agent_manager pending list so both agents stay in sync
    with agent_manager._pending_lock:
        agent_manager._pending_approvals[mac] = device

    text = (
        f"⚠️ *New Device Detected on Your Network!*\n\n"
        f"📱 *Name:* {name}\n"
        f"🌐 *IP Address:* `{ip}`\n"
        f"🔌 *MAC Address:* `{mac}`\n\n"
        f"Would you like to approve or block this device?"
    )

    # Inline keyboard markup
    reply_markup = {
        "inline_keyboard": [
            [
                {"text": "🚫 Block", "callback_data": f"block|{mac}|{ip}"},
                {"text": "✓ Allow", "callback_data": f"allow|{mac}|{ip}"}
            ]
        ]
    }

    _send_request("sendMessage", {
        "chat_id": _chat_id,
        "text": text,
        "parse_mode": "Markdown",
        "reply_markup": reply_markup
    })

def send_text(text: str):
    """Send plain text notification."""
    if not is_configured():
        return
    _send_request("sendMessage", {
        "chat_id": _chat_id,
        "text": text,
        "parse_mode": "Markdown"
    })

# ─────────────────────────────────────────
# Callback and Long Polling Worker
# ─────────────────────────────────────────

def _polling_worker():
    """Background worker that queries Telegram updates to handle button click callbacks."""
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
    """Parse incoming event. Specifically looking for callback_query (button clicks)."""
    if "callback_query" not in update:
        return

    query = update["callback_query"]
    query_id = query["id"]
    data = query.get("data", "")
    message = query.get("message", {})
    chat_id = message.get("chat", {}).get("id")
    msg_id = message.get("message_id")
    original_text = message.get("text", "")

    # Answer callback to clear loading spinner on user client
    _send_request("answerCallbackQuery", {"callback_query_id": query_id})

    # Validate action
    if not data or "|" not in data:
        return

    action, mac, ip = data.split("|", 2)
    mac = mac.lower()

    if action == "block":
        # Call block function
        logger.warning(f"Telegram user requested BLOCK for {mac} / {ip}")
        
        # Enforce
        res = blocker.block_device(ip, mac)
        if res["success"]:
            # Update DB
            database.execute_write_async(
                "INSERT INTO blocked_devices (ip, mac, hostname, blocked_by) VALUES (?,?,?,'telegram_bot')",
                (ip, mac, f"Device-{mac[-5:]}")
            )
            database.execute_write_async("UPDATE devices SET is_approved=-1 WHERE mac_address=?", (mac,))
            agent_manager.remove_pending(mac)
            
            # Edit original message to show action success
            edited_text = original_text + "\n\n🚫 *Blocked by Admin via Telegram.*"
            _send_request("editMessageText", {
                "chat_id": chat_id,
                "message_id": msg_id,
                "text": edited_text,
                "parse_mode": "Markdown",
                "reply_markup": {"inline_keyboard": []}  # Remove buttons
            })
        else:
            send_text(f"❌ Blocker Error: {res.get('message', 'Failed to block.')}")

    elif action == "allow":
        logger.info(f"Telegram user requested ALLOW for {mac}")
        
        database.execute_write_async("UPDATE devices SET is_approved=1 WHERE mac_address=?", (mac,))
        agent_manager.remove_pending(mac)
        
        edited_text = original_text + "\n\n✅ *Approved by Admin via Telegram.*"
        _send_request("editMessageText", {
            "chat_id": chat_id,
            "message_id": msg_id,
            "text": edited_text,
            "parse_mode": "Markdown",
            "reply_markup": {"inline_keyboard": []}  # Remove buttons
        })

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
