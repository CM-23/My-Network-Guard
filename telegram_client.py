import os
import json
import logging
import requests
import database

logger = logging.getLogger("TelegramClient")

_bot_token = ""

def init_client(token=None):
    global _bot_token
    if token:
        _bot_token = token
        return
        
    # Fallback to env or config.json
    _bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    if not _bot_token:
        try:
            if os.path.exists("config.json"):
                with open("config.json") as f:
                    cfg = json.load(f)
                    _bot_token = cfg.get("telegram", {}).get("bot_token", "").strip()
        except Exception as e:
            logger.error(f"Error loading config.json in telegram_client: {e}")

def get_bot_token():
    global _bot_token
    if not _bot_token:
        init_client()
    return _bot_token

def send_message(chat_id, text):
    token = get_bot_token()
    if not token:
        logger.warning("Telegram Bot token not configured. Cannot send message.")
        return False
        
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "Markdown"
    }
    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200:
            return True
        else:
            logger.error(f"Failed to send Telegram message to {chat_id}. Code: {r.status_code}, Response: {r.text}")
            return False
    except Exception as e:
        logger.error(f"Error calling Telegram API: {e}")
        return False

def send_alert_to_subscribers(alert_type, description, severity, timestamp):
    """Dispatches a formatted alert to all registered subscribers on Telegram."""
    # Send all security alerts (like MASS_SCAN, BEACONING_C2, etc.) to Telegram subscribers

        
    subscribers = database.execute_read("SELECT chat_id FROM telegram_subscribers")
    if not subscribers:
        logger.info("No Telegram subscribers registered. Skipping message dispatch.")
        return

    emoji = "🚨" if severity == "HIGH" else "⚠️" if severity == "MEDIUM" else "ℹ️"
    text = (
        f"{emoji} *NIDS Notification: {alert_type}*\n\n"
        f"• *Description:* {description}\n"
        f"• *Severity:* `{severity}`\n"
        f"• *Timestamp:* `{timestamp}`"
    )

    success_count = 0
    for sub in subscribers:
        chat_id = sub["chat_id"]
        if send_message(chat_id, text):
            success_count += 1
            
    logger.info(f"Dispatched Telegram alerts to {success_count}/{len(subscribers)} subscribers.")
