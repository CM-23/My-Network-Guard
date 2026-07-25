import ipaddress
import json
import logging
import queue
import socket
import threading
import time
from urllib.parse import urlparse

import requests

logger = logging.getLogger("Notifier")

_notification_queue = queue.Queue()
_notifier_thread = None
_shutdown_event = threading.Event()
_webhook_url = ""


def is_safe_url(url):
    """Prevent SSRF attacks by resolving URL hostname and validating IP ranges."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = parsed.hostname
        if not host:
            return False

        # Resolve to IP to prevent DNS rebinding
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)

        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            return False
        return True
    except Exception:
        return False


def start_notifier(webhook_url=""):
    """Start the background notification worker thread."""
    global _notifier_thread, _webhook_url
    _webhook_url = webhook_url
    _shutdown_event.clear()

    if not _webhook_url:
        logger.warning("No Webhook URL configured. Notifications will be logged only.")

    _notifier_thread = threading.Thread(target=_notifier_worker, name="NotifierThread", daemon=True)
    _notifier_thread.start()


def stop_notifier():
    """Stop the background notification worker thread gracefully."""
    global _notifier_thread
    if _notifier_thread:
        logger.info("Shutting down notifier worker...")
        _shutdown_event.set()
        _notification_queue.put(None)
        _notifier_thread.join(timeout=5.0)
        _notifier_thread = None


def update_webhook_url(url):
    """Dynamically update the webhook URL during runtime."""
    global _webhook_url
    _webhook_url = url
    if url:
        logger.info(f"Webhook URL updated: {url[:30]}...")
    else:
        logger.info("Webhook URL cleared. Notifications disabled.")


def queue_alert(alert_type, description, severity, timestamp):
    """Enqueues an alert to be sent via webhook."""
    alert_payload = {
        "alert_type": alert_type,
        "description": description,
        "severity": severity,
        "timestamp": timestamp,
    }
    _notification_queue.put(alert_payload)


def _notifier_worker():
    """Background worker loop that dequeues and POSTs notifications."""
    logger.info("Notification worker thread started.")

    while not _shutdown_event.is_set() or not _notification_queue.empty():
        try:
            try:
                alert = _notification_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if alert is None:
                _notification_queue.task_done()
                break

            # Log the alert locally anyway
            logger.warning(
                f"[ALERT] Type: {alert['alert_type']} | Severity: {alert['severity']} | {alert['description']}"
            )

            # Dispatch to Telegram subscribers
            try:
                import telegram_client

                telegram_client.send_alert_to_subscribers(
                    alert["alert_type"],
                    alert["description"],
                    alert["severity"],
                    alert["timestamp"],
                )
            except Exception as tg_ex:
                logger.error(f"Error dispatching Telegram subscriber alerts: {tg_ex}")

            if not _webhook_url:
                _notification_queue.task_done()
                continue

            if not is_safe_url(_webhook_url):
                logger.error(f"SSRF Alert: blocked attempt to dispatch notification to unsafe URL: {_webhook_url}")
                _notification_queue.task_done()
                continue

            # Dispatch webhook
            try:
                # Format payload
                is_discord = "discord.com/api/webhooks" in _webhook_url or "discordapp.com/api/webhooks" in _webhook_url

                if is_discord:
                    # Professional Discord embed
                    color_map = {
                        "HIGH": 15158332,
                        "MEDIUM": 15105536,
                        "LOW": 3066993,
                    }  # Red  # Orange  # Green
                    color = color_map.get(alert["severity"], 3066993)

                    payload = {
                        "username": "Traffic Anomaly Detector",
                        "avatar_url": "https://img.icons8.com/color/96/shield.png",
                        "embeds": [
                            {
                                "title": f"🚨 NIDS Alert: {alert['alert_type']}",
                                "description": alert["description"],
                                "color": color,
                                "fields": [
                                    {
                                        "name": "Severity",
                                        "value": f"`{alert['severity']}`",
                                        "inline": True,
                                    },
                                    {
                                        "name": "Timestamp",
                                        "value": alert["timestamp"],
                                        "inline": True,
                                    },
                                ],
                                "footer": {"text": "Localized Network Intrusion Detection System"},
                            }
                        ],
                    }
                else:
                    # Standard JSON payload
                    payload = alert

                headers = {"Content-Type": "application/json"}
                max_retries = 3
                retry_delay = 2.0

                for attempt in range(1, max_retries + 1):
                    logger.info(f"Webhook dispatch attempt {attempt}/{max_retries}:")
                    logger.info(f"  URL    : {_webhook_url}")
                    logger.info("  Method : POST")
                    logger.info(f"  Headers: {headers}")
                    logger.info(f"  Payload: {json.dumps(payload)}")

                    try:
                        response = requests.post(_webhook_url, json=payload, headers=headers, timeout=5.0)
                        logger.info(f"  Response Code: {response.status_code}")
                        logger.info(f"  Response Body: {response.text[:200]}")

                        if response.status_code < 400:
                            logger.info(f"Webhook notification dispatched successfully on attempt {attempt}.")
                            break

                        # Check if error is non-transient (400, 401, 403, 404, 405)
                        if response.status_code in (400, 401, 403, 404, 405):
                            logger.error(f"Non-transient error {response.status_code} received. Skipping retries.")
                            break

                        # If transient, sleep and retry
                        logger.warning(f"Transient error {response.status_code} on attempt {attempt}. Retrying...")
                    except Exception as e:
                        logger.error(f"Network error on attempt {attempt}: {e}")
                        if attempt == max_retries:
                            raise

                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
            except Exception as ex:
                logger.error(f"Error dispatching webhook request: {ex}")
            finally:
                _notification_queue.task_done()

        except Exception as e:
            logger.error(f"Error in _notifier_worker loop: {e}")

    logger.info("Notification worker thread stopped.")
