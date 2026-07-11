import queue
import threading
import requests
import logging
import json

logger = logging.getLogger("Notifier")

_notification_queue = queue.Queue()
_notifier_thread = None
_shutdown_event = threading.Event()
_webhook_url = ""

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
        "timestamp": timestamp
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
            logger.warning(f"[ALERT] Type: {alert['alert_type']} | Severity: {alert['severity']} | {alert['description']}")
            
            if not _webhook_url:
                _notification_queue.task_done()
                continue
                
            # Dispatch webhook
            try:
                # Format payload
                is_discord = "discord.com/api/webhooks" in _webhook_url or "discordapp.com/api/webhooks" in _webhook_url
                
                if is_discord:
                    # Professional Discord embed
                    color_map = {
                        "HIGH": 15158332,    # Red
                        "MEDIUM": 15105536,  # Orange
                        "LOW": 3066993        # Green
                    }
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
                                    {"name": "Severity", "value": f"`{alert['severity']}`", "inline": True},
                                    {"name": "Timestamp", "value": alert["timestamp"], "inline": True}
                                ],
                                "footer": {
                                    "text": "Localized Network Intrusion Detection System"
                                }
                            }
                        ]
                    }
                else:
                    # Standard JSON payload
                    payload = alert
                    
                headers = {"Content-Type": "application/json"}
                response = requests.post(_webhook_url, json=payload, headers=headers, timeout=5.0)
                
                if response.status_code >= 400:
                    logger.error(f"Failed to send webhook. Response code: {response.status_code}. Message: {response.text}")
                else:
                    logger.info(f"Webhook notification dispatched successfully for {alert['alert_type']}.")
                    
            except Exception as ex:
                logger.error(f"Error dispatching webhook request: {ex}")
            finally:
                _notification_queue.task_done()
                
        except Exception as e:
            logger.error(f"Error in _notifier_worker loop: {e}")
            
    logger.info("Notification worker thread stopped.")
