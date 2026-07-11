"""
agent_manager.py
Manages Twilio SMS/WhatsApp notifications and synchronizes pending approvals.
"""
import logging
import threading
import queue

logger = logging.getLogger("AgentManager")

_twilio_sid = ""
_twilio_token = ""
_twilio_from = ""
_use_whatsapp = False
_root_user_phone = ""
_root_user_name = "Admin"

_send_queue = queue.Queue()
_worker_thread = None
_shutdown_event = threading.Event()

_pending_approvals = {}
_pending_lock = threading.Lock()

def start_agent(config: dict):
    global _twilio_sid, _twilio_token, _twilio_from, _use_whatsapp
    global _root_user_phone, _root_user_name, _worker_thread
    
    twilio_cfg = config.get("twilio", {})
    _twilio_sid = twilio_cfg.get("account_sid", "").strip()
    _twilio_token = twilio_cfg.get("auth_token", "").strip()
    _twilio_from = twilio_cfg.get("from_number", "").strip()
    _use_whatsapp = twilio_cfg.get("use_whatsapp", False)
    
    root_cfg = config.get("root_user", {})
    _root_user_phone = root_cfg.get("phone", "").strip()
    _root_user_name = root_cfg.get("name", "Admin").strip()
    
    _shutdown_event.clear()
    _worker_thread = threading.Thread(
        target=_sender_worker,
        name="AgentSenderThread",
        daemon=True
    )
    _worker_thread.start()
    logger.info("Agent manager started.")

def stop_agent():
    global _worker_thread
    if _worker_thread:
        _shutdown_event.set()
        _send_queue.put(None)
        _worker_thread.join(timeout=5.0)
        _worker_thread = None
    logger.info("Agent manager stopped.")

def update_config(config: dict):
    global _twilio_sid, _twilio_token, _twilio_from, _use_whatsapp
    global _root_user_phone, _root_user_name
    
    twilio_cfg = config.get("twilio", {})
    _twilio_sid = twilio_cfg.get("account_sid", "").strip()
    _twilio_token = twilio_cfg.get("auth_token", "").strip()
    _twilio_from = twilio_cfg.get("from_number", "").strip()
    _use_whatsapp = twilio_cfg.get("use_whatsapp", False)
    
    root_cfg = config.get("root_user", {})
    _root_user_phone = root_cfg.get("phone", "").strip()
    _root_user_name = root_cfg.get("name", "Admin").strip()
    
    logger.info("Agent config updated.")

def is_configured() -> bool:
    return bool(_twilio_sid and _twilio_token and _twilio_from and _root_user_phone)

def alert_new_device(device: dict):
    if not is_configured():
        logger.warning("Agent not configured. Skipping SMS alert.")
        return
    
    mac = device.get("mac_address", "Unknown")
    ip = device.get("last_known_ip", "Unknown")
    name = device.get("hostname") or device.get("custom_name") or f"Device-{mac[-5:].replace(':', '')}"
    
    with _pending_lock:
        _pending_approvals[mac] = device
        
    body = (
        f"⚠️ *New Device Detected on Your Network!*\n\n"
        f"📱 *Name:* {name}\n"
        f"🌐 *IP Address:* `{ip}`\n"
        f"🔌 *MAC Address:* `{mac}`\n\n"
        f"Reply *BLOCK* to block this device\n"
        f"Reply *ALLOW* to approve it\n\n"
        f"_Or manage from your Network Scanner dashboard._"
    )
    
    _send_queue.put({"to": _root_user_phone, "body": body})
    logger.info(f"New device SMS queued for {_root_user_phone}.")

def send_custom_message(message: str):
    if not is_configured():
        logger.warning("Agent not configured.")
        return
    _send_queue.put({"to": _root_user_phone, "body": message})

def handle_sms_reply(from_number: str, body: str) -> dict:
    body = body.strip().upper()
    tokens = body.split()
    action = tokens[0] if tokens else ""
    identifier = tokens[1] if len(tokens) > 1 else None
    
    normalized_from = "".join(filter(str.isdigit, from_number))
    normalized_root = "".join(filter(str.isdigit, _root_user_phone))
    
    if normalized_from not in normalized_root and normalized_root not in normalized_from:
        logger.warning(f"Ignoring SMS reply from unknown number: {from_number}")
        return {"action": "UNKNOWN", "message": "Unauthorized sender."}
        
    with _pending_lock:
        target = None
        if identifier:
            for mac, dev in _pending_approvals.items():
                if identifier.upper() in mac.upper() or identifier == dev.get("last_known_ip", ""):
                    target = (mac, dev)
                    break
        else:
            if _pending_approvals:
                last_mac = list(_pending_approvals.keys())[-1]
                target = (last_mac, _pending_approvals[last_mac])
                
        if not target:
            return {"action": action, "message": "No pending device found to act on."}
            
        mac, dev = target
        ip = dev.get("last_known_ip", "")
        
        if action == "BLOCK":
            _pending_approvals.pop(mac, None)
            logger.warning(f"Root user replied BLOCK for {mac} / {ip}")
            return {
                "action": "BLOCK",
                "mac": mac,
                "ip": ip,
                "message": f"Blocking {ip}..."
            }
        elif action == "ALLOW":
            _pending_approvals.pop(mac, None)
            logger.info(f"Root user replied ALLOW for {mac} / {ip}")
            return {
                "action": "ALLOW",
                "mac": mac,
                "ip": ip,
                "message": f"Device {ip} approved."
            }
        else:
            return {
                "action": "UNKNOWN",
                "message": f"Unknown command '{action}'. Reply BLOCK or ALLOW."
            }

def get_pending_approvals() -> list:
    with _pending_lock:
        return list(_pending_approvals.values())

def remove_pending(mac: str):
    with _pending_lock:
        _pending_approvals.pop(mac.lower(), None)

def _sender_worker():
    logger.info("Agent SMS sender thread started.")
    while not _shutdown_event.is_set() or not _send_queue.empty():
        try:
            item = _send_queue.get(timeout=1.0)
            if item is None:
                _send_queue.task_done()
                break
            try:
                _dispatch_sms(item["to"], item["body"])
            except Exception as e:
                logger.error(f"Agent sender error: {e}")
            finally:
                _send_queue.task_done()
        except queue.Empty:
            continue
    logger.info("Agent SMS sender thread stopped.")

def _dispatch_sms(to_number: str, body: str):
    try:
        from twilio.rest import Client
        client = Client(_twilio_sid, _twilio_token)
        
        if _use_whatsapp:
            from_addr = f"whatsapp:{_twilio_from}"
            to_addr = f"whatsapp:{to_number}"
        else:
            from_addr = _twilio_from
            to_addr = to_number
            
        logger.info(f"Dispatching Twilio message. From: {from_addr} | To: {to_addr}")
        message = client.messages.create(
            body=body,
            from_=from_addr,
            to=to_addr
        )
        logger.info(f"SMS sent to {to_number}. SID: {message.sid}")
    except ImportError:
        logger.error("Twilio package not installed. Run: pip install twilio")
    except Exception as e:
        logger.error(f"Twilio send error: {e}")
