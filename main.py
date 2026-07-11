import os
import sys
import time
import queue
import argparse
import logging
import json
import signal
import threading

# ── Load .env FIRST (before any other imports use env vars) ──
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env", override=False)  # override=False: real env vars (Render) take priority
except ImportError:
    pass  # dotenv not installed — rely on OS environment variables

import database
import sniffer
import evaluator
import notifier
import telegram_agent
import blocker
from app import app, set_app_config

# ─── Logging Setup ───
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("nids.log", encoding="utf-8")
    ]
)
logger = logging.getLogger("Main")

_purge_thread = None
_shutdown_event = threading.Event()
_config = {}

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────

def load_config():
    global _config
    defaults = {
        "interface": "",
        "webhook_url": "",
        "root_user": {"name": "", "phone": ""},
        "twilio": {
            "account_sid": "",
            "auth_token": "",
            "from_number": "",
            "use_whatsapp": True
        },
        "telegram": {
            "bot_token": "",
            "chat_id": ""
        },
        "appliance_macs": [],
        "local_networks": ["192.168.", "10.", "172.16."],
        "out_of_hours_start": "01:00",
        "out_of_hours_end": "05:00",
        "out_of_hours_packet_limit": 50,
        "dns_entropy_threshold": 4.5,
        "dns_length_threshold": 60,
        "purge_interval_hours": 24,
        "traffic_retention_days": 7
    }

    if os.path.exists("config.json"):
        try:
            with open("config.json") as f:
                _config = json.load(f)
            for k, v in defaults.items():
                if k not in _config:
                    _config[k] = v
            # Ensure nested dicts have defaults
            _config.setdefault("root_user", defaults["root_user"])
            _config.setdefault("twilio", defaults["twilio"])
            _config.setdefault("telegram", defaults["telegram"])
            for k, v in defaults["twilio"].items():
                _config["twilio"].setdefault(k, v)
            for k, v in defaults["telegram"].items():
                _config["telegram"].setdefault(k, v)
            logger.info("Config loaded from config.json.")
        except Exception as e:
            logger.error(f"Config load error: {e}. Using defaults.")
            _config = defaults
    else:
        _config = defaults
        try:
            with open("config.json", "w") as f:
                json.dump(_config, f, indent=2)
            logger.info("Default config.json created.")
        except Exception:
            pass

    # ── Apply environment variables (override config.json) ──
    # .env values > config.json values. Render env vars > .env values.
    _apply_env_overrides(_config)

    return _config

def _apply_env_overrides(config: dict):
    """Overlay .env / OS environment variables onto the loaded config dict."""
    env = os.environ

    # Twilio (Removed - Using Telegram Bot)

    # Root user
    config.setdefault("root_user", {})
    if env.get("ROOT_USER_NAME"):  config["root_user"]["name"]  = env["ROOT_USER_NAME"]
    if env.get("ROOT_USER_PHONE"): config["root_user"]["phone"] = env["ROOT_USER_PHONE"]

    # Telegram
    config.setdefault("telegram", {})
    if env.get("TELEGRAM_BOT_TOKEN"): config["telegram"]["bot_token"] = env["TELEGRAM_BOT_TOKEN"]
    if env.get("TELEGRAM_CHAT_ID"):   config["telegram"]["chat_id"]   = env["TELEGRAM_CHAT_ID"]

    # Misc
    if env.get("WEBHOOK_URL"):           config["webhook_url"]           = env["WEBHOOK_URL"]
    if env.get("NETWORK_INTERFACE"):     config["interface"]             = env["NETWORK_INTERFACE"]
    if env.get("TRAFFIC_RETENTION_DAYS"):
        config["traffic_retention_days"] = int(env["TRAFFIC_RETENTION_DAYS"])
    if env.get("PURGE_INTERVAL_HOURS"):
        config["purge_interval_hours"]   = int(env["PURGE_INTERVAL_HOURS"])

# ─────────────────────────────────────────
# Background Workers
# ─────────────────────────────────────────

def purge_worker_loop():
    logger.info("Auto-purge loop started.")
    interval = _config.get("purge_interval_hours", 24) * 3600
    days = _config.get("traffic_retention_days", 7)
    while not _shutdown_event.is_set():
        for _ in range(int(interval)):
            if _shutdown_event.is_set():
                break
            time.sleep(1.0)
        if _shutdown_event.is_set():
            break
        try:
            database.execute_write_async(
                "DELETE FROM traffic_logs WHERE last_active < DATETIME('now', ?)",
                (f"-{days} days",)
            )
            logger.info("Scheduled log purge complete.")
        except Exception as e:
            logger.error(f"Purge error: {e}")
    logger.info("Auto-purge loop stopped.")

# ─────────────────────────────────────────
# Shutdown
# ─────────────────────────────────────────

def shutdown_system(signum=None, frame=None):
    if _shutdown_event.is_set():
        return
    logger.info("Shutting down Network Scanner...")
    _shutdown_event.set()
    sniffer.stop_sniffer()
    evaluator.stop_evaluator()
    notifier.stop_notifier()
    telegram_agent.stop_agent()
    if _purge_thread:
        _purge_thread.join(timeout=3.0)
    database.stop_db_worker()
    logger.info("Network Scanner offline.")
    if signum is not None:
        sys.exit(0)

# ─────────────────────────────────────────
# Main Entry Point
# ─────────────────────────────────────────

def main():
    global _purge_thread

    parser = argparse.ArgumentParser(description="Network Scanner — Your devices guard")
    parser.add_argument("-i", "--interface", help="Network interface (e.g. eth0, wlan0)")
    parser.add_argument("-s", "--simulation", action="store_true", help="Force simulation mode")
    parser.add_argument("-p", "--port", type=int, default=None, help="Dashboard port (default: 5000 or $PORT env)")
    parser.add_argument("--host", default=None, help="Bind host (default: 0.0.0.0 for Render, 127.0.0.1 locally)")
    parser.add_argument("--db", default="nids.db", help="SQLite database path")
    args = parser.parse_args()

    config = load_config()
    if args.interface:
        config["interface"] = args.interface

    # ── Render / cloud hosting compatibility ──
    # Render sets PORT env variable; also bind to 0.0.0.0 for public access
    port = args.port or int(os.environ.get("PORT", 5000))
    host = args.host or os.environ.get("HOST", "0.0.0.0")

    signal.signal(signal.SIGINT, shutdown_system)
    signal.signal(signal.SIGTERM, shutdown_system)

    packet_queue = queue.Queue(maxsize=2000)

    # Start all subsystems
    database.start_db_worker(args.db)
    blocker.load_blocked_from_db(database.execute_read)
    notifier.start_notifier(config.get("webhook_url", ""))
    telegram_agent.start_agent(config)
    evaluator.start_evaluator(packet_queue, config)
    sniffer.start_sniffer(
        packet_queue=packet_queue,
        interface=config.get("interface"),
        simulation_mode=(config.get("simulation_mode", False) or args.simulation)
    )

    set_app_config(config, packet_queue)

    # Purge worker
    _shutdown_event.clear()
    _purge_thread = threading.Thread(target=purge_worker_loop, name="PurgeThread", daemon=True)
    _purge_thread.start()

    logger.info(f"Network Scanner starting on http://{host}:{port}/")
    if host == "0.0.0.0":
        logger.info("Publicly accessible — suitable for Render/cloud deployment.")
    logger.info(f"Twilio WhatsApp webhook endpoint: http://YOUR-RENDER-URL/api/agent/reply")

    try:
        app.run(host=host, port=port, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logger.error(f"Flask error: {e}")
    finally:
        shutdown_system()

if __name__ == "__main__":
    main()
