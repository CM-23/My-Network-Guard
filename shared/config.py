"""
shared/config.py — Centralised configuration management.

Single source of truth for all application configuration.
Environment variables override config.json values.
Render/cloud env vars override .env values.

Priority chain:
  OS environment (Render) > .env file > config.json > hardcoded defaults

OWASP ASVS V2.10: Do not hardcode secrets.
OWASP ASVS V14.2: Dependency/configuration review.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Config")

_CONFIG_FILE = "config.json"


@dataclass
class TelegramConfig:
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class AppConfig:
    """
    Master application configuration.
    All fields have safe, functional defaults.
    """

    # ── Network ──────────────────────────────────────────────────────────
    interface: str = ""
    local_networks: List[str] = field(default_factory=lambda: ["192.168.", "10.", "172.16."])

    # ── Notifications ────────────────────────────────────────────────────
    webhook_url: str = ""
    telegram: TelegramConfig = field(default_factory=TelegramConfig)

    # ── User ─────────────────────────────────────────────────────────────
    root_user: Dict[str, str] = field(default_factory=lambda: {"name": "", "phone": ""})

    # ── Threat Detection Tuning ───────────────────────────────────────────
    appliance_macs: List[str] = field(default_factory=list)
    out_of_hours_start: str = "01:00"
    out_of_hours_end: str = "05:00"
    out_of_hours_packet_limit: int = 50
    dns_entropy_threshold: float = 4.5
    dns_length_threshold: int = 60

    # ── Data Retention ───────────────────────────────────────────────────
    purge_interval_hours: int = 24
    traffic_retention_days: int = 7

    # ── Scanner ──────────────────────────────────────────────────────────
    simulation_mode: bool = False
    scan_interval_seconds: int = 30

    # ── Server ───────────────────────────────────────────────────────────
    port: int = 5000
    host: str = "127.0.0.1"

    # ── Auth ─────────────────────────────────────────────────────────────
    require_auth: bool = False
    jwt_secret: str = ""  # Loaded from env; never from config.json

    # ── Feature Flags ────────────────────────────────────────────────────
    enable_threat_detection: bool = True
    enable_fingerprinting: bool = True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Never expose secrets
        d.pop("jwt_secret", None)
        if "telegram" in d:
            d["telegram"].pop("bot_token", None)
        return d


_app_config: Optional[AppConfig] = None


def load_config(config_path: str = _CONFIG_FILE) -> AppConfig:
    """
    Load configuration from config.json and apply environment variable overrides.
    Returns the global AppConfig singleton.
    """
    global _app_config

    cfg = AppConfig()
    raw: Dict[str, Any] = {}

    # 1. Load from JSON file
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            logger.info(f"Configuration loaded from {config_path}")
        except (json.JSONDecodeError, OSError) as e:
            logger.error(f"Failed to parse {config_path}: {e}. Using defaults.")
            raw = {}
    else:
        logger.info(f"No {config_path} found. Using defaults + env vars.")

    # Apply JSON values
    _apply_json(cfg, raw)

    # 2. Apply environment variable overrides (higher priority)
    _apply_env(cfg)

    _app_config = cfg

    # 3. Persist defaults back if file didn't exist
    if not os.path.exists(config_path):
        save_config(cfg, config_path)

    return cfg


def save_config(cfg: AppConfig, config_path: str = _CONFIG_FILE) -> None:
    """Persist configuration to config.json (excludes secrets)."""
    try:
        data = cfg.to_dict()
        # Always write telegram as nested object (without bot_token)
        data["telegram"] = {"chat_id": cfg.telegram.chat_id}
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        if os.name != "nt":
            os.chmod(config_path, 0o600)

        logger.debug(f"Configuration saved to {config_path}")
    except OSError as e:
        logger.error(f"Failed to save config: {e}")


def get_config() -> AppConfig:
    """Return the loaded config. Call load_config() first."""
    global _app_config
    if _app_config is None:
        _app_config = load_config()
    return _app_config


def update_config_field(key: str, value: Any) -> None:
    """Update a single field on the live config and persist."""
    cfg = get_config()
    if hasattr(cfg, key):
        setattr(cfg, key, value)
        save_config(cfg)
    else:
        logger.warning(f"Attempted to update unknown config key: {key}")


# ─── Internal Helpers ─────────────────────────────────────────────────────────


def _apply_json(cfg: AppConfig, raw: Dict[str, Any]) -> None:
    """Map JSON dict values onto the AppConfig dataclass."""
    str_fields = ["interface", "webhook_url", "out_of_hours_start", "out_of_hours_end", "host"]
    int_fields = [
        "out_of_hours_packet_limit",
        "dns_length_threshold",
        "purge_interval_hours",
        "traffic_retention_days",
        "scan_interval_seconds",
        "port",
    ]
    float_fields = ["dns_entropy_threshold"]
    bool_fields = ["simulation_mode", "require_auth", "enable_threat_detection", "enable_fingerprinting"]
    list_fields = ["appliance_macs", "local_networks"]

    for f in str_fields:
        if f in raw and isinstance(raw[f], str):
            setattr(cfg, f, raw[f])
    for f in int_fields:
        if f in raw:
            try:
                setattr(cfg, f, int(raw[f]))
            except (ValueError, TypeError):
                pass
    for f in float_fields:
        if f in raw:
            try:
                setattr(cfg, f, float(raw[f]))
            except (ValueError, TypeError):
                pass
    for f in bool_fields:
        if f in raw:
            setattr(cfg, f, bool(raw[f]))
    for f in list_fields:
        if f in raw and isinstance(raw[f], list):
            setattr(cfg, f, raw[f])

    # Nested: root_user
    if "root_user" in raw and isinstance(raw["root_user"], dict):
        cfg.root_user = {
            "name": str(raw["root_user"].get("name", "")),
            "phone": str(raw["root_user"].get("phone", "")),
        }

    # Nested: telegram
    if "telegram" in raw and isinstance(raw["telegram"], dict):
        cfg.telegram = TelegramConfig(
            bot_token=str(raw["telegram"].get("bot_token", "")),
            chat_id=str(raw["telegram"].get("chat_id", "")),
        )


def _apply_env(cfg: AppConfig) -> None:
    """Override config fields with environment variable values."""
    env = os.environ

    # Server
    if env.get("PORT"):
        try:
            cfg.port = int(env["PORT"])
        except ValueError:
            pass
    if env.get("HOST"):
        cfg.host = env["HOST"]

    # Auth
    if env.get("REQUIRE_AUTH"):
        cfg.require_auth = env["REQUIRE_AUTH"].lower() in ("true", "1", "yes")
    if env.get("JWT_SECRET"):
        cfg.jwt_secret = env["JWT_SECRET"]

    # Network
    if env.get("NETWORK_INTERFACE"):
        cfg.interface = env["NETWORK_INTERFACE"]

    # Notifications
    if env.get("WEBHOOK_URL"):
        cfg.webhook_url = env["WEBHOOK_URL"]

    # Telegram (never from config.json — env only)
    if env.get("TELEGRAM_BOT_TOKEN"):
        cfg.telegram.bot_token = env["TELEGRAM_BOT_TOKEN"]
    if env.get("TELEGRAM_CHAT_ID"):
        cfg.telegram.chat_id = env["TELEGRAM_CHAT_ID"]

    # Root user
    if env.get("ROOT_USER_NAME"):
        cfg.root_user["name"] = env["ROOT_USER_NAME"]
    if env.get("ROOT_USER_PHONE"):
        cfg.root_user["phone"] = env["ROOT_USER_PHONE"]

    # Retention
    if env.get("TRAFFIC_RETENTION_DAYS"):
        try:
            cfg.traffic_retention_days = int(env["TRAFFIC_RETENTION_DAYS"])
        except ValueError:
            pass
    if env.get("PURGE_INTERVAL_HOURS"):
        try:
            cfg.purge_interval_hours = int(env["PURGE_INTERVAL_HOURS"])
        except ValueError:
            pass

    # Simulation mode
    if env.get("SIMULATION_MODE"):
        cfg.simulation_mode = env["SIMULATION_MODE"].lower() in ("true", "1", "yes")
