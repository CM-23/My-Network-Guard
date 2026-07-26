import json
import os
import tempfile


from shared.config import (AppConfig, TelegramConfig, _apply_env, _apply_json,
                           get_config, load_config, save_config,
                           update_config_field)


def test_telegram_config_defaults():
    tc = TelegramConfig()
    assert tc.bot_token == ""
    assert tc.chat_id == ""


def test_app_config_defaults():
    cfg = AppConfig()
    assert cfg.port == 5000
    assert cfg.host == "127.0.0.1"
    assert cfg.require_auth is False
    assert cfg.jwt_secret == ""


def test_to_dict_hides_secrets():
    tc = TelegramConfig(bot_token="secret_bot", chat_id="123")
    cfg = AppConfig(jwt_secret="secret_jwt", telegram=tc)

    d = cfg.to_dict()
    assert "jwt_secret" not in d
    assert "bot_token" not in d["telegram"]
    assert d["telegram"]["chat_id"] == "123"
    assert d["port"] == 5000


def test_apply_json():
    cfg = AppConfig()
    raw = {
        "port": "8080",
        "host": "0.0.0.0",
        "simulation_mode": True,
        "appliance_macs": ["aa:bb:cc"],
        "root_user": {"name": "Admin", "phone": "123"},
        "telegram": {"bot_token": "bt", "chat_id": "cid"},
    }
    _apply_json(cfg, raw)

    assert cfg.port == 8080
    assert cfg.host == "0.0.0.0"
    assert cfg.simulation_mode is True
    assert cfg.appliance_macs == ["aa:bb:cc"]
    assert cfg.root_user["name"] == "Admin"
    assert cfg.telegram.bot_token == "bt"
    assert cfg.telegram.chat_id == "cid"


def test_apply_env(monkeypatch):
    monkeypatch.setenv("PORT", "9090")
    monkeypatch.setenv("HOST", "1.1.1.1")
    monkeypatch.setenv("REQUIRE_AUTH", "yes")
    monkeypatch.setenv("JWT_SECRET", "supersecret")
    monkeypatch.setenv("NETWORK_INTERFACE", "eth1")
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "newbt")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "newcid")

    cfg = AppConfig()
    _apply_env(cfg)

    assert cfg.port == 9090
    assert cfg.host == "1.1.1.1"
    assert cfg.require_auth is True
    assert cfg.jwt_secret == "supersecret"
    assert cfg.interface == "eth1"
    assert cfg.telegram.bot_token == "newbt"
    assert cfg.telegram.chat_id == "newcid"


def test_load_save_get_config(monkeypatch):
    import shared.config

    # Use a temporary file for config.json
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"{}")
        tmp_path = f.name

    # Mock save_config so it writes to tmp_path
    original_save_config = save_config

    def mocked_save_config(cfg, config_path=tmp_path):
        return original_save_config(cfg, tmp_path)

    monkeypatch.setattr(shared.config, "save_config", mocked_save_config)

    # Clear any loaded config state
    shared.config._app_config = None

    try:
        # Load from empty json should create defaults
        cfg = load_config(tmp_path)
        assert cfg.port == 5000

        # Test update config field
        update_config_field("port", 3000)

        cfg2 = get_config()
        assert cfg2.port == 3000

        # Check file content
        with open(tmp_path, "r") as f:
            data = json.load(f)
            assert data["port"] == 3000
            assert "jwt_secret" not in data

    finally:
        os.unlink(tmp_path)
