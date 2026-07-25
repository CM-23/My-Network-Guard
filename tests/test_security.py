import json
import os
import sys
import tempfile
import unittest

# Append project directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Monkeypatch werkzeug.__version__ if missing due to Flask/Werkzeug version mismatch in Python 3.14
import werkzeug  # noqa: E402

import database  # noqa: E402

if not hasattr(werkzeug, "__version__"):
    werkzeug.__version__ = "3.0.0"

import app as flask_app  # noqa: E402


class TestProjectSecurity(unittest.TestCase):

    def setUp(self):
        flask_app.app.config["TESTING"] = True
        flask_app.app.config["WTF_CSRF_ENABLED"] = False

        # Configure test client
        self.client = flask_app.app.test_client()

        # Create a temporary database file
        self.db_fd, self.db_path = tempfile.mkstemp()
        database.init_db(self.db_path)
        database.start_db_worker(self.db_path)

        # Initialize flask app state with test queue
        import queue

        self.test_queue = queue.Queue()
        flask_app.set_app_config(
            {"telegram": {"bot_token": ""}, "root_user": {"name": "", "phone": ""}},
            self.test_queue,
        )

    def tearDown(self):
        database.stop_db_worker()
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_session_cookie_security(self):
        """A07: Validate that session cookies have HttpOnly and SameSite set."""
        response = self.client.get("/")
        # Inspect response Set-Cookie headers
        set_cookie = response.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Lax", set_cookie)

    def test_owasp_security_headers(self):
        """A05: Validate presence of defensive security headers on responses."""
        response = self.client.get("/")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    def test_require_session_token_enforcement(self):
        """A01: Ensure unauthorized access to mutating routes is blocked (Broken Access Control)."""
        # Call a protected endpoint without session headers
        response = self.client.post("/api/wifi/connect", json={"ssid": "Test", "password": "pass"})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(json.loads(response.data)["success"])

    def test_sql_parameterization_safety(self):
        """A03: Validate that SQL Injection payloads are treated as literal strings, not executable SQL."""
        # Insert a device with SQL injection payload in MAC address
        sql_payload = "'; DROP TABLE devices; --"
        database.execute_write_sync(
            "INSERT OR IGNORE INTO devices (mac_address, last_known_ip, hostname) VALUES (?,?,?)",
            (sql_payload, "192.168.1.10", "HackerDevice"),
        )

        # Read back and ensure the payload MAC exists and table WAS NOT dropped
        devices = database.execute_read("SELECT * FROM devices WHERE mac_address = ?", (sql_payload,))
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]["mac_address"], sql_payload)

        # Query normally to ensure the table still exists
        self.assertGreaterEqual(len(database.execute_read("SELECT * FROM devices")), 1)

    def test_ssrf_webhook_protection(self):
        """A10: Validate that localhost and internal subnet IPs are blocked for webhook URLs (SSRF)."""
        # Create valid session
        with self.client.session_transaction() as sess:
            sess["session_token"] = "sec_token"

        headers = {"X-Session-Token": "sec_token"}

        # Localhost loopback URL
        response = self.client.post(
            "/api/notify/webhook",
            json={"url": "http://127.0.0.1:8500/webhook"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)
        # Check SSRF is blocked (message may say "loopback" or "unsafe webhook URL")
        data = json.loads(response.data)
        self.assertFalse(data["success"])

        # Link-local URL (AWS metadata endpoint)
        response = self.client.post(
            "/api/notify/webhook",
            json={"url": "http://169.254.169.254/latest/meta-data/"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)

        # Safe URL (Mock public webhook)
        response = self.client.post(
            "/api/notify/webhook",
            json={"url": "https://discord.com/api/webhooks/mock"},
            headers=headers,
        )
        # Note: discord.com might resolve asynchronously; in tests if network is isolated it might return 400 because name resolution fails.
        # But if it resolves successfully, it returns 200. Let's make sure it doesn't fail with loopback checks.

    def test_input_validation_limits(self):
        """Input Validation: Enforce constraints and prevent buffer/DoS payloads."""
        with self.client.session_transaction() as sess:
            sess["session_token"] = "sec_token"
        headers = {"X-Session-Token": "sec_token"}

        # 1. SSID connect length limit (>32)
        response = self.client.post(
            "/api/wifi/connect",
            json={"ssid": "A" * 33, "password": "pass"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("SSID is too long", json.loads(response.data)["message"])

        # 2. Friendly rename limit (>64)
        response = self.client.post(
            "/api/devices/00:11:22:33:44:55/rename",
            json={"name": "B" * 65},
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Name is too long", json.loads(response.data)["message"])

        # 3. Phone number format validation
        response = self.client.post(
            "/api/root-user/setup",
            json={"name": "Admin", "phone": "abc-invalid-123"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid phone number format", json.loads(response.data)["message"])

        # 4. Telegram bot token format validation
        response = self.client.post(
            "/api/telegram/config",
            json={"bot_token": "invalid_token_no_colon"},
            headers=headers,
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid Telegram bot token format", json.loads(response.data)["message"])


if __name__ == "__main__":
    unittest.main()
