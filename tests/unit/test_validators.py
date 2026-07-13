"""
tests/unit/test_validators.py — Unit tests for shared input validators.

Validates all edge cases, boundary conditions, and security-relevant inputs.
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.validators import (
    validate_mac,
    validate_ip,
    validate_ssid,
    validate_password,
    validate_friendly_name,
    validate_phone,
    validate_chat_id,
    validate_bot_token,
    validate_alert_id,
    validate_severity,
    validate_notes,
    is_safe_url,
)
from common.exceptions import (
    ValidationError,
    InputTooLongError,
    InvalidFormatError,
    SSRFAttemptError,
)


class TestMACValidator(unittest.TestCase):

    def test_valid_mac_colon(self):
        self.assertEqual(validate_mac("AA:BB:CC:DD:EE:FF"), "aa:bb:cc:dd:ee:ff")

    def test_valid_mac_dash(self):
        self.assertEqual(validate_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")

    def test_lowercase_passthrough(self):
        self.assertEqual(validate_mac("aa:bb:cc:dd:ee:ff"), "aa:bb:cc:dd:ee:ff")

    def test_invalid_mac_too_short(self):
        with self.assertRaises(InvalidFormatError):
            validate_mac("aa:bb:cc:dd:ee")

    def test_invalid_mac_letters(self):
        with self.assertRaises(InvalidFormatError):
            validate_mac("gg:hh:ii:jj:kk:ll")

    def test_empty_mac(self):
        with self.assertRaises(InvalidFormatError):
            validate_mac("")

    def test_none_mac(self):
        with self.assertRaises(InvalidFormatError):
            validate_mac(None)


class TestIPValidator(unittest.TestCase):

    def test_valid_ipv4(self):
        self.assertEqual(validate_ip("192.168.1.1"), "192.168.1.1")

    def test_valid_public_ip(self):
        self.assertEqual(validate_ip("8.8.8.8"), "8.8.8.8")

    def test_invalid_ip_letters(self):
        with self.assertRaises(InvalidFormatError):
            validate_ip("not-an-ip")

    def test_invalid_ip_out_of_range(self):
        with self.assertRaises(InvalidFormatError):
            validate_ip("256.1.1.1")

    def test_empty_ip(self):
        with self.assertRaises(InvalidFormatError):
            validate_ip("")


class TestSSIDValidator(unittest.TestCase):

    def test_valid_ssid(self):
        self.assertEqual(validate_ssid("MyNetwork"), "MyNetwork")

    def test_max_length_exactly_32(self):
        ssid = "A" * 32
        self.assertEqual(validate_ssid(ssid), ssid)

    def test_too_long_33_chars(self):
        with self.assertRaises(InputTooLongError) as ctx:
            validate_ssid("A" * 33)
        self.assertIn("SSID is too long", str(ctx.exception))

    def test_empty_ssid(self):
        with self.assertRaises(ValidationError):
            validate_ssid("")

    def test_ssid_with_spaces_is_valid(self):
        self.assertEqual(validate_ssid("My Home Network"), "My Home Network")


class TestPasswordValidator(unittest.TestCase):

    def test_valid_password(self):
        result = validate_password("Password123!")
        self.assertEqual(result, "Password123!")

    def test_too_long_password(self):
        with self.assertRaises(InputTooLongError):
            validate_password("A" * 65)

    def test_empty_password_returns_empty(self):
        self.assertEqual(validate_password(""), "")


class TestFriendlyNameValidator(unittest.TestCase):

    def test_valid_name(self):
        self.assertEqual(validate_friendly_name("Alice's Laptop"), "Alice's Laptop")

    def test_too_long_name(self):
        with self.assertRaises(InputTooLongError) as ctx:
            validate_friendly_name("B" * 65)
        self.assertIn("Name is too long", str(ctx.exception))

    def test_empty_name(self):
        with self.assertRaises(ValidationError):
            validate_friendly_name("")

    def test_html_angle_brackets_rejected(self):
        with self.assertRaises(InvalidFormatError):
            validate_friendly_name("<script>alert(1)</script>")

    def test_name_with_numbers(self):
        self.assertEqual(validate_friendly_name("Device 42"), "Device 42")


class TestPhoneValidator(unittest.TestCase):

    def test_valid_phone_with_plus(self):
        self.assertEqual(validate_phone("+1 555 123 4567"), "+1 555 123 4567")

    def test_valid_phone_dashes(self):
        self.assertEqual(validate_phone("+44-20-7946-0958"), "+44-20-7946-0958")

    def test_invalid_phone_letters(self):
        with self.assertRaises(InvalidFormatError) as ctx:
            validate_phone("abc-invalid-123")
        self.assertIn("Invalid phone number format", str(ctx.exception))

    def test_too_long_phone(self):
        with self.assertRaises(InputTooLongError):
            validate_phone("1" * 21)


class TestChatIDValidator(unittest.TestCase):

    def test_valid_positive_chat_id(self):
        self.assertEqual(validate_chat_id("123456789"), "123456789")

    def test_valid_negative_group_id(self):
        self.assertEqual(validate_chat_id("-100123456"), "-100123456")

    def test_invalid_chat_id_letters(self):
        with self.assertRaises(InvalidFormatError):
            validate_chat_id("notanumber")

    def test_empty_chat_id(self):
        with self.assertRaises(ValidationError):
            validate_chat_id("")


class TestBotTokenValidator(unittest.TestCase):

    def test_valid_bot_token(self):
        token = "123456789:AABBccddEEFFggHHiiJJkkLLmmNNooP"
        self.assertEqual(validate_bot_token(token), token)

    def test_invalid_no_colon(self):
        with self.assertRaises(InvalidFormatError) as ctx:
            validate_bot_token("invalid_token_no_colon")
        self.assertIn("Invalid Telegram bot token format", str(ctx.exception))

    def test_invalid_empty(self):
        with self.assertRaises(ValidationError):
            validate_bot_token("")


class TestAlertIDValidator(unittest.TestCase):

    def test_valid_alert_id(self):
        self.assertEqual(validate_alert_id("42"), 42)

    def test_zero_is_invalid(self):
        with self.assertRaises(ValidationError):
            validate_alert_id("0")

    def test_negative_is_invalid(self):
        with self.assertRaises(ValidationError):
            validate_alert_id("-5")

    def test_non_numeric_is_invalid(self):
        with self.assertRaises(ValidationError):
            validate_alert_id("abc")


class TestSSRFProtection(unittest.TestCase):

    def test_localhost_blocked(self):
        self.assertFalse(is_safe_url("http://localhost/webhook"))

    def test_loopback_blocked(self):
        self.assertFalse(is_safe_url("http://127.0.0.1:8080/hook"))

    def test_link_local_blocked(self):
        self.assertFalse(is_safe_url("http://169.254.169.254/latest/meta-data"))

    def test_private_class_a_blocked(self):
        self.assertFalse(is_safe_url("http://10.0.0.1/internal"))

    def test_private_class_c_blocked(self):
        self.assertFalse(is_safe_url("http://192.168.1.1/hook"))

    def test_invalid_scheme_rejected(self):
        self.assertFalse(is_safe_url("ftp://example.com/hook"))

    def test_public_url_allowed(self):
        self.assertTrue(is_safe_url("https://discord.com/api/webhooks/test/abcdef"))


class TestSeverityValidator(unittest.TestCase):

    def test_valid_severities(self):
        self.assertEqual(validate_severity("HIGH"), "HIGH")
        self.assertEqual(validate_severity("low"), "LOW")
        self.assertEqual(validate_severity("Medium"), "MEDIUM")

    def test_invalid_severity(self):
        with self.assertRaises(ValidationError):
            validate_severity("EXTREME")

    def test_empty_severity_returns_empty(self):
        self.assertEqual(validate_severity(""), "")


class TestNotesValidator(unittest.TestCase):

    def test_valid_notes(self):
        self.assertEqual(validate_notes("This is a normal note."), "This is a normal note.")

    def test_html_stripped(self):
        result = validate_notes("<b>Bold</b> text")
        self.assertNotIn("<b>", result)
        self.assertIn("Bold", result)

    def test_too_long_notes(self):
        with self.assertRaises(InputTooLongError):
            validate_notes("A" * 501)

    def test_non_string_returns_empty(self):
        self.assertEqual(validate_notes(None), "")


if __name__ == "__main__":
    unittest.main()
