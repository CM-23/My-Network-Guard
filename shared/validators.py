"""
shared/validators.py — Centralised input validation utilities.

All user-supplied input passes through these validators before use.
This is the single enforcement point for input constraints.

OWASP ASVS V5.1: Input Validation
OWASP Top 10 A03: Injection
OWASP Top 10 A10: SSRF
"""

from __future__ import annotations

import re
import ipaddress
import socket
from typing import Optional
from urllib.parse import urlparse

from common.constants import InputLimits
from common.exceptions import (
    ValidationError,
    InputTooLongError,
    InvalidFormatError,
    SSRFAttemptError,
)


# ─── MAC Address ─────────────────────────────────────────────────────────────

_MAC_RE = re.compile(r"^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$", re.IGNORECASE)


def validate_mac(mac: str) -> str:
    """
    Validate and normalise a MAC address to lowercase colon-separated form.
    Raises InvalidFormatError on bad input.
    """
    if not mac or not isinstance(mac, str):
        raise InvalidFormatError("MAC address is required.")
    mac = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(mac):
        raise InvalidFormatError(f"Invalid MAC address format: '{mac}'")
    return mac


# ─── IP Address ──────────────────────────────────────────────────────────────

def validate_ip(ip: str) -> str:
    """
    Validate an IPv4 address string.
    Raises InvalidFormatError on bad input.
    """
    if not ip or not isinstance(ip, str):
        raise InvalidFormatError("IP address is required.")
    ip = ip.strip()
    try:
        ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        raise InvalidFormatError(f"Invalid IPv4 address: '{ip}'")
    return ip


# ─── SSID ────────────────────────────────────────────────────────────────────

def validate_ssid(ssid: str) -> str:
    """
    Validate WiFi SSID:
      - Required
      - Max 32 characters (IEEE 802.11 limit)
    Raises ValidationError on bad input.
    """
    if not ssid or not isinstance(ssid, str):
        raise ValidationError("SSID is required.")
    ssid = ssid.strip()
    if len(ssid) == 0:
        raise ValidationError("SSID cannot be empty.")
    if len(ssid) > InputLimits.MAX_SSID_LEN:
        raise InputTooLongError(f"SSID is too long. Max {InputLimits.MAX_SSID_LEN} characters.")
    return ssid


def validate_password(password: str) -> str:
    """
    Validate WiFi password:
      - Max 64 characters (WPA2 limit)
    """
    if not isinstance(password, str):
        return ""
    if len(password) > InputLimits.MAX_PASSWORD_LEN:
        raise InputTooLongError(f"Password is too long. Max {InputLimits.MAX_PASSWORD_LEN} characters.")
    return password


# ─── Friendly Name / Display Name ────────────────────────────────────────────

def validate_friendly_name(name: str) -> str:
    """
    Validate a user-supplied display name.
      - Required and non-empty
      - Max 64 characters
      - No HTML/script tags (prevent stored XSS)
    """
    if not name or not isinstance(name, str):
        raise ValidationError("Name is required.")
    name = name.strip()
    if len(name) == 0:
        raise ValidationError("Name cannot be empty.")
    if len(name) > InputLimits.MAX_NAME_LEN:
        raise InputTooLongError(f"Name is too long. Max {InputLimits.MAX_NAME_LEN} characters.")
    # Strip HTML tags to prevent stored XSS
    if re.search(r"[<>]", name):
        raise InvalidFormatError("Name must not contain HTML characters (< or >).")
    return name


# ─── Phone Number ────────────────────────────────────────────────────────────

_PHONE_RE = re.compile(r"^\+?[\d\s\-]+$")


def validate_phone(phone: str) -> str:
    """
    Validate a phone number:
      - Max 20 characters
      - Digits, spaces, dashes, optional leading +
    """
    if not phone or not isinstance(phone, str):
        raise ValidationError("Phone number is required.")
    phone = phone.strip()
    if len(phone) > InputLimits.MAX_PHONE_LEN:
        raise InputTooLongError(f"Phone number is too long. Max {InputLimits.MAX_PHONE_LEN} characters.")
    if not _PHONE_RE.match(phone):
        raise InvalidFormatError("Invalid phone number format.")
    return phone


# ─── Telegram Chat ID ────────────────────────────────────────────────────────

_CHAT_ID_RE = re.compile(r"^\-?\d+$")


def validate_chat_id(chat_id: str) -> str:
    """
    Validate a Telegram chat_id:
      - Max 20 characters
      - Numeric (optionally negative for group chats)
    """
    if not chat_id or not isinstance(chat_id, str):
        raise ValidationError("chat_id is required.")
    chat_id = chat_id.strip()
    if len(chat_id) > InputLimits.MAX_CHAT_ID_LEN:
        raise InputTooLongError("chat_id is too long.")
    if not _CHAT_ID_RE.match(chat_id):
        raise InvalidFormatError("Invalid chat_id format. Must be numeric.")
    return chat_id


# ─── Telegram Bot Token ──────────────────────────────────────────────────────

_BOT_TOKEN_RE = re.compile(r"^\d+:[\w\-]+$")


def validate_bot_token(token: str) -> str:
    """
    Validate a Telegram bot token:
      - Format: <numeric_id>:<alphanumeric_secret>
      - Max 100 characters
    """
    if not token or not isinstance(token, str):
        raise ValidationError("Bot token is required.")
    token = token.strip()
    if len(token) > InputLimits.MAX_TOKEN_LEN:
        raise InputTooLongError("Bot token is too long.")
    if not _BOT_TOKEN_RE.match(token):
        raise InvalidFormatError("Invalid Telegram bot token format.")
    return token


# ─── Webhook URL (SSRF Protection) ───────────────────────────────────────────

_ALLOWED_SCHEMES = {"http", "https"}


def validate_webhook_url(url: str) -> str:
    """
    Validate a webhook URL with full SSRF protection:
      1. Schema must be http or https
      2. Hostname must resolve
      3. Resolved IP must not be loopback, private, link-local, or reserved
      4. Max 2048 characters

    OWASP Top 10 A10: SSRF
    """
    if not url or not isinstance(url, str):
        raise ValidationError("Webhook URL is required.")
    url = url.strip()
    if len(url) > InputLimits.MAX_URL_LEN:
        raise InputTooLongError(f"Webhook URL is too long. Max {InputLimits.MAX_URL_LEN} characters.")

    parsed = urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise InvalidFormatError("Webhook URL must use http or https.")
    if not parsed.hostname:
        raise InvalidFormatError("Webhook URL must include a valid hostname.")

    # Resolve and validate IP — prevent DNS rebinding
    try:
        ip_str = socket.gethostbyname(parsed.hostname)
        ip = ipaddress.ip_address(ip_str)
    except OSError:
        raise InvalidFormatError(f"Cannot resolve hostname: '{parsed.hostname}'")
    except ValueError:
        raise InvalidFormatError("Cannot parse resolved IP address.")

    if ip.is_loopback:
        raise SSRFAttemptError("Webhook URL resolves to loopback address (SSRF blocked).")
    if ip.is_private:
        raise SSRFAttemptError("Webhook URL resolves to private subnet (SSRF blocked).")
    if ip.is_link_local:
        raise SSRFAttemptError("Webhook URL resolves to link-local address (SSRF blocked).")
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise SSRFAttemptError("Webhook URL resolves to a reserved/multicast address (SSRF blocked).")

    return url


def is_safe_url(url: str) -> bool:
    """
    Convenience wrapper for SSRF check that returns bool instead of raising.
    Preserves backward compatibility with notifier.py.
    """
    try:
        validate_webhook_url(url)
        return True
    except Exception:
        return False


# ─── Alert ID ────────────────────────────────────────────────────────────────

def validate_alert_id(alert_id) -> int:
    """Validate an alert ID is a positive integer."""
    try:
        aid = int(alert_id)
        if aid <= 0:
            raise ValueError
        return aid
    except (ValueError, TypeError):
        raise ValidationError("Invalid alert ID. Must be a positive integer.")


# ─── Severity Filter ──────────────────────────────────────────────────────────

def validate_severity(severity: str) -> str:
    """Validate a severity filter value."""
    from common.constants import Severity
    if not severity:
        return ""
    sev = severity.strip().upper()
    if sev not in Severity.ALL:
        raise ValidationError(f"Invalid severity. Must be one of: {', '.join(Severity.ALL)}")
    return sev


# ─── Notes / Text Fields ──────────────────────────────────────────────────────

def validate_notes(notes: str) -> str:
    """Validate and sanitise a free-text notes field."""
    if not isinstance(notes, str):
        return ""
    notes = notes.strip()
    if len(notes) > InputLimits.MAX_NOTES_LEN:
        raise InputTooLongError(f"Notes too long. Max {InputLimits.MAX_NOTES_LEN} characters.")
    # Strip HTML to prevent stored XSS
    notes = re.sub(r"<[^>]+>", "", notes)
    return notes
