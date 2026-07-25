"""
backend_api/middleware/auth_middleware.py — Optional JWT authentication.

When REQUIRE_AUTH=true (e.g., cloud/Render deployments), all mutating
endpoints require a valid JWT access token.

When REQUIRE_AUTH=false (default, local use), the existing session-token
CSRF protection is used instead — no login screen required.

Roles:
  admin   — full read/write access, can delete devices and resolve all alerts
  analyst — read + resolve alerts, rename devices; cannot modify settings
  viewer  — read-only

OWASP ASVS V2.1: Authentication Security
OWASP ASVS V4.1: Access Control
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Optional

from flask import jsonify, request, session

logger = logging.getLogger("Auth")

# ─── Constants ────────────────────────────────────────────────────────────────

_REQUIRE_AUTH = False
_JWT_SECRET = ""

# Revoked JTI set (in-memory — cleared on restart)
_revoked_jtis: set[str] = set()


def configure_auth(require_auth: bool, jwt_secret: str) -> None:
    """Initialize auth module from app config."""
    global _REQUIRE_AUTH, _JWT_SECRET
    _REQUIRE_AUTH = require_auth
    _JWT_SECRET = jwt_secret or secrets.token_hex(32)
    if require_auth:
        logger.info("JWT authentication ENABLED (REQUIRE_AUTH=true)")
    else:
        logger.info("JWT authentication DISABLED — using session token CSRF mode")


def revoke_token(jti: str) -> None:
    """Add a JTI to the revocation set (logout)."""
    _revoked_jtis.add(jti)


# ─── Session Token CSRF (legacy/local mode) ──────────────────────────────────


def require_session_token(f: Callable) -> Callable:
    """
    CSRF protection decorator using X-Session-Token header.
    Used when REQUIRE_AUTH=false (local mode).
    The session token is injected into the HTML page and must match
    the value stored in the server-side session.

    OWASP ASVS V4.3.1: CSRF token verification
    """

    @wraps(f)
    def decorated(*args: Any, **kwargs: Any) -> Any:
        # If JWT auth is enabled, skip session token check
        if _REQUIRE_AUTH:
            return f(*args, **kwargs)

        token = request.headers.get("X-Session-Token", "")
        expected = session.get("session_token", "")

        if not expected or not token:
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Unauthorized: missing session token.",
                    }
                ),
                403,
            )

        # Constant-time comparison to prevent timing attacks
        if not secrets.compare_digest(token, expected):
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Unauthorized: invalid session token.",
                    }
                ),
                403,
            )

        return f(*args, **kwargs)

    return decorated


# ─── JWT Auth (cloud/production mode) ────────────────────────────────────────


def _decode_jwt(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT token.
    Returns the payload dict or None on failure.
    Uses HS256 with the configured secret.
    Pure-Python implementation to avoid heavy dependency for simple use.
    """
    try:
        import base64
        import hashlib
        import hmac
        import json

        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts

        # Verify signature
        msg = f"{header_b64}.{payload_b64}".encode()
        secret = _JWT_SECRET.encode()
        expected_sig = hmac.new(secret, msg, hashlib.sha256).digest()

        # Decode signature from base64url
        def _b64url_decode(s: str) -> bytes:
            s += "=" * (-len(s) % 4)
            return base64.urlsafe_b64decode(s)

        actual_sig = _b64url_decode(sig_b64)

        if not hmac.compare_digest(expected_sig, actual_sig):
            logger.warning("JWT signature verification failed.")
            return None

        # Decode payload
        payload = json.loads(_b64url_decode(payload_b64).decode())

        # Check expiry
        exp = payload.get("exp")
        if exp and datetime.now(timezone.utc).timestamp() > exp:
            logger.warning("JWT token expired.")
            return None

        # Check revocation
        jti = payload.get("jti", "")
        if jti in _revoked_jtis:
            logger.warning(f"JWT JTI {jti} has been revoked.")
            return None

        return payload

    except Exception as e:
        logger.debug(f"JWT decode error: {e}")
        return None


def _generate_jwt(
    user_id: str,
    role: str,
    expires_minutes: int = 60,
) -> str:
    """Generate a signed HS256 JWT token."""
    import base64
    import hashlib
    import hmac
    import json
    import uuid

    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        "jti": str(uuid.uuid4()),
    }

    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_enc = _b64url_encode(json.dumps(payload).encode())
    msg = f"{header}.{payload_enc}".encode()
    sig = hmac.new(_JWT_SECRET.encode(), msg, hashlib.sha256).digest()
    return f"{header}.{payload_enc}.{_b64url_encode(sig)}"


def create_tokens(user_id: str, role: str) -> dict:
    """Create access + refresh token pair."""
    access_token = _generate_jwt(user_id, role, expires_minutes=60)
    refresh_token = _generate_jwt(user_id, role, expires_minutes=60 * 24 * 7)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }


def require_auth(roles: Optional[list] = None) -> Callable:
    """
    Decorator for JWT-protected endpoints (only active when REQUIRE_AUTH=true).
    Accepts an optional list of allowed roles.

    Usage:
        @require_auth(roles=["admin", "analyst"])
        def my_route(): ...
    """

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args: Any, **kwargs: Any) -> Any:
            if not _REQUIRE_AUTH:
                # Auth disabled — fall through
                return f(*args, **kwargs)

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Authorization header missing or malformed.",
                        }
                    ),
                    401,
                )

            token = auth_header[7:]
            payload = _decode_jwt(token)

            if not payload:
                return (
                    jsonify({"success": False, "message": "Invalid or expired token."}),
                    401,
                )

            user_role = payload.get("role", "viewer")
            if roles and user_role not in roles:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"Insufficient permissions. Required: {roles}. Your role: {user_role}",
                        }
                    ),
                    403,
                )

            # Inject user context into kwargs
            kwargs["_current_user"] = payload
            return f(*args, **kwargs)

        return decorated

    return decorator
