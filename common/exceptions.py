"""
common/exceptions.py — Custom exception hierarchy.

Centralised exceptions prevent bare Exception catches and enable
structured error handling aligned with OWASP ASVS V7.4 (Error Handling).
"""


class AppBaseError(Exception):
    """Base class for all application-specific exceptions."""
    http_status: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str = "An unexpected error occurred."):
        super().__init__(message)
        self.message = message

    def to_dict(self) -> dict:
        return {
            "success": False,
            "error": self.error_code,
            "message": self.message
        }


# ─── Validation Errors ────────────────────────────────────────────────────────

class ValidationError(AppBaseError):
    """Input failed validation constraints."""
    http_status = 400
    error_code = "VALIDATION_ERROR"


class InputTooLongError(ValidationError):
    """Input exceeds maximum allowed length."""
    error_code = "INPUT_TOO_LONG"


class InvalidFormatError(ValidationError):
    """Input does not match the required format."""
    error_code = "INVALID_FORMAT"


# ─── Auth Errors ──────────────────────────────────────────────────────────────

class AuthError(AppBaseError):
    """Authentication or authorisation failure."""
    http_status = 401
    error_code = "AUTH_ERROR"


class InvalidTokenError(AuthError):
    """JWT token is missing, expired, or invalid."""
    error_code = "INVALID_TOKEN"


class InsufficientPermissionsError(AuthError):
    """Authenticated user lacks required role/permission."""
    http_status = 403
    error_code = "INSUFFICIENT_PERMISSIONS"


class SessionExpiredError(AuthError):
    """Session or token has expired."""
    error_code = "SESSION_EXPIRED"


# ─── Resource Errors ─────────────────────────────────────────────────────────

class NotFoundError(AppBaseError):
    """Requested resource does not exist."""
    http_status = 404
    error_code = "NOT_FOUND"


class ConflictError(AppBaseError):
    """Resource already exists or state conflict."""
    http_status = 409
    error_code = "CONFLICT"


# ─── Rate Limiting ────────────────────────────────────────────────────────────

class RateLimitError(AppBaseError):
    """Client has exceeded the rate limit."""
    http_status = 429
    error_code = "RATE_LIMIT_EXCEEDED"


# ─── Scanner Errors ───────────────────────────────────────────────────────────

class ScanError(AppBaseError):
    """Error during network scanning."""
    http_status = 500
    error_code = "SCAN_ERROR"


class NpcapMissingError(ScanError):
    """Npcap/WinPcap driver is not installed."""
    http_status = 503
    error_code = "NPCAP_MISSING"


class InsufficientPrivilegesError(ScanError):
    """Process lacks required OS privileges for packet capture."""
    http_status = 403
    error_code = "INSUFFICIENT_PRIVILEGES"


class ScapyUnavailableError(ScanError):
    """Scapy library is not installed or cannot be imported."""
    http_status = 503
    error_code = "SCAPY_UNAVAILABLE"


# ─── Database Errors ──────────────────────────────────────────────────────────

class DatabaseError(AppBaseError):
    """Database operation failed."""
    http_status = 503
    error_code = "DATABASE_ERROR"


class DatabaseTimeoutError(DatabaseError):
    """Database write operation timed out."""
    error_code = "DATABASE_TIMEOUT"


# ─── Security Errors ─────────────────────────────────────────────────────────

class SSRFAttemptError(AppBaseError):
    """Blocked SSRF attempt to private/loopback address."""
    http_status = 400
    error_code = "SSRF_BLOCKED"


class CommandInjectionError(AppBaseError):
    """Potential command injection payload detected."""
    http_status = 400
    error_code = "INJECTION_BLOCKED"
