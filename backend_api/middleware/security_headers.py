"""
backend_api/middleware/security_headers.py — Security response headers.

Applies OWASP-recommended security headers to every response.

OWASP ASVS V14.4: HTTP Security Headers
OWASP Top 10 A05: Security Misconfiguration
"""

from flask import Flask, request


def apply_security_headers(app: Flask) -> None:
    """Register an after_request hook that injects security headers."""

    @app.after_request
    def add_headers(response):
        # Content-Security-Policy: restrict resource loading
        # Allow Google Fonts + FontAwesome CDN for the dashboard
        csp_parts = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",  # inline JS needed for dashboard charts
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
            "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:",
            "img-src 'self' data: blob:",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_parts)

        # Anti-clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # MIME type sniffing prevention
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Referrer information control
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Limit browser API permissions
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), usb=(), payment=()"

        # HSTS — only over HTTPS
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"

        # Remove server banner
        response.headers.pop("Server", None)
        response.headers.pop("X-Powered-By", None)

        return response
