"""
backend_api/middleware/rate_limiter.py — In-memory rate limiting middleware.

Provides per-endpoint rate limiting without a Redis dependency.
Uses a sliding window counter per (IP, route) pair.

Limits:
  - Read endpoints:  60 req/min
  - Write endpoints: 10 req/min
  - Auth endpoints:   5 req/min

OWASP ASVS V13.2.6: Rate limiting on APIs
OWASP Top 10 A04: Insecure Design
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Dict, List, Tuple

from flask import Flask, jsonify, request

# ─── Configuration ────────────────────────────────────────────────────────────

_LIMITS: Dict[str, Tuple[int, int]] = {
    # route_pattern -> (max_requests, window_seconds)
    "auth": (5, 60),
    "write": (20, 60),
    "default": (60, 60),
}

# ─── State ───────────────────────────────────────────────────────────────────

_lock = threading.Lock()
# key: (ip, route, window_start_min) -> count
_counters: Dict[Tuple, List[float]] = defaultdict(list)


def _get_client_ip() -> str:
    """Extract the real client IP, respecting X-Forwarded-For behind proxies."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        # Take the first IP (client), not proxy IPs
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _classify_request() -> str:
    """Classify the current request to determine applicable rate limit tier."""
    path = request.path.lower()
    method = request.method.upper()

    if "/auth/" in path or path.endswith("/login") or path.endswith("/refresh"):
        return "auth"
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "write"
    return "default"


def _check_rate_limit(ip: str, route: str, limit: int, window: int) -> bool:
    """
    Sliding window rate limiter.
    Returns True if the request is allowed, False if rate-limited.
    """
    now = time.time()
    key = (ip, route)

    with _lock:
        # Filter timestamps within the current window
        timestamps = _counters[key]
        cutoff = now - window
        _counters[key] = [t for t in timestamps if t > cutoff]

        if len(_counters[key]) >= limit:
            return False  # Rate limit exceeded

        _counters[key].append(now)
        return True


def apply_rate_limiting(app: Flask) -> None:
    """Register rate limiting as a before_request hook."""

    @app.before_request
    def rate_limit():
        # Skip for static files
        if request.path.startswith("/static/"):
            return None

        ip = _get_client_ip()
        tier = _classify_request()
        max_req, window = _LIMITS.get(tier, _LIMITS["default"])
        route = request.endpoint or request.path

        if not _check_rate_limit(ip, route, max_req, window):
            retry_after = window
            response = jsonify(
                {
                    "success": False,
                    "error": "RATE_LIMIT_EXCEEDED",
                    "message": f"Too many requests. Limit: {max_req} per {window}s.",
                }
            )
            response.status_code = 429
            response.headers["Retry-After"] = str(retry_after)
            response.headers["X-RateLimit-Limit"] = str(max_req)
            response.headers["X-RateLimit-Window"] = str(window)
            return response

        return None


def cleanup_old_counters() -> None:
    """
    Purge expired counter entries.
    Call from a background thread periodically to prevent memory growth.
    """
    cutoff = time.time() - 120  # 2 minute window
    with _lock:
        stale = [k for k, ts_list in _counters.items() if not ts_list or max(ts_list) < cutoff]
        for k in stale:
            del _counters[k]
