## 2025-02-21 - IP Spoofing Rate Limit Bypass
**Vulnerability:** The rate limiter middleware (`_get_client_ip`) relied on the `X-Forwarded-For` header for client IP extraction without validating the trusted proxy.
**Learning:** Parsing `X-Forwarded-For` manually opens up IP spoofing when deployed directly or without proper proxy setup. Attackers could evade the 5 req/min authentication rate limits by forging the header.
**Prevention:** Remove manual parsing of `X-Forwarded-For` and use `request.remote_addr` as the default source of truth. Rely on official middleware (e.g., `Werkzeug ProxyFix`) when deployed behind a proxy.
