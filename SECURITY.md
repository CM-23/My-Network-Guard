# Security Policy — My Network Guard

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Current |
| 1.x     | ❌ End of Life |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

If you discover a security vulnerability in this project, please report it responsibly:

1. Email the maintainer directly with the subject: `[SECURITY] My Network Guard`
2. Include:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Your suggested fix (optional but appreciated)

You will receive acknowledgment within 48 hours and a full response within 7 days.

---

## Security Controls Implemented

### OWASP Top 10 Mitigations

| Risk | Mitigation |
|------|-----------|
| **A01: Broken Access Control** | Session token CSRF verification on all mutating routes; JWT RBAC in cloud mode |
| **A02: Cryptographic Failures** | Secrets injected via env vars only; HTTPS enforced via HSTS header; no hardcoded credentials |
| **A03: Injection** | All SQL queries use parameterized inputs; HTML stripped from user-supplied strings |
| **A04: Insecure Design** | Input validation at API boundary (shared/validators.py); rate limiting middleware |
| **A05: Security Misconfiguration** | Security headers on all responses (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) |
| **A06: Vulnerable Components** | Dependency scanning via Safety in CI; Bandit SAST in CI |
| **A07: Auth Failures** | HttpOnly + SameSite session cookies; constant-time CSRF token comparison |
| **A08: Software Integrity** | GitHub Actions CI prevents deploying untested changes; Docker image signed |
| **A09: Logging Failures** | Structured JSON logging; audit_log table records all mutations |
| **A10: SSRF** | Webhook URL resolver blocks loopback, private, link-local, and multicast IPs |

### OWASP ASVS Controls

- **V2.10**: No hardcoded credentials — all secrets from environment
- **V3.4.1**: HttpOnly + SameSite session cookies
- **V4.3.1**: CSRF token verification (constant-time comparison)
- **V5.1**: Input validation on all user-supplied data
- **V7.1**: Sufficient log data for incident response
- **V7.3**: Audit log is append-only (INSERT only; no UPDATE/DELETE)
- **V13.2.6**: API rate limiting (60/20/5 req/min by tier)
- **V14.4**: Security response headers on all endpoints

---

## Operational Security Note

This application is designed for **authorized network monitoring only**.

On startup, the application enforces an authorization confirmation step:
```
⚠️ Do you confirm that you own or have administrative authorization to monitor this target network? (y/N):
```

Monitoring networks without explicit permission is illegal in most jurisdictions.
