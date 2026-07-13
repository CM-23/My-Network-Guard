# Changelog — My Network Guard

All notable changes are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2025-07

### Architecture
- Extracted scanner engine into `scanner_agent/` package
- Introduced `backend_api/` Blueprint route modules
- Added `shared/` package (models, validators, config)
- Added `common/` package (constants, exceptions, logging)
- Flask app refactored to app factory pattern

### Security
- Centralised input validation (`shared/validators.py`)
- SSRF protection via `validate_webhook_url()` (DNS resolution + IP range checks)
- Rate limiting middleware (60/20/5 req/min per API tier)
- JWT optional auth mode (`REQUIRE_AUTH=true` for cloud deployments)
- Audit log table tracking all user mutations
- Structured JSON logging for cloud aggregators
- Expanded security headers (Permissions-Policy added)
- Constant-time CSRF token comparison

### Threat Detection
- **NEW**: ARP Spoofing / Cache Poisoning detector (MITRE T1557.002)
- **NEW**: MAC Spoofing detector (MITRE T1036)
- **NEW**: Port Scan detector (MITRE T1046)
- **NEW**: Mass Scan detector (MITRE T1595)
- **NEW**: Rogue DHCP Server detector (MITRE T1557.003)
- **NEW**: C2 Beaconing detector (MITRE T1071)
- **NEW**: Lateral Movement detector (MITRE T1021)
- Enhanced DNS Tunneling — higher accuracy, safe-domain whitelist, confidence scoring
- Out-of-Hours detector — improved time window logic
- All alerts include MITRE ATT&CK ID, CWE ID, confidence score, evidence dict, recommended action

### Database
- New columns: `confidence`, `evidence`, `mitre_attack`, `cwe_id`, `recommended_action`, `cvss_score` on `alerts`
- New columns: `risk_score`, `is_whitelisted`, `is_blacklisted`, `notes`, `open_ports`, `mitre_tags`, `deleted_at` on `devices`
- New table: `audit_log` (append-only user action audit trail)
- New table: `device_history` (IP/hostname change timeline)
- Performance indexes on all frequently-queried columns
- Soft deletes (deleted_at) replacing hard DELETEs on devices

### API
- API versioning: all endpoints accessible at `/api/v1/` (legacy `/api/` routes preserved)
- Pagination on `/api/devices` and `/api/alerts`
- Sorting and filtering on device and alert lists
- New endpoints: `/api/v1/alerts/stats`, `/api/v1/stats`, `/api/v1/stats/top-talkers`, `/api/v1/stats/protocols`
- Prometheus metrics at `/api/metrics`
- Device whitelist/blacklist endpoints
- Device history and per-device alerts endpoints

### Fingerprinting
- Extracted into `scanner_agent/fingerprint.py`
- 7 signal sources: OUI, TTL, hostname, DHCP, SSDP, mDNS, protocol
- 400+ OUI table entries (expanded from 300+)
- Evidence source tracking for transparency

### DevOps
- Multi-stage Dockerfile (non-root runtime, minimal image)
- Docker Compose with health check and volume persistence
- GitHub Actions CI: lint + unit + integration + security + SAST + dependency scan + Docker build
- GitHub Actions release pipeline on version tags
- Makefile with all developer commands
- requirements-dev.txt for test/lint tools

### Documentation
- Complete professional README
- SECURITY.md with OWASP controls reference
- CONTRIBUTING.md with development guidelines
- docs/ARCHITECTURE.md with design decisions
- docs/API.md with full endpoint reference
- docs/DEPLOYMENT.md with cloud deployment guide

---

## [1.0.0] — 2025-05

### Initial Release
- Passive traffic monitoring with Scapy
- Device discovery and OUI-based vendor identification
- WiFi connection management (Windows/Linux/macOS)
- DNS Tunneling detection
- Out-of-Hours activity monitoring
- New device discovery alerts
- Telegram bot integration
- Discord/Slack webhook support
- Server-Sent Events live dashboard
- SQLite persistence
- CSRF session token protection
