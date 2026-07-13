# My Network Guard 🛡️

> **Enterprise-grade Network Detection & Response (NDR) platform for home and office networks.**

[![CI](https://github.com/yourusername/my-network-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/my-network-guard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![OWASP](https://img.shields.io/badge/OWASP-ASVS%20Compliant-green.svg)](SECURITY.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-Bandit%20SAST-orange.svg)](.github/workflows/ci.yml)

---

A production-quality, passive Network Intrusion Detection System (NIDS) built with Python, Scapy, and SQLite. Silently monitors your local network, fingerprints connected devices, detects cyber threats, and delivers real-time alerts via Telegram and Discord/Slack webhooks — all from a stunning live dashboard.

---

> [!IMPORTANT]
> **Operational Scope & Authorization**
> This application is fully passive and read-only — it captures network traffic without injecting packets, blocking traffic, or interfering with connections.
>
> On startup, you must confirm authorization to monitor the target network. Monitoring without explicit permission is illegal.

---

## 🚀 Quick Start (3 commands)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start in simulation mode (no root/admin required)
python main.py --simulation --confirm-owner

# 3. Open dashboard
# http://localhost:5000
```

For live capture (requires Npcap on Windows, sudo on Linux):
```bash
# Windows (run as Administrator)
python main.py --confirm-owner

# Linux
sudo python main.py --confirm-owner
```

---

## ✨ Key Features

### 🔍 Passive Network Monitoring
- Scapy-based packet capture with BPF filters (`ip or arp`)
- Simulation mode for testing without hardware
- ARP cache + active ARP scan + passive discovery fallback chain
- Multi-protocol discovery: ARP, mDNS, SSDP, DHCP, NBNS, ICMP

### 🔬 Device Fingerprinting (7 Signal Sources)
| Source | Example |
|--------|---------|
| MAC OUI Prefix | `00:11:24:xx:xx:xx` → Apple |
| IP TTL Analysis | TTL 128 → Windows |
| Hostname Patterns | `iphone-alice` → iOS Phone |
| DHCP Vendor Class | `MSFT 5.0` → Windows |
| SSDP/UPnP Headers | `LGE WebOS` → LG Smart TV |
| mDNS Service Types | `_googlecast` → Chromecast |
| Protocol Hints | DHCP from new MAC → device join |

### 🚨 Threat Detection Engine (9 Detectors)

| Detection | MITRE ATT&CK | Severity |
|-----------|-------------|---------|
| **ARP Spoofing** — multiple MACs claim same IP | T1557.002 | HIGH |
| **DNS Tunneling** — high-entropy/long subdomains | T1071.004 | MEDIUM–HIGH |
| **Port Scan** — >15 unique ports probed | T1046 | MEDIUM–HIGH |
| **Mass Scan** — >150 packets/minute | T1595 | HIGH |
| **Rogue DHCP Server** — unexpected DHCP responder | T1557.003 | HIGH |
| **MAC Spoofing** — IP changes MAC address | T1036 | MEDIUM |
| **C2 Beaconing** — low-jitter regular intervals to WAN | T1071 | HIGH |
| **Out-of-Hours Activity** — appliance active during off-hours | T1078 | HIGH |
| **Lateral Movement** — device connects to >10 internal hosts | T1021 | HIGH |

Every alert includes: **MITRE ATT&CK ID**, **CWE ID**, **confidence score**, **evidence dictionary**, and **recommended action**.

### 📊 Live Dashboard
- Real-time device cards with vendor, OS badge, risk score, online indicator
- Alert threat feed with severity color coding
- System health panel (Npcap, Scapy, DB, Internet, Telegram, Webhook, Interface)
- Traffic flow visualization
- Dark mode design

### 🔔 Multi-Channel Alerting
- **Telegram Bot**: Auto-subscribe via `/start` command or manual Chat ID entry
- **Discord/Slack Webhooks**: SSRF-protected URL validation
- Test notifications from the dashboard

---

## 🏗️ Architecture

```
my-network-guard/
├── scanner_agent/          # Local scanning engine (Scapy, ARP, fingerprinting)
│   ├── sniffer.py          # Packet capture
│   ├── fingerprint.py      # Device OS/type detection (7 signals)
│   ├── threat_detector.py  # 9 threat heuristics with MITRE mapping
│   └── oui_table.py        # MAC vendor database (400+ entries)
├── backend_api/            # REST API layer
│   ├── routes/             # Blueprint modules per resource
│   └── middleware/         # Auth, rate limiting, security headers
├── shared/                 # DTOs, validators, config
│   ├── models.py           # Device, Alert, PacketPayload dataclasses
│   ├── validators.py       # Input validation (SSRF, SQL, XSS protection)
│   └── config.py           # Centralized configuration management
├── common/                 # Infrastructure
│   ├── constants.py        # MITRE codes, CWE IDs, severity levels
│   ├── exceptions.py       # Custom exception hierarchy
│   └── logging_config.py   # Structured JSON logging
├── templates/              # Dashboard HTML
├── static/                 # CSS + JavaScript
├── tests/
│   ├── unit/               # Threat detector, fingerprint, validator tests
│   ├── integration/        # API endpoint tests
│   └── security/           # OWASP tests
├── docker/                 # Dockerfile + docker-compose
└── docs/                   # Architecture, API, deployment guides
```

---

## 🌐 REST API Reference

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/health` | GET | None | Liveness probe |
| `/api/v1/health` | GET | None | Full component health |
| `/api/v1/stats` | GET | None | Aggregated network statistics |
| `/api/v1/devices` | GET | None | List devices (filter, sort, paginate) |
| `/api/v1/devices/<mac>` | GET | None | Device detail with fingerprint |
| `/api/v1/devices/<mac>` | PATCH | ✅ | Update friendly name |
| `/api/v1/devices/<mac>/whitelist` | POST | ✅ | Whitelist device |
| `/api/v1/devices/<mac>/history` | GET | None | IP/hostname change timeline |
| `/api/v1/devices/<mac>/alerts` | GET | None | Alerts for device |
| `/api/v1/alerts` | GET | None | List alerts (filter, paginate) |
| `/api/v1/alerts/<id>` | GET | None | Alert detail with evidence |
| `/api/v1/alerts/<id>/resolve` | POST | ✅ | Resolve alert |
| `/api/v1/alerts/stats` | GET | None | Alert statistics |
| `/api/v1/stats/top-talkers` | GET | None | Top 10 source IPs |
| `/api/v1/stats/protocols` | GET | None | Protocol distribution |
| `/api/notify/telegram/subscribe` | POST | ✅ | Subscribe Telegram chat |
| `/api/notify/webhook` | POST | ✅ | Update webhook URL |
| `/api/scan/trigger` | POST | ✅ | Trigger ARP scan |
| `/api/stream` | GET | None | SSE real-time event stream |
| `/api/metrics` | GET | None | Prometheus metrics |

---

## 🔐 Security Features (OWASP ASVS)

| Control | Implementation |
|---------|---------------|
| Input Validation (V5.1) | `shared/validators.py` — single enforcement point |
| SQL Injection (A03) | Parameterized queries throughout |
| CSRF Protection (V4.3.1) | Session token; constant-time comparison |
| SSRF Protection (A10) | DNS resolution + IP range blocking on webhook URLs |
| Security Headers (V14.4) | CSP, X-Frame-Options, X-Content-Type-Options, HSTS |
| Rate Limiting (V13.2.6) | 60/20/5 req/min by API tier |
| Audit Logging (V7.2) | Append-only `audit_log` table |
| Secret Management (V2.10) | All secrets via environment variables only |
| Session Cookies (V3.4.1) | HttpOnly + SameSite=Lax |

---

## 📋 Prerequisites

| Platform | Requirement |
|----------|-------------|
| All | Python 3.9+ |
| Windows | [Npcap](https://npcap.com/) (select WinPcap-compatible mode) |
| Linux | `sudo apt install libpcap-dev` |
| macOS | libpcap (pre-installed) |

---

## 🐳 Docker Deployment

```bash
# Build image
docker build -f docker/Dockerfile -t my-network-guard:latest .

# Run (simulation mode)
docker run -p 5000:5000 -e SIMULATION_MODE=true -e CONFIRM_OWNER=true my-network-guard:latest

# Or with Docker Compose
docker-compose -f docker/docker-compose.yml up
```

---

## ☁️ Cloud Deployment (Render)

> [!WARNING]
> Cloud deployments **cannot** access local network hardware. Real-time capture, ARP scanning, and WiFi management require a physical network adapter and admin privileges.
>
> Render instances run in **simulation mode** — ideal for exploring the dashboard interface and testing alert pipelines.

Deploy in one click:
```
render.yaml is pre-configured for Render.com deployment.
```

---

## 🧪 Testing

```bash
# Run all tests
make test

# Unit tests (threat detector, fingerprint, validators)
make test-unit

# Integration tests (API endpoints)
make test-int

# OWASP security tests
make test-security

# Coverage report
make coverage
```

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

---

## 📄 License

[MIT License](LICENSE)

---

## 📚 Documentation

- [Architecture Guide](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)
