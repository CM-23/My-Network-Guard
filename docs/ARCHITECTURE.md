# Architecture — My Network Guard

## Overview

My Network Guard is structured as an **Enhanced Monorepo** with clear package-level boundaries. Each package has a single responsibility and explicit inter-package contracts.

```
┌─────────────────────────────────────────────────────────────┐
│                         NETWORK                              │
│    (Local LAN: ARP, mDNS, SSDP, DHCP, NBNS packets)        │
└────────────────────────────────┬────────────────────────────┘
                                 │ raw frames
                                 ▼
┌─────────────────────────────────────────────────────────────┐
│                      scanner_agent/                          │
│                                                             │
│  sniffer.py ──────► threat_detector.py ──► ThreatEvent      │
│  (Scapy/Npcap)      (9 heuristics,          (to DB)         │
│                      MITRE mapping)                          │
│                                                             │
│  sniffer.py ──────► fingerprint.py ─────► FingerprintResult │
│  (ARP/mDNS/SSDP)    (7 signal sources,     (to DB)          │
│                      confidence scoring)                     │
│                                                             │
│  oui_table.py ◄────── fingerprint.py (OUI lookup)           │
└─────────────────────────────────┬───────────────────────────┘
                                  │ PacketPayload → queue
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                        evaluator.py                          │
│            (Consumes queue; writes to database)              │
└─────────────────────────────────┬───────────────────────────┘
                                  │ execute_write_async()
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                        database.py                           │
│    (WAL-mode SQLite; single-writer thread; parameterized)    │
│    Tables: devices, alerts, traffic_logs, audit_log,         │
│            device_history, telegram_subscribers              │
└─────────────────────────────────┬───────────────────────────┘
                                  │ execute_read()
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                        backend_api/                          │
│                                                             │
│   Flask App Factory (app.py)                                │
│   ├── routes/health.py      (/api/health, /api/v1/health)   │
│   ├── routes/devices.py     (/api/v1/devices)               │
│   ├── routes/alerts.py      (/api/v1/alerts)                │
│   ├── routes/statistics.py  (/api/v1/stats)                 │
│   ├── routes/notifications.py (/api/notify/*)               │
│   ├── routes/settings.py    (/api/v1/settings)              │
│   ├── middleware/security_headers.py                        │
│   ├── middleware/rate_limiter.py                            │
│   └── middleware/auth_middleware.py (JWT optional)          │
└─────────────────────────────────┬───────────────────────────┘
                                  │ HTTP + SSE
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                          Browser                             │
│           Dashboard (templates/index.html + app.js)          │
│           Real-time via SSE (/api/stream)                    │
└─────────────────────────────────────────────────────────────┘
```

---

## Package Responsibilities

### `scanner_agent/`
The **local network scanning engine**. Has zero knowledge of Flask or the web layer.

| Module | Responsibility |
|--------|---------------|
| `sniffer.py` | Packet capture via Scapy/Npcap; ARP scanning; simulation mode |
| `fingerprint.py` | Device OS/type detection from 7 signal sources |
| `threat_detector.py` | 9 threat heuristics; MITRE ATT&CK + CWE mapping |
| `oui_table.py` | Offline MAC OUI → vendor database (400+ entries) |

### `backend_api/`
The **REST API and middleware layer**. Has zero network scanning code.

| Module | Responsibility |
|--------|---------------|
| `routes/` | Flask Blueprint modules per resource type |
| `middleware/security_headers.py` | CSP, X-Frame, HSTS, Referrer-Policy |
| `middleware/rate_limiter.py` | Sliding window rate limits (no Redis) |
| `middleware/auth_middleware.py` | Session-token CSRF + optional JWT RBAC |

### `shared/`
**Data transfer objects and utilities** shared between scanner and API.

| Module | Responsibility |
|--------|---------------|
| `models.py` | Dataclasses: Device, Alert, ThreatEvent, PacketPayload |
| `validators.py` | Input validation; SSRF protection |
| `config.py` | Config loading with env-var override chain |

### `common/`
**Infrastructure** shared by all packages.

| Module | Responsibility |
|--------|---------------|
| `constants.py` | MITRE IDs, CWE IDs, severity levels, device types |
| `exceptions.py` | Custom exception hierarchy with HTTP status codes |
| `logging_config.py` | JSON + human-readable log formatters |

---

## Key Design Decisions

### 1. Why Monorepo instead of Microservices?
A full microservices split (separate scanner agent + backend processes) would require a message broker (Redis/RabbitMQ) or HTTP transport between processes, adding significant complexity to local deployment and demo setup. The current folder-package approach:
- Keeps "one command to run" simplicity for local use
- Makes future splitting trivial — just add network transport between packages
- Clearly communicates the intended component boundaries

### 2. Why SQLite + WAL instead of PostgreSQL?
- Zero-config local deployment (no DB server)
- WAL mode provides concurrent reads with a single write worker
- SQLAlchemy can be added as an abstraction layer, making PostgreSQL a config-change

### 3. Why in-memory rate limiting instead of Redis?
- Eliminates a hard dependency for local use
- Good enough for single-instance deployment (which covers 99% of local NDR use cases)
- Redis adapter can be swapped in if horizontal scaling is needed

### 4. Why optional JWT auth?
- Home/office use: session-token CSRF is sufficient; no login screen reduces friction
- Cloud deployment: `REQUIRE_AUTH=true` enables full JWT RBAC
- Gradual adoption without breaking existing functionality

---

## Inter-Package Communication

```
scanner_agent → evaluator.py → database.py    [thread-safe queue]
database.py   → backend_api/routes/            [execute_read()]
backend_api   → shared/validators              [direct import]
backend_api   → shared/config                 [get_config()]
All packages  → common/constants              [direct import]
All packages  → common/exceptions             [direct import]
```

---

## Concurrency Model

```
Thread 1: PacketCaptureThread    (sniffer.py)      → queue.put()
Thread 2: EvaluatorThread        (evaluator.py)    → queue.get() → db_write_queue.put()
Thread 3: DBWorkerThread         (database.py)     → db_write_queue.get() → sqlite3
Thread 4: NotificationDispatcher (notifier.py)     → HTTP POST (webhook/Telegram)
Thread 5: TelegramPollerThread   (telegram_agent.py)
Thread 6: Flask Request Threads  (backend_api/)    → execute_read() → sqlite3 (WAL)
Thread 7: ARPScanTimer           (sniffer.py)      → trigger_arp_scan() every 30s
```

SQLite WAL mode allows multiple simultaneous readers alongside the single writer (Thread 3). The `db_write_queue` (a Python `queue.Queue`) ensures all writes are serialized through Thread 3, preventing write contention.

---

## Security Architecture

```
User Input
    │
    ▼
shared/validators.py ──── Reject ──► 400 Bad Request
    │                   (ValidationError)
    │ Clean
    ▼
backend_api/middleware/auth_middleware.py
    │ Session token / JWT verified
    │ Rate limit checked
    ▼
backend_api/routes/*.py ──► database.py (parameterized SQL)
    │                              │
    │                              ▼
    │                         audit_log (immutable record)
    │
    ▼
backend_api/middleware/security_headers.py
    │ CSP + X-Frame + HSTS
    ▼
Browser
```
