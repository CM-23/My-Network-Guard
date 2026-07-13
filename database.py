"""
database.py — Async-safe SQLite database layer.

Architecture:
  - Single background write worker thread with a Queue prevents concurrent
    write contention on SQLite (which has a single writer at a time).
  - Reads are thread-safe under WAL mode; each read opens its own connection.
  - Schema migrations are additive (ALTER TABLE ADD COLUMN) — safe to re-run.

OWASP ASVS V3.5: Session management uses parameterized queries.
OWASP A03: All queries use parameterized inputs; no string concatenation.
"""

import logging
import queue
import sqlite3
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger("Database")

# ─── Module State ────────────────────────────────────────────────────────────

_db_write_queue = queue.Queue()
_db_worker_thread: Optional[threading.Thread] = None
_db_path = "nids.db"
_shutdown_event = threading.Event()


# ─── Schema Initialization ───────────────────────────────────────────────────


def init_db(db_path: str = "nids.db") -> None:
    """
    Initialize the SQLite database and create all tables.
    Safe to call on an existing database; existing rows are preserved.
    """
    global _db_path
    _db_path = db_path

    conn = sqlite3.connect(_db_path)
    try:
        # High-concurrency settings
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA temp_store=MEMORY;")

        cur = conn.cursor()

        # ── devices ──────────────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac_address      TEXT PRIMARY KEY,
            last_known_ip    TEXT NOT NULL,
            hostname         TEXT DEFAULT 'Unknown',
            custom_name      TEXT DEFAULT NULL,
            friendly_name    TEXT DEFAULT NULL,
            vendor           TEXT DEFAULT 'Unknown',
            device_type      TEXT DEFAULT 'unknown',
            operating_system TEXT DEFAULT 'Unknown',
            confidence_score INTEGER DEFAULT 0,
            is_online        INTEGER DEFAULT 1,
            is_approved      INTEGER DEFAULT 0,
            is_whitelisted   INTEGER DEFAULT 0,
            is_blacklisted   INTEGER DEFAULT 0,
            risk_score       INTEGER DEFAULT 0,
            notes            TEXT DEFAULT '',
            open_ports       TEXT DEFAULT '',
            mitre_tags       TEXT DEFAULT '',
            first_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_at       TIMESTAMP DEFAULT NULL
        );
        """)

        # ── alerts ───────────────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            alert_type         TEXT NOT NULL,
            description        TEXT NOT NULL,
            severity           TEXT CHECK(severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
            confidence         INTEGER DEFAULT 50,
            evidence           TEXT DEFAULT '',
            affected_mac       TEXT DEFAULT NULL,
            mitre_attack       TEXT DEFAULT '',
            cwe_id             TEXT DEFAULT '',
            recommended_action TEXT DEFAULT '',
            cvss_score         REAL DEFAULT NULL,
            is_resolved        INTEGER DEFAULT 0
        );
        """)

        # ── traffic_logs ──────────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip    TEXT NOT NULL,
            dest_ip      TEXT NOT NULL,
            dest_port    INTEGER NOT NULL,
            protocol     TEXT NOT NULL,
            packet_count INTEGER DEFAULT 1,
            last_active  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source_ip, dest_ip, dest_port, protocol)
        );
        """)

        # ── telegram_subscribers ─────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS telegram_subscribers (
            chat_id  TEXT PRIMARY KEY,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # ── wifi_sessions ────────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS wifi_sessions (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid           TEXT NOT NULL,
            bssid          TEXT,
            connected_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            disconnected_at TIMESTAMP
        );
        """)

        # ── audit_log ────────────────────────────────────────────────────────
        # Tracks all user actions for OWASP ASVS V7.2 audit trail.
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action     TEXT NOT NULL,
            entity     TEXT NOT NULL,
            entity_id  TEXT,
            old_value  TEXT,
            new_value  TEXT,
            actor      TEXT DEFAULT 'system',
            ip_address TEXT DEFAULT ''
        );
        """)

        # ── device_history ───────────────────────────────────────────────────
        # Tracks IP/hostname changes per device for timeline view.
        cur.execute("""
        CREATE TABLE IF NOT EXISTS device_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL,
            ip_address  TEXT,
            hostname    TEXT,
            event_type  TEXT NOT NULL,
            timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (mac_address) REFERENCES devices(mac_address)
        );
        """)

        # ── blocked_devices ──────────────────────────────────────────────────
        cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_devices (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT NOT NULL,
            mac        TEXT NOT NULL,
            hostname   TEXT DEFAULT 'Unknown',
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_by TEXT DEFAULT 'admin',
            is_active  INTEGER DEFAULT 1
        );
        """)

        # ── Run migrations ───────────────────────────────────────────────────
        _run_migrations(cur)

        # ── Create indexes ───────────────────────────────────────────────────
        _create_indexes(cur)

        conn.commit()
        logger.info(f"Database initialized at '{_db_path}' with WAL mode.")

    except Exception as e:
        logger.error(f"Database initialization error: {e}")
        raise
    finally:
        conn.close()


def _run_migrations(cur: sqlite3.Cursor) -> None:
    """
    Additive schema migrations — safe to re-run.
    Each migration is wrapped in a try/except to handle 'column already exists'.
    """
    migrations = [
        # devices — new columns added in v2.0
        "ALTER TABLE devices ADD COLUMN friendly_name TEXT DEFAULT NULL;",
        "ALTER TABLE devices ADD COLUMN vendor TEXT DEFAULT 'Unknown';",
        "ALTER TABLE devices ADD COLUMN is_online INTEGER DEFAULT 1;",
        "ALTER TABLE devices ADD COLUMN operating_system TEXT DEFAULT 'Unknown';",
        "ALTER TABLE devices ADD COLUMN confidence_score INTEGER DEFAULT 0;",
        "ALTER TABLE devices ADD COLUMN is_whitelisted INTEGER DEFAULT 0;",
        "ALTER TABLE devices ADD COLUMN is_blacklisted INTEGER DEFAULT 0;",
        "ALTER TABLE devices ADD COLUMN risk_score INTEGER DEFAULT 0;",
        "ALTER TABLE devices ADD COLUMN notes TEXT DEFAULT '';",
        "ALTER TABLE devices ADD COLUMN open_ports TEXT DEFAULT '';",
        "ALTER TABLE devices ADD COLUMN mitre_tags TEXT DEFAULT '';",
        "ALTER TABLE devices ADD COLUMN deleted_at TIMESTAMP DEFAULT NULL;",
        # alerts — new columns added in v2.0
        "ALTER TABLE alerts ADD COLUMN confidence INTEGER DEFAULT 50;",
        "ALTER TABLE alerts ADD COLUMN evidence TEXT DEFAULT '';",
        "ALTER TABLE alerts ADD COLUMN affected_mac TEXT DEFAULT NULL;",
        "ALTER TABLE alerts ADD COLUMN mitre_attack TEXT DEFAULT '';",
        "ALTER TABLE alerts ADD COLUMN cwe_id TEXT DEFAULT '';",
        "ALTER TABLE alerts ADD COLUMN recommended_action TEXT DEFAULT '';",
        "ALTER TABLE alerts ADD COLUMN cvss_score REAL DEFAULT NULL;",
    ]
    for sql in migrations:
        try:
            cur.execute(sql)
        except sqlite3.OperationalError:
            pass  # Column already exists — expected on existing databases


def _create_indexes(cur: sqlite3.Cursor) -> None:
    """Create performance indexes on frequently queried columns."""
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_devices_ip       ON devices (last_known_ip);",
        "CREATE INDEX IF NOT EXISTS idx_devices_online   ON devices (is_online);",
        "CREATE INDEX IF NOT EXISTS idx_devices_seen     ON devices (last_seen);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts (severity);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_resolved  ON alerts (is_resolved);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_alerts_mac       ON alerts (affected_mac);",
        "CREATE INDEX IF NOT EXISTS idx_traffic_src      ON traffic_logs (source_ip);",
        "CREATE INDEX IF NOT EXISTS idx_traffic_active   ON traffic_logs (last_active);",
        "CREATE INDEX IF NOT EXISTS idx_audit_entity     ON audit_log (entity, entity_id);",
        "CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_log (timestamp);",
        "CREATE INDEX IF NOT EXISTS idx_history_mac      ON device_history (mac_address);",
    ]
    for sql in indexes:
        try:
            cur.execute(sql)
        except sqlite3.OperationalError:
            pass


# ─── Write Worker ─────────────────────────────────────────────────────────────


def db_worker() -> None:
    """
    Background thread that processes database write operations serially.
    Single persistent connection for efficient write batching.
    """
    logger.info("Database write worker started.")
    conn = sqlite3.connect(_db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA foreign_keys=ON;")

    while not _shutdown_event.is_set() or not _db_write_queue.empty():
        try:
            try:
                task = _db_write_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            if task is None:
                _db_write_queue.task_done()
                break

            query, params, res_event, res_holder = task
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                conn.commit()
                res_holder["lastrowid"] = cur.lastrowid
                res_holder["rowcount"] = cur.rowcount
                res_holder["success"] = True
            except Exception as ex:
                conn.rollback()
                logger.error(f"DB write error for query '{query[:80]}': {ex}")
                res_holder["success"] = False
                res_holder["error"] = ex
            finally:
                if res_event:
                    res_event.set()
                _db_write_queue.task_done()

        except Exception as e:
            logger.error(f"DB worker loop error: {e}")

    conn.close()
    logger.info("Database write worker stopped.")


def start_db_worker(db_path: str = "nids.db") -> None:
    """Start the background database write worker thread."""
    global _db_worker_thread, _db_path
    _db_path = db_path
    _shutdown_event.clear()

    init_db(_db_path)

    _db_worker_thread = threading.Thread(target=db_worker, name="DBWorkerThread", daemon=True)
    _db_worker_thread.start()


def stop_db_worker() -> None:
    """Gracefully stop the database write worker thread."""
    global _db_worker_thread
    if _db_worker_thread:
        logger.info("Stopping database worker...")
        _shutdown_event.set()
        _db_write_queue.put(None)
        _db_worker_thread.join(timeout=5.0)
        _db_worker_thread = None


# ─── Public API ──────────────────────────────────────────────────────────────


def execute_write_async(query: str, params: tuple = ()) -> None:
    """
    Enqueue a write operation without blocking.
    OWASP A03: All writes use parameterized queries.
    """
    res_holder: Dict[str, Any] = {}
    _db_write_queue.put((query, params, None, res_holder))


def execute_write_sync(query: str, params: tuple = (), timeout: float = 5.0) -> Dict[str, Any]:
    """
    Enqueue a write and block until complete.
    Returns dict with 'lastrowid', 'rowcount', 'success'.
    Raises TimeoutError or the underlying exception on failure.
    """
    res_event = threading.Event()
    res_holder: Dict[str, Any] = {}
    _db_write_queue.put((query, params, res_event, res_holder))

    if not res_event.wait(timeout=timeout):
        raise TimeoutError(f"Database write timed out after {timeout}s for query: {query[:80]}")

    if not res_holder.get("success", False):
        err = res_holder.get("error")
        raise err if err else RuntimeError("Unknown database write error.")

    return res_holder


def execute_read(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """
    Execute a read query in the calling thread.
    Thread-safe under SQLite WAL mode.
    OWASP A03: Parameterized queries only.
    """
    conn = sqlite3.connect(_db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"DB read error: {e} | query: {query[:80]}")
        return []
    finally:
        conn.close()


def record_audit(
    action: str,
    entity: str,
    entity_id: str = "",
    old_value: str = "",
    new_value: str = "",
    actor: str = "system",
    ip_address: str = "",
) -> None:
    """
    Write an immutable audit log entry.
    OWASP ASVS V7.2: Log all security-relevant events.
    """
    execute_write_async(
        """
        INSERT INTO audit_log
            (action, entity, entity_id, old_value, new_value, actor, ip_address)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (action, entity, entity_id, old_value, new_value, actor, ip_address),
    )
