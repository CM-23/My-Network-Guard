import os
import sqlite3
import queue
import threading
import logging

logger = logging.getLogger("Database")

# Global write queue for database writes
_db_write_queue = queue.Queue()
_db_worker_thread = None
_db_path = "nids.db"
_shutdown_event = threading.Event()

def init_db(db_path="nids.db"):
    """Initialize the SQLite database and create tables if they do not exist."""
    global _db_path
    _db_path = db_path
    
    # Establish connection to initialize schema
    conn = sqlite3.connect(_db_path)
    try:
        # Enable WAL mode for high concurrency (concurrent reads while writing)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        
        cursor = conn.cursor()
        
        # Create devices table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac_address TEXT PRIMARY KEY,
            last_known_ip TEXT NOT NULL,
            hostname TEXT DEFAULT 'Unknown',
            custom_name TEXT DEFAULT NULL,
            is_approved INTEGER DEFAULT 0,
            device_type TEXT DEFAULT 'unknown',
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # Migrations for existing databases
        for migration in [
            "ALTER TABLE devices ADD COLUMN custom_name TEXT DEFAULT NULL;",
            "ALTER TABLE devices ADD COLUMN is_approved INTEGER DEFAULT 0;",
            "ALTER TABLE devices ADD COLUMN device_type TEXT DEFAULT 'unknown';",
        ]:
            try:
                cursor.execute(migration)
            except Exception:
                pass  # Column already exists

        # Create traffic_logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            dest_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            packet_count INTEGER DEFAULT 1,
            last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(source_ip, dest_ip, dest_port, protocol)
        );
        """)

        # Create alerts table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH')),
            is_resolved INTEGER DEFAULT 0
        );
        """)

        # Create blocked_devices table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocked_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL,
            hostname TEXT DEFAULT 'Unknown',
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            blocked_by TEXT DEFAULT 'admin',
            is_active INTEGER DEFAULT 1
        );
        """)
        
        conn.commit()
        logger.info("Database initialized successfully with WAL mode.")
    except Exception as e:
        logger.error(f"Error during database initialization: {e}")
        raise e
    finally:
        conn.close()

def db_worker():
    """Worker thread that executes database write operations sequentially from the queue."""
    logger.info("Database write worker thread started.")
    # Keep a single persistent connection for the write worker
    conn = sqlite3.connect(_db_path)
    # Ensure WAL is set
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    
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
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                # Store last inserted row id or row count if useful
                res_holder['lastrowid'] = cursor.lastrowid
                res_holder['rowcount'] = cursor.rowcount
                res_holder['success'] = True
            except Exception as ex:
                conn.rollback()
                logger.error(f"DB Write error running query '{query}': {ex}")
                res_holder['success'] = False
                res_holder['error'] = ex
            finally:
                if res_event:
                    res_event.set()
                _db_write_queue.task_done()
                
        except Exception as e:
            logger.error(f"Error in db_worker loop: {e}")
            
    conn.close()
    logger.info("Database write worker thread stopped.")

def start_db_worker(db_path="nids.db"):
    """Start the background database writer thread."""
    global _db_worker_thread, _db_path
    _db_path = db_path
    _shutdown_event.clear()
    
    # Initialize the database schema first
    init_db(_db_path)
    
    _db_worker_thread = threading.Thread(target=db_worker, name="DBWorkerThread", daemon=True)
    _db_worker_thread.start()

def stop_db_worker():
    """Stop the background database writer thread gracefully."""
    global _db_worker_thread
    if _db_worker_thread:
        logger.info("Shutting down database worker...")
        _shutdown_event.set()
        _db_write_queue.put(None)
        _db_worker_thread.join(timeout=5.0)
        _db_worker_thread = None

def execute_write_async(query, params=()):
    """Asynchronously enqueues a write operation to the database. Does not block."""
    res_holder = {}
    _db_write_queue.put((query, params, None, res_holder))

def execute_write_sync(query, params=(), timeout=5.0):
    """Enqueues a write operation and blocks until complete, returning results or raising errors."""
    res_event = threading.Event()
    res_holder = {}
    _db_write_queue.put((query, params, res_event, res_holder))
    
    if not res_event.wait(timeout=timeout):
        raise TimeoutError("Database write operation timed out.")
        
    if not res_holder.get('success', False):
        raise res_holder.get('error', RuntimeError("Unknown database write error."))
        
    return res_holder

def execute_read(query, params=()):
    """Executes a read query directly in the calling thread (thread-safe due to SQLite WAL mode)."""
    conn = sqlite3.connect(_db_path)
    # Enable row factory for dictionary-like results
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        # Convert sqlite3.Row objects to standard python dicts for easier usage
        return [dict(row) for row in rows]
    except Exception as e:
        logger.error(f"DB Read error: {e}")
        return []
    finally:
        conn.close()
