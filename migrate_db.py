import sqlite3
import os
import logging

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s")
logger = logging.getLogger("Migrator")

def run_migration(db_path="nids.db"):
    if not os.path.exists(db_path):
        logger.info(f"Database {db_path} does not exist yet. It will be initialized on startup.")
        return

    logger.info(f"Connecting to database: {db_path}")
    conn = sqlite3.connect(db_path)
    try:
        # Enable WAL mode
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        
        cursor = conn.cursor()
        
        # 1. Extend devices table
        migrations = [
            ("ALTER TABLE devices ADD COLUMN vendor TEXT DEFAULT 'Unknown';", "vendor column"),
            ("ALTER TABLE devices ADD COLUMN friendly_name TEXT;", "friendly_name column"),
            ("ALTER TABLE devices ADD COLUMN is_online INTEGER DEFAULT 1;", "is_online column"),
            ("ALTER TABLE devices ADD COLUMN operating_system TEXT DEFAULT 'Unknown';", "operating_system column"),
            ("ALTER TABLE devices ADD COLUMN confidence_score INTEGER DEFAULT 0;", "confidence_score column")
        ]
        
        for query, desc in migrations:
            try:
                cursor.execute(query)
                logger.info(f"Successfully added {desc} to devices table.")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e).lower() or "already exists" in str(e).lower():
                    logger.info(f"Column for {desc} already exists. Skipping.")
                else:
                    logger.error(f"Error adding {desc}: {e}")
                    raise e

        # 2. Create wifi_sessions table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS wifi_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ssid TEXT NOT NULL,
            bssid TEXT,
            connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            disconnected_at TIMESTAMP
        );
        """)
        logger.info("Checked/created wifi_sessions table.")

        # 3. Create telegram_subscribers table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS telegram_subscribers (
            chat_id TEXT PRIMARY KEY,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)
        logger.info("Checked/created telegram_subscribers table.")

        conn.commit()
        logger.info("Schema migration completed successfully.")
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Migration failed: {e}")
        raise e
    finally:
        conn.close()

if __name__ == "__main__":
    run_migration()
