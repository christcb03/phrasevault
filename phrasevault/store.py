# phrasevault/store.py
import sqlite3
from pathlib import Path
from typing import Optional

DEFAULT_DB = Path("data/truth_forest.db")

def open_db(db_path: Optional[Path] = None) -> sqlite3.Connection:
    db_path = db_path or DEFAULT_DB
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def init_schema(conn: sqlite3.Connection):
    conn.execute("""CREATE TABLE IF NOT EXISTS forest_nodes ( ... )""")  # unchanged

    conn.execute("""CREATE TABLE IF NOT EXISTS entries ( ... )""")  # unchanged

    # === NEW: Relationship table with learning ===
    conn.execute("""
        CREATE TABLE IF NOT EXISTS node_relationships (
            source_address TEXT,
            target_address TEXT,
            relationship_tag TEXT,
            expected_strength REAL DEFAULT 0.0,
            observed_strength REAL DEFAULT 0.0,
            usage_count INTEGER DEFAULT 0,
            encrypted_by TEXT DEFAULT 'owner',
            created_at INTEGER DEFAULT (strftime('%s','now')),
            PRIMARY KEY (source_address, target_address, relationship_tag)
        )
    """)

    conn.commit()
    print("✅ Database schema initialized with relationship strength learning")