"""
phrasevault/store.py
────────────────────
SQLite storage layer — zero crypto, zero business logic.
Every function does exactly ONE thing.

Schema:
  entries   — one row per encrypted triplet
  chain     — tracks chain head per passphrase-slot (address of last entry)

All binary data (addresses, nonces, ciphertext) is stored as BLOB.
All scores and timestamps are stored as REAL/INTEGER (exact, no rounding).
"""

import sqlite3
import time
from pathlib import Path


# Default DB location — inside HomeLab so it persists across sessions
DEFAULT_DB = Path(__file__).parent.parent / "phrasevault.db"


# ══════════════════════════════════════════════════════════════════════════════
# CONNECTION
# ══════════════════════════════════════════════════════════════════════════════

def open_db(db_path: Path = DEFAULT_DB) -> sqlite3.Connection:
    """
    Open (or create) the SQLite database and return a connection.
    WAL mode: safe for concurrent readers + one writer.
    foreign_keys: ON so chain integrity is enforced at DB level.
    """
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row          # rows accessible by column name
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")  # safe + fast
    return conn


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMA
# ══════════════════════════════════════════════════════════════════════════════

SCHEMA = """
CREATE TABLE IF NOT EXISTS forest_nodes (
    -- The public/unencrypted layer: node graph for scoring and verification
    node_id         TEXT    PRIMARY KEY,
    tree_id         TEXT    NOT NULL DEFAULT 'CORE_truth_tree',
    shell           INTEGER NOT NULL DEFAULT 3,
    truth_score     REAL    NOT NULL,
    impossibility_measure REAL NOT NULL,
    node_type       TEXT,
    superseded      INTEGER NOT NULL DEFAULT 0,
    words_json      TEXT,           -- JSON array of the three words
    links_json      TEXT,           -- JSON array of linked node_ids
    links_cross_json TEXT,          -- JSON array of cross-tree links
    source          TEXT,           -- 'local', 'v3_new', etc.
    note            TEXT,
    -- forest fingerprint at time of insert (T33 signing mechanism)
    signed_by       TEXT,           -- node_id that signed this (e.g. T33)
    inserted_at_ns  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000000000)
);

CREATE INDEX IF NOT EXISTS idx_forest_nodes_score ON forest_nodes(truth_score);
CREATE INDEX IF NOT EXISTS idx_forest_nodes_tree  ON forest_nodes(tree_id);

CREATE TABLE IF NOT EXISTS forest_signatures (
    -- T33 tree-signing mechanism: fingerprint of entire forest at a point in time
    sig_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    forest_id       TEXT    NOT NULL,
    version         TEXT    NOT NULL,
    node_count      INTEGER NOT NULL,
    fingerprint     TEXT    NOT NULL,   -- BLAKE3 hex of sorted node_id:score pairs
    signed_at_ns    INTEGER NOT NULL,
    signing_node    TEXT                -- e.g. 'T33_Tree_Signing_Mechanism'
);

CREATE TABLE IF NOT EXISTS entries (
    -- identity
    address         BLOB    PRIMARY KEY,      -- 32-byte BLAKE3 chain address
    chain_position  INTEGER NOT NULL,         -- 0 = genesis, +1 each entry
    prev_address    BLOB,                     -- NULL for genesis entry

    -- encrypted payload
    nonce           BLOB    NOT NULL,         -- 24-byte XSalsa20 nonce
    ciphertext      BLOB    NOT NULL,         -- encrypted triplet + metadata

    -- unencrypted metadata (for indexing; reveals nothing about content)
    timestamp_ns    INTEGER NOT NULL,         -- nanoseconds since Unix epoch
    confidence      REAL    NOT NULL          -- [0.0, 1.0) stored score
                            CHECK(confidence >= 0.0 AND confidence < 1.0),
    shell           INTEGER NOT NULL DEFAULT 3,  -- prime shell (1,3,5,7,11...)
    superseded      INTEGER NOT NULL DEFAULT 0,  -- 1 = newer node exists

    -- pi checkpoint for dual-layer tamper detection
    pi_checkpoint   BLOB,                     -- 16 bytes of pi at this position

    -- transfer tracking
    origin_instance TEXT,                     -- NULL = local; else instance ID
    received_at_ns  INTEGER                   -- NULL = local; else import time
);

CREATE TABLE IF NOT EXISTS chain_heads (
    slot            TEXT    PRIMARY KEY,      -- passphrase slot identifier
    head_address    BLOB    NOT NULL,         -- address of most recent entry
    head_position   INTEGER NOT NULL,         -- chain_position of head entry
    updated_at_ns   INTEGER NOT NULL          -- when head was last updated
);

CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON entries(timestamp_ns);
CREATE INDEX IF NOT EXISTS idx_entries_confidence ON entries(confidence);
CREATE INDEX IF NOT EXISTS idx_entries_shell ON entries(shell);
CREATE INDEX IF NOT EXISTS idx_entries_superseded ON entries(superseded);

CREATE TABLE IF NOT EXISTS identity_keys (
    -- One row per passphrase-slot.  The private key is NEVER stored here —
    -- it is always re-derived from the passphrase via Argon2id when needed.
    -- Only the public key is cached so we can show the DID/address instantly.
    slot            TEXT    PRIMARY KEY,      -- same slot as chain_heads
    public_key      BLOB    NOT NULL,         -- 33-byte compressed secp256k1
    eth_address     TEXT    NOT NULL,         -- '0x...' derived from pubkey
    did             TEXT    NOT NULL,         -- 'did:ethr:0x...'
    created_at_ns   INTEGER NOT NULL
);
"""

def init_schema(conn: sqlite3.Connection) -> None:
    """Create all tables and indexes if they don't exist yet. Idempotent."""
    conn.executescript(SCHEMA)
    conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# WRITE OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def insert_entry(
    conn: sqlite3.Connection,
    address: bytes,
    chain_position: int,
    prev_address: bytes | None,
    nonce: bytes,
    ciphertext: bytes,
    timestamp_ns: int,
    confidence: float,
    shell: int = 3,
    pi_checkpoint: bytes | None = None,
    origin_instance: str | None = None,
) -> None:
    """
    Write one encrypted entry to the database.
    Raises sqlite3.IntegrityError if address already exists (collision = bug).
    """
    conn.execute(
        """
        INSERT INTO entries
            (address, chain_position, prev_address, nonce, ciphertext,
             timestamp_ns, confidence, shell, pi_checkpoint, origin_instance,
             received_at_ns)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            address,
            chain_position,
            prev_address,
            nonce,
            ciphertext,
            timestamp_ns,
            confidence,
            shell,
            pi_checkpoint,
            origin_instance,
            int(time.time_ns()) if origin_instance else None,
        ),
    )
    conn.commit()


def update_chain_head(
    conn: sqlite3.Connection,
    slot: str,
    head_address: bytes,
    head_position: int,
) -> None:
    """
    Update (or insert) the chain head pointer for a given slot.
    Call this after every successful insert_entry.
    """
    conn.execute(
        """
        INSERT INTO chain_heads (slot, head_address, head_position, updated_at_ns)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(slot) DO UPDATE SET
            head_address  = excluded.head_address,
            head_position = excluded.head_position,
            updated_at_ns = excluded.updated_at_ns
        """,
        (slot, head_address, head_position, int(time.time_ns())),
    )
    conn.commit()


def mark_superseded(conn: sqlite3.Connection, address: bytes) -> None:
    """Mark an entry as superseded (e.g., after a typo correction per T30)."""
    conn.execute(
        "UPDATE entries SET superseded = 1 WHERE address = ?",
        (address,),
    )
    conn.commit()


# ══════════════════════════════════════════════════════════════════════════════
# READ OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def fetch_entry(conn: sqlite3.Connection, address: bytes) -> sqlite3.Row | None:
    """Fetch one entry by its 32-byte address.  Returns None if not found."""
    return conn.execute(
        "SELECT * FROM entries WHERE address = ?", (address,)
    ).fetchone()


def fetch_chain_head(conn: sqlite3.Connection, slot: str) -> sqlite3.Row | None:
    """Return the current chain head for a slot. None if slot is new."""
    return conn.execute(
        "SELECT * FROM chain_heads WHERE slot = ?", (slot,)
    ).fetchone()


def fetch_entries_by_confidence(
    conn: sqlite3.Connection,
    max_confidence: float = 1.0,
    min_confidence: float = 0.0,
    limit: int = 100,
    include_superseded: bool = False,
) -> list[sqlite3.Row]:
    """
    Return entries sorted by confidence (ascending = most certain first).
    Useful for building the score ladder view.
    """
    sup_filter = "" if include_superseded else "AND superseded = 0"
    return conn.execute(
        f"""
        SELECT * FROM entries
        WHERE confidence >= ? AND confidence < ?
        {sup_filter}
        ORDER BY confidence ASC
        LIMIT ?
        """,
        (min_confidence, max_confidence, limit),
    ).fetchall()


def fetch_all_entries(
    conn: sqlite3.Connection,
    include_superseded: bool = False,
) -> list[sqlite3.Row]:
    """Return all entries ordered by chain_position then timestamp."""
    sup_filter = "" if include_superseded else "WHERE superseded = 0"
    return conn.execute(
        f"SELECT * FROM entries {sup_filter} ORDER BY chain_position ASC, timestamp_ns ASC"
    ).fetchall()


def count_entries(conn: sqlite3.Connection) -> int:
    """Total number of non-superseded entries in the database."""
    return conn.execute(
        "SELECT COUNT(*) FROM entries WHERE superseded = 0"
    ).fetchone()[0]


# ══════════════════════════════════════════════════════════════════════════════
# IDENTITY OPERATIONS
# ══════════════════════════════════════════════════════════════════════════════

def store_identity(
    conn: sqlite3.Connection,
    slot: str,
    public_key: bytes,
    eth_address: str,
    did: str,
) -> None:
    """
    Cache the public identity for a passphrase slot.
    Idempotent: silently replaces if the slot already exists
    (e.g. re-running keygen after a DB migration).
    """
    conn.execute(
        """
        INSERT INTO identity_keys (slot, public_key, eth_address, did, created_at_ns)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(slot) DO UPDATE SET
            public_key  = excluded.public_key,
            eth_address = excluded.eth_address,
            did         = excluded.did,
            created_at_ns = excluded.created_at_ns
        """,
        (slot, public_key, eth_address, did, int(time.time_ns())),
    )
    conn.commit()


def fetch_identity(conn: sqlite3.Connection, slot: str) -> sqlite3.Row | None:
    """Return the cached identity row for a slot, or None if keygen hasn't run."""
    return conn.execute(
        "SELECT * FROM identity_keys WHERE slot = ?", (slot,)
    ).fetchone()
