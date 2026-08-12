//! log.db — the canonical store (spec §7) and tamper-evident hash chain (§7.1).
//!
//! chain_hash[seq] = BLAKE3( chain_hash[seq-1] || PCE(seq, kind, body, written_at) )
//! chain_hash[0]   = BLAKE3( "pvfs:log:v1:" || PCE(instance_id, forest_id) )
//!
//! P7.2a (doc 20 §2.3): region logs are separate files with the same schema
//! and the same chain rules, ATTACHed under other names — every primitive here
//! takes the attached-db name in its `_in` form; the historical single-log
//! names are wrappers over the top log ("log").

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::encoding::Enc;
use crate::error::{map_db, Result};
use crate::event::Event;

/// The attached-db name of the top region's log (the historical log.db).
pub const TOP_LOG: &str = "log";

pub fn log_schema(db: &str) -> String {
    format!(
        "CREATE TABLE IF NOT EXISTS {db}.events (
  seq        INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,
  body       BLOB NOT NULL,
  chain_hash BLOB NOT NULL,
  written_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS {db}.idx_events_kind ON events(kind);"
    )
}

pub const LOG_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS log.events (
  seq        INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,
  body       BLOB NOT NULL,
  chain_hash BLOB NOT NULL,
  written_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS log.idx_events_kind ON events(kind);
";

/// Forest-specific genesis seed (spec §7.1).
pub fn genesis_seed(instance_id: &str, forest_id: &str) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(instance_id).string(forest_id);
    let mut h = blake3::Hasher::new();
    h.update(b"pvfs:log:v1:");
    h.update(&e.finish());
    *h.finalize().as_bytes()
}

/// Region-log genesis seed (doc 20 §2.3): identity + the baseline row's
/// position in the enclosing log + the canonical state commitment. The
/// enclosing head hash is deliberately absent — the baseline event itself is
/// chain-bound in the enclosing log at `baseline_seq`, so the parent linkage
/// is already pinned there.
pub fn region_genesis_seed(
    instance_id: &str,
    forest_id: &str,
    region_root_id: &str,
    baseline_seq: u64,
    state_root: &[u8],
) -> [u8; 32] {
    let mut e = Enc::new();
    e.string(instance_id)
        .string(forest_id)
        .string(region_root_id)
        .u64(baseline_seq)
        .bytes(state_root);
    let mut h = blake3::Hasher::new();
    h.update(b"pvfs:regionlog:v1:");
    h.update(&e.finish());
    *h.finalize().as_bytes()
}

/// One chain step.
pub fn chain_step(prev: &[u8; 32], seq: u64, kind: &str, body: &[u8], written_at: u64) -> [u8; 32] {
    let mut e = Enc::new();
    e.u64(seq).string(kind).bytes(body).u64(written_at);
    let mut h = blake3::Hasher::new();
    h.update(prev);
    h.update(&e.finish());
    *h.finalize().as_bytes()
}

/// Append one event inside an open transaction. `seq` is assigned explicitly
/// (spec §9.1) because the chain hash binds it before the insert.
pub fn append_event_in(
    tx: &Transaction<'_>,
    db: &str,
    prev_chain: &[u8; 32],
    seq: u64,
    event: &Event,
    written_at: u64,
) -> Result<[u8; 32]> {
    let kind = event.kind();
    let body = event.encode_body();
    let chain = chain_step(prev_chain, seq, kind, &body, written_at);
    tx.execute(
        &format!(
            "INSERT INTO {db}.events (seq, kind, body, chain_hash, written_at) VALUES (?1, ?2, ?3, ?4, ?5)"
        ),
        params![seq as i64, kind, body, chain.as_slice(), written_at as i64],
    )
    .map_err(map_db("append event"))?;
    Ok(chain)
}

pub fn append_event(
    tx: &Transaction<'_>,
    prev_chain: &[u8; 32],
    seq: u64,
    event: &Event,
    written_at: u64,
) -> Result<[u8; 32]> {
    append_event_in(tx, TOP_LOG, prev_chain, seq, event, written_at)
}

pub fn max_seq_in(conn: &Connection, db: &str) -> Result<u64> {
    let v: Option<i64> = conn
        .query_row(&format!("SELECT MAX(seq) FROM {db}.events"), [], |r| r.get(0))
        .map_err(map_db("read max seq"))?;
    Ok(v.unwrap_or(0) as u64)
}

pub fn max_seq(conn: &Connection) -> Result<u64> {
    max_seq_in(conn, TOP_LOG)
}

/// Raw event row.
pub struct EventRow {
    pub seq: u64,
    pub kind: String,
    pub body: Vec<u8>,
    pub chain_hash: Vec<u8>,
    pub written_at: u64,
}

/// Rows `[from_seq ..]` in seq order, at most `max` (log shipping, F2).
pub fn read_range_in(
    conn: &Connection,
    db: &str,
    from_seq: u64,
    max: usize,
) -> Result<Vec<EventRow>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT seq, kind, body, chain_hash, written_at FROM {db}.events
             WHERE seq >= ?1 ORDER BY seq LIMIT ?2"
        ))
        .map_err(map_db("read range"))?;
    let rows = stmt
        .query_map(params![from_seq as i64, max as i64], |r| {
            Ok(EventRow {
                seq: r.get::<_, i64>(0)? as u64,
                kind: r.get(1)?,
                body: r.get(2)?,
                chain_hash: r.get(3)?,
                written_at: r.get::<_, i64>(4)? as u64,
            })
        })
        .map_err(map_db("read range"))?;
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(map_db("read range"))
}

pub fn read_range(conn: &Connection, from_seq: u64, max: usize) -> Result<Vec<EventRow>> {
    read_range_in(conn, TOP_LOG, from_seq, max)
}

pub fn read_event_in(conn: &Connection, db: &str, seq: u64) -> Result<Option<EventRow>> {
    conn.query_row(
        &format!(
            "SELECT seq, kind, body, chain_hash, written_at FROM {db}.events WHERE seq = ?1"
        ),
        params![seq as i64],
        |r| {
            Ok(EventRow {
                seq: r.get::<_, i64>(0)? as u64,
                kind: r.get(1)?,
                body: r.get(2)?,
                chain_hash: r.get(3)?,
                written_at: r.get::<_, i64>(4)? as u64,
            })
        },
    )
    .optional()
    .map_err(map_db("read event"))
}

pub fn read_event(conn: &Connection, seq: u64) -> Result<Option<EventRow>> {
    read_event_in(conn, TOP_LOG, seq)
}
