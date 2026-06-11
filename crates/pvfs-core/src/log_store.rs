//! log.db — the canonical store (spec §7) and tamper-evident hash chain (§7.1).
//!
//! chain_hash[seq] = BLAKE3( chain_hash[seq-1] || PCE(seq, kind, body, written_at) )
//! chain_hash[0]   = BLAKE3( "pvfs:log:v1:" || PCE(instance_id, forest_id) )

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::encoding::Enc;
use crate::error::{map_db, Result};
use crate::event::Event;

pub const LOG_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS log.events (
  seq        INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,
  body       BLOB NOT NULL,
  chain_hash BLOB NOT NULL,
  written_at INTEGER NOT NULL
);
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
pub fn append_event(
    tx: &Transaction<'_>,
    prev_chain: &[u8; 32],
    seq: u64,
    event: &Event,
    written_at: u64,
) -> Result<[u8; 32]> {
    let kind = event.kind();
    let body = event.encode_body();
    let chain = chain_step(prev_chain, seq, kind, &body, written_at);
    tx.execute(
        "INSERT INTO log.events (seq, kind, body, chain_hash, written_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![seq as i64, kind, body, chain.as_slice(), written_at as i64],
    )
    .map_err(map_db("append event"))?;
    Ok(chain)
}

pub fn max_seq(conn: &Connection) -> Result<u64> {
    let v: Option<i64> = conn
        .query_row("SELECT MAX(seq) FROM log.events", [], |r| r.get(0))
        .map_err(map_db("read max seq"))?;
    Ok(v.unwrap_or(0) as u64)
}

/// Raw event row.
pub struct EventRow {
    pub seq: u64,
    pub kind: String,
    pub body: Vec<u8>,
    pub chain_hash: Vec<u8>,
    pub written_at: u64,
}

pub fn read_event(conn: &Connection, seq: u64) -> Result<Option<EventRow>> {
    conn.query_row(
        "SELECT seq, kind, body, chain_hash, written_at FROM log.events WHERE seq = ?1",
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
