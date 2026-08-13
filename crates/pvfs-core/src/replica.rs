//! F2 — replica forests (doc 17 §5, doc 03 §1.3 Mode A).
//!
//! A replica is a **full, verified, read-only copy** of another instance's
//! forest: its log shipped row-for-row, its projection rebuilt locally. The
//! trust story is the existing one — every event is signed and hash-chained,
//! and the standard startup replay ([`crate::projection::startup_check`])
//! verifies chain continuity, event signatures, and replay-time authorization
//! for the whole log — so a replica proves the owner's history rather than
//! trusting the wire. Ingest additionally verifies chain linkage row-by-row
//! (fail fast on a tampered tail before anything opens).
//!
//! On disk a replica is an ordinary forest data dir plus a `replica` marker
//! recording the source; [`crate::Engine::open`] routes marked dirs to
//! [`crate::Engine::open_replica`], which refuses all log writes. The owner
//! instance stays the forest's only writer (doc 03 §1.1).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension};

use crate::engine::bad;
use crate::error::{PvfsError, Result};
use crate::event::Event;
use crate::log_store::{self, EventRow};

pub const REPLICA_MARKER: &str = "replica";
const MARKER_HEADER: &str = "pvfs-replica 1";

/// Where a replica fetched its log from — enough for `replica sync` to dial
/// the source again. `pin` is empty for a Unix-socket source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicaSource {
    /// `tcp` (a `pvfsd --listen` address) or `socket` (a local Unix socket).
    pub transport: String,
    /// The address (`host:port`) or socket path.
    pub target: String,
    /// The source's transport pin (F1) — empty for `socket`.
    pub pin: String,
    /// P7.2b: region scope — the region root this replica is scoped to, or
    /// empty for a whole-forest replica. `replica sync`/`follow` keep the
    /// recorded scope.
    pub region: String,
}

pub fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(REPLICA_MARKER)
}

impl ReplicaSource {
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        if self.transport != "tcp" && self.transport != "socket" {
            return Err(bad("transport", "must be tcp or socket"));
        }
        let mut text = format!(
            "{MARKER_HEADER}\ntransport {}\ntarget {}\npin {}\n",
            self.transport, self.target, self.pin
        );
        if !self.region.is_empty() {
            text.push_str(&format!("region {}\n", self.region));
        }
        std::fs::write(marker_path(data_dir), text)
            .map_err(|e| PvfsError::io("write replica marker", e))
    }

    pub fn load(data_dir: &Path) -> Result<ReplicaSource> {
        let text = std::fs::read_to_string(marker_path(data_dir))
            .map_err(|e| PvfsError::io("read replica marker", e))?;
        let mut lines = text.lines();
        if lines.next() != Some(MARKER_HEADER) {
            return Err(bad("replica", "unrecognized replica marker"));
        }
        let (mut transport, mut target, mut pin, mut region) =
            (String::new(), String::new(), String::new(), String::new());
        for line in lines {
            if let Some(v) = line.strip_prefix("transport ") {
                transport = v.into();
            } else if let Some(v) = line.strip_prefix("target ") {
                target = v.into();
            } else if let Some(v) = line.strip_prefix("pin ") {
                pin = v.into();
            } else if let Some(v) = line.strip_prefix("region ") {
                region = v.into();
            }
        }
        if transport.is_empty() || target.is_empty() {
            return Err(bad("replica", "corrupt replica marker"));
        }
        Ok(ReplicaSource {
            transport,
            target,
            pin,
            region,
        })
    }
}

/// A region **generation** address on the wire (P7.2b, doc 20 §2.4):
/// `<region-root-hex>/g-<host>-<seq>.db`, exactly the generation file's path
/// under `regions/`. Strictly validated — the region root (for the ACL gate)
/// and the relative file path come only from a parse that admits no
/// traversal.
pub fn parse_region_addr(addr: &str) -> Option<(String, String)> {
    let (root, file) = addr.split_once('/')?;
    if root.len() != 64 || !root.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
        return None;
    }
    let rest = file.strip_prefix("g-")?.strip_suffix(".db")?;
    let (host, seq) = rest.rsplit_once('-')?;
    let host_ok = host == "top"
        || (!host.is_empty()
            && host.len() <= 8
            && host.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    if !host_ok || seq.is_empty() || !seq.chars().all(|c| c.is_ascii_digit()) || seq.starts_with('0')
    {
        return None;
    }
    Some((root.to_string(), format!("regions/{root}/{file}")))
}

/// The wire address for a generation identified by its baseline row (the
/// inverse of [`parse_region_addr`]).
pub fn region_addr(region_root: &str, baseline_log: &str, baseline_seq: u64) -> String {
    let rel = crate::projection::region_log_rel_path(region_root, baseline_log, baseline_seq);
    rel.strip_prefix("regions/").unwrap_or(&rel).to_string()
}

/// The replica's local log store during ingest (`replica add` / `sync`).
/// Opens the same databases an engine would; only the log is written here —
/// the projection is rebuilt by the verified replay at the next open.
pub struct ReplicaStore {
    conn: Connection,
    data_dir: PathBuf,
}

impl ReplicaStore {
    /// Open (creating on first use) the log store under `data_dir`.
    pub fn open(data_dir: &Path) -> Result<ReplicaStore> {
        std::fs::create_dir_all(data_dir).map_err(|e| PvfsError::io("create replica dir", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700));
        }
        let conn = crate::engine::open_connection(data_dir)?;
        Ok(ReplicaStore {
            conn,
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Highest ingested seq (0 = empty).
    pub fn tip(&self) -> Result<u64> {
        log_store::max_seq(&self.conn)
    }

    /// `(instance_id, forest_id)` from the ingested genesis row — the inputs
    /// region-generation genesis seeds bind (P7.2b).
    pub fn identity(&self) -> Result<(String, String)> {
        let row = log_store::read_event(&self.conn, 1)?.ok_or_else(|| {
            bad("replica", "store has no genesis row yet — ship the top log first")
        })?;
        match Event::decode(&row.kind, &row.body)? {
            Event::ForestCreated {
                instance_id,
                forest_id,
                ..
            } => Ok((instance_id, forest_id)),
            _ => Err(bad("replica", "first event is not ForestCreated")),
        }
    }

    /// Highest ingested seq of a region generation (0 = absent/empty).
    /// `rel_file` is the `regions/…` path from [`parse_region_addr`].
    pub fn region_tip(&self, rel_file: &str) -> Result<u64> {
        let path = self.data_dir.join(rel_file);
        if !path.exists() {
            return Ok(0);
        }
        let conn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(crate::error::map_db("open region log"))?;
        let tip: i64 = conn
            .query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| r.get(0))
            .unwrap_or(0);
        Ok(tip as u64)
    }

    /// Ingest shipped rows into a region generation file, chain-verified from
    /// `genesis` — the seed the client computed from the generation's
    /// **committed baseline row** (root, seq, state_root), so a shipped region
    /// chain is verified against the enclosing log's commitment before any
    /// row lands (P7.2b, doc 20 §2.4). Same contiguity rules as [`append`].
    pub fn append_region(
        &mut self,
        rel_file: &str,
        genesis: &[u8; 32],
        rows: &[EventRow],
    ) -> Result<u64> {
        let path = self.data_dir.join(rel_file);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("create region dir", e))?;
        }
        let mut conn =
            Connection::open(&path).map_err(crate::error::map_db("open region log"))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
               seq        INTEGER PRIMARY KEY,
               kind       TEXT NOT NULL,
               body       BLOB NOT NULL,
               chain_hash BLOB NOT NULL,
               written_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);",
        )
        .map_err(crate::error::map_db("region log schema"))?;
        if rows.is_empty() {
            let tip: i64 = conn
                .query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| r.get(0))
                .map_err(crate::error::map_db("read region tip"))?;
            return Ok(tip as u64);
        }
        // Two writers legitimately race here: the follow job's sweep and a
        // manual `replica sync` fetch the same tail concurrently (found by
        // fleet phase H as a PRIMARY KEY failure on the seal sync). Take the
        // write lock FIRST (immediate transaction, with a busy wait), read
        // the tip inside it, and treat rows another writer already landed as
        // overlap: verify they match what's stored, then skip.
        conn.busy_timeout(std::time::Duration::from_secs(10))
            .map_err(crate::error::map_db("region busy timeout"))?;
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(crate::error::map_db("begin region ingest"))?;
        let tip: i64 = tx
            .query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| r.get(0))
            .map_err(crate::error::map_db("read region tip"))?;
        let tip = tip as u64;
        let mut prev: [u8; 32] = if tip == 0 {
            *genesis
        } else {
            let chain: Vec<u8> = tx
                .query_row(
                    "SELECT chain_hash FROM events WHERE seq = ?1",
                    rusqlite::params![tip as i64],
                    |r| r.get(0),
                )
                .map_err(crate::error::map_db("read region tip"))?;
            chain
                .as_slice()
                .try_into()
                .map_err(|_| PvfsError::Corruption {
                    db: rel_file.into(),
                    detail: "chain hash wrong length".into(),
                    seq: Some(tip),
                })?
        };
        let mut expect_seq = tip;
        for row in rows {
            if row.seq <= tip {
                // Overlap: the racing writer got here first. The stored row
                // must be byte-identical (same chain hash) — anything else is
                // a diverging source, not a race.
                let stored: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT chain_hash FROM events WHERE seq = ?1",
                        rusqlite::params![row.seq as i64],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(crate::error::map_db("read overlap row"))?;
                match stored {
                    Some(h) if h == row.chain_hash => continue,
                    _ => {
                        return Err(PvfsError::LogChainBroken {
                            seq: row.seq,
                            expected: hex::encode(&row.chain_hash),
                            actual: "diverges from the already-ingested row".into(),
                        })
                    }
                }
            }
            expect_seq += 1;
            if row.seq != expect_seq {
                return Err(bad(
                    "replica",
                    &format!(
                        "non-contiguous region ship: expected seq {expect_seq}, got {}",
                        row.seq
                    ),
                ));
            }
            let step = log_store::chain_step(&prev, row.seq, &row.kind, &row.body, row.written_at);
            if step.as_slice() != row.chain_hash.as_slice() {
                return Err(PvfsError::LogChainBroken {
                    seq: row.seq,
                    expected: hex::encode(step),
                    actual: hex::encode(&row.chain_hash),
                });
            }
            tx.execute(
                "INSERT INTO events (seq, kind, body, chain_hash, written_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    row.seq as i64,
                    row.kind,
                    row.body,
                    row.chain_hash,
                    row.written_at as i64
                ],
            )
            .map_err(crate::error::map_db("ingest region event"))?;
            prev = step;
        }
        tx.commit()
            .map_err(crate::error::map_db("commit region ingest"))?;
        Ok(expect_seq)
    }

    /// Every `RegionBaseline` row in an ingested log — `(region_root,
    /// baseline_seq, state_root)` — the recursive generation-discovery step
    /// (doc 20 §2.4): scan the top log, pull those generations, scan them,
    /// repeat. `rel_file` = `None` for the top log.
    pub fn scan_baselines(&self, rel_file: Option<&str>) -> Result<Vec<(String, u64, Vec<u8>)>> {
        let rows: Vec<(i64, String, Vec<u8>)> = match rel_file {
            None => {
                let mut stmt = self
                    .conn
                    .prepare("SELECT seq, kind, body FROM log.events WHERE kind = ?1 ORDER BY seq")
                    .map_err(crate::error::map_db("scan baselines"))?;
                let it = stmt
                    .query_map(rusqlite::params![crate::event::K_REGION_BASELINE], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                    .map_err(crate::error::map_db("scan baselines"))?;
                it.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(crate::error::map_db("scan baselines"))?
            }
            Some(rel) => {
                let path = self.data_dir.join(rel);
                if !path.exists() {
                    return Ok(Vec::new());
                }
                let conn = Connection::open_with_flags(
                    &path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )
                .map_err(crate::error::map_db("open region log"))?;
                let mut stmt = conn
                    .prepare("SELECT seq, kind, body FROM events WHERE kind = ?1 ORDER BY seq")
                    .map_err(crate::error::map_db("scan baselines"))?;
                let it = stmt
                    .query_map(rusqlite::params![crate::event::K_REGION_BASELINE], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                    })
                    .map_err(crate::error::map_db("scan baselines"))?;
                it.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(crate::error::map_db("scan baselines"))?
            }
        };
        let mut out = Vec::with_capacity(rows.len());
        for (seq, kind, body) in rows {
            if let Event::RegionBaseline {
                node_id, state_root, ..
            } = Event::decode(&kind, &body)?
            {
                out.push((node_id, seq as u64, state_root));
            }
        }
        Ok(out)
    }

    /// Append shipped rows **verbatim**, verifying that each links from the
    /// current chain tip (`chain_hash[seq] = H(prev ‖ PCE(seq, kind, body,
    /// written_at))`). Rows must be contiguous from `tip + 1`. Signatures and
    /// replay authorization are verified by the rebuild at open — this check
    /// exists to fail fast (and atomically) on a tampered or torn tail.
    pub fn append(&mut self, rows: &[EventRow]) -> Result<u64> {
        if rows.is_empty() {
            return self.tip();
        }
        // Same race as `append_region`: the follow job and a manual sync
        // legitimately ship the same tail concurrently. Write lock first,
        // tip inside the transaction, overlap verified-then-skipped.
        self.conn
            .busy_timeout(std::time::Duration::from_secs(10))
            .map_err(crate::error::map_db("replica busy timeout"))?;
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(crate::error::map_db("begin replica ingest"))?;
        let tip: i64 = tx
            .query_row("SELECT IFNULL(MAX(seq),0) FROM log.events", [], |r| r.get(0))
            .map_err(crate::error::map_db("read replica tip"))?;
        let tip = tip as u64;
        let mut prev: [u8; 32] = if tip == 0 {
            // The genesis seed binds (instance_id, forest_id) from the
            // ForestCreated event the first shipped row must carry.
            let first = &rows[0];
            if first.seq != 1 {
                return Err(bad("replica", "log ship must start at seq 1"));
            }
            match Event::decode(&first.kind, &first.body)? {
                Event::ForestCreated {
                    instance_id,
                    forest_id,
                    ..
                } => log_store::genesis_seed(&instance_id, &forest_id),
                _ => return Err(bad("replica", "first event is not ForestCreated")),
            }
        } else {
            let chain: Vec<u8> = tx
                .query_row(
                    "SELECT chain_hash FROM log.events WHERE seq = ?1",
                    rusqlite::params![tip as i64],
                    |r| r.get(0),
                )
                .map_err(crate::error::map_db("read replica tip"))?;
            chain
                .as_slice()
                .try_into()
                .map_err(|_| PvfsError::Corruption {
                    db: "log.db".into(),
                    detail: "chain hash wrong length".into(),
                    seq: Some(tip),
                })?
        };

        let mut expect_seq = tip;
        for row in rows {
            if row.seq <= tip {
                let stored: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT chain_hash FROM log.events WHERE seq = ?1",
                        rusqlite::params![row.seq as i64],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(crate::error::map_db("read overlap row"))?;
                match stored {
                    Some(h) if h == row.chain_hash => continue,
                    _ => {
                        return Err(PvfsError::LogChainBroken {
                            seq: row.seq,
                            expected: hex::encode(&row.chain_hash),
                            actual: "diverges from the already-ingested row".into(),
                        })
                    }
                }
            }
            expect_seq += 1;
            if row.seq != expect_seq {
                return Err(bad(
                    "replica",
                    &format!("non-contiguous log ship: expected seq {expect_seq}, got {}", row.seq),
                ));
            }
            let step = log_store::chain_step(&prev, row.seq, &row.kind, &row.body, row.written_at);
            if step.as_slice() != row.chain_hash.as_slice() {
                return Err(PvfsError::LogChainBroken {
                    seq: row.seq,
                    expected: hex::encode(step),
                    actual: hex::encode(&row.chain_hash),
                });
            }
            tx.execute(
                "INSERT INTO log.events (seq, kind, body, chain_hash, written_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    row.seq as i64,
                    row.kind,
                    row.body,
                    row.chain_hash,
                    row.written_at as i64
                ],
            )
            .map_err(crate::error::map_db("ingest event"))?;
            prev = step;
        }
        // The projection now lags the log; the next open's startup check
        // replays (and fully verifies) the new tail.
        tx.commit()
            .map_err(crate::error::map_db("commit replica ingest"))?;
        Ok(expect_seq)
    }
}
