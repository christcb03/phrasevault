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

use rusqlite::Connection;

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
}

pub fn marker_path(data_dir: &Path) -> PathBuf {
    data_dir.join(REPLICA_MARKER)
}

impl ReplicaSource {
    pub fn save(&self, data_dir: &Path) -> Result<()> {
        if self.transport != "tcp" && self.transport != "socket" {
            return Err(bad("transport", "must be tcp or socket"));
        }
        let text = format!(
            "{MARKER_HEADER}\ntransport {}\ntarget {}\npin {}\n",
            self.transport, self.target, self.pin
        );
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
        let (mut transport, mut target, mut pin) = (String::new(), String::new(), String::new());
        for line in lines {
            if let Some(v) = line.strip_prefix("transport ") {
                transport = v.into();
            } else if let Some(v) = line.strip_prefix("target ") {
                target = v.into();
            } else if let Some(v) = line.strip_prefix("pin ") {
                pin = v.into();
            }
        }
        if transport.is_empty() || target.is_empty() {
            return Err(bad("replica", "corrupt replica marker"));
        }
        Ok(ReplicaSource {
            transport,
            target,
            pin,
        })
    }
}

/// The replica's local log store during ingest (`replica add` / `sync`).
/// Opens the same databases an engine would; only the log is written here —
/// the projection is rebuilt by the verified replay at the next open.
pub struct ReplicaStore {
    conn: Connection,
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
        Ok(ReplicaStore { conn })
    }

    /// Highest ingested seq (0 = empty).
    pub fn tip(&self) -> Result<u64> {
        log_store::max_seq(&self.conn)
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
        let tip = self.tip()?;
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
            let row = log_store::read_event(&self.conn, tip)?.ok_or_else(|| {
                PvfsError::Corruption {
                    db: "log.db".into(),
                    detail: format!("missing event at seq {tip}"),
                    seq: Some(tip),
                }
            })?;
            row.chain_hash
                .as_slice()
                .try_into()
                .map_err(|_| PvfsError::Corruption {
                    db: "log.db".into(),
                    detail: "chain hash wrong length".into(),
                    seq: Some(tip),
                })?
        };

        let tx = self
            .conn
            .transaction()
            .map_err(crate::error::map_db("begin replica ingest"))?;
        let mut expect_seq = tip;
        for row in rows {
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
