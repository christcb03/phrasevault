//! Engine — the public facade (spec §11) and write protocol (§9.1).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use rusqlite::{params, Connection, DatabaseName, OptionalExtension, Transaction};

use crate::crypto;
use crate::error::{map_db, IntegrityReason, PvfsError, Result};
use crate::event::{self, Event};
use crate::identity::{self, DeviceKeyCache, Mnemonic};
use crate::link::{self, Link, LinkId, LINK_CONTAINS};
use crate::log_store;
use crate::node::{self, Node, NodeId, LABEL_SOFT_CAP, VISIBILITY_PUBLIC};
use crate::orderkey::OrderKey;
use crate::projection::{self, ForestIdentity};
use crate::walk::{TreeWalk, WalkEntry};

const LOG_FILE: &str = "log.db";
const INDEX_FILE: &str = "index.db";

/// Caller-provided inputs for `add_node`; the engine fills id/sig/created_at.
#[derive(Debug, Clone)]
pub struct NodeSpec {
    pub node_type: String,
    pub label: String,
    /// Already PCE-encoded for the type (empty for `folder`).
    pub payload: Vec<u8>,
    pub is_temp: bool,
    /// None ⇒ engine assigns a random nonce.
    pub creation_nonce: Option<u64>,
}

/// The current ledger head of a secure blob (doc 12 §8.2):
/// `(content_hash, size, updated_at, author)`.
pub type SecureBlobHead = (Vec<u8>, u64, u64, Vec<u8>);

/// One ordered child of a parent (merged `contains` + `ref`).
#[derive(Debug, Clone)]
pub struct ChildEntry {
    pub node: Node,
    pub link_id: LinkId,
    pub link_type: String,
    pub order_key: String,
}

/// A split region's generation state (P7.2a, doc 20 §2.3).
#[derive(Debug, Clone)]
pub struct RegionInfo {
    pub marked_at: u64,
    /// The baseline row's position in its host log — the generation identity.
    pub baseline_seq: u64,
    /// Log id hosting the baseline ('' = top); immutable for the generation.
    pub baseline_log: String,
    /// Where future heads/unmark author ('' = top); reparented on enclosing unmark.
    pub parent_log: String,
    /// Generation file, relative to the data dir.
    pub log_file: Option<String>,
    /// Last head the enclosing log attests (0/"" until the first commitment).
    pub committed_seq: u64,
    pub committed_head: String,
    /// The region log's live tip.
    pub tip_seq: u64,
}

/// One event awaiting a member's signature (doc 07 §5): the assembled, unsigned
/// event and the 32-byte digest its author must sign.
#[derive(Debug, Clone)]
pub struct PreparedEvent {
    pub event: Event,
    pub digest: [u8; 32],
}

/// One direct grant listed by `acl ls`: `(principal, authority, rights,
/// expires_at)` — `authority` is the granting key for `tag:` grants (doc 10,
/// empty otherwise); `expires_at` is ms epoch, 0 = never (doc 13 Q-E1).
pub type AclEntry = (crate::acl::Principal, Vec<u8>, u8, u64);

/// A two-phase member write prepared by the daemon for the member to sign.
#[derive(Debug, Clone)]
pub struct PreparedWrite {
    /// Events to sign, in order; the member returns one signature per event.
    pub events: Vec<PreparedEvent>,
    /// The id the committed write yields (e.g. the new node id).
    pub result_id: String,
}

pub struct Engine {
    pub(crate) conn: Connection,
    pub(crate) data_dir: PathBuf,
    pub(crate) device: DeviceKeyCache,
    pub identity: ForestIdentity,
    pub(crate) closed: bool,
    /// A replica forest (doc 03 §1.1): full verified copy, local writes
    /// refused — the owner instance is the forest's only writer.
    pub(crate) replica: bool,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn bad(field: &str, reason: &str) -> PvfsError {
    PvfsError::BadInput {
        field: field.into(),
        reason: reason.into(),
    }
}

/// Open the same databases **read-only** for a metadata read view (doc 07 §6).
/// WAL lets these run concurrently with the single writer connection; the -shm
/// coordination file already exists because the writer is open (same process).
fn open_connection_read_only(data_dir: &Path) -> Result<Connection> {
    use rusqlite::OpenFlags;
    let conn = Connection::open_with_flags(
        data_dir.join(INDEX_FILE),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(map_db("open index.db read-only"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(map_db("busy timeout"))?;
    let log_path = data_dir.join(LOG_FILE).to_string_lossy().into_owned();
    // The attached db inherits the connection's read-only mode; no schema
    // creation and no journal-mode pragma — the writer configured WAL already.
    conn.execute("ATTACH DATABASE ?1 AS log", params![log_path])
        .map_err(map_db("attach log.db read-only"))?;
    Ok(conn)
}

pub(crate) fn open_connection(data_dir: &Path) -> Result<Connection> {
    let conn = Connection::open(data_dir.join(INDEX_FILE)).map_err(map_db("open index.db"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(map_db("busy timeout"))?;
    let log_path = data_dir
        .join(LOG_FILE)
        .to_string_lossy()
        .into_owned();
    conn.execute("ATTACH DATABASE ?1 AS log", params![log_path])
        .map_err(map_db("attach log.db"))?;
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(Some(DatabaseName::Attached("log")), "journal_mode", "WAL");
    conn.execute_batch(log_store::LOG_SCHEMA)
        .map_err(map_db("create log schema"))?;
    Ok(conn)
}

/// Fetch a node from either table. Returns `(node, is_temp_table)`.
pub(crate) fn fetch_node(conn: &Connection, id: &str) -> Result<Option<Node>> {
    for (table, is_temp) in [("nodes", false), ("temp_nodes", true)] {
        let got = conn
            .query_row(
                &format!(
                    "SELECT id, node_type, label, visibility, payload, creation_nonce,
                            created_at, author, sig FROM {table} WHERE id = ?1"
                ),
                params![id],
                |r| {
                    Ok(Node {
                        id: r.get(0)?,
                        node_type: r.get(1)?,
                        label: r.get(2)?,
                        visibility: r.get(3)?,
                        payload: r.get(4)?,
                        creation_nonce: r.get::<_, i64>(5)? as u64,
                        created_at: r.get::<_, i64>(6)? as u64,
                        author: r.get(7)?,
                        sig: r.get(8)?,
                        is_temp,
                    })
                },
            )
            .optional()
            .map_err(map_db("fetch node"))?;
        if got.is_some() {
            return Ok(got);
        }
    }
    Ok(None)
}

pub(crate) fn active_inbound_count(conn: &Connection, id: &str) -> Result<u64> {
    let n: i64 = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM links WHERE child_id = ?1 AND removed_at IS NULL)
                  + (SELECT COUNT(*) FROM temp_links WHERE child_id = ?1 AND removed_at IS NULL)",
            params![id],
            |r| r.get(0),
        )
        .map_err(map_db("count inbound"))?;
    Ok(n as u64)
}

/// The node's active `contains` home, if any: `(link_id, parent_id)`.
pub(crate) fn active_home(conn: &Connection, child: &str) -> Result<Option<(String, Option<String>)>> {
    for table in ["links", "temp_links"] {
        let got = conn
            .query_row(
                &format!(
                    "SELECT id, parent_id FROM {table}
                     WHERE child_id = ?1 AND link_type = ?2 AND removed_at IS NULL"
                ),
                params![child, LINK_CONTAINS],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .optional()
            .map_err(map_db("find home"))?;
        if got.is_some() {
            return Ok(got);
        }
    }
    Ok(None)
}

pub(crate) fn max_order_key(conn: &Connection, parent: &str) -> Result<Option<OrderKey>> {
    let v: Option<String> = conn
        .query_row(
            "SELECT MAX(order_key) FROM (
               SELECT order_key FROM links WHERE parent_id = ?1 AND removed_at IS NULL
               UNION ALL
               SELECT order_key FROM temp_links WHERE parent_id = ?1 AND removed_at IS NULL
             )",
            params![parent],
            |r| r.get(0),
        )
        .map_err(map_db("max order key"))?;
    match v {
        None => Ok(None),
        Some(s) => Ok(Some(OrderKey::parse(&s)?)),
    }
}

impl Engine {
    // ---- lifecycle -----------------------------------------------------------

    /// First-time setup (spec §6 init flow): generate mnemonic + keys, write
    /// the genesis events. Returns the mnemonic for ONE-TIME display.
    pub fn init(data_dir: &Path) -> Result<(Engine, Mnemonic)> {
        let mnemonic = identity::generate_mnemonic()?;
        let root_key = identity::root_key(&mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        let device_key = identity::device_key(&mnemonic, "", 0)?;
        let engine = Self::init_with_keys(data_dir, &root_pub, device_key, 0, |digest| {
            crypto::sign_digest(&root_key, digest)
        })?;
        Ok((engine, mnemonic))
    }

    /// Create a forest whose **root key** is supplied externally (doc 14 genesis
    /// via companion): `sign_root` produces root signatures for `ForestCreated`
    /// and this machine's `DeviceAuthorized`. A fresh local **device key** is
    /// generated (not the seed) and cached under `.pvfs/device.key`.
    ///
    /// Used when a running companion already holds the human's seed — no new
    /// recovery phrase is created.
    pub fn init_with_root_signer(
        data_dir: &Path,
        root_pub: &[u8],
        mut sign_root: impl FnMut(&[u8; 32]) -> Result<Vec<u8>>,
    ) -> Result<Engine> {
        crypto::validate_pubkey(root_pub)?;
        let device_key = identity::generate_device_key();
        Self::init_with_keys(data_dir, root_pub, device_key, 0, |d| sign_root(d))
    }

    fn init_with_keys(
        data_dir: &Path,
        root_pub: &[u8],
        device_key: identity::SigningKey,
        device_index: u64,
        mut sign_root: impl FnMut(&[u8; 32]) -> Result<Vec<u8>>,
    ) -> Result<Engine> {
        std::fs::create_dir_all(data_dir).map_err(|e| PvfsError::io("create data dir", e))?;
        // Engine state is private to its creator: an unshared forest is reachable
        // only through the owner's own daemon (doc 06 §2). Cross-user sharing is
        // ACL-enforced over the socket, never via file-permission bits on `.pvfs/`.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| PvfsError::io("chmod state dir", e))?;
        }
        if data_dir.join(LOG_FILE).exists() {
            return Err(PvfsError::AlreadyExists {
                kind: "forest",
                id: data_dir.to_string_lossy().into_owned(),
            });
        }
        let root_pub = root_pub.to_vec();
        let device_pub = crypto::pubkey_bytes(&device_key);

        let instance_id = std::env::var("PVFS_INSTANCE_ID").unwrap_or_else(|_| {
            let mut b = [0u8; 4];
            rand::thread_rng().fill_bytes(&mut b);
            format!("pvfs-{}", hex::encode(b))
        });
        let forest_id = uuid::Uuid::new_v4().to_string();
        let t = now_ms();

        // Root folder node (everyday record — authored by the device key).
        let mut nonce_bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let creation_nonce = u64::from_le_bytes(nonce_bytes);
        let payload = node::folder_payload();
        let root_digest = node::compute_id_digest(
            node::TYPE_FOLDER,
            "root",
            VISIBILITY_PUBLIC,
            &payload,
            false,
            creation_nonce,
            t,
            &device_pub,
        );
        let root_node = Node {
            id: hex::encode(root_digest),
            node_type: node::TYPE_FOLDER.into(),
            label: "root".into(),
            visibility: VISIBILITY_PUBLIC.into(),
            payload,
            is_temp: false,
            creation_nonce,
            created_at: t,
            author: device_pub.clone(),
            sig: crypto::sign_digest(&device_key, &root_digest)?,
        };

        let fc_sig = sign_root(&event::msg_forest_created(
            &instance_id,
            &forest_id,
            &root_node.id,
            t,
            &root_pub,
        ))?;
        let da_sig = sign_root(&event::msg_device_authorized(
            &device_pub,
            device_index,
            t,
            &root_pub,
        ))?;

        let link_digest = link::compute_id_digest(None, &root_node.id, LINK_CONTAINS, 0);
        let root_link = Link {
            id: hex::encode(link_digest),
            parent_id: None,
            child_id: root_node.id.clone(),
            link_type: LINK_CONTAINS.into(),
            link_nonce: 0,
            order_key: OrderKey::middle().as_str().into(),
            created_at: t,
            author: device_pub.clone(),
            sig: crypto::sign_digest(&device_key, &link_digest)?,
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        };

        let events = vec![
            Event::ForestCreated {
                instance_id: instance_id.clone(),
                forest_id: forest_id.clone(),
                root_node_id: root_node.id.clone(),
                created_at: t,
                author: root_pub.clone(),
                sig: fc_sig,
            },
            Event::DeviceAuthorized {
                device_pubkey: device_pub.clone(),
                device_index,
                authorized_at: t,
                author: root_pub.clone(),
                sig: da_sig,
            },
            Event::NodeCreated(root_node.clone()),
            Event::LinkCreated(root_link),
        ];

        let mut conn = open_connection(data_dir)?;
        projection::create_schema(&conn)?;
        {
            let tx = conn.transaction().map_err(map_db("begin init"))?;
            let mut chain = log_store::genesis_seed(&instance_id, &forest_id);
            let mut seq = 0u64;
            for ev in &events {
                seq += 1;
                chain = log_store::append_event(&tx, &chain, seq, ev, t)?;
                projection::fold(&tx, "", seq, ev)?;
            }
            projection::applied_set(&tx, "", seq, &hex::encode(chain))?;
            tx.commit().map_err(map_db("commit init"))?;
        }
        projection::meta_set(&conn, "clean_shutdown", "0")?;

        let device = DeviceKeyCache {
            signing_key: device_key,
            device_index,
        };
        device.save(data_dir)?;

        Ok(Engine {
            conn,
            data_dir: data_dir.to_path_buf(),
            device,
            identity: ForestIdentity {
                instance_id,
                forest_id,
                root_node_id: root_node.id,
                root_pubkey: root_pub,
            },
            closed: false,
            replica: false,
        })
    }

    /// Open an existing data dir using the cached device key (spec §9.3 runs
    /// on every open).
    pub fn open(data_dir: &Path) -> Result<Engine> {
        // A marked replica dir routes to the read-only open (F2, doc 17 §5) —
        // callers need not know which kind of forest a data dir holds.
        if crate::replica::marker_path(data_dir).exists() {
            return Self::open_replica(data_dir);
        }
        let device = DeviceKeyCache::load(data_dir)?;
        let mut conn = open_connection(data_dir)?;
        let identity = projection::startup_check(&mut conn, data_dir)?;
        projection::meta_set(&conn, "clean_shutdown", "0")?;
        let mut engine = Engine {
            conn,
            data_dir: data_dir.to_path_buf(),
            device,
            identity,
            closed: false,
            replica: false,
        };
        engine.ensure_device_active()?;
        engine.sweep_temp_spool()?; // doc 04 §7 startup reconciliation
        engine.split_unsplit_regions()?; // P7.2a upgrade path (doc 20 §2.3)
        Ok(engine)
    }

    /// P7.2a upgrade path (doc 20 §2.3): a region marked before physical logs
    /// existed is split lazily at first writer open — baseline commitment now,
    /// fresh generation from here. Outer regions split before nested ones so
    /// each baseline's host log exists when it authors.
    fn split_unsplit_regions(&mut self) -> Result<()> {
        loop {
            let next: Option<String> = self
                .conn
                .query_row(
                    "SELECT r.node_id FROM regions r
                     WHERE r.state_root IS NULL
                       AND (r.parent_log = '' OR EXISTS (
                         SELECT 1 FROM regions p
                         WHERE p.node_id = r.parent_log AND p.state_root IS NOT NULL))
                     LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("find unsplit region"))?;
            let Some(node) = next else {
                let stuck: i64 = self
                    .conn
                    .query_row(
                        "SELECT COUNT(*) FROM regions WHERE state_root IS NULL",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(map_db("count unsplit"))?;
                if stuck > 0 {
                    return Err(PvfsError::Corruption {
                        db: "index.db".into(),
                        detail: format!(
                            "{stuck} region(s) cannot split: their enclosing region \
                             rows are missing"
                        ),
                        seq: None,
                    });
                }
                return Ok(());
            };
            let state_root = projection::canonical_state_root(&self.conn, &node)?;
            let t = now_ms();
            let me = self.device.pubkey();
            let sig = crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_region_baseline(&node, &state_root, t, &me),
            )?;
            self.append_durable(vec![Event::RegionBaseline {
                node_id: node,
                state_root: state_root.to_vec(),
                at: t,
                author: me,
                sig,
            }])?;
        }
    }

    /// An additional **read-only view** of an already-open forest, for the
    /// daemon's concurrent metadata reads (doc 07 §6): the same databases on a
    /// `SQLITE_OPEN_READ_ONLY` connection, with none of `open`'s startup writes
    /// (no clean-shutdown flip, no self-heal, no spool sweep — the primary
    /// writer engine did those; a view that finds a schema it doesn't speak
    /// errors instead of rebuilding). Read methods behave identically; any
    /// mutating call fails at the SQLite layer, so misuse cannot corrupt.
    /// Open views only while a writer `Engine` has the forest open.
    pub fn open_read_view(data_dir: &Path) -> Result<Engine> {
        let device = DeviceKeyCache::load(data_dir)?;
        let conn = open_connection_read_only(data_dir)?;
        let identity = projection::read_view_check(&conn)?;
        Ok(Engine {
            conn,
            data_dir: data_dir.to_path_buf(),
            device,
            identity,
            // `closed: true` keeps Drop from touching the clean-shutdown flag —
            // shutdown bookkeeping belongs to the writer engine alone.
            closed: true,
            replica: false,
        })
    }

    /// Open a **replica** forest read-only (F2, doc 17 §5): the standard
    /// startup check replays and verifies the shipped log (chain, signatures,
    /// replay authorization), so a replica that opens is a *proven* copy.
    /// There is no device key — the local machine is not a member of the
    /// replicated forest by construction — so an ephemeral key satisfies the
    /// engine plumbing and every log write is refused.
    pub fn open_replica(data_dir: &Path) -> Result<Engine> {
        let device = DeviceKeyCache::ephemeral()?;
        let mut conn = open_connection(data_dir)?;
        let identity = projection::startup_check(&mut conn, data_dir)?;
        projection::meta_set(&conn, "clean_shutdown", "0")?;
        Ok(Engine {
            conn,
            data_dir: data_dir.to_path_buf(),
            device,
            identity,
            closed: false,
            replica: true,
        })
    }

    /// True when `pubkey` is an authorized, unrevoked member/device key —
    /// the bar for member-gated operational reads (punch F, doc 18).
    pub fn is_active_member(&self, pubkey: &[u8]) -> Result<bool> {
        let n: i64 = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM device_keys WHERE device_pubkey = ?1 AND revoked_at IS NULL)",
                params![pubkey],
                |r| r.get(0),
            )
            .map_err(map_db("member check"))?;
        Ok(n != 0)
    }

    /// True for a replica forest (local writes refused).
    pub fn is_replica(&self) -> bool {
        self.replica
    }

    /// Highest seq in the log (the chain tip position).
    pub fn log_tip(&self) -> Result<u64> {
        log_store::max_seq(&self.conn)
    }

    /// Raw log rows `[from_seq ..]`, at most `max` (log shipping, F2). The
    /// caller gates access — a full log reveals the whole forest's history.
    pub fn log_events(&self, from_seq: u64, max: usize) -> Result<Vec<log_store::EventRow>> {
        log_store::read_range(&self.conn, from_seq, max)
    }

    /// A cheap signal that **any** log (top or region) advanced: the total of
    /// the per-log applied marks. Not monotone across unmarks (a seal drops a
    /// row) — consumers compare for *change*, not order. The daemon's
    /// `LogWait` uses it to wake followers for region sweeps (P7.2b).
    pub fn log_activity(&self) -> Result<u64> {
        self.conn
            .query_row(
                "SELECT IFNULL(TOTAL(seq),0) FROM applied_marks",
                [],
                |r| r.get::<_, f64>(0),
            )
            .map(|v| v as u64)
            .map_err(map_db("log activity"))
    }

    /// A region generation's `(tip, rows [from_seq..])` for log shipping
    /// (P7.2b, doc 20 §2.4). `rel_file` is the validated `regions/…` path
    /// from [`crate::replica::parse_region_addr`]; the caller gates access
    /// (admin on the region root). `NotFound` when this instance does not
    /// hold the generation.
    pub fn region_log_events(
        &self,
        rel_file: &str,
        from_seq: u64,
        max: usize,
    ) -> Result<(u64, Vec<log_store::EventRow>)> {
        let path = self.data_dir.join(rel_file);
        if !path.exists() {
            return Err(PvfsError::NotFound {
                kind: "region log",
                id: rel_file.into(),
            });
        }
        let conn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(map_db("open region log"))?;
        let tip: i64 = conn
            .query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| r.get(0))
            .map_err(map_db("read region tip"))?;
        let mut stmt = conn
            .prepare(
                "SELECT seq, kind, body, chain_hash, written_at FROM events
                 WHERE seq >= ?1 ORDER BY seq LIMIT ?2",
            )
            .map_err(map_db("read region range"))?;
        let rows = stmt
            .query_map(params![from_seq as i64, max as i64], |r| {
                Ok(log_store::EventRow {
                    seq: r.get::<_, i64>(0)? as u64,
                    kind: r.get(1)?,
                    body: r.get(2)?,
                    chain_hash: r.get(3)?,
                    written_at: r.get::<_, i64>(4)? as u64,
                })
            })
            .map_err(map_db("read region range"))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("read region range"))?;
        Ok((tip as u64, rows))
    }

    /// Recover onto a machine from the mnemonic: re-derive the device key and
    /// (if needed) self-authorize it with the identity root (spec §10).
    pub fn recover(data_dir: &Path, mnemonic: &Mnemonic, device_index: u64) -> Result<Engine> {
        let root_key = identity::root_key(mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        let device_key = identity::device_key(mnemonic, "", device_index)?;
        let device_pub = crypto::pubkey_bytes(&device_key);

        let mut conn = open_connection(data_dir)?;
        let identity = projection::startup_check(&mut conn, data_dir)?;
        // Compare against the CURRENT lineage root (doc 15 §C2), not the genesis
        // root: after a root rotation only the new seed recovers, and the old
        // (compromised) seed is rejected here rather than writing a device cert
        // its author no longer has authority for.
        let current_root = projection::current_root(&conn, &identity)?;
        if current_root != root_pub {
            return Err(PvfsError::Identity {
                detail: "mnemonic does not match this forest's current identity root".into(),
            });
        }
        let device = DeviceKeyCache {
            signing_key: device_key,
            device_index,
        };
        let mut engine = Engine {
            conn,
            data_dir: data_dir.to_path_buf(),
            device,
            identity,
            closed: false,
            replica: false,
        };
        if !engine.device_known(&device_pub)? {
            let t = now_ms();
            let sig = crypto::sign_digest(
                &root_key,
                &event::msg_device_authorized(&device_pub, device_index, t, &root_pub),
            )?;
            engine.append_durable(vec![Event::DeviceAuthorized {
                device_pubkey: device_pub,
                device_index,
                authorized_at: t,
                author: root_pub,
                sig,
            }])?;
        }
        engine.device.save(data_dir)?;
        engine.split_unsplit_regions()?; // P7.2a upgrade path (doc 20 §2.3)
        projection::meta_set(&engine.conn, "clean_shutdown", "0")?;
        engine.ensure_device_active()?;
        engine.sweep_temp_spool()?; // doc 04 §7 — rebuild empties temp ⇒ spool emptied
        Ok(engine)
    }

    /// Graceful close — sets the clean-shutdown flag (spec §9.3).
    pub fn close(mut self) -> Result<()> {
        // P7.2a: leave every region head attested at rest (doc 20 §2.3).
        // Best-effort — closing must succeed even if a head can't author.
        if !self.replica {
            let _ = self.commit_region_heads();
        }
        projection::meta_set(&self.conn, "clean_shutdown", "1")?;
        self.closed = true;
        Ok(())
    }

    /// Flush the write-ahead logs and record a clean shutdown **without** consuming
    /// the engine (doc 08 §4 item 4). The daemon holds its `Engine` behind a `Mutex`
    /// and can't call `close(self)`, so on SIGTERM/SIGINT it calls this: it runs
    /// `wal_checkpoint(TRUNCATE)` on the projection (`index.db`) and the attached
    /// `log` db so no WAL frames are left pending, then sets `clean_shutdown = 1` so
    /// the next startup takes the fast path. Idempotent and safe to call once at exit.
    pub fn shutdown_checkpoint(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA log.wal_checkpoint(TRUNCATE);",
            )
            .map_err(map_db("wal checkpoint"))?;
        projection::meta_set(&self.conn, "clean_shutdown", "1")?;
        Ok(())
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn device_pubkey(&self) -> Vec<u8> {
        self.device.pubkey()
    }

    /// Fetch a durable node's metadata by id, or `None` if it doesn't exist.
    pub fn node(&self, id: &NodeId) -> Result<Option<Node>> {
        fetch_node(&self.conn, id)
    }

    /// The node's home (`contains`) parent, `None` for a tree root.
    pub fn parent_of(&self, id: &NodeId) -> Result<Option<String>> {
        crate::projection::contains_parent(&self.conn, id)
    }

    // ---- internal helpers ------------------------------------------------------

    fn device_known(&self, pubkey: &[u8]) -> Result<bool> {
        let got: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM device_keys WHERE device_pubkey = ?1",
                params![pubkey],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("device lookup"))?;
        Ok(got.is_some())
    }

    /// Local API events must be authored by an authorized, unrevoked device
    /// key (spec §6 device-key acceptance rule). A replica short-circuits to
    /// the read-only refusal — its ephemeral key is deliberately no one.
    pub(crate) fn ensure_device_active(&self) -> Result<()> {
        if self.replica {
            return Err(PvfsError::Forbidden {
                action: "write".into(),
                reason: "replica forest is read-only — its owner instance is the only writer"
                    .into(),
            });
        }
        let pk = self.device.pubkey();
        let active: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM device_keys WHERE device_pubkey = ?1 AND revoked_at IS NULL",
                params![pk],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("device check"))?;
        if active.is_none() {
            return Err(PvfsError::Integrity {
                kind: "device",
                id: hex::encode(pk),
                reason: IntegrityReason::UnknownAuthor,
            });
        }
        Ok(())
    }

    /// The log a node's events author in (P7.2a routing): a marked node is
    /// its own region's root; otherwise the fold-maintained sticky column
    /// ('' = the top log). Nodes not yet in the projection resolve through
    /// the batch's own homing links (`batch_homes`).
    fn resolve_region(
        &self,
        node: &str,
        batch_homes: &std::collections::HashMap<String, String>,
    ) -> Result<String> {
        let mut cur = node.to_string();
        for _ in 0..batch_homes.len() + 1 {
            let marked: Option<i64> = self
                .conn
                .query_row(
                    "SELECT 1 FROM regions WHERE node_id = ?1",
                    params![cur],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("region lookup"))?;
            if marked.is_some() {
                return Ok(cur);
            }
            let known: Option<Option<String>> = self
                .conn
                .query_row(
                    "SELECT region_id FROM nodes WHERE id = ?1",
                    params![cur],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("region lookup"))?;
            if let Some(region) = known {
                return Ok(region.unwrap_or_default());
            }
            match batch_homes.get(&cur) {
                Some(parent) => cur = parent.clone(),
                None => return Ok(String::new()),
            }
        }
        Ok(String::new())
    }

    /// The log where a region's boundary events (mark/unmark/baseline/head)
    /// author: the enclosing region — the active row's `parent_log` when the
    /// region exists, else the home parent's region (a first mark).
    fn enclosing_log(&self, node: &str) -> Result<String> {
        let parent_log: Option<String> = self
            .conn
            .query_row(
                "SELECT parent_log FROM regions WHERE node_id = ?1",
                params![node],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("region lookup"))?;
        if let Some(p) = parent_log {
            return Ok(p);
        }
        let parent: Option<String> = self
            .conn
            .query_row(
                "SELECT parent_id FROM links WHERE child_id = ?1 AND link_type = ?2
                   AND removed_at IS NULL LIMIT 1",
                params![node, LINK_CONTAINS],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("region lookup"))?
            .flatten();
        match parent {
            Some(p) => self.resolve_region(&p, &std::collections::HashMap::new()),
            None => Ok(String::new()),
        }
    }

    /// P7.2a event routing (doc 20 §2.3): the target log per event, computed
    /// against pre-transaction state plus the batch's own homing links.
    fn route_events(&self, events: &[Event]) -> Result<Vec<String>> {
        use std::collections::HashMap;
        let mut batch_homes: HashMap<String, String> = HashMap::new();
        for ev in events {
            if let Event::LinkCreated(l) = ev {
                if l.link_type == LINK_CONTAINS {
                    if let Some(p) = &l.parent_id {
                        batch_homes.insert(l.child_id.clone(), p.clone());
                    }
                }
            }
        }
        let mut routes = Vec::with_capacity(events.len());
        for ev in events {
            let route = match ev {
                // Forest-scoped kinds always author in the top log.
                Event::ForestCreated { .. }
                | Event::DeviceAuthorized { .. }
                | Event::DeviceRevoked { .. }
                | Event::RootRotated { .. }
                | Event::RecoveryKeyRegistered { .. }
                | Event::RecoveryKeyRevoked { .. }
                | Event::MemberTagged { .. } => String::new(),
                // Region boundary events author in the enclosing region.
                Event::RegionMarked { node_id, .. }
                | Event::RegionUnmarked { node_id, .. }
                | Event::RegionBaseline { node_id, .. }
                | Event::SubRegionHead { node_id, .. } => self.enclosing_log(node_id)?,
                Event::NodeCreated(n) => self.resolve_region(&n.id, &batch_homes)?,
                Event::LinkCreated(l) => match &l.parent_id {
                    Some(p) => self.resolve_region(p, &batch_homes)?,
                    None => String::new(),
                },
                Event::LinkRemoved { link_id, .. }
                | Event::LinkReordered { link_id, .. }
                | Event::LinkSuspended { link_id, .. }
                | Event::LinkUnsuspended { link_id, .. } => self.route_by_link(link_id, &batch_homes)?,
                Event::LinkSuperseded { old_link_id, .. } => {
                    self.route_by_link(old_link_id, &batch_homes)?
                }
                Event::FileLocationAdded { file_id, .. }
                | Event::FileLocationRemoved { file_id, .. } => {
                    self.resolve_region(file_id, &batch_homes)?
                }
                Event::NodePurged { node_id, .. }
                | Event::FolderBound { folder_id: node_id, .. }
                | Event::FolderUnbound { folder_id: node_id, .. }
                | Event::AclSet { node_id, .. } => self.resolve_region(node_id, &batch_homes)?,
                Event::SecureBlobUpdated { blob_id, .. } => {
                    self.resolve_region(blob_id, &batch_homes)?
                }
            };
            routes.push(route);
        }
        Ok(routes)
    }

    /// Link-state events route by the link's containing side (root links by
    /// the child, matching their authorization rule).
    fn route_by_link(
        &self,
        link_id: &str,
        batch_homes: &std::collections::HashMap<String, String>,
    ) -> Result<String> {
        let row: Option<(Option<String>, String)> = self
            .conn
            .query_row(
                "SELECT parent_id, child_id FROM links WHERE id = ?1",
                params![link_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_db("link route lookup"))?;
        match row {
            Some((Some(parent), _)) => self.resolve_region(&parent, batch_homes),
            Some((None, child)) => self.resolve_region(&child, batch_homes),
            None => Ok(String::new()),
        }
    }

    /// Append durable events + fold, atomically (spec §9.1), with optional
    /// extra temp-table work in the same transaction. P7.2a: each event is
    /// routed to its region's log (doc 20 §2.3); a batch may span logs, and
    /// per-log applied marks advance together with the folds.
    pub(crate) fn append_durable_with(
        &mut self,
        events: Vec<Event>,
        temp_ops: impl FnOnce(&Transaction<'_>) -> Result<()>,
    ) -> Result<()> {
        if self.replica {
            return Err(PvfsError::Forbidden {
                action: "write".into(),
                reason: "replica forest is read-only — its owner instance is the only writer"
                    .into(),
            });
        }
        let routes = self.route_events(&events)?;
        // Attach every non-top target before the transaction (ATTACH cannot
        // run inside one). The region must be split — the writer splits all
        // active regions at open, so an unsplit target here is a logic error.
        let mut targets: Vec<String> = routes
            .iter()
            .filter(|r| !r.is_empty())
            .cloned()
            .collect();
        targets.sort();
        targets.dedup();
        for tgt in &targets {
            let file: Option<Option<String>> = self
                .conn
                .query_row(
                    "SELECT log_file FROM regions WHERE node_id = ?1 AND state_root IS NOT NULL",
                    params![tgt],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("region log lookup"))?;
            let file = file.flatten().ok_or_else(|| PvfsError::Corruption {
                db: format!("region log {tgt}"),
                detail: "write routed to a region that has no split log".into(),
                seq: None,
            })?;
            if let Some(dir) = self.data_dir.join(&file).parent() {
                std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("create region dir", e))?;
            }
            projection::attach_log(&self.conn, &self.data_dir, tgt, &file)?;
        }
        let result = (|| {
            let tx = self.conn.transaction().map_err(map_db("begin write"))?;
            let t = now_ms();
            // Per-log cursors, loaded lazily from each log's tip.
            let mut cursors: std::collections::HashMap<String, (u64, [u8; 32])> =
                std::collections::HashMap::new();
            for (ev, route) in events.iter().zip(&routes) {
                if !cursors.contains_key(route) {
                    let db = projection::attach_name(route);
                    let seq = log_store::max_seq_in(&tx, &db)?;
                    let chain = if seq == 0 {
                        projection::log_genesis(&tx, &self.identity, route)?
                    } else {
                        let row = log_store::read_event_in(&tx, &db, seq)?.ok_or_else(|| {
                            PvfsError::Corruption {
                                db: format!("log {route}"),
                                detail: format!("missing event at seq {seq}"),
                                seq: Some(seq),
                            }
                        })?;
                        if row.chain_hash.len() != 32 {
                            return Err(PvfsError::Corruption {
                                db: format!("log {route}"),
                                detail: "chain hash wrong length".into(),
                                seq: Some(seq),
                            });
                        }
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&row.chain_hash);
                        a
                    };
                    cursors.insert(route.clone(), (seq, chain));
                }
                let cur = cursors.get_mut(route).expect("cursor just inserted");
                cur.0 += 1;
                cur.1 = log_store::append_event_in(
                    &tx,
                    &projection::attach_name(route),
                    &cur.1,
                    cur.0,
                    ev,
                    t,
                )?;
                projection::fold(&tx, route, cur.0, ev)?;
            }
            for (log_id, (seq, chain)) in &cursors {
                projection::applied_set(&tx, log_id, *seq, &hex::encode(chain))?;
            }
            temp_ops(&tx)?;
            tx.commit().map_err(map_db("commit write"))?;
            Ok(())
        })();
        for tgt in &targets {
            let _ = projection::detach_log(&self.conn, tgt);
        }
        result
    }

    pub(crate) fn append_durable(&mut self, events: Vec<Event>) -> Result<()> {
        self.append_durable_with(events, |_| Ok(()))
    }

    /// Run only temp-table work in one transaction (no events, no log touch).
    pub(crate) fn temp_write(&mut self, ops: impl FnOnce(&Transaction<'_>) -> Result<()>) -> Result<()> {
        let tx = self.conn.transaction().map_err(map_db("begin temp write"))?;
        ops(&tx)?;
        tx.commit().map_err(map_db("commit temp write"))
    }

    pub(crate) fn sign_node(&self, mut n: Node) -> Result<Node> {
        let digest = n.id_digest();
        n.id = hex::encode(digest);
        n.sig = crypto::sign_digest(&self.device.signing_key, &digest)?;
        Ok(n)
    }

    pub(crate) fn sign_link(&self, mut l: Link) -> Result<Link> {
        let digest = l.id_digest();
        l.id = hex::encode(digest);
        l.sig = crypto::sign_digest(&self.device.signing_key, &digest)?;
        Ok(l)
    }

    /// Cycle guard (spec §12): walking up from `parent` via active `contains`
    /// links must never reach `child`.
    fn check_no_cycle(&self, parent: &str, child: &str) -> Result<()> {
        let mut path = vec![parent.to_string()];
        let mut current = parent.to_string();
        loop {
            if current == child {
                return Err(PvfsError::CycleDetected {
                    parent: parent.into(),
                    child: child.into(),
                    path: path.join(" -> "),
                });
            }
            match active_home(&self.conn, &current)? {
                Some((_, Some(p))) => {
                    path.push(p.clone());
                    current = p;
                }
                _ => return Ok(()),
            }
        }
    }

    /// Immediate temp purge with cascade (design doc §6.2): delete every temp
    /// node in `candidates` that now has zero active inbound links, cascading
    /// through its temp children, all inside the caller's transaction.
    pub(crate) fn temp_purge_cascade(tx: &Transaction<'_>, candidates: Vec<String>) -> Result<()> {
        let mut queue = candidates;
        while let Some(id) = queue.pop() {
            let is_temp: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM temp_nodes WHERE id = ?1",
                    params![id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("temp purge lookup"))?;
            if is_temp.is_none() {
                continue;
            }
            let inbound: i64 = tx
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM links WHERE child_id = ?1 AND removed_at IS NULL)
                          + (SELECT COUNT(*) FROM temp_links WHERE child_id = ?1 AND removed_at IS NULL)",
                    params![id],
                    |r| r.get(0),
                )
                .map_err(map_db("temp purge inbound"))?;
            if inbound > 0 {
                continue;
            }
            // collect temp children before deleting outbound links
            let children: Vec<String> = {
                let mut stmt = tx
                    .prepare(
                        "SELECT child_id FROM temp_links WHERE parent_id = ?1 AND removed_at IS NULL",
                    )
                    .map_err(map_db("temp purge children"))?;
                let rows = stmt
                    .query_map(params![id], |r| r.get::<_, String>(0))
                    .map_err(map_db("temp purge children"))?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(map_db("temp purge children"))?
            };
            tx.execute("DELETE FROM temp_nodes WHERE id = ?1", params![id])
                .map_err(map_db("temp purge"))?;
            tx.execute(
                "DELETE FROM temp_links WHERE parent_id = ?1 OR child_id = ?1",
                params![id],
            )
            .map_err(map_db("temp purge"))?;
            tx.execute(
                "DELETE FROM temp_file_locations WHERE file_id = ?1",
                params![id],
            )
            .map_err(map_db("temp purge"))?;
            queue.extend(children);
        }
        Ok(())
    }

    // ---- public API (spec §11) -------------------------------------------------

    /// Create a tree: a root folder node + a root link (`parent_id = None`).
    pub fn create_tree(&mut self, label: &str) -> Result<NodeId> {
        self.validate_label(label)?;
        self.ensure_device_active()?;
        let t = now_ms();
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        let n = self.sign_node(Node {
            id: String::new(),
            node_type: node::TYPE_FOLDER.into(),
            label: label.into(),
            visibility: VISIBILITY_PUBLIC.into(),
            payload: node::folder_payload(),
            is_temp: false,
            creation_nonce: u64::from_le_bytes(nonce),
            created_at: t,
            author: self.device.pubkey(),
            sig: Vec::new(),
        })?;
        let l = self.sign_link(Link {
            id: String::new(),
            parent_id: None,
            child_id: n.id.clone(),
            link_type: LINK_CONTAINS.into(),
            link_nonce: 0,
            order_key: OrderKey::middle().as_str().into(),
            created_at: t,
            author: self.device.pubkey(),
            sig: Vec::new(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        })?;
        let id = n.id.clone();
        self.append_durable(vec![Event::NodeCreated(n), Event::LinkCreated(l)])?;
        Ok(id)
    }

    pub(crate) fn validate_label(&self, label: &str) -> Result<()> {
        if label.is_empty() {
            return Err(bad("label", "must not be empty"));
        }
        if label.len() > LABEL_SOFT_CAP {
            return Err(bad("label", "exceeds 4 KiB soft cap"));
        }
        Ok(())
    }

    /// Create a node under `parent`, ordered at the end of its children.
    pub fn add_node(&mut self, parent: &NodeId, spec: NodeSpec) -> Result<NodeId> {
        self.validate_label(&spec.label)?;
        if spec.node_type.is_empty() {
            return Err(bad("node_type", "must not be empty"));
        }
        self.ensure_device_active()?;
        let parent_node = fetch_node(&self.conn, parent)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: parent.clone(),
        })?;

        let creation_nonce = spec.creation_nonce.unwrap_or_else(|| {
            let mut b = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut b);
            u64::from_le_bytes(b)
        });
        let t = now_ms();
        let n = self.sign_node(Node {
            id: String::new(),
            node_type: spec.node_type.clone(),
            label: spec.label.clone(),
            visibility: VISIBILITY_PUBLIC.into(),
            payload: spec.payload.clone(),
            is_temp: spec.is_temp,
            creation_nonce,
            created_at: t,
            author: self.device.pubkey(),
            sig: Vec::new(),
        })?;

        // API idempotency / conflict (spec §7): identical record ⇒ Ok(id).
        if let Some(existing) = fetch_node(&self.conn, &n.id)? {
            return if existing == n {
                Ok(n.id)
            } else {
                Err(PvfsError::AlreadyExists {
                    kind: "node",
                    id: n.id,
                })
            };
        }

        let order = OrderKey::after(max_order_key(&self.conn, parent)?.as_ref())?;
        let l = self.sign_link(Link {
            id: String::new(),
            parent_id: Some(parent.clone()),
            child_id: n.id.clone(),
            link_type: LINK_CONTAINS.into(),
            link_nonce: 0,
            order_key: order.as_str().into(),
            created_at: t,
            author: self.device.pubkey(),
            sig: Vec::new(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        })?;

        let id = n.id.clone();
        let link_is_temp = n.is_temp || parent_node.is_temp;
        if n.is_temp {
            // fully temp: node + link in temp tables, no events
            self.temp_write(|tx| {
                insert_temp_node(tx, &n)?;
                insert_temp_link(tx, &l)
            })?;
        } else if link_is_temp {
            // durable node, temp home (under a temp parent): node is logged,
            // the link is temp-only (design doc §2 temp exception)
            self.append_durable_with(vec![Event::NodeCreated(n)], |tx| insert_temp_link(tx, &l))?;
        } else {
            self.append_durable(vec![Event::NodeCreated(n), Event::LinkCreated(l)])?;
        }
        Ok(id)
    }

    /// Add an explicit link (e.g. a `ref` cross-link).
    pub fn link(
        &mut self,
        parent: &NodeId,
        child: &NodeId,
        link_type: &str,
        order: Option<&OrderKey>,
        link_nonce: u64,
    ) -> Result<LinkId> {
        if link_type.is_empty() {
            return Err(bad("link_type", "must not be empty"));
        }
        self.ensure_device_active()?;
        let parent_node = fetch_node(&self.conn, parent)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: parent.clone(),
        })?;
        let child_node = fetch_node(&self.conn, child)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: child.clone(),
        })?;

        if link_type == LINK_CONTAINS {
            // one-home rule (spec §5.2)
            if let Some((_, existing_parent)) = active_home(&self.conn, child)? {
                return Err(PvfsError::AlreadyContained {
                    child: child.clone(),
                    existing_parent: existing_parent.unwrap_or_else(|| "(tree root)".into()),
                });
            }
            self.check_no_cycle(parent, child)?;
            // P7.2a (doc 20 §2.3): adopting an orphan across a region boundary
            // IS a cross-region move — its history lives in its sticky region's
            // log. Refused until the paired-event protocol (P7.2c).
            let none = std::collections::HashMap::new();
            if self.resolve_region(child, &none)? != self.resolve_region(parent, &none)? {
                return Err(bad(
                    "link",
                    "node and new parent are in different regions — cross-region \
                     moves land with the paired-event protocol (doc 20 §2)",
                ));
            }
        }

        let order = match order {
            Some(o) => o.clone(),
            None => OrderKey::after(max_order_key(&self.conn, parent)?.as_ref())?,
        };
        let t = now_ms();
        let l = self.sign_link(Link {
            id: String::new(),
            parent_id: Some(parent.clone()),
            child_id: child.clone(),
            link_type: link_type.into(),
            link_nonce,
            order_key: order.as_str().into(),
            created_at: t,
            author: self.device.pubkey(),
            sig: Vec::new(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        })?;

        // logical-id conflict (spec §7 API idempotency — the link case)
        if let Some(existing) = fetch_link(&self.conn, &l.id)? {
            let same = existing.created_at == l.created_at
                && existing.author == l.author
                && existing.order_key == l.order_key
                && existing.removed_at.is_none();
            return if same {
                Ok(l.id)
            } else {
                Err(PvfsError::AlreadyExists {
                    kind: "link",
                    id: l.id,
                })
            };
        }

        let id = l.id.clone();
        if parent_node.is_temp || child_node.is_temp {
            self.temp_write(|tx| insert_temp_link(tx, &l))?;
        } else {
            self.append_durable(vec![Event::LinkCreated(l)])?;
        }
        Ok(id)
    }

    /// Soft-remove a link; triggers the temp-purge check (design doc §6.2).
    pub fn remove_link(&mut self, link_id: &LinkId) -> Result<()> {
        self.ensure_device_active()?;
        let t = now_ms();
        if let Some(l) = fetch_link(&self.conn, link_id)? {
            if l.removed_at.is_some() {
                return Ok(()); // idempotent
            }
            let me = self.device.pubkey();
            let sig = crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_link_removed(link_id, t, &me),
            )?;
            return self.append_durable(vec![Event::LinkRemoved {
                link_id: link_id.clone(),
                removed_at: t,
                removed_by: me,
                removal_sig: sig,
            }]);
        }
        if let Some(l) = fetch_temp_link(&self.conn, link_id)? {
            if l.removed_at.is_some() {
                return Ok(());
            }
            let child = l.child_id.clone();
            return self.temp_write(|tx| {
                tx.execute(
                    "UPDATE temp_links SET removed_at = ?1 WHERE id = ?2",
                    params![t as i64, l.id],
                )
                .map_err(map_db("remove temp link"))?;
                Engine::temp_purge_cascade(tx, vec![child])
            });
        }
        Err(PvfsError::NotFound {
            kind: "link",
            id: link_id.clone(),
        })
    }

    /// Change a link's sibling order.
    pub fn reorder_link(&mut self, link_id: &LinkId, new_key: &OrderKey) -> Result<()> {
        self.ensure_device_active()?;
        if let Some(_l) = fetch_link(&self.conn, link_id)? {
            let me = self.device.pubkey();
            let sig = crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_link_reordered(link_id, new_key.as_str(), &me),
            )?;
            return self.append_durable(vec![Event::LinkReordered {
                link_id: link_id.clone(),
                new_order_key: new_key.as_str().into(),
                author: me,
                sig,
            }]);
        }
        if fetch_temp_link(&self.conn, link_id)?.is_some() {
            let key = new_key.as_str().to_string();
            let lid = link_id.clone();
            return self.temp_write(|tx| {
                tx.execute(
                    "UPDATE temp_links SET order_key = ?1 WHERE id = ?2",
                    params![key, lid],
                )
                .map_err(map_db("reorder temp link"))?;
                Ok(())
            });
        }
        Err(PvfsError::NotFound {
            kind: "link",
            id: link_id.clone(),
        })
    }

    // ---- file locations (spec §4.3 / §6) ----------------------------------------

    pub fn add_location(&mut self, file: &NodeId, uri: &str) -> Result<()> {
        if uri.is_empty() {
            return Err(bad("uri", "must not be empty"));
        }
        self.ensure_device_active()?;
        let n = fetch_node(&self.conn, file)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: file.clone(),
        })?;
        if n.node_type == node::TYPE_SECURE {
            // doc 12 §8.3: a secure blob takes exactly ONE location (v1).
            let existing = self.locations(file)?;
            if !existing.is_empty() && existing.iter().any(|u| u != uri) {
                return Err(bad("uri", "a secure node takes exactly one location (doc 12 §8.3)"));
            }
        } else if n.node_type != node::TYPE_FILE {
            return Err(bad("file", "locations can only be added to file or secure nodes"));
        }
        let t = now_ms();
        if n.is_temp {
            let (f, u) = (file.clone(), uri.to_string());
            return self.temp_write(|tx| {
                tx.execute(
                    "INSERT INTO temp_file_locations (file_id, uri, added_at, removed_at)
                     VALUES (?1, ?2, ?3, NULL)
                     ON CONFLICT(file_id, uri) DO UPDATE SET
                       added_at = excluded.added_at, removed_at = NULL",
                    params![f, u, t as i64],
                )
                .map_err(map_db("add temp location"))?;
                Ok(())
            });
        }
        // idempotent: already-active location is a no-op (no junk event)
        let already: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM file_locations WHERE file_id = ?1 AND uri = ?2 AND removed_at IS NULL",
                params![file, uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("location lookup"))?;
        if already.is_some() {
            return Ok(());
        }
        let me = self.device.pubkey();
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_file_location_added(file, uri, t, &me),
        )?;
        self.append_durable(vec![Event::FileLocationAdded {
            file_id: file.clone(),
            uri: uri.into(),
            added_at: t,
            author: me,
            sig,
        }])
    }

    pub fn remove_location(&mut self, file: &NodeId, uri: &str) -> Result<()> {
        self.ensure_device_active()?;
        let n = fetch_node(&self.conn, file)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: file.clone(),
        })?;
        let t = now_ms();
        if n.is_temp {
            let (f, u) = (file.clone(), uri.to_string());
            return self.temp_write(|tx| {
                let changed = tx
                    .execute(
                        "UPDATE temp_file_locations SET removed_at = ?1
                         WHERE file_id = ?2 AND uri = ?3 AND removed_at IS NULL",
                        params![t as i64, f, u],
                    )
                    .map_err(map_db("remove temp location"))?;
                if changed == 0 {
                    return Err(PvfsError::NotFound {
                        kind: "location",
                        id: format!("{f} {u}"),
                    });
                }
                Ok(())
            });
        }
        let active: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM file_locations WHERE file_id = ?1 AND uri = ?2 AND removed_at IS NULL",
                params![file, uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("location lookup"))?;
        if active.is_none() {
            return Err(PvfsError::NotFound {
                kind: "location",
                id: format!("{file} {uri}"),
            });
        }
        let me = self.device.pubkey();
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_file_location_removed(file, uri, t, &me),
        )?;
        self.append_durable(vec![Event::FileLocationRemoved {
            file_id: file.clone(),
            uri: uri.into(),
            removed_at: t,
            removed_by: me,
            removal_sig: sig,
        }])
    }

    /// Active URIs for a file node. The managed sync store (F3) is included
    /// by **existence, not record**: `pvfs-sync:///<id>` appears whenever the
    /// store holds the file, so synced bytes survive projection rebuilds with
    /// no table to keep consistent.
    pub fn locations(&self, file: &NodeId) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT uri FROM file_locations WHERE file_id = ?1 AND removed_at IS NULL
                 UNION ALL
                 SELECT uri FROM temp_file_locations WHERE file_id = ?1 AND removed_at IS NULL
                 ORDER BY uri",
            )
            .map_err(map_db("locations"))?;
        let rows = stmt
            .query_map(params![file], |r| r.get::<_, String>(0))
            .map_err(map_db("locations"))?;
        let mut out: Vec<String> = rows
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("locations"))?;
        if crate::sync::sync_store_lookup(&self.data_dir, file)?.is_some() {
            out.push(crate::sync::sync_uri(file));
        }
        Ok(out)
    }

    /// Catalog locations bearing THIS instance's pin that have been retired
    /// (`FileLocationRemoved`) and not re-added — the mover's eviction signal
    /// (F5.3, doc 17 §7.4): `(file_id, uri, local_path)` rows whose bytes
    /// this host may now delete, once it confirms another live location.
    /// Empty when this instance has no transport pin.
    pub fn retired_own_host_locations(&self) -> Result<Vec<(NodeId, String, PathBuf)>> {
        let Some(pin) = crate::storage::host_pin(&self.data_dir) else {
            return Ok(Vec::new());
        };
        let prefix = format!("{}{pin}/", crate::storage::HOST_URI_PREFIX);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT DISTINCT file_id, uri FROM file_locations l1
                 WHERE uri LIKE ?1 || '%' AND removed_at IS NOT NULL
                   AND NOT EXISTS (SELECT 1 FROM file_locations l2
                                   WHERE l2.file_id = l1.file_id AND l2.uri = l1.uri
                                     AND l2.removed_at IS NULL)",
            )
            .map_err(map_db("retired locations"))?;
        let rows = stmt
            .query_map(params![prefix], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(map_db("retired locations"))?;
        let mut out = Vec::new();
        for row in rows {
            let (file_id, uri) = row.map_err(map_db("retired locations"))?;
            if let Some((_, path)) = crate::storage::parse_host_uri(&uri) {
                out.push((file_id, uri.clone(), PathBuf::from(path)));
            }
        }
        Ok(out)
    }

    // ---- reads -------------------------------------------------------------------

    pub fn get_node(&self, id: &NodeId) -> Result<Option<Node>> {
        fetch_node(&self.conn, id)
    }

    /// Ordered children of a parent — `contains` and `ref` merged by
    /// `order_key`, each tagged with its link type (spec §12).
    pub fn children(&self, parent: &NodeId) -> Result<Vec<ChildEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT child_id, id, link_type, order_key FROM (
                   SELECT child_id, id, link_type, order_key FROM links
                    WHERE parent_id = ?1 AND removed_at IS NULL AND suspended_at IS NULL
                   UNION ALL
                   SELECT child_id, id, link_type, order_key FROM temp_links
                    WHERE parent_id = ?1 AND removed_at IS NULL AND suspended_at IS NULL
                 ) ORDER BY order_key, child_id",
            )
            .map_err(map_db("children"))?;
        let rows = stmt
            .query_map(params![parent], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(map_db("children"))?;
        let mut out = Vec::new();
        for row in rows {
            let (child_id, link_id, link_type, order_key) = row.map_err(map_db("children"))?;
            if let Some(n) = fetch_node(&self.conn, &child_id)? {
                out.push(ChildEntry {
                    node: n,
                    link_id,
                    link_type,
                    order_key,
                });
            }
        }
        Ok(out)
    }

    /// Pre-order walk (spec §12): descends `contains` only; `ref` children
    /// are yielded but never descended. Visits each node exactly once —
    /// the one-home rule makes the contains hierarchy a strict tree, so no
    /// visited-set is needed.
    pub fn walk(&self, root: &NodeId) -> Result<TreeWalk> {
        let root_node = fetch_node(&self.conn, root)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: root.clone(),
        })?;
        let mut entries = vec![WalkEntry {
            node: root_node,
            depth: 0,
            link_type: LINK_CONTAINS.into(),
        }];
        self.preorder_into(root, 1, &mut entries)?;
        Ok(TreeWalk { entries })
    }

    fn preorder_into(&self, parent: &str, depth: usize, out: &mut Vec<WalkEntry>) -> Result<()> {
        for k in self.children(&parent.to_string())? {
            let id = k.node.id.clone();
            let descend = k.link_type == LINK_CONTAINS;
            out.push(WalkEntry {
                node: k.node,
                depth,
                link_type: k.link_type,
            });
            if descend {
                self.preorder_into(&id, depth + 1, out)?;
            }
        }
        Ok(())
    }

    /// Recompute id + check signature (spec §4.4). Ok(true) when valid;
    /// integrity failures surface as typed errors with detail (§13.3).
    pub fn verify(&self, id: &NodeId) -> Result<bool> {
        let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: id.clone(),
        })?;
        n.verify()?;
        Ok(true)
    }

    // ---- lifecycle: orphans & purge ----------------------------------------------

    /// Durable nodes with zero active inbound links (counted across BOTH
    /// links and temp_links — design doc §6.1).
    pub fn list_orphans(&self) -> Result<Vec<Node>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id FROM nodes WHERE id NOT IN (
                   SELECT child_id FROM links WHERE removed_at IS NULL
                   UNION
                   SELECT child_id FROM temp_links WHERE removed_at IS NULL
                 )",
            )
            .map_err(map_db("list orphans"))?;
        let ids = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_db("list orphans"))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("list orphans"))?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(n) = fetch_node(&self.conn, &id)? {
                out.push(n);
            }
        }
        Ok(out)
    }

    /// Explicit hard delete — purge protocol (spec §9.2): orphans only;
    /// auto-emits LinkRemoved for the node's active outbound links first.
    pub fn purge(&mut self, ids: &[NodeId]) -> Result<()> {
        self.ensure_device_active()?;
        for id in ids {
            let n = fetch_node(&self.conn, id)?.ok_or(PvfsError::NotFound {
                kind: "node",
                id: id.clone(),
            })?;
            // P7.2a (doc 20 §2.3): purging through a region boundary would
            // scatter one cascade across logs and orphan a live region log.
            let marked_inside: Option<String> = self
                .conn
                .query_row(
                    "WITH RECURSIVE sub(nid) AS (
                       SELECT ?1
                       UNION
                       SELECT l.child_id FROM links l JOIN sub s ON l.parent_id = s.nid
                       WHERE l.link_type = ?2 AND l.removed_at IS NULL
                     )
                     SELECT r.node_id FROM regions r JOIN sub s ON r.node_id = s.nid LIMIT 1",
                    params![id, LINK_CONTAINS],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("purge region check"))?;
            if let Some(region) = marked_inside {
                return Err(bad(
                    "purge",
                    &format!(
                        "subtree contains region boundary {region} — `pvfs region \
                         unmark` it first, then purge (doc 20 §2.3)"
                    ),
                ));
            }
            let inbound = active_inbound_count(&self.conn, id)?;
            if inbound > 0 {
                return Err(PvfsError::NotOrphan {
                    id: id.clone(),
                    active_inbound: inbound,
                });
            }
            let t = now_ms();
            if n.is_temp {
                // temp: plain local delete, no events
                let nid = id.clone();
                self.temp_write(|tx| Engine::temp_purge_cascade(tx, vec![nid]))?;
                continue;
            }
            // active outbound durable links → LinkRemoved events
            let outbound: Vec<String> = {
                let mut stmt = self
                    .conn
                    .prepare("SELECT id FROM links WHERE parent_id = ?1 AND removed_at IS NULL")
                    .map_err(map_db("purge outbound"))?;
                let rows = stmt
                    .query_map(params![id], |r| r.get::<_, String>(0))
                    .map_err(map_db("purge outbound"))?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(map_db("purge outbound"))?
            };
            // active outbound temp links (durable parent → temp child)
            let temp_children: Vec<String> = {
                let mut stmt = self
                    .conn
                    .prepare(
                        "SELECT child_id FROM temp_links WHERE parent_id = ?1 AND removed_at IS NULL",
                    )
                    .map_err(map_db("purge temp outbound"))?;
                let rows = stmt
                    .query_map(params![id], |r| r.get::<_, String>(0))
                    .map_err(map_db("purge temp outbound"))?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(map_db("purge temp outbound"))?
            };

            let me = self.device.pubkey();
            let mut events = Vec::new();
            for link_id in outbound {
                let sig = crypto::sign_digest(
                    &self.device.signing_key,
                    &event::msg_link_removed(&link_id, t, &me),
                )?;
                events.push(Event::LinkRemoved {
                    link_id,
                    removed_at: t,
                    removed_by: me.clone(),
                    removal_sig: sig,
                });
            }
            let purge_sig = crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_node_purged(id, t, &me),
            )?;
            events.push(Event::NodePurged {
                node_id: id.clone(),
                purged_at: t,
                author: me,
                sig: purge_sig,
            });
            let nid = id.clone();
            self.append_durable_with(events, move |tx| {
                tx.execute(
                    "UPDATE temp_links SET removed_at = ?1 WHERE parent_id = ?2 AND removed_at IS NULL",
                    params![t as i64, nid],
                )
                .map_err(map_db("purge temp links"))?;
                Engine::temp_purge_cascade(tx, temp_children)
            })?;
        }
        Ok(())
    }

    // ---- device certificates (spec §10) --------------------------------------------

    /// Authorize a new device key under this forest's identity root.
    pub fn authorize_device(&mut self, mnemonic: &Mnemonic, device_index: u64) -> Result<Vec<u8>> {
        let root_key = identity::root_key(mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        if root_pub != self.current_root()? {
            return Err(PvfsError::Identity {
                detail: "mnemonic does not match this forest's current identity root".into(),
            });
        }
        let device_key = identity::device_key(mnemonic, "", device_index)?;
        let device_pub = crypto::pubkey_bytes(&device_key);
        let t = now_ms();
        let sig = crypto::sign_digest(
            &root_key,
            &event::msg_device_authorized(&device_pub, device_index, t, &root_pub),
        )?;
        self.append_durable(vec![Event::DeviceAuthorized {
            device_pubkey: device_pub.clone(),
            device_index,
            authorized_at: t,
            author: root_pub,
            sig,
        }])?;
        Ok(device_pub)
    }

    /// Authorize an externally-supplied **member key** (another user's device)
    /// as a writer under this forest's identity root (doc 06 §3). The member
    /// signs their own events; this only admits their public key. Requires the
    /// recovery phrase, since only the identity root may authorize devices.
    pub fn authorize_member(&mut self, mnemonic: &Mnemonic, member_pubkey: &[u8]) -> Result<()> {
        crypto::validate_pubkey(member_pubkey)?;
        let root_key = identity::root_key(mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        let current = self.current_root()?;
        if root_pub != current {
            return Err(PvfsError::Identity {
                detail: "mnemonic does not match this forest's current identity root".into(),
            });
        }
        if member_pubkey == current.as_slice() {
            return Err(PvfsError::BadInput {
                field: "member_pubkey".into(),
                reason: "refusing to authorize the identity root as a device".into(),
            });
        }
        if self.device_known(member_pubkey)? {
            return Err(PvfsError::AlreadyExists {
                kind: "device",
                id: hex::encode(member_pubkey),
            });
        }
        let t = now_ms();
        // External members are not HD-derived from this forest's seed; record the
        // reserved index that marks a member (ACL-gated, not an owner device).
        let device_index = crate::acl::MEMBER_DEVICE_INDEX;
        let sig = crypto::sign_digest(
            &root_key,
            &event::msg_device_authorized(member_pubkey, device_index, t, &root_pub),
        )?;
        self.append_durable(vec![Event::DeviceAuthorized {
            device_pubkey: member_pubkey.to_vec(),
            device_index,
            authorized_at: t,
            author: root_pub,
            sig,
        }])
    }

    /// Revoke a device key for new appends (its valid history stands).
    pub fn revoke_device(&mut self, mnemonic: &Mnemonic, device_pubkey: &[u8]) -> Result<()> {
        let root_key = identity::root_key(mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        if root_pub != self.current_root()? {
            return Err(PvfsError::Identity {
                detail: "mnemonic does not match this forest's current identity root".into(),
            });
        }
        if !self.device_known(device_pubkey)? {
            return Err(PvfsError::NotFound {
                kind: "device",
                id: hex::encode(device_pubkey),
            });
        }
        let t = now_ms();
        let sig = crypto::sign_digest(
            &root_key,
            &event::msg_device_revoked(device_pubkey, t, &root_pub),
        )?;
        self.append_durable(vec![Event::DeviceRevoked {
            device_pubkey: device_pubkey.to_vec(),
            revoked_at: t,
            author: root_pub,
            sig,
        }])
    }

    /// Authorize an external member key signed by the **local device** — no
    /// recovery phrase (doc 09 §2.2). The local device must hold admin (`a`) on
    /// the forest root (owner devices do).
    pub fn authorize_member_by_device(&mut self, member_pubkey: &[u8]) -> Result<()> {
        self.ensure_device_active()?;
        crypto::validate_pubkey(member_pubkey)?;
        if member_pubkey == self.current_root()?.as_slice() {
            return Err(bad(
                "member_pubkey",
                "refusing to authorize the identity root as a device",
            ));
        }
        self.require_local_admin("authorize member")?;
        if self.device_known(member_pubkey)? {
            return Err(PvfsError::AlreadyExists {
                kind: "device",
                id: hex::encode(member_pubkey),
            });
        }
        let t = now_ms();
        let author = self.device_pubkey();
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_device_authorized(member_pubkey, crate::acl::MEMBER_DEVICE_INDEX, t, &author),
        )?;
        self.append_durable(vec![Event::DeviceAuthorized {
            device_pubkey: member_pubkey.to_vec(),
            device_index: crate::acl::MEMBER_DEVICE_INDEX,
            authorized_at: t,
            author,
            sig,
        }])
    }

    /// Revoke a device/member key signed by the **local device** — no recovery
    /// phrase. The local device must hold admin (`a`) on the forest root.
    pub fn revoke_by_device(&mut self, device_pubkey: &[u8]) -> Result<()> {
        self.ensure_device_active()?;
        self.require_local_admin("revoke device")?;
        if !self.device_known(device_pubkey)? {
            return Err(PvfsError::NotFound {
                kind: "device",
                id: hex::encode(device_pubkey),
            });
        }
        let t = now_ms();
        let author = self.device_pubkey();
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_device_revoked(device_pubkey, t, &author),
        )?;
        self.append_durable(vec![Event::DeviceRevoked {
            device_pubkey: device_pubkey.to_vec(),
            revoked_at: t,
            author,
            sig,
        }])
    }

    /// Require the local device to hold admin (`a`) on the forest root.
    fn require_local_admin(&self, action: &'static str) -> Result<()> {
        let root = self.identity.root_node_id.clone();
        let me = crate::acl::Principal::Key(self.device_pubkey());
        if projection::effective_rights(&self.conn, &me, &root)? & crate::acl::ACL_A == 0 {
            return Err(PvfsError::Forbidden {
                action: action.into(),
                reason: "this device lacks admin (a) on the forest root".into(),
            });
        }
        Ok(())
    }

    // ---- access control (doc 06 §4) ------------------------------------------------

    /// Set (or, with `rights == 0`, clear) one principal's rights on `node_id`.
    /// Authored by the local device, which must hold admin (`a`) on the node —
    /// owner devices always do. The principal signs their *own* writes later
    /// (Phase C); this only records the grant.
    pub fn set_acl(
        &mut self,
        node_id: &NodeId,
        principal: &crate::acl::Principal,
        rights: u8,
    ) -> Result<()> {
        self.set_acl_expiring(node_id, principal, rights, 0)
    }

    /// [`set_acl`](Self::set_acl) with an expiry (doc 13 Q-E1): the grant goes
    /// inert once `expires_at` (ms epoch) passes; `0` = never. A past instant is
    /// accepted — the grant is simply born inert (useful for tests and imports).
    pub fn set_acl_expiring(
        &mut self,
        node_id: &NodeId,
        principal: &crate::acl::Principal,
        rights: u8,
        expires_at: u64,
    ) -> Result<()> {
        self.ensure_device_active()?;
        if fetch_node(&self.conn, node_id)?.is_none() {
            return Err(PvfsError::NotFound {
                kind: "node",
                id: node_id.clone(),
            });
        }
        let me = crate::acl::Principal::Key(self.device_pubkey());
        if projection::effective_rights(&self.conn, &me, node_id)? & crate::acl::ACL_A == 0 {
            return Err(PvfsError::BadInput {
                field: "acl".into(),
                reason: "this device lacks admin (a) on the node".into(),
            });
        }
        let t = now_ms();
        let kind = principal.kind();
        let id = principal.id().to_vec();
        let author = self.device_pubkey();
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_acl_set(node_id, kind, &id, rights as u64, t, expires_at, &author),
        )?;
        self.append_durable(vec![Event::AclSet {
            node_id: node_id.clone(),
            principal_kind: kind,
            principal_id: id,
            rights: rights as u64,
            set_at: t,
            expires_at,
            author,
            sig,
        }])
    }

    /// Effective rights for `principal` on `node_id` (doc 06 §4.2) — what the
    /// daemon (Phase C) will consult per connected caller.
    pub fn effective_rights(
        &self,
        principal: &crate::acl::Principal,
        node_id: &NodeId,
    ) -> Result<u8> {
        projection::effective_rights(&self.conn, principal, node_id)
    }

    /// Direct ACL grants on `node_id` (not inherited), for `acl ls`. Each entry is
    /// `(principal, authority, rights, expires_at)`; `authority` is the granting
    /// key for `tag:` grants (doc 10) and empty for `public`/`any`/`key` grants;
    /// `expires_at` is ms epoch, 0 = never (doc 13 Q-E1).
    pub fn acl_entries(&self, node_id: &NodeId) -> Result<Vec<AclEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT principal_kind, principal_id, authority, rights, expires_at
                 FROM acl WHERE node_id = ?1
                 ORDER BY principal_kind, principal_id, authority",
            )
            .map_err(map_db("prepare acl list"))?;
        let rows = stmt
            .query_map(params![node_id], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)? as u8,
                    r.get::<_, i64>(4)? as u64,
                ))
            })
            .map_err(map_db("query acl list"))?;
        let mut out = Vec::new();
        for row in rows {
            let (kind, id, authority, rights, expires_at) = row.map_err(map_db("read acl row"))?;
            out.push((
                crate::acl::Principal::from_wire(kind, id)?,
                authority,
                rights,
                expires_at,
            ));
        }
        Ok(out)
    }

    /// Whether a grant/membership **authority** is still a live (authorized,
    /// unrevoked) member (doc 10 §9.2). An empty authority — the `public`/`any`/
    /// `key` principals — is always active. A tag grant or membership whose
    /// authority is inactive is **inert**: masked on the read path and cleaned up
    /// by compaction (doc 11). Inspection commands (`acl ls`, `tag ls`) use this to
    /// flag such rows for audit clarity.
    pub fn authority_active(&self, authority: &[u8]) -> Result<bool> {
        projection::authority_active(&self.conn, authority)
    }

    /// Forest-wide authorization audit (doc 08 §4 item 14) — the `pvfs audit`
    /// counterpart to `pvfs verify`. Returns every **tag grant** under a revoked
    /// authority as `(node_id, tag_name, authority, rights)`. Read-only: these are
    /// inert (masked, flagged `[inert]` by `acl ls`); cleanup is compaction's job.
    pub fn inert_tag_grants(&self) -> Result<Vec<projection::InertTagGrant>> {
        projection::inert_tag_grants(&self.conn)
    }

    /// Forest-wide audit: every tag **membership** under a revoked authority as
    /// `(member_pubkey, tag, authority)`. The membership counterpart of
    /// [`inert_tag_grants`](Self::inert_tag_grants).
    pub fn inert_memberships(&self) -> Result<Vec<projection::InertMembership>> {
        projection::inert_memberships(&self.conn)
    }

    /// Forest-wide audit: every direct `key:` grant to a **revoked** device key
    /// as `(node_id, key, rights)` — inert on the read path (doc 06 §5); a
    /// never-authorized guest key's grants are live and not reported (doc 13 §E).
    pub fn inert_key_grants(&self) -> Result<Vec<projection::InertKeyGrant>> {
        projection::inert_key_grants(&self.conn)
    }

    /// Forest-wide audit: every grant past its `expires_at` (doc 13 Q-E1), as
    /// `(node_id, principal, authority, rights, expires_at)` — inert, judged now.
    pub fn expired_grants(&self) -> Result<Vec<projection::ExpiredGrant>> {
        projection::expired_grants(&self.conn, now_ms())
    }

    /// Assign (`granted = true`) or remove a membership tag from a member key
    /// (doc 09 §1). Authored by the local device, which must hold admin (`a`) on
    /// the forest root (owner devices always do).
    pub fn set_member_tag(
        &mut self,
        member_pubkey: &[u8],
        tag: &str,
        granted: bool,
    ) -> Result<()> {
        // Per-key tags (doc 10 §4): any authorized member may assign a tag under its
        // own authority — the local device signs as itself, so `ensure_device_active`
        // is the whole requirement. (Was: admin on the forest root.)
        self.ensure_device_active()?;
        crate::acl::validate_tag(tag)?;
        let t = now_ms();
        let author = self.device_pubkey();
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_member_tagged(member_pubkey, tag, granted, t, &author),
        )?;
        self.append_durable(vec![Event::MemberTagged {
            member_pubkey: member_pubkey.to_vec(),
            tag: tag.to_string(),
            granted,
            set_at: t,
            author,
            sig,
        }])
    }

    /// The membership tags a member key currently holds, as `(authority, tag)`
    /// pairs (doc 10): the same name held under two authorities is two memberships.
    pub fn member_tags(&self, member_pubkey: &[u8]) -> Result<Vec<(Vec<u8>, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT authority, tag FROM member_tags WHERE member_pubkey = ?1
                 ORDER BY tag, authority",
            )
            .map_err(map_db("prepare member tags"))?;
        let rows = stmt
            .query_map(params![member_pubkey], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(map_db("query member tags"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_db("read member tag"))?);
        }
        Ok(out)
    }

    /// Whether `principal` holds every bit in `right` on `node_id` (doc 06 §4.2).
    pub fn can(
        &self,
        principal: &crate::acl::Principal,
        node_id: &NodeId,
        right: u8,
    ) -> Result<bool> {
        Ok(self.effective_rights(principal, node_id)? & right == right)
    }

    /// Children of `node_id` that `principal` may read — what the daemon (Phase C)
    /// returns when a non-owner caller lists a folder.
    pub fn readable_children(
        &self,
        principal: &crate::acl::Principal,
        node_id: &NodeId,
    ) -> Result<Vec<ChildEntry>> {
        let mut out = Vec::new();
        for c in self.children(node_id)? {
            if self.effective_rights(principal, &c.node.id)? & crate::acl::ACL_R != 0 {
                out.push(c);
            }
        }
        Ok(out)
    }

    // ---- two-phase member writes (doc 07 §5) ---------------------------------------

    /// Phase 1: build the unsigned events to create a node under `parent`, authored
    /// by `author_pub`. The author must be an authorized member holding write (`w`)
    /// on `parent` — re-checked at commit and at replay. The daemon returns the
    /// digests for the member to sign; the engine state is not changed.
    pub fn prepare_add_node(
        &self,
        author_pub: &[u8],
        parent: &NodeId,
        spec: NodeSpec,
    ) -> Result<PreparedWrite> {
        self.validate_label(&spec.label)?;
        if spec.node_type.is_empty() {
            return Err(bad("node_type", "must not be empty"));
        }
        let parent_node = fetch_node(&self.conn, parent)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: parent.clone(),
        })?;
        if parent_node.is_temp {
            return Err(bad("parent", "cannot place a member node under a temp parent"));
        }
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &author, parent)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: "create node".into(),
                reason: format!("you lack write (w) on {parent}"),
            });
        }
        let creation_nonce = spec.creation_nonce.unwrap_or_else(|| {
            let mut b = [0u8; 8];
            rand::thread_rng().fill_bytes(&mut b);
            u64::from_le_bytes(b)
        });
        let t = now_ms();
        let mut node = Node {
            id: String::new(),
            node_type: spec.node_type.clone(),
            label: spec.label.clone(),
            visibility: VISIBILITY_PUBLIC.into(),
            payload: spec.payload.clone(),
            is_temp: false,
            creation_nonce,
            created_at: t,
            author: author_pub.to_vec(),
            sig: Vec::new(),
        };
        let node_digest = node.id_digest();
        node.id = hex::encode(node_digest);

        let order = OrderKey::after(max_order_key(&self.conn, parent)?.as_ref())?;
        let mut link = Link {
            id: String::new(),
            parent_id: Some(parent.clone()),
            child_id: node.id.clone(),
            link_type: LINK_CONTAINS.into(),
            link_nonce: 0,
            order_key: order.as_str().into(),
            created_at: t,
            author: author_pub.to_vec(),
            sig: Vec::new(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        };
        let link_digest = link.id_digest();
        link.id = hex::encode(link_digest);

        Ok(PreparedWrite {
            result_id: node.id.clone(),
            events: vec![
                PreparedEvent {
                    digest: node_digest,
                    event: Event::NodeCreated(node),
                },
                PreparedEvent {
                    digest: link_digest,
                    event: Event::LinkCreated(link),
                },
            ],
        })
    }

    /// Phase 2: verify each member-signed event (signature valid, author authorized,
    /// ACL satisfied) and append atomically. The events must already carry the
    /// member's signatures (see [`Event::set_author_sig`]).
    pub fn commit_member_write(&mut self, events: Vec<Event>) -> Result<()> {
        let root = self.current_root()?;
        for ev in &events {
            ev.verify_sig()?;
            match ev {
                // Device certs follow the root-or-admin rule (doc 09 §2.2), where
                // "root" is the current lineage root (doc 15 §C2).
                Event::DeviceAuthorized { .. } | Event::DeviceRevoked { .. } => {
                    projection::check_device_cert(
                        &self.conn,
                        &root,
                        &self.identity.root_node_id,
                        ev.author(),
                        now_ms(),
                    )?;
                }
                // Root rotation: current root or a registered recovery key (§C2).
                Event::RootRotated { author, .. } => {
                    if author.as_slice() != root.as_slice()
                        && !projection::is_recovery_key(&self.conn, author)?
                    {
                        return Err(PvfsError::Forbidden {
                            action: "rotate root".into(),
                            reason: "not the current root or a registered recovery key".into(),
                        });
                    }
                }
                // Recovery-key register/revoke: current root only (§C5/§C6a).
                Event::RecoveryKeyRegistered { author, .. }
                | Event::RecoveryKeyRevoked { author, .. } => {
                    if author.as_slice() != root.as_slice() {
                        return Err(PvfsError::Forbidden {
                            action: "recovery key".into(),
                            reason: "only the current root may register/revoke a recovery key".into(),
                        });
                    }
                }
                // Live commit judges ACL expiry at the wall clock (an expired
                // grant must not admit new writes); replay re-judges at the
                // row's `written_at`, which is at/after this instant.
                _ => projection::check_member_event(&self.conn, ev, now_ms())?,
            }
        }
        // Idempotent double-commit of the same prepared node ⇒ success, no re-append.
        if let Some(Event::NodeCreated(n)) = events.first() {
            if let Some(existing) = fetch_node(&self.conn, &n.id)? {
                return if &existing == n {
                    Ok(())
                } else {
                    Err(PvfsError::AlreadyExists {
                        kind: "node",
                        id: n.id.clone(),
                    })
                };
            }
        }
        self.append_durable(events)
    }

    /// Phase 1 of a member remove: build the unsigned `LinkRemoved` that unlinks
    /// `node_id` from its home (`contains`) parent. The author must hold write on
    /// that parent (re-checked at commit and replay). Returns the removed link id.
    pub fn prepare_remove_node(&self, author_pub: &[u8], node_id: &NodeId) -> Result<PreparedWrite> {
        let home: Option<(String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT id, parent_id FROM links
                 WHERE child_id = ?1 AND link_type = ?2 AND removed_at IS NULL LIMIT 1",
                params![node_id, LINK_CONTAINS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_db("find home link"))?;
        let (link_id, parent_id) = home.ok_or(PvfsError::NotFound {
            kind: "home link",
            id: node_id.clone(),
        })?;
        let parent = parent_id.ok_or_else(|| PvfsError::Forbidden {
            action: "remove".into(),
            reason: "cannot remove the forest root".into(),
        })?;
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &author, &parent)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: "remove".into(),
                reason: format!("you lack write (w) on {parent}"),
            });
        }
        let t = now_ms();
        let digest = event::msg_link_removed(&link_id, t, author_pub);
        Ok(PreparedWrite {
            result_id: link_id.clone(),
            events: vec![PreparedEvent {
                digest,
                event: Event::LinkRemoved {
                    link_id,
                    removed_at: t,
                    removed_by: author_pub.to_vec(),
                    removal_sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1 of a member location-add: build the unsigned `FileLocationAdded`
    /// recording where a file node's bytes live. The author must hold write on
    /// the file (re-checked at commit and replay).
    pub fn prepare_add_location(
        &self,
        author_pub: &[u8],
        file: &NodeId,
        uri: &str,
    ) -> Result<PreparedWrite> {
        if uri.is_empty() {
            return Err(bad("uri", "must not be empty"));
        }
        let n = fetch_node(&self.conn, file)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: file.clone(),
        })?;
        if n.node_type != node::TYPE_FILE {
            return Err(bad("file", "locations can only be added to file nodes"));
        }
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &author, file)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: "add location".into(),
                reason: format!("you lack write (w) on {file}"),
            });
        }
        let t = now_ms();
        let digest = event::msg_file_location_added(file, uri, t, author_pub);
        Ok(PreparedWrite {
            result_id: file.clone(),
            events: vec![PreparedEvent {
                digest,
                event: Event::FileLocationAdded {
                    file_id: file.clone(),
                    uri: uri.to_string(),
                    added_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1 of a member move: re-home `node_id` under `new_parent` by removing
    /// its current `contains` link and creating a new one. The author must hold
    /// write on **both** the old and the new parent (enforced live and on replay).
    pub fn prepare_move_node(
        &self,
        author_pub: &[u8],
        node_id: &NodeId,
        new_parent: &NodeId,
    ) -> Result<PreparedWrite> {
        let home: Option<(String, Option<String>)> = self
            .conn
            .query_row(
                "SELECT id, parent_id FROM links
                 WHERE child_id = ?1 AND link_type = ?2 AND removed_at IS NULL LIMIT 1",
                params![node_id, LINK_CONTAINS],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_db("find home link"))?;
        let (old_link_id, old_parent) = home.ok_or(PvfsError::NotFound {
            kind: "home link",
            id: node_id.clone(),
        })?;
        let old_parent = old_parent.ok_or_else(|| PvfsError::Forbidden {
            action: "move".into(),
            reason: "cannot move the forest root".into(),
        })?;
        if fetch_node(&self.conn, new_parent)?.is_none() {
            return Err(PvfsError::NotFound {
                kind: "node",
                id: new_parent.clone(),
            });
        }
        self.check_no_cycle(new_parent, node_id)?;
        // P7.0 (doc 20 §2): cross-region moves are refused until physical
        // region logs answer the both-logs authoring question (doc 13 §B).
        if self.region_of(&old_parent)? != self.region_of(new_parent)? {
            return Err(bad(
                "mv",
                "source and destination are in different regions — cross-region \
                 moves land with physical region logs (doc 20 §2)",
            ));
        }
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        for parent in [&old_parent, new_parent] {
            if projection::effective_rights(&self.conn, &author, parent)? & crate::acl::ACL_W == 0 {
                return Err(PvfsError::Forbidden {
                    action: "move".into(),
                    reason: format!("you lack write (w) on {parent}"),
                });
            }
        }
        let t = now_ms();
        let rm_digest = event::msg_link_removed(&old_link_id, t, author_pub);
        let order = OrderKey::after(max_order_key(&self.conn, new_parent)?.as_ref())?;
        let mut link = Link {
            id: String::new(),
            parent_id: Some(new_parent.clone()),
            child_id: node_id.clone(),
            link_type: LINK_CONTAINS.into(),
            link_nonce: 0,
            order_key: order.as_str().into(),
            created_at: t,
            author: author_pub.to_vec(),
            sig: Vec::new(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        };
        let link_digest = link.id_digest();
        link.id = hex::encode(link_digest);
        Ok(PreparedWrite {
            result_id: node_id.clone(),
            events: vec![
                PreparedEvent {
                    digest: rm_digest,
                    event: Event::LinkRemoved {
                        link_id: old_link_id,
                        removed_at: t,
                        removed_by: author_pub.to_vec(),
                        removal_sig: Vec::new(),
                    },
                },
                PreparedEvent {
                    digest: link_digest,
                    event: Event::LinkCreated(link),
                },
            ],
        })
    }

    /// Phase 1 of a member `loc rm` (P6.0, doc 19 §2): retract a recorded
    /// location. The author must hold write on the file — the same bar as
    /// adding one. Temp nodes stay forest-local (no wire op).
    pub fn prepare_remove_location(
        &self,
        author_pub: &[u8],
        file: &NodeId,
        uri: &str,
    ) -> Result<PreparedWrite> {
        let n = fetch_node(&self.conn, file)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: file.clone(),
        })?;
        if n.is_temp {
            return Err(bad("file", "temp nodes are forest-local (no wire ops)"));
        }
        let active: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM file_locations WHERE file_id = ?1 AND uri = ?2 AND removed_at IS NULL",
                params![file, uri],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("location lookup"))?;
        if active.is_none() {
            return Err(PvfsError::NotFound {
                kind: "location",
                id: format!("{file} {uri}"),
            });
        }
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &author, file)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: "remove location".into(),
                reason: format!("you lack write (w) on {file}"),
            });
        }
        let t = now_ms();
        let digest = event::msg_file_location_removed(file, uri, t, author_pub);
        Ok(PreparedWrite {
            result_id: file.clone(),
            events: vec![PreparedEvent {
                digest,
                event: Event::FileLocationRemoved {
                    file_id: file.clone(),
                    uri: uri.to_string(),
                    removed_at: t,
                    removed_by: author_pub.to_vec(),
                    removal_sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1 of a member `link` (P6.0, doc 19 §2): the same construction and
    /// checks as the local op — one-home rule + cycle check for `contains`,
    /// write on the parent — authored by the member. Temp endpoints refuse
    /// (forest-local by design).
    pub fn prepare_link(
        &self,
        author_pub: &[u8],
        parent: &NodeId,
        child: &NodeId,
        link_type: &str,
        order_key: Option<&str>,
    ) -> Result<PreparedWrite> {
        if link_type.is_empty() {
            return Err(bad("link_type", "must not be empty"));
        }
        let parent_node = fetch_node(&self.conn, parent)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: parent.clone(),
        })?;
        let child_node = fetch_node(&self.conn, child)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: child.clone(),
        })?;
        if parent_node.is_temp || child_node.is_temp {
            return Err(bad("link", "temp nodes are forest-local (no wire ops)"));
        }
        if link_type == LINK_CONTAINS {
            if let Some((_, existing_parent)) = active_home(&self.conn, child)? {
                return Err(PvfsError::AlreadyContained {
                    child: child.clone(),
                    existing_parent: existing_parent.unwrap_or_else(|| "(tree root)".into()),
                });
            }
            self.check_no_cycle(parent, child)?;
            // P7.2a: same boundary rule as the local path — adoption across
            // regions is a cross-region move (doc 20 §2.3).
            let none = std::collections::HashMap::new();
            if self.resolve_region(child, &none)? != self.resolve_region(parent, &none)? {
                return Err(bad(
                    "link",
                    "node and new parent are in different regions — cross-region \
                     moves land with the paired-event protocol (doc 20 §2)",
                ));
            }
        }
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &author, parent)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: "link".into(),
                reason: format!("you lack write (w) on {parent}"),
            });
        }
        let order = match order_key {
            Some(k) => OrderKey::parse(k)?,
            None => OrderKey::after(max_order_key(&self.conn, parent)?.as_ref())?,
        };
        let mut link = Link {
            id: String::new(),
            parent_id: Some(parent.clone()),
            child_id: child.clone(),
            link_type: link_type.into(),
            link_nonce: 0,
            order_key: order.as_str().into(),
            created_at: now_ms(),
            author: author_pub.to_vec(),
            sig: Vec::new(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        };
        let link_digest = link.id_digest();
        link.id = hex::encode(link_digest);
        Ok(PreparedWrite {
            result_id: link.id.clone(),
            events: vec![PreparedEvent {
                digest: link_digest,
                event: Event::LinkCreated(link),
            }],
        })
    }

    /// The durable link + its parent, with the member's write-on-parent check —
    /// shared by the unlink/reorder prepares. Links on the tree root (no
    /// parent) stay owner-only.
    fn link_for_member_edit(
        &self,
        author_pub: &[u8],
        link_id: &LinkId,
        action: &'static str,
    ) -> Result<Link> {
        let l = fetch_link(&self.conn, link_id)?.ok_or(PvfsError::NotFound {
            kind: "link",
            id: link_id.clone(),
        })?;
        let parent = l.parent_id.clone().ok_or_else(|| PvfsError::Forbidden {
            action: action.into(),
            reason: "root links are owner-only".into(),
        })?;
        let author = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &author, &parent)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: action.into(),
                reason: format!("you lack write (w) on {parent}"),
            });
        }
        Ok(l)
    }

    /// Phase 1 of a member `unlink` (P6.0, doc 19 §2). Already-removed links
    /// report NotFound — the wire has no signed no-op.
    pub fn prepare_remove_link(
        &self,
        author_pub: &[u8],
        link_id: &LinkId,
    ) -> Result<PreparedWrite> {
        let l = self.link_for_member_edit(author_pub, link_id, "unlink")?;
        if l.removed_at.is_some() {
            return Err(PvfsError::NotFound {
                kind: "link",
                id: link_id.clone(),
            });
        }
        let t = now_ms();
        let digest = event::msg_link_removed(link_id, t, author_pub);
        Ok(PreparedWrite {
            result_id: link_id.clone(),
            events: vec![PreparedEvent {
                digest,
                event: Event::LinkRemoved {
                    link_id: link_id.clone(),
                    removed_at: t,
                    removed_by: author_pub.to_vec(),
                    removal_sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1 of a member `reorder` (P6.0, doc 19 §2).
    pub fn prepare_reorder_link(
        &self,
        author_pub: &[u8],
        link_id: &LinkId,
        new_key: &str,
    ) -> Result<PreparedWrite> {
        let key = OrderKey::parse(new_key)?;
        let _ = self.link_for_member_edit(author_pub, link_id, "reorder")?;
        let digest = event::msg_link_reordered(link_id, key.as_str(), author_pub);
        Ok(PreparedWrite {
            result_id: link_id.clone(),
            events: vec![PreparedEvent {
                digest,
                event: Event::LinkReordered {
                    link_id: link_id.clone(),
                    new_order_key: key.as_str().into(),
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    // ---- regions (P7.0, doc 20 §2 / doc 13 §B) --------------------------------

    /// Mark `node` as a region boundary — its contains-closure (minus nested
    /// regions) becomes its own replication/compaction unit. Device-signed;
    /// replay requires admin (a) on the node. Idempotent re-marks re-stamp.
    /// P7.2a (doc 20 §2.3): a fresh mark IS the split — the same commit
    /// carries the baseline commitment, and the region's own log begins from
    /// it. A re-mark of an already-split region only re-stamps: its live
    /// generation must not be reset under itself.
    pub fn region_mark(&mut self, node: &NodeId) -> Result<()> {
        self.ensure_device_active()?;
        let n = fetch_node(&self.conn, node)?.ok_or(PvfsError::NotFound {
            kind: "node",
            id: node.clone(),
        })?;
        if n.is_temp {
            return Err(bad("region", "temp nodes are forest-local (no region marks)"));
        }
        let already_split: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM regions WHERE node_id = ?1 AND state_root IS NOT NULL",
                params![node],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("region lookup"))?;
        let t = now_ms();
        let me = self.device.pubkey();
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_region_marked(node, t, &me),
        )?;
        let mut events = vec![Event::RegionMarked {
            node_id: node.clone(),
            marked_at: t,
            author: me.clone(),
            sig,
        }];
        if already_split.is_none() {
            let state_root = projection::canonical_state_root(&self.conn, node)?;
            let bsig = crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_region_baseline(node, &state_root, t, &me),
            )?;
            events.push(Event::RegionBaseline {
                node_id: node.clone(),
                state_root: state_root.to_vec(),
                at: t,
                author: me,
                sig: bsig,
            });
        }
        self.append_durable(events)
    }

    /// Remove a region boundary; the subtree folds back into the enclosing
    /// region. Unmarking an unmarked node errors NotFound (nothing to erase).
    /// P7.2a: the same commit carries the **final head commitment** — the seal.
    /// The generation file stays in place for verification; nothing routes to
    /// it once the region row is gone.
    pub fn region_unmark(&mut self, node: &NodeId) -> Result<()> {
        self.ensure_device_active()?;
        let row: Option<(Option<String>, Option<String>)> = self
            .conn
            .query_row(
                "SELECT state_root, log_file FROM regions WHERE node_id = ?1",
                params![node],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(map_db("region lookup"))?;
        let Some((state_root, log_file)) = row else {
            return Err(PvfsError::NotFound {
                kind: "region",
                id: node.clone(),
            });
        };
        let t = now_ms();
        let me = self.device.pubkey();
        let mut events = Vec::with_capacity(2);
        if state_root.is_some() {
            let (head_seq, head_hash) = self.region_log_tip(node, log_file.as_deref())?;
            let hsig = crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_sub_region_head(node, head_seq, &head_hash, t, &me),
            )?;
            events.push(Event::SubRegionHead {
                node_id: node.clone(),
                head_seq,
                head_hash,
                at: t,
                author: me.clone(),
                sig: hsig,
            });
        }
        let sig = crypto::sign_digest(
            &self.device.signing_key,
            &event::msg_region_unmarked(node, t, &me),
        )?;
        events.push(Event::RegionUnmarked {
            node_id: node.clone(),
            unmarked_at: t,
            author: me,
            sig,
        });
        self.append_durable(events)
    }

    /// A split region's current log tip `(seq, chain_hash)` — the genesis seed
    /// when the generation has no rows yet (or no file at all).
    fn region_log_tip(&self, node: &str, log_file: Option<&str>) -> Result<(u64, Vec<u8>)> {
        let genesis = || -> Result<Vec<u8>> {
            Ok(projection::log_genesis(&self.conn, &self.identity, node)?.to_vec())
        };
        let Some(file) = log_file else {
            return Ok((0, genesis()?));
        };
        let path = self.data_dir.join(file);
        if !path.exists() {
            return Ok((0, genesis()?));
        }
        let rconn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(map_db("open region log"))?;
        let tip: u64 = rconn
            .query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|v| v as u64)
            .unwrap_or(0);
        if tip == 0 {
            return Ok((0, genesis()?));
        }
        let chain: Vec<u8> = rconn
            .query_row(
                "SELECT chain_hash FROM events WHERE seq = ?1",
                params![tip as i64],
                |r| r.get(0),
            )
            .map_err(map_db("read region tip"))?;
        Ok((tip, chain))
    }

    /// Commit a `SubRegionHead` for every active split region whose log has
    /// advanced past its last attested head (doc 20 §2.3). Called at close and
    /// on demand; the daemon's periodic trigger lands with P7.2b.
    pub fn commit_region_heads(&mut self) -> Result<usize> {
        if self.replica {
            return Ok(0);
        }
        let rows: Vec<(String, Option<String>, u64, String)> = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT node_id, log_file, committed_seq, committed_head
                     FROM regions WHERE state_root IS NOT NULL",
                )
                .map_err(map_db("list regions"))?;
            let it = stmt
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get::<_, i64>(2)? as u64,
                        r.get(3)?,
                    ))
                })
                .map_err(map_db("list regions"))?;
            it.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(map_db("list regions"))?
        };
        let mut events = Vec::new();
        let t = now_ms();
        let me = self.device.pubkey();
        for (node, file, committed_seq, committed_head) in rows {
            let (tip, chain) = self.region_log_tip(&node, file.as_deref())?;
            if tip == committed_seq && hex::encode(&chain) == committed_head {
                continue;
            }
            if tip == 0 && committed_head.is_empty() {
                continue; // nothing written and nothing attested yet
            }
            let sig = crypto::sign_digest(
                &self.device.signing_key,
                &event::msg_sub_region_head(&node, tip, &chain, t, &me),
            )?;
            events.push(Event::SubRegionHead {
                node_id: node,
                head_seq: tip,
                head_hash: chain,
                at: t,
                author: me.clone(),
                sig,
            });
        }
        let n = events.len();
        if n > 0 {
            self.append_durable(events)?;
        }
        Ok(n)
    }

    /// A split region's generation state (P7.2a): the baseline position, the
    /// generation file, the last attested head, and the log's live tip.
    pub fn region_info(&self, node: &NodeId) -> Result<Option<RegionInfo>> {
        let row: Option<RegionInfo> = self
            .conn
            .query_row(
                "SELECT marked_at, baseline_seq, baseline_log, parent_log, log_file,
                        committed_seq, committed_head
                 FROM regions WHERE node_id = ?1 AND state_root IS NOT NULL",
                params![node],
                |r| {
                    Ok(RegionInfo {
                        marked_at: r.get::<_, i64>(0)? as u64,
                        baseline_seq: r.get::<_, i64>(1)? as u64,
                        baseline_log: r.get(2)?,
                        parent_log: r.get(3)?,
                        log_file: r.get(4)?,
                        committed_seq: r.get::<_, i64>(5)? as u64,
                        committed_head: r.get(6)?,
                        tip_seq: 0,
                    })
                },
            )
            .optional()
            .map_err(map_db("region info"))?;
        let Some(mut info) = row else {
            return Ok(None);
        };
        let (tip_seq, _) = self.region_log_tip(node, info.log_file.as_deref())?;
        info.tip_seq = tip_seq;
        Ok(Some(info))
    }

    /// All marked region boundaries, `(node_id, marked_at)`.
    pub fn regions(&self) -> Result<Vec<(NodeId, u64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT node_id, marked_at FROM regions ORDER BY marked_at")
            .map_err(map_db("regions"))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)))
            .map_err(map_db("regions"))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("regions"))
    }

    /// The region `node` belongs to: the nearest marked ancestor (a marked
    /// node is its own region's root), else the forest root — the implicit
    /// top region (doc 13 §B). P7.2a: an O(1) read of the fold-maintained
    /// column (which also makes an orphan's region sticky) instead of the
    /// containment walk.
    pub fn region_of(&self, node: &NodeId) -> Result<NodeId> {
        let region = self.resolve_region(node, &std::collections::HashMap::new())?;
        if region.is_empty() {
            let exists: Option<i64> = self
                .conn
                .query_row("SELECT 1 FROM nodes WHERE id = ?1", params![node], |r| r.get(0))
                .optional()
                .map_err(map_db("region lookup"))?;
            if exists.is_none() {
                return Err(PvfsError::NotFound {
                    kind: "node",
                    id: node.clone(),
                });
            }
            return Ok(self.identity.root_node_id.clone());
        }
        Ok(region)
    }

    // ---- admin ops over the daemon (doc 09 §3c), all prepared for an external
    //      admin signer (the owner's device, or root via the companion) ----------

    /// The current root of the lineage (doc 15 §C2) — the latest `RootRotated`'s
    /// key, else the genesis root. All root-authority checks use this, not the
    /// fixed genesis key, so authority moves with a rotation.
    pub fn current_root(&self) -> Result<Vec<u8>> {
        projection::current_root(&self.conn, &self.identity)
    }

    fn require_admin_on_root(&self, author_pub: &[u8], action: &'static str) -> Result<()> {
        // The identity root may always author device certificates (doc 09 §2.2) —
        // it isn't a device in the ACL table, so check it explicitly here, mirroring
        // `projection::check_device_cert`'s root-or-admin rule used at commit/replay.
        // This is the path the companion uses to root-sign a `DeviceAuthorized`
        // (doc 14 §3); without it the prepare step would reject the root while the
        // commit step accepts it. "Root" is the CURRENT lineage root (doc 15 §C2).
        if author_pub == self.current_root()?.as_slice() {
            return Ok(());
        }
        let root = self.identity.root_node_id.clone();
        let who = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &who, &root)? & crate::acl::ACL_A == 0 {
            return Err(PvfsError::Forbidden {
                action: action.into(),
                reason: "you lack admin (a) on the forest root".into(),
            });
        }
        Ok(())
    }

    /// Require that `author_pub` is a currently authorized, unrevoked member (doc 10
    /// §4 — the bar for assigning a tag under one's own authority).
    fn require_active_member(&self, author_pub: &[u8], action: &'static str) -> Result<()> {
        let active: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM device_keys WHERE device_pubkey = ?1 AND revoked_at IS NULL",
                params![author_pub],
                |r| r.get(0),
            )
            .optional()
            .map_err(map_db("member check"))?;
        if active.is_none() {
            return Err(PvfsError::Forbidden {
                action: action.into(),
                reason: "not an authorized member of this forest".into(),
            });
        }
        Ok(())
    }

    /// Phase 1: build an unsigned `AclSet`. The author must hold admin on the node.
    pub fn prepare_set_acl(
        &self,
        author_pub: &[u8],
        node_id: &NodeId,
        principal: &crate::acl::Principal,
        rights: u8,
    ) -> Result<PreparedWrite> {
        self.prepare_set_acl_expiring(author_pub, node_id, principal, rights, 0)
    }

    /// [`prepare_set_acl`](Self::prepare_set_acl) with an expiry (doc 13 Q-E1):
    /// ms epoch after which the grant is inert; `0` = never.
    pub fn prepare_set_acl_expiring(
        &self,
        author_pub: &[u8],
        node_id: &NodeId,
        principal: &crate::acl::Principal,
        rights: u8,
        expires_at: u64,
    ) -> Result<PreparedWrite> {
        if fetch_node(&self.conn, node_id)?.is_none() {
            return Err(PvfsError::NotFound {
                kind: "node",
                id: node_id.clone(),
            });
        }
        let who = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &who, node_id)? & crate::acl::ACL_A == 0 {
            return Err(PvfsError::Forbidden {
                action: "set acl".into(),
                reason: format!("you lack admin (a) on {node_id}"),
            });
        }
        let t = now_ms();
        let (kind, id) = (principal.kind(), principal.id().to_vec());
        let digest = event::msg_acl_set(node_id, kind, &id, rights as u64, t, expires_at, author_pub);
        Ok(PreparedWrite {
            result_id: node_id.clone(),
            events: vec![PreparedEvent {
                digest,
                event: Event::AclSet {
                    node_id: node_id.clone(),
                    principal_kind: kind,
                    principal_id: id,
                    rights: rights as u64,
                    set_at: t,
                    expires_at,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1: build an unsigned `MemberTagged`. Per-key tags (doc 10 §4): any
    /// authorized member may assign a tag under its own authority, so the author need
    /// only be an active member (not an admin). Re-checked on commit/replay.
    pub fn prepare_set_member_tag(
        &self,
        author_pub: &[u8],
        member_pubkey: &[u8],
        tag: &str,
        granted: bool,
    ) -> Result<PreparedWrite> {
        crate::acl::validate_tag(tag)?;
        self.require_active_member(author_pub, "tag member")?;
        let t = now_ms();
        let digest = event::msg_member_tagged(member_pubkey, tag, granted, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(member_pubkey),
            events: vec![PreparedEvent {
                digest,
                event: Event::MemberTagged {
                    member_pubkey: member_pubkey.to_vec(),
                    tag: tag.to_string(),
                    granted,
                    set_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1: build an unsigned `DeviceAuthorized` admitting `member_pubkey`. The
    /// author must hold admin on root (or be the root — see `check_device_cert`).
    pub fn prepare_authorize_member(
        &self,
        author_pub: &[u8],
        member_pubkey: &[u8],
    ) -> Result<PreparedWrite> {
        crypto::validate_pubkey(member_pubkey)?;
        self.require_admin_on_root(author_pub, "authorize member")?;
        if self.device_known(member_pubkey)? {
            return Err(PvfsError::AlreadyExists {
                kind: "device",
                id: hex::encode(member_pubkey),
            });
        }
        let t = now_ms();
        let idx = crate::acl::MEMBER_DEVICE_INDEX;
        let digest = event::msg_device_authorized(member_pubkey, idx, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(member_pubkey),
            events: vec![PreparedEvent {
                digest,
                event: Event::DeviceAuthorized {
                    device_pubkey: member_pubkey.to_vec(),
                    device_index: idx,
                    authorized_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1: build an unsigned `DeviceAuthorized` admitting the human's
    /// **identity key** (doc 14 §1) as an owner. The `IDENTITY_DEVICE_INDEX`
    /// sentinel marks it as derived from the `3'/<id>'` branch (not `1'/n'`), while
    /// the projection treats any non-member index as an owner: full rights and an
    /// active membership, so the key's tag grants count for liveness (doc 10 §9.2).
    /// The author must hold admin on root (or be the root).
    pub fn prepare_authorize_identity(
        &self,
        author_pub: &[u8],
        identity_pubkey: &[u8],
    ) -> Result<PreparedWrite> {
        crypto::validate_pubkey(identity_pubkey)?;
        self.require_admin_on_root(author_pub, "authorize identity")?;
        if self.device_known(identity_pubkey)? {
            return Err(PvfsError::AlreadyExists {
                kind: "device",
                id: hex::encode(identity_pubkey),
            });
        }
        let t = now_ms();
        let idx = crate::acl::IDENTITY_DEVICE_INDEX;
        let digest = event::msg_device_authorized(identity_pubkey, idx, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(identity_pubkey),
            events: vec![PreparedEvent {
                digest,
                event: Event::DeviceAuthorized {
                    device_pubkey: identity_pubkey.to_vec(),
                    device_index: idx,
                    authorized_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1 (doc 12 §8.2): build an unsigned `SecureBlobUpdated` advancing a
    /// secure blob's content-free ledger. The node must exist and be `secure`;
    /// the author must hold write (`w`) on it — re-checked at commit and replay.
    pub fn prepare_secure_update(
        &self,
        author_pub: &[u8],
        blob_id: &NodeId,
        content_hash: &[u8; 32],
        size: u64,
    ) -> Result<PreparedWrite> {
        let node = fetch_node(&self.conn, blob_id)?.ok_or_else(|| PvfsError::NotFound {
            kind: "node",
            id: blob_id.clone(),
        })?;
        if node.node_type != node::TYPE_SECURE {
            return Err(PvfsError::BadInput {
                field: "node".into(),
                reason: format!("{blob_id} is a {} node, not secure", node.node_type),
            });
        }
        let who = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &who, blob_id)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: "update secure blob".into(),
                reason: format!("author lacks write (w) on {blob_id}"),
            });
        }
        let t = now_ms();
        let digest = event::msg_secure_blob_updated(blob_id, content_hash, size, t, author_pub);
        Ok(PreparedWrite {
            result_id: blob_id.clone(),
            events: vec![PreparedEvent {
                digest,
                event: Event::SecureBlobUpdated {
                    blob_id: blob_id.clone(),
                    content_hash: content_hash.to_vec(),
                    size,
                    updated_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// The current ledger head of a secure blob (doc 12 §8.2):
    /// `(content_hash, size, updated_at, author)`; `None` before its first update.
    pub fn secure_current(&self, blob_id: &NodeId) -> Result<Option<SecureBlobHead>> {
        self.conn
            .query_row(
                "SELECT content_hash, size, updated_at, author FROM secure_blobs WHERE blob_id = ?1",
                params![blob_id],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, i64>(1)? as u64,
                        r.get::<_, i64>(2)? as u64,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(map_db("secure blob head"))
    }

    /// The secure blob's single location (doc 12 §8.3), verified to exist and
    /// be a `secure` node. Errors if no location has been added yet.
    fn secure_location(&self, blob_id: &NodeId) -> Result<String> {
        let node = fetch_node(&self.conn, blob_id)?.ok_or_else(|| PvfsError::NotFound {
            kind: "node",
            id: blob_id.clone(),
        })?;
        if node.node_type != node::TYPE_SECURE {
            return Err(PvfsError::BadInput {
                field: "node".into(),
                reason: format!("{blob_id} is a {} node, not secure", node.node_type),
            });
        }
        self.locations(blob_id)?
            .into_iter()
            .next()
            .ok_or_else(|| PvfsError::BadInput {
                field: "location".into(),
                reason: format!("secure node {blob_id} has no location yet — add one"),
            })
    }

    /// The filesystem path of a secure blob's single location (doc 12 §8.3) —
    /// for the daemon, which writes/reads ciphertext it cannot decrypt.
    pub fn secure_location_path(&self, blob_id: &NodeId) -> Result<std::path::PathBuf> {
        crate::storage::uri_to_path(&self.secure_location(blob_id)?)
    }

    /// The **managed** ciphertext location for a secure blob (doc 12 §8.3):
    /// `<data_dir>/secure/<blob_id>`, allocated on the blob's first write so an
    /// app never chooses a filesystem path (and a member can't point a location
    /// at an arbitrary owner path). Deterministic from the node id.
    pub fn secure_managed_uri(&self, blob_id: &NodeId) -> Result<String> {
        let base = std::fs::canonicalize(&self.data_dir)
            .map_err(|e| PvfsError::io("resolve data dir", e))?;
        crate::storage::path_to_uri(&base.join("secure").join(blob_id))
    }

    /// Phase 1 (doc 12 §8.3/§8.5): prepare a secure write — the `SecureBlobUpdated`
    /// ledger event, plus a `FileLocationAdded` for the **managed** location when
    /// the blob has none yet (first write). So `secure create` needs only mint the
    /// node; the location materializes here, works identically local or over the
    /// daemon, and needs no path from the caller. Returns the prepared events and
    /// the filesystem path the ciphertext bytes go to. Author must hold write.
    pub fn prepare_secure_write(
        &self,
        author_pub: &[u8],
        blob_id: &NodeId,
        content_hash: &[u8; 32],
        size: u64,
    ) -> Result<(PreparedWrite, std::path::PathBuf)> {
        let node = fetch_node(&self.conn, blob_id)?.ok_or_else(|| PvfsError::NotFound {
            kind: "node",
            id: blob_id.clone(),
        })?;
        if node.node_type != node::TYPE_SECURE {
            return Err(PvfsError::BadInput {
                field: "node".into(),
                reason: format!("{blob_id} is a {} node, not secure", node.node_type),
            });
        }
        let who = crate::acl::Principal::Key(author_pub.to_vec());
        if projection::effective_rights(&self.conn, &who, blob_id)? & crate::acl::ACL_W == 0 {
            return Err(PvfsError::Forbidden {
                action: "write secure blob".into(),
                reason: format!("author lacks write (w) on {blob_id}"),
            });
        }
        let t = now_ms();
        let mut events = Vec::new();
        // Allocate the managed location on the first write.
        let uri = match self.locations(blob_id)?.into_iter().next() {
            Some(existing) => existing,
            None => {
                let uri = self.secure_managed_uri(blob_id)?;
                let digest = event::msg_file_location_added(blob_id, &uri, t, author_pub);
                events.push(PreparedEvent {
                    digest,
                    event: Event::FileLocationAdded {
                        file_id: blob_id.clone(),
                        uri: uri.clone(),
                        added_at: t,
                        author: author_pub.to_vec(),
                        sig: Vec::new(),
                    },
                });
                uri
            }
        };
        let path = crate::storage::uri_to_path(&uri)?;
        let digest = event::msg_secure_blob_updated(blob_id, content_hash, size, t, author_pub);
        events.push(PreparedEvent {
            digest,
            event: Event::SecureBlobUpdated {
                blob_id: blob_id.clone(),
                content_hash: content_hash.to_vec(),
                size,
                updated_at: t,
                author: author_pub.to_vec(),
                sig: Vec::new(),
            },
        });
        Ok((
            PreparedWrite {
                result_id: blob_id.clone(),
                events,
            },
            path,
        ))
    }

    /// Phase 2 (doc 12 §8.3): replace the blob's ciphertext **in place**
    /// (tmp + fsync + rename; superseded bytes unlinked) and advance the signed
    /// ledger in the same call, authored by this device. Validation happens
    /// before any bytes move; a crash between the write and the commit is
    /// detected by [`secure_verify`](Self::secure_verify) as a mismatch.
    /// Returns the new ciphertext hash.
    pub fn secure_put_local(&mut self, blob_id: &NodeId, ciphertext: &[u8]) -> Result<[u8; 32]> {
        self.ensure_device_active()?;
        let hash: [u8; 32] = blake3::hash(ciphertext).into();
        let me = self.device.pubkey();
        // Full validation (type + author-w) and location allocation, then self-sign.
        let (prep, path) =
            self.prepare_secure_write(&me, blob_id, &hash, ciphertext.len() as u64)?;
        let mut events = Vec::new();
        for pe in prep.events {
            let mut ev = pe.event;
            ev.set_author_sig(crypto::sign_digest(&self.device.signing_key, &pe.digest)?);
            events.push(ev);
        }
        crate::storage::atomic_overwrite(&path, ciphertext)?;
        self.commit_member_write(events)?;
        Ok(hash)
    }

    /// Phase 2: read the blob's ciphertext, **verifying it against the signed
    /// ledger head first** — integrity-on-read without ever needing a key.
    pub fn secure_read(&self, blob_id: &NodeId) -> Result<Vec<u8>> {
        let (head, _size, _t, _a) =
            self.secure_current(blob_id)?
                .ok_or_else(|| PvfsError::NotFound {
                    kind: "secure blob head",
                    id: blob_id.clone(),
                })?;
        let uri = self.secure_location(blob_id)?;
        let path = crate::storage::uri_to_path(&uri)?;
        let bytes = std::fs::read(&path).map_err(|e| PvfsError::io("read secure blob", e))?;
        let actual: [u8; 32] = blake3::hash(&bytes).into();
        if actual.as_slice() != head.as_slice() {
            return Err(PvfsError::Integrity {
                kind: "secure blob",
                id: blob_id.clone(),
                reason: crate::error::IntegrityReason::IdMismatch {
                    expected: hex::encode(&head),
                    actual: hex::encode(actual),
                },
            });
        }
        Ok(bytes)
    }

    /// Phase 2: do the location bytes match the signed ledger head?
    pub fn secure_verify(&self, blob_id: &NodeId) -> Result<bool> {
        match self.secure_read(blob_id) {
            Ok(_) => Ok(true),
            Err(PvfsError::Integrity { .. }) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Phase 1 (doc 15 §1 A2): build the atomic **identity swap** — revoke the
    /// old identity key and admit its replacement (`IDENTITY_DEVICE_INDEX`) as a
    /// single two-event commit, so the compromise window closes in one append.
    /// The old key's grants go inert at that instant (doc 10 §9.2 masking); the
    /// re-homing is [`prepare_reissue_authority`](Self::prepare_reissue_authority).
    /// The author must hold admin on root (or be the root).
    pub fn prepare_replace_identity(
        &self,
        author_pub: &[u8],
        old_pub: &[u8],
        new_pub: &[u8],
    ) -> Result<PreparedWrite> {
        crypto::validate_pubkey(new_pub)?;
        self.require_admin_on_root(author_pub, "replace identity")?;
        if !self.authority_active(old_pub)? {
            return Err(PvfsError::BadInput {
                field: "old identity".into(),
                reason: "not an active key in this forest".into(),
            });
        }
        if self.device_known(new_pub)? {
            return Err(PvfsError::AlreadyExists {
                kind: "device",
                id: hex::encode(new_pub),
            });
        }
        let t = now_ms();
        let idx = crate::acl::IDENTITY_DEVICE_INDEX;
        let revoke_digest = event::msg_device_revoked(old_pub, t, author_pub);
        let admit_digest = event::msg_device_authorized(new_pub, idx, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(new_pub),
            events: vec![
                PreparedEvent {
                    digest: revoke_digest,
                    event: Event::DeviceRevoked {
                        device_pubkey: old_pub.to_vec(),
                        revoked_at: t,
                        author: author_pub.to_vec(),
                        sig: Vec::new(),
                    },
                },
                PreparedEvent {
                    digest: admit_digest,
                    event: Event::DeviceAuthorized {
                        device_pubkey: new_pub.to_vec(),
                        device_index: idx,
                        authorized_at: t,
                        author: author_pub.to_vec(),
                        sig: Vec::new(),
                    },
                },
            ],
        })
    }

    /// Phase 1 (doc 15 §1 A3): **re-home** the live state a replaced authority
    /// authored. Scans the projection for `old_pub`'s footprint and prepares the
    /// same grants re-authored under `new_pub`: tag memberships it granted, ACL
    /// `tag:` grants it authored, and ACL grants made *to* `key:old` (re-granted
    /// to `key:new`). Old rows are left to masking now and compaction later —
    /// history is never rewritten. The new key must already be an active member
    /// (run the swap first); events may be empty when there is nothing to do.
    pub fn prepare_reissue_authority(
        &self,
        old_pub: &[u8],
        new_pub: &[u8],
    ) -> Result<PreparedWrite> {
        self.require_active_member(new_pub, "reissue authority")?;
        let t = now_ms();
        let mut events = Vec::new();

        // Tag memberships granted under the old authority (doc 10 §4).
        let mut stmt = self
            .conn
            .prepare(
                "SELECT member_pubkey, tag FROM member_tags WHERE authority = ?1
                 ORDER BY tag, member_pubkey",
            )
            .map_err(map_db("prepare reissue memberships"))?;
        let rows = stmt
            .query_map(params![old_pub], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(map_db("query reissue memberships"))?;
        for row in rows {
            let (member, tag) = row.map_err(map_db("read reissue membership"))?;
            if member == old_pub {
                continue; // never re-grant the replaced key its own memberships
            }
            let digest = event::msg_member_tagged(&member, &tag, true, t, new_pub);
            events.push(PreparedEvent {
                digest,
                event: Event::MemberTagged {
                    member_pubkey: member,
                    tag,
                    granted: true,
                    set_at: t,
                    author: new_pub.to_vec(),
                    sig: Vec::new(),
                },
            });
        }

        // ACL `tag:` grants the old key authored, and grants *to* `key:old`.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT node_id, principal_kind, principal_id, rights, expires_at FROM acl
                 WHERE (principal_kind = 3 AND authority = ?1)
                    OR (principal_kind = 1 AND principal_id = ?1)
                 ORDER BY node_id, principal_kind, principal_id",
            )
            .map_err(map_db("prepare reissue acl"))?;
        let rows = stmt
            .query_map(params![old_pub], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)? as u64,
                    r.get::<_, Vec<u8>>(2)?,
                    r.get::<_, i64>(3)? as u64,
                    r.get::<_, i64>(4)? as u64,
                ))
            })
            .map_err(map_db("query reissue acl"))?;
        for row in rows {
            let (node_id, kind, pid, rights, expires_at) = row.map_err(map_db("read reissue acl"))?;
            // A grant TO the old key becomes a grant to the new key; a tag grant
            // keeps its name and gets the new key as its (implicit) authority.
            // An expiry rides along unchanged — reissue never extends a grant.
            let principal_id = if kind == 1 { new_pub.to_vec() } else { pid };
            let digest =
                event::msg_acl_set(&node_id, kind, &principal_id, rights, t, expires_at, new_pub);
            events.push(PreparedEvent {
                digest,
                event: Event::AclSet {
                    node_id,
                    principal_kind: kind,
                    principal_id,
                    rights,
                    set_at: t,
                    expires_at,
                    author: new_pub.to_vec(),
                    sig: Vec::new(),
                },
            });
        }

        Ok(PreparedWrite {
            result_id: hex::encode(new_pub),
            events,
        })
    }

    /// Phase 1: build an unsigned `DeviceRevoked`. The author must hold admin on root.
    pub fn prepare_revoke(
        &self,
        author_pub: &[u8],
        device_pubkey: &[u8],
    ) -> Result<PreparedWrite> {
        self.require_admin_on_root(author_pub, "revoke device")?;
        if !self.device_known(device_pubkey)? {
            return Err(PvfsError::NotFound {
                kind: "device",
                id: hex::encode(device_pubkey),
            });
        }
        let t = now_ms();
        let digest = event::msg_device_revoked(device_pubkey, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(device_pubkey),
            events: vec![PreparedEvent {
                digest,
                event: Event::DeviceRevoked {
                    device_pubkey: device_pubkey.to_vec(),
                    revoked_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1 (doc 15 §C2): build an unsigned `RootRotated` re-anchoring the
    /// forest to `new_root_pubkey`. `author_pub` must be the **current** root or a
    /// registered recovery key — re-checked at commit and replay. This is signed
    /// with the OLD root (or the recovery key); the caller holds that key.
    pub fn prepare_rotate_root(
        &self,
        author_pub: &[u8],
        new_root_pubkey: &[u8],
    ) -> Result<PreparedWrite> {
        crypto::validate_pubkey(new_root_pubkey)?;
        let current = self.current_root()?;
        if author_pub != current.as_slice()
            && !projection::is_recovery_key(&self.conn, author_pub)?
        {
            return Err(PvfsError::Forbidden {
                action: "rotate root".into(),
                reason: "only the current root or a registered recovery key may rotate".into(),
            });
        }
        let t = now_ms();
        let digest = event::msg_root_rotated(new_root_pubkey, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(new_root_pubkey),
            events: vec![PreparedEvent {
                digest,
                event: Event::RootRotated {
                    new_root_pubkey: new_root_pubkey.to_vec(),
                    rotated_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase 1 (doc 15 §C5): build an unsigned `RecoveryKeyRegistered`.
    /// `author_pub` must be the **current** root — and, per §6 decision 4, the
    /// caller signs with the root key derived from the typed recovery phrase
    /// (never the companion), so this has no mid-life companion-signable path.
    pub fn prepare_register_recovery(
        &self,
        author_pub: &[u8],
        recovery_pubkey: &[u8],
    ) -> Result<PreparedWrite> {
        crypto::validate_pubkey(recovery_pubkey)?;
        if author_pub != self.current_root()?.as_slice() {
            return Err(PvfsError::Forbidden {
                action: "register recovery key".into(),
                reason: "only the current root may register a recovery key".into(),
            });
        }
        let t = now_ms();
        let digest = event::msg_recovery_key_registered(recovery_pubkey, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(recovery_pubkey),
            events: vec![PreparedEvent {
                digest,
                event: Event::RecoveryKeyRegistered {
                    recovery_pubkey: recovery_pubkey.to_vec(),
                    registered_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Phase (doc 15 §C6a): build an unsigned `RecoveryKeyRevoked` retiring a
    /// registered recovery key without rotating. `author_pub` must be the current
    /// root (phrase-authenticated). A `RootRotated` clears them all anyway; this
    /// is for retiring one deliberately.
    pub fn prepare_revoke_recovery(
        &self,
        author_pub: &[u8],
        recovery_pubkey: &[u8],
    ) -> Result<PreparedWrite> {
        if author_pub != self.current_root()?.as_slice() {
            return Err(PvfsError::Forbidden {
                action: "revoke recovery key".into(),
                reason: "only the current root may revoke a recovery key".into(),
            });
        }
        if !projection::is_recovery_key(&self.conn, recovery_pubkey)? {
            return Err(PvfsError::NotFound {
                kind: "recovery key",
                id: hex::encode(recovery_pubkey),
            });
        }
        let t = now_ms();
        let digest = event::msg_recovery_key_revoked(recovery_pubkey, t, author_pub);
        Ok(PreparedWrite {
            result_id: hex::encode(recovery_pubkey),
            events: vec![PreparedEvent {
                digest,
                event: Event::RecoveryKeyRevoked {
                    recovery_pubkey: recovery_pubkey.to_vec(),
                    revoked_at: t,
                    author: author_pub.to_vec(),
                    sig: Vec::new(),
                },
            }],
        })
    }

    /// Read helpers for the CLI/status: the current root and the registered
    /// recovery keys (doc 15 §C).
    pub fn is_recovery_key(&self, pubkey: &[u8]) -> Result<bool> {
        projection::is_recovery_key(&self.conn, pubkey)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.closed {
            let _ = projection::meta_set(&self.conn, "clean_shutdown", "1");
        }
    }
}

// ---- row helpers -------------------------------------------------------------

fn link_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Link> {
    Ok(Link {
        id: r.get(0)?,
        parent_id: r.get(1)?,
        child_id: r.get(2)?,
        link_type: r.get(3)?,
        link_nonce: r.get::<_, i64>(4)? as u64,
        order_key: r.get(5)?,
        created_at: r.get::<_, i64>(6)? as u64,
        author: r.get(7)?,
        sig: r.get(8)?,
        removed_at: r.get::<_, Option<i64>>(9)?.map(|v| v as u64),
        superseded_by: r.get(10)?,
        suspended_at: r.get::<_, Option<i64>>(11)?.map(|v| v as u64),
    })
}

const LINK_COLS: &str = "id, parent_id, child_id, link_type, link_nonce, order_key, created_at,
                         author, sig, removed_at, superseded_by, suspended_at";

pub(crate) fn fetch_link(conn: &Connection, id: &str) -> Result<Option<Link>> {
    conn.query_row(
        &format!("SELECT {LINK_COLS} FROM links WHERE id = ?1"),
        params![id],
        link_from_row,
    )
    .optional()
    .map_err(map_db("fetch link"))
}

pub(crate) fn fetch_temp_link(conn: &Connection, id: &str) -> Result<Option<Link>> {
    conn.query_row(
        &format!("SELECT {LINK_COLS} FROM temp_links WHERE id = ?1"),
        params![id],
        link_from_row,
    )
    .optional()
    .map_err(map_db("fetch temp link"))
}

pub(crate) fn insert_temp_node(tx: &Transaction<'_>, n: &Node) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO temp_nodes
         (id, node_type, label, visibility, payload, creation_nonce, created_at, author, sig)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            n.id,
            n.node_type,
            n.label,
            n.visibility,
            n.payload,
            n.creation_nonce as i64,
            n.created_at as i64,
            n.author,
            n.sig
        ],
    )
    .map_err(map_db("insert temp node"))?;
    Ok(())
}

pub(crate) fn insert_temp_link(tx: &Transaction<'_>, l: &Link) -> Result<()> {
    tx.execute(
        "INSERT OR IGNORE INTO temp_links
         (id, parent_id, child_id, link_type, link_nonce, order_key, created_at, author, sig,
          removed_at, superseded_by, suspended_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL)",
        params![
            l.id,
            l.parent_id,
            l.child_id,
            l.link_type,
            l.link_nonce as i64,
            l.order_key,
            l.created_at as i64,
            l.author,
            l.sig
        ],
    )
    .map_err(map_db("insert temp link"))?;
    Ok(())
}
