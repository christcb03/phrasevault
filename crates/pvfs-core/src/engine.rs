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

/// One ordered child of a parent (merged `contains` + `ref`).
#[derive(Debug, Clone)]
pub struct ChildEntry {
    pub node: Node,
    pub link_id: LinkId,
    pub link_type: String,
    pub order_key: String,
}

pub struct Engine {
    pub(crate) conn: Connection,
    pub(crate) data_dir: PathBuf,
    pub(crate) device: DeviceKeyCache,
    pub identity: ForestIdentity,
    pub(crate) closed: bool,
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

fn open_connection(data_dir: &Path) -> Result<Connection> {
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
        std::fs::create_dir_all(data_dir).map_err(|e| PvfsError::io("create data dir", e))?;
        if data_dir.join(LOG_FILE).exists() {
            return Err(PvfsError::AlreadyExists {
                kind: "forest",
                id: data_dir.to_string_lossy().into_owned(),
            });
        }
        let mnemonic = identity::generate_mnemonic()?;
        let root_key = identity::root_key(&mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        let device_key = identity::device_key(&mnemonic, "", 0)?;
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

        let fc_sig = crypto::sign_digest(
            &root_key,
            &event::msg_forest_created(&instance_id, &forest_id, &root_node.id, t, &root_pub),
        )?;
        let da_sig = crypto::sign_digest(
            &root_key,
            &event::msg_device_authorized(&device_pub, 0, t, &root_pub),
        )?;

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
                device_index: 0,
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
                projection::fold(&tx, ev)?;
            }
            tx.execute(
                "UPDATE projection_meta SET v = ?1 WHERE k = 'last_applied_seq'",
                params![seq.to_string()],
            )
            .map_err(map_db("init meta"))?;
            tx.execute(
                "UPDATE projection_meta SET v = ?1 WHERE k = 'last_applied_chain_hash'",
                params![hex::encode(chain)],
            )
            .map_err(map_db("init meta"))?;
            tx.commit().map_err(map_db("commit init"))?;
        }
        projection::meta_set(&conn, "clean_shutdown", "0")?;

        let device = DeviceKeyCache {
            signing_key: device_key,
            device_index: 0,
        };
        device.save(data_dir)?;

        let engine = Engine {
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
        };
        Ok((engine, mnemonic))
    }

    /// Open an existing data dir using the cached device key (spec §9.3 runs
    /// on every open).
    pub fn open(data_dir: &Path) -> Result<Engine> {
        let device = DeviceKeyCache::load(data_dir)?;
        let mut conn = open_connection(data_dir)?;
        let identity = projection::startup_check(&mut conn)?;
        projection::meta_set(&conn, "clean_shutdown", "0")?;
        let mut engine = Engine {
            conn,
            data_dir: data_dir.to_path_buf(),
            device,
            identity,
            closed: false,
        };
        engine.ensure_device_active()?;
        engine.sweep_temp_spool()?; // doc 04 §7 startup reconciliation
        Ok(engine)
    }

    /// Recover onto a machine from the mnemonic: re-derive the device key and
    /// (if needed) self-authorize it with the identity root (spec §10).
    pub fn recover(data_dir: &Path, mnemonic: &Mnemonic, device_index: u64) -> Result<Engine> {
        let root_key = identity::root_key(mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        let device_key = identity::device_key(mnemonic, "", device_index)?;
        let device_pub = crypto::pubkey_bytes(&device_key);

        let mut conn = open_connection(data_dir)?;
        let identity = projection::startup_check(&mut conn)?;
        if identity.root_pubkey != root_pub {
            return Err(PvfsError::Identity {
                detail: "mnemonic does not match this forest's identity root".into(),
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
        projection::meta_set(&engine.conn, "clean_shutdown", "0")?;
        engine.ensure_device_active()?;
        engine.sweep_temp_spool()?; // doc 04 §7 — rebuild empties temp ⇒ spool emptied
        Ok(engine)
    }

    /// Graceful close — sets the clean-shutdown flag (spec §9.3).
    pub fn close(mut self) -> Result<()> {
        projection::meta_set(&self.conn, "clean_shutdown", "1")?;
        self.closed = true;
        Ok(())
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn device_pubkey(&self) -> Vec<u8> {
        self.device.pubkey()
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
    /// key (spec §6 device-key acceptance rule).
    pub(crate) fn ensure_device_active(&self) -> Result<()> {
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

    /// Append durable events + fold, atomically (spec §9.1), with optional
    /// extra temp-table work in the same transaction.
    pub(crate) fn append_durable_with(
        &mut self,
        events: Vec<Event>,
        temp_ops: impl FnOnce(&Transaction<'_>) -> Result<()>,
    ) -> Result<()> {
        let genesis = log_store::genesis_seed(&self.identity.instance_id, &self.identity.forest_id);
        let tx = self.conn.transaction().map_err(map_db("begin write"))?;
        let mut seq = log_store::max_seq(&tx)?;
        let mut chain = if seq == 0 {
            genesis
        } else {
            let row = log_store::read_event(&tx, seq)?.ok_or_else(|| PvfsError::Corruption {
                db: "log.db".into(),
                detail: format!("missing event at seq {seq}"),
                seq: Some(seq),
            })?;
            let mut a = [0u8; 32];
            if row.chain_hash.len() != 32 {
                return Err(PvfsError::Corruption {
                    db: "log.db".into(),
                    detail: "chain hash wrong length".into(),
                    seq: Some(seq),
                });
            }
            a.copy_from_slice(&row.chain_hash);
            a
        };
        let t = now_ms();
        for ev in &events {
            seq += 1;
            chain = log_store::append_event(&tx, &chain, seq, ev, t)?;
            projection::fold(&tx, ev)?;
        }
        if !events.is_empty() {
            tx.execute(
                "INSERT INTO projection_meta (k, v) VALUES ('last_applied_seq', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![seq.to_string()],
            )
            .map_err(map_db("update meta"))?;
            tx.execute(
                "INSERT INTO projection_meta (k, v) VALUES ('last_applied_chain_hash', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![hex::encode(chain)],
            )
            .map_err(map_db("update meta"))?;
        }
        temp_ops(&tx)?;
        tx.commit().map_err(map_db("commit write"))?;
        Ok(())
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
        if n.node_type != node::TYPE_FILE {
            return Err(bad("file", "locations can only be added to file nodes"));
        }
        let t = now_ms();
        if n.is_temp {
            let (f, u) = (file.clone(), uri.to_string());
            return self.temp_write(|tx| {
                tx.execute(
                    "INSERT OR IGNORE INTO temp_file_locations (file_id, uri, added_at, removed_at)
                     VALUES (?1, ?2, ?3, NULL)",
                    params![f, u, t as i64],
                )
                .map_err(map_db("add temp location"))?;
                Ok(())
            });
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

    /// Active URIs for a file node.
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
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("locations"))
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
        if root_pub != self.identity.root_pubkey {
            return Err(PvfsError::Identity {
                detail: "mnemonic does not match this forest's identity root".into(),
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

    /// Revoke a device key for new appends (its valid history stands).
    pub fn revoke_device(&mut self, mnemonic: &Mnemonic, device_pubkey: &[u8]) -> Result<()> {
        let root_key = identity::root_key(mnemonic, "")?;
        let root_pub = crypto::pubkey_bytes(&root_key);
        if root_pub != self.identity.root_pubkey {
            return Err(PvfsError::Identity {
                detail: "mnemonic does not match this forest's identity root".into(),
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
        |r| link_from_row(r),
    )
    .optional()
    .map_err(map_db("fetch link"))
}

pub(crate) fn fetch_temp_link(conn: &Connection, id: &str) -> Result<Option<Link>> {
    conn.query_row(
        &format!("SELECT {LINK_COLS} FROM temp_links WHERE id = ?1"),
        params![id],
        |r| link_from_row(r),
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
