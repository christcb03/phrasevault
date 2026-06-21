//! index.db — the projection (spec §8), fold rules (§9.2), and the startup
//! integrity check & recovery (§9.3).

use rusqlite::{params, Connection, OptionalExtension, Transaction};

use crate::acl::{self, Principal};
use crate::error::{map_db, PvfsError, Result};
use crate::event::Event;
use crate::log_store;

// v2 (doc 10): per-key tag authority — `acl`/`member_tags` carry an `authority`
// column and tag matching is scoped to `(authority, name)`. Non-additive, so the
// projection (a pure cache of the log) is dropped and replayed on upgrade.
pub const SCHEMA_VERSION: u32 = 2;

pub const INDEX_SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS nodes (
  id             TEXT PRIMARY KEY,
  node_type      TEXT NOT NULL,
  label          TEXT NOT NULL,
  visibility     TEXT NOT NULL DEFAULT 'public',
  payload        BLOB NOT NULL,
  creation_nonce INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  author         BLOB NOT NULL,
  sig            BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS links (
  id            TEXT PRIMARY KEY,
  parent_id     TEXT,
  child_id      TEXT NOT NULL,
  link_type     TEXT NOT NULL,
  link_nonce    INTEGER NOT NULL,
  order_key     TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  author        BLOB NOT NULL,
  sig           BLOB NOT NULL,
  removed_at    INTEGER,
  superseded_by TEXT,
  suspended_at  INTEGER
);

CREATE TABLE IF NOT EXISTS file_locations (
  file_id    TEXT NOT NULL,
  uri        TEXT NOT NULL,
  added_at   INTEGER NOT NULL,
  removed_at INTEGER,
  PRIMARY KEY (file_id, uri)
);

CREATE TABLE IF NOT EXISTS device_keys (
  device_pubkey BLOB PRIMARY KEY,
  device_index  INTEGER NOT NULL,
  authorized_at INTEGER NOT NULL,
  revoked_at    INTEGER
);

CREATE TABLE IF NOT EXISTS acl (
  node_id        TEXT    NOT NULL,
  principal_kind INTEGER NOT NULL,   -- 0=any, 1=key, 2=public, 3=tag
  principal_id   BLOB    NOT NULL,   -- pubkey for key; tag name for tag; empty for any/public
  authority      BLOB    NOT NULL,   -- (doc 10) tag grants: the AclSet author; empty for non-tag
  rights         INTEGER NOT NULL,   -- bitmask r=1 w=2 a=4; row absent => none
  set_at         INTEGER NOT NULL,
  PRIMARY KEY (node_id, principal_kind, principal_id, authority)
);

CREATE TABLE IF NOT EXISTS member_tags (
  member_pubkey BLOB NOT NULL,
  tag           TEXT NOT NULL,
  authority     BLOB NOT NULL,       -- (doc 10) the MemberTagged author = the tag authority
  set_at        INTEGER NOT NULL,
  PRIMARY KEY (member_pubkey, tag, authority)
);

CREATE TABLE IF NOT EXISTS temp_nodes (
  id             TEXT PRIMARY KEY,
  node_type      TEXT NOT NULL,
  label          TEXT NOT NULL,
  visibility     TEXT NOT NULL DEFAULT 'public',
  payload        BLOB NOT NULL,
  creation_nonce INTEGER NOT NULL,
  created_at     INTEGER NOT NULL,
  author         BLOB NOT NULL,
  sig            BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS temp_links (
  id            TEXT PRIMARY KEY,
  parent_id     TEXT,
  child_id      TEXT NOT NULL,
  link_type     TEXT NOT NULL,
  link_nonce    INTEGER NOT NULL,
  order_key     TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  author        BLOB NOT NULL,
  sig           BLOB NOT NULL,
  removed_at    INTEGER,
  superseded_by TEXT,
  suspended_at  INTEGER
);

CREATE TABLE IF NOT EXISTS temp_file_locations (
  file_id    TEXT NOT NULL,
  uri        TEXT NOT NULL,
  added_at   INTEGER NOT NULL,
  removed_at INTEGER,
  PRIMARY KEY (file_id, uri)
);

CREATE TABLE IF NOT EXISTS folder_bindings (
  folder_id   TEXT PRIMARY KEY,
  source_uri  TEXT NOT NULL,
  recursive   INTEGER NOT NULL,
  auto_index  INTEGER NOT NULL,
  extensions  TEXT NOT NULL,
  hash_policy TEXT NOT NULL,
  bound_at    INTEGER NOT NULL,
  unbound_at  INTEGER
);

-- Local observations (P1 spec §8): never folded from events; cleared by a
-- rebuild and re-discovered by the next scan/verify.
CREATE TABLE IF NOT EXISTS pending_changes (
  file_id     TEXT NOT NULL,
  uri         TEXT NOT NULL,
  old_size    INTEGER NOT NULL,
  old_mtime   INTEGER NOT NULL,
  new_size    INTEGER NOT NULL,
  new_mtime   INTEGER NOT NULL,
  detected_at INTEGER NOT NULL,
  PRIMARY KEY (file_id, uri)
);

CREATE TABLE IF NOT EXISTS location_quarantine (
  file_id     TEXT NOT NULL,
  uri         TEXT NOT NULL,
  reason      TEXT NOT NULL,
  detected_at INTEGER NOT NULL,
  PRIMARY KEY (file_id, uri)
);

CREATE TABLE IF NOT EXISTS scan_state (
  uri        TEXT PRIMARY KEY,
  size_bytes INTEGER NOT NULL,
  mtime_ms   INTEGER NOT NULL,
  file_id    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projection_meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_links_parent_order ON links(parent_id, order_key) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_links_child        ON links(child_id)             WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_nodes_type         ON nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_file_locations_file ON file_locations(file_id) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tlinks_parent_order ON temp_links(parent_id, order_key) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tlinks_child        ON temp_links(child_id)             WHERE removed_at IS NULL;
";

const MAIN_OBJECTS: &[&str] = &[
    "nodes",
    "links",
    "file_locations",
    "device_keys",
    "acl",
    "member_tags",
    "temp_nodes",
    "temp_links",
    "temp_file_locations",
    "folder_bindings",
    "pending_changes",
    "location_quarantine",
    "scan_state",
    "projection_meta",
];

// ---- meta helpers -----------------------------------------------------------

pub fn meta_get(conn: &Connection, k: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT v FROM projection_meta WHERE k = ?1",
        params![k],
        |r| r.get(0),
    )
    .optional()
    .map_err(map_db("read projection_meta"))
}

pub fn meta_set(conn: &Connection, k: &str, v: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO projection_meta (k, v) VALUES (?1, ?2)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![k, v],
    )
    .map_err(map_db("write projection_meta"))?;
    Ok(())
}

pub fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(INDEX_SCHEMA)
        .map_err(map_db("create index schema"))?;
    if meta_get(conn, "schema_version")?.is_none() {
        meta_set(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
        meta_set(conn, "last_applied_seq", "0")?;
        meta_set(conn, "last_applied_chain_hash", "")?;
        meta_set(conn, "clean_shutdown", "1")?;
    }
    Ok(())
}

// ---- fold rules (spec §9.2) -------------------------------------------------

pub fn fold(tx: &Transaction<'_>, event: &Event) -> Result<()> {
    let m = map_db("fold event");
    match event {
        Event::ForestCreated {
            instance_id,
            forest_id,
            root_node_id,
            author,
            ..
        } => {
            for (k, v) in [
                ("instance_id", instance_id.as_str()),
                ("forest_id", forest_id.as_str()),
                ("forest_root_node_id", root_node_id.as_str()),
            ] {
                tx.execute(
                    "INSERT INTO projection_meta (k, v) VALUES (?1, ?2)
                     ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                    params![k, v],
                )
                .map_err(&m)?;
            }
            tx.execute(
                "INSERT INTO projection_meta (k, v) VALUES ('identity_root_pubkey', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![hex::encode(author)],
            )
            .map_err(&m)?;
        }
        Event::DeviceAuthorized {
            device_pubkey,
            device_index,
            authorized_at,
            ..
        } => {
            tx.execute(
                "INSERT OR IGNORE INTO device_keys (device_pubkey, device_index, authorized_at, revoked_at)
                 VALUES (?1, ?2, ?3, NULL)",
                params![device_pubkey, *device_index as i64, *authorized_at as i64],
            )
            .map_err(&m)?;
        }
        Event::DeviceRevoked {
            device_pubkey,
            revoked_at,
            ..
        } => {
            tx.execute(
                "UPDATE device_keys SET revoked_at = ?1 WHERE device_pubkey = ?2",
                params![*revoked_at as i64, device_pubkey],
            )
            .map_err(&m)?;
        }
        Event::AclSet {
            node_id,
            principal_kind,
            principal_id,
            rights,
            set_at,
            author,
            ..
        } => {
            // A tag grant is scoped to the key that authored it (doc 10 §3); other
            // principals (public/any/key) carry an empty authority, so their rows
            // collapse on `(node, kind, id)` exactly as before.
            let authority: &[u8] = if *principal_kind == 3 { author.as_slice() } else { &[] };
            if *rights == 0 {
                tx.execute(
                    "DELETE FROM acl WHERE node_id = ?1 AND principal_kind = ?2 AND principal_id = ?3 AND authority = ?4",
                    params![node_id, *principal_kind as i64, principal_id, authority],
                )
                .map_err(&m)?;
            } else {
                tx.execute(
                    "INSERT INTO acl (node_id, principal_kind, principal_id, authority, rights, set_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(node_id, principal_kind, principal_id, authority)
                     DO UPDATE SET rights = excluded.rights, set_at = excluded.set_at",
                    params![node_id, *principal_kind as i64, principal_id, authority, *rights as i64, *set_at as i64],
                )
                .map_err(&m)?;
            }
        }
        Event::MemberTagged {
            member_pubkey,
            tag,
            granted,
            set_at,
            author,
            ..
        } => {
            // The author is the tag's authority (doc 10 §3): a membership only
            // satisfies a node's tag grant authored by the same key.
            if *granted {
                tx.execute(
                    "INSERT INTO member_tags (member_pubkey, tag, authority, set_at) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(member_pubkey, tag, authority) DO UPDATE SET set_at = excluded.set_at",
                    params![member_pubkey, tag, author, *set_at as i64],
                )
                .map_err(&m)?;
            } else {
                tx.execute(
                    "DELETE FROM member_tags WHERE member_pubkey = ?1 AND tag = ?2 AND authority = ?3",
                    params![member_pubkey, tag, author],
                )
                .map_err(&m)?;
            }
        }
        Event::NodeCreated(n) => {
            tx.execute(
                "INSERT OR IGNORE INTO nodes
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
            .map_err(&m)?;
        }
        Event::LinkCreated(l) => {
            tx.execute(
                "INSERT OR IGNORE INTO links
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
            .map_err(&m)?;
        }
        Event::LinkRemoved {
            link_id, removed_at, ..
        } => {
            tx.execute(
                "UPDATE links SET removed_at = ?1 WHERE id = ?2",
                params![*removed_at as i64, link_id],
            )
            .map_err(&m)?;
        }
        Event::LinkReordered {
            link_id,
            new_order_key,
            ..
        } => {
            tx.execute(
                "UPDATE links SET order_key = ?1 WHERE id = ?2",
                params![new_order_key, link_id],
            )
            .map_err(&m)?;
        }
        Event::LinkSuperseded {
            old_link_id,
            new_link_id,
            ..
        } => {
            tx.execute(
                "UPDATE links SET superseded_by = ?1 WHERE id = ?2",
                params![new_link_id, old_link_id],
            )
            .map_err(&m)?;
        }
        Event::LinkSuspended {
            link_id,
            suspended_at,
            ..
        } => {
            tx.execute(
                "UPDATE links SET suspended_at = ?1 WHERE id = ?2",
                params![*suspended_at as i64, link_id],
            )
            .map_err(&m)?;
        }
        Event::LinkUnsuspended { link_id, .. } => {
            tx.execute(
                "UPDATE links SET suspended_at = NULL WHERE id = ?1",
                params![link_id],
            )
            .map_err(&m)?;
        }
        Event::FileLocationAdded {
            file_id,
            uri,
            added_at,
            ..
        } => {
            // Re-adding a previously soft-removed location must REACTIVATE it
            // (a plain INSERT OR IGNORE would leave removed_at set forever).
            tx.execute(
                "INSERT INTO file_locations (file_id, uri, added_at, removed_at)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT(file_id, uri) DO UPDATE SET
                   added_at = excluded.added_at, removed_at = NULL",
                params![file_id, uri, *added_at as i64],
            )
            .map_err(&m)?;
        }
        Event::FileLocationRemoved {
            file_id,
            uri,
            removed_at,
            ..
        } => {
            tx.execute(
                "UPDATE file_locations SET removed_at = ?1 WHERE file_id = ?2 AND uri = ?3",
                params![*removed_at as i64, file_id, uri],
            )
            .map_err(&m)?;
        }
        Event::NodePurged { node_id, .. } => {
            tx.execute("DELETE FROM nodes WHERE id = ?1", params![node_id])
                .map_err(&m)?;
            tx.execute(
                "DELETE FROM file_locations WHERE file_id = ?1",
                params![node_id],
            )
            .map_err(&m)?;
        }
        Event::FolderBound {
            folder_id,
            source_uri,
            recursive,
            auto_index,
            extensions,
            hash_policy,
            bound_at,
            ..
        } => {
            tx.execute(
                "INSERT INTO folder_bindings
                 (folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at, unbound_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL)
                 ON CONFLICT(folder_id) DO UPDATE SET
                   source_uri = excluded.source_uri,
                   recursive = excluded.recursive,
                   auto_index = excluded.auto_index,
                   extensions = excluded.extensions,
                   hash_policy = excluded.hash_policy,
                   bound_at = excluded.bound_at,
                   unbound_at = NULL",
                params![
                    folder_id,
                    source_uri,
                    *recursive as i64,
                    *auto_index as i64,
                    extensions,
                    hash_policy,
                    *bound_at as i64
                ],
            )
            .map_err(&m)?;
        }
        Event::FolderUnbound {
            folder_id,
            unbound_at,
            ..
        } => {
            tx.execute(
                "UPDATE folder_bindings SET unbound_at = ?1 WHERE folder_id = ?2",
                params![*unbound_at as i64, folder_id],
            )
            .map_err(&m)?;
        }
    }
    Ok(())
}

// ---- startup integrity check & recovery (spec §9.3) -------------------------

pub struct ForestIdentity {
    pub instance_id: String,
    pub forest_id: String,
    pub root_node_id: String,
    pub root_pubkey: Vec<u8>,
}

fn decode_genesis(conn: &Connection) -> Result<ForestIdentity> {
    let row = log_store::read_event(conn, 1)?.ok_or_else(|| PvfsError::Corruption {
        db: "log.db".into(),
        detail: "log has no genesis event (seq 1 missing)".into(),
        seq: Some(1),
    })?;
    if row.kind != crate::event::K_FOREST_CREATED {
        return Err(PvfsError::Corruption {
            db: "log.db".into(),
            detail: format!("first event is {:?}, expected ForestCreated", row.kind),
            seq: Some(1),
        });
    }
    let ev = Event::decode(&row.kind, &row.body)?;
    ev.verify_sig()?;
    match ev {
        Event::ForestCreated {
            instance_id,
            forest_id,
            root_node_id,
            author,
            ..
        } => Ok(ForestIdentity {
            instance_id,
            forest_id,
            root_node_id,
            root_pubkey: author,
        }),
        _ => unreachable!("kind checked above"),
    }
}

fn quick_check(conn: &Connection, db: &str) -> Result<bool> {
    let res: std::result::Result<String, rusqlite::Error> = conn.query_row(
        &format!("PRAGMA {db}.quick_check"),
        [],
        |r| r.get(0),
    );
    match res {
        Ok(s) => Ok(s == "ok"),
        Err(_) => Ok(false),
    }
}

/// Verify the per-event signature and the root-only rule for device events,
/// then fold. Used by both catch-up replay and full rebuild.
fn replay_one(
    tx: &Transaction<'_>,
    identity: &ForestIdentity,
    row: &log_store::EventRow,
    prev_chain: &[u8; 32],
) -> Result<[u8; 32]> {
    // chain verification (spec §9.3 step 4)
    let expect = log_store::chain_step(prev_chain, row.seq, &row.kind, &row.body, row.written_at);
    if expect.as_slice() != row.chain_hash.as_slice() {
        return Err(PvfsError::LogChainBroken {
            seq: row.seq,
            expected: hex::encode(expect),
            actual: hex::encode(&row.chain_hash),
        });
    }
    let ev = Event::decode(&row.kind, &row.body)?;
    ev.verify_sig()?;
    match &ev {
        Event::ForestCreated { .. } if row.seq != 1 => {
            return Err(PvfsError::Corruption {
                db: "log.db".into(),
                detail: "second ForestCreated event".into(),
                seq: Some(row.seq),
            })
        }
        // Device certificates: root- or admin-device-signed (doc 09 §2.2). Genesis's
        // device-0 cert is root-signed (no admin device exists yet).
        Event::DeviceAuthorized { author, .. } | Event::DeviceRevoked { author, .. } => {
            check_device_cert(tx, &identity.root_pubkey, &identity.root_node_id, author)
                .map_err(|_| unauthorized(row.seq, ev.kind()))?;
        }
        Event::ForestCreated { .. } => {} // genesis (seq 1), root-authored
        // Every other event is device-authored: enforce the same author + ACL
        // rules used by live member writes, so a tampered or synced log can't
        // carry an event its author had no right to (doc 06 §4.3, doc 07 §5).
        _ => check_member_event(tx, &ev).map_err(|_| unauthorized(row.seq, ev.kind()))?,
    }
    fold(tx, &ev)?;
    Ok(expect)
}

fn unauthorized(seq: u64, kind: &str) -> PvfsError {
    PvfsError::Integrity {
        kind: "event",
        id: format!("seq {seq} ({kind})"),
        reason: crate::error::IntegrityReason::UnknownAuthor,
    }
}

/// Authorization for a device-authored event (not genesis / device certificate):
/// the author must be an authorized, unrevoked device **and** hold the rights the
/// event requires — admin (`a`) for an `AclSet`, write (`w`) on the parent for a
/// placing `LinkCreated`. Shared by replay (rebuild/sync) and the live member-write
/// commit, so the replicated and live rules can never drift. Owner devices have
/// implicit full rights (via `effective_rights`), so existing forests are unaffected.
pub fn check_member_event(conn: &Connection, ev: &Event) -> Result<()> {
    let author = ev.author();
    let active: i64 = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM device_keys WHERE device_pubkey = ?1 AND revoked_at IS NULL)",
            params![author],
            |r| r.get(0),
        )
        .map_err(map_db("device authorization check"))?;
    if active == 0 {
        return Err(PvfsError::Integrity {
            kind: "event",
            id: ev.kind().into(),
            reason: crate::error::IntegrityReason::UnknownAuthor,
        });
    }
    match ev {
        Event::AclSet { node_id, .. } => require_right(conn, author, node_id, acl::ACL_A, "set acl")?,
        Event::LinkCreated(l) => {
            if let Some(parent) = &l.parent_id {
                require_right(conn, author, parent, acl::ACL_W, "create link")?;
            }
        }
        Event::LinkRemoved { link_id, .. } => {
            // Unlinking needs write on the removed link's parent (admin on the node
            // itself for a root link). A link that's already gone ⇒ no-op, allowed.
            let row: Option<(Option<String>, String)> = conn
                .query_row(
                    "SELECT parent_id, child_id FROM links WHERE id = ?1",
                    params![link_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(map_db("acl link lookup"))?;
            if let Some((parent, child)) = row {
                let (target, needed) = match parent {
                    Some(p) => (p, acl::ACL_W),
                    None => (child, acl::ACL_A),
                };
                require_right(conn, author, &target, needed, "remove link")?;
            }
        }
        Event::FileLocationAdded { file_id, .. } => {
            require_right(conn, author, file_id, acl::ACL_W, "add location")?
        }
        Event::MemberTagged { .. } => {
            // Per-key tags (doc 10 §4): any authorized member may assign a tag under
            // its **own** authority — and the authority *is* the signed author, so a
            // member cannot forge a tag under another key. The active-author check at
            // the top of this function is therefore sufficient; the old "admin on the
            // forest root" requirement was over-broad (it existed only because tags
            // were unscoped) and is dropped. A key-scoped membership only unlocks
            // nodes whose `Tag` grant that same key authored — i.e. nodes it controls.
        }
        _ => {}
    }
    Ok(())
}

/// A device certificate (`DeviceAuthorized`/`DeviceRevoked`) is valid when signed
/// by the identity root **or** by a device holding admin (`a`) on the forest root
/// (doc 09 §2.2). Shared by replay and the live admin-op commit.
pub fn check_device_cert(
    conn: &Connection,
    root_pubkey: &[u8],
    root_node_id: &str,
    author: &[u8],
) -> Result<()> {
    let by_root = author == root_pubkey;
    let by_admin = !by_root
        && effective_rights(conn, &Principal::Key(author.to_vec()), root_node_id)? & acl::ACL_A != 0;
    if by_root || by_admin {
        Ok(())
    } else {
        Err(PvfsError::Integrity {
            kind: "event",
            id: "device certificate".into(),
            reason: crate::error::IntegrityReason::UnknownAuthor,
        })
    }
}

/// Require that `author` holds every bit in `right` on `node`, else `Forbidden`.
fn require_right(conn: &Connection, author: &[u8], node: &str, right: u8, action: &str) -> Result<()> {
    if effective_rights(conn, &Principal::Key(author.to_vec()), node)? & right != right {
        return Err(PvfsError::Forbidden {
            action: action.into(),
            reason: format!("author lacks the required right on {node}"),
        });
    }
    Ok(())
}

// ---- ACL evaluation (doc 06 §4.2) -------------------------------------------------

/// Effective rights for `principal` on `node_id` (doc 06 §4.2 / doc 07 §4). An
/// authorized, unrevoked **owner** device (HD index, not the member sentinel) gets
/// full rights. Otherwise, walking the node and its `contains`-ancestors, the union
/// of: **`Public` grants always**; **`Any` grants iff the caller is an authorized
/// member**; and **`Key(pk)` grants for the caller's own key**. Grant-only — grants
/// flow down the tree. Accepts `&Connection`; a `&Transaction` derefs to it, so
/// replay can call it too.
pub fn effective_rights(conn: &Connection, principal: &Principal, node_id: &str) -> Result<u8> {
    // An owner device short-circuits to full rights. Otherwise determine whether
    // the caller is an authorized member (so `Any` grants apply) and, for a member
    // key, which tags they hold (so the node's `tag:` grants apply).
    let (is_member, member_tags): (bool, Vec<(Vec<u8>, String)>) = match principal {
        Principal::Public | Principal::Tag(_) => (false, Vec::new()),
        Principal::Any => (true, Vec::new()),
        Principal::Key(pk) => {
            let (authorized, is_owner) = device_status(conn, pk)?;
            if is_owner {
                return Ok(acl::ACL_RWA);
            }
            if authorized {
                (true, member_tags_of(conn, pk)?)
            } else {
                (false, Vec::new())
            }
        }
    };
    // A `Tag` query reports only that tag's grants (no `public` floor).
    let include_public = !matches!(principal, Principal::Tag(_));
    let mut rights = 0u8;
    let mut cur = Some(node_id.to_string());
    let mut guard = 0u32;
    while let Some(n) = cur {
        if include_public {
            rights |= grant_for(conn, &n, 2, &[], &[])?; // Public — applies to everyone
        }
        if is_member {
            rights |= grant_for(conn, &n, 0, &[], &[])?; // Any — authorized members
        }
        match principal {
            Principal::Key(pk) => {
                rights |= grant_for(conn, &n, 1, pk, &[])?; // this specific key
                // A tag the member holds unlocks only the node's `Tag` grants
                // authored by the *same* authority (doc 10 §3).
                for (authority, t) in &member_tags {
                    rights |= grant_for(conn, &n, 3, t.as_bytes(), authority)?;
                }
            }
            Principal::Tag(t) => {
                // Inspection (`acl check tag:<name>`): report this name's grants
                // across every authority that set one.
                rights |= grant_for_tag_any_authority(conn, &n, t.as_bytes())?;
            }
            _ => {}
        }
        if rights & acl::ACL_RWA == acl::ACL_RWA {
            break; // already maximal — stop walking
        }
        cur = contains_parent(conn, &n)?;
        guard += 1;
        if guard > 100_000 {
            break; // defensive: never loop forever on a malformed graph
        }
    }
    Ok(rights)
}

/// The `(authority, tag)` memberships a key holds whose **authority is still an
/// active, unrevoked member** (doc 10 §9.2 liveness). A tag granted by a revoked
/// authority is masked here — counted by no node — so access drops immediately;
/// the dead row itself is cleaned up later by the signed sweep (doc 08 §4 item 13).
fn member_tags_of(conn: &Connection, pubkey: &[u8]) -> Result<Vec<(Vec<u8>, String)>> {
    let mut stmt = conn
        .prepare(
            "SELECT mt.authority, mt.tag FROM member_tags mt
             WHERE mt.member_pubkey = ?1
               AND EXISTS (SELECT 1 FROM device_keys dk
                           WHERE dk.device_pubkey = mt.authority AND dk.revoked_at IS NULL)",
        )
        .map_err(map_db("prepare member tags"))?;
    let rows = stmt
        .query_map(params![pubkey], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(map_db("query member tags"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(map_db("read member tag"))?);
    }
    Ok(out)
}

/// `(authorized_and_unrevoked, is_owner_device)` for a key in `device_keys`.
fn device_status(conn: &Connection, pubkey: &[u8]) -> Result<(bool, bool)> {
    let idx: Option<i64> = conn
        .query_row(
            "SELECT device_index FROM device_keys WHERE device_pubkey = ?1 AND revoked_at IS NULL",
            params![pubkey],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("acl device status"))?;
    match idx {
        Some(i) => Ok((true, (i as u64) != acl::MEMBER_DEVICE_INDEX)),
        None => Ok((false, false)),
    }
}

fn grant_for(conn: &Connection, node_id: &str, kind: u64, id: &[u8], authority: &[u8]) -> Result<u8> {
    let r: Option<i64> = conn
        .query_row(
            "SELECT rights FROM acl WHERE node_id = ?1 AND principal_kind = ?2 AND principal_id = ?3 AND authority = ?4",
            params![node_id, kind as i64, id, authority],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("acl lookup"))?;
    Ok(r.unwrap_or(0) as u8)
}

/// Union of a tag name's grants on `node_id` across **every** authority that set
/// one — for inspection only (`acl check tag:<name>`), never for an access
/// decision (those resolve a specific `(authority, name)` via `grant_for`).
fn grant_for_tag_any_authority(conn: &Connection, node_id: &str, name: &[u8]) -> Result<u8> {
    let mut stmt = conn
        .prepare("SELECT rights FROM acl WHERE node_id = ?1 AND principal_kind = 3 AND principal_id = ?2")
        .map_err(map_db("prepare tag grants"))?;
    let rows = stmt
        .query_map(params![node_id, name], |r| r.get::<_, i64>(0))
        .map_err(map_db("query tag grants"))?;
    let mut rights = 0u8;
    for r in rows {
        rights |= r.map_err(map_db("read tag grant"))? as u8;
    }
    Ok(rights)
}

/// The node's `contains` (home) parent, or `None` at the root / for an orphan.
fn contains_parent(conn: &Connection, node_id: &str) -> Result<Option<String>> {
    let p: Option<Option<String>> = conn
        .query_row(
            "SELECT parent_id FROM links WHERE child_id = ?1 AND link_type = ?2 AND removed_at IS NULL LIMIT 1",
            params![node_id, crate::link::LINK_CONTAINS],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("acl parent walk"))?;
    Ok(p.flatten())
}

/// Replay events `from..=to` inside one transaction, updating meta at the end.
fn replay_range(
    conn: &mut Connection,
    identity: &ForestIdentity,
    mut chain: [u8; 32],
    from: u64,
    to: u64,
) -> Result<[u8; 32]> {
    let tx = conn.transaction().map_err(map_db("begin replay"))?;
    for seq in from..=to {
        let row = log_store::read_event(&tx, seq)?.ok_or_else(|| PvfsError::Corruption {
            db: "log.db".into(),
            detail: format!("missing event at seq {seq}"),
            seq: Some(seq),
        })?;
        chain = replay_one(&tx, identity, &row, &chain)?;
    }
    tx.execute(
        "INSERT INTO projection_meta (k, v) VALUES ('last_applied_seq', ?1)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![to.to_string()],
    )
    .map_err(map_db("update meta"))?;
    tx.execute(
        "INSERT INTO projection_meta (k, v) VALUES ('last_applied_chain_hash', ?1)
         ON CONFLICT(k) DO UPDATE SET v = excluded.v",
        params![hex::encode(chain)],
    )
    .map_err(map_db("update meta"))?;
    tx.commit().map_err(map_db("commit replay"))?;
    Ok(chain)
}

/// Full rebuild (spec §9.3 step 5): drop and recreate the index schema, then
/// replay everything from the genesis seed. Temp tables start empty.
pub fn full_rebuild(conn: &mut Connection) -> Result<ForestIdentity> {
    let identity = decode_genesis(conn)?;
    for t in MAIN_OBJECTS {
        conn.execute_batch(&format!("DROP TABLE IF EXISTS {t};"))
            .map_err(map_db("drop projection table"))?;
    }
    create_schema(conn)?;
    let top = log_store::max_seq(conn)?;
    let genesis = log_store::genesis_seed(&identity.instance_id, &identity.forest_id);
    replay_range(conn, &identity, genesis, 1, top)?;
    meta_set(conn, "clean_shutdown", "0")?;
    Ok(identity)
}

/// The §9.3 startup check. Runs on every open, after both files are attached.
/// Returns the forest identity on success.
pub fn startup_check(conn: &mut Connection) -> Result<ForestIdentity> {
    // Step 1 — structural check.
    if !quick_check(conn, "log")? {
        return Err(PvfsError::Corruption {
            db: "log.db".into(),
            detail: "PRAGMA quick_check failed".into(),
            seq: None,
        });
    }
    let index_ok = quick_check(conn, "main")?;
    if !index_ok {
        return full_rebuild(conn);
    }
    create_schema(conn)?; // ensure tables exist on first open of a fresh index

    let identity = decode_genesis(conn)?;
    let genesis = log_store::genesis_seed(&identity.instance_id, &identity.forest_id);

    // Step 2 — positions.
    let sl = log_store::max_seq(conn)?;
    let si: u64 = meta_get(conn, "last_applied_seq")?
        .unwrap_or_else(|| "0".into())
        .parse()
        .unwrap_or(0);
    let hi = meta_get(conn, "last_applied_chain_hash")?.unwrap_or_default();
    let clean = meta_get(conn, "clean_shutdown")?.unwrap_or_else(|| "1".into());

    let version: u32 = meta_get(conn, "schema_version")?
        .unwrap_or_else(|| SCHEMA_VERSION.to_string())
        .parse()
        .unwrap_or(SCHEMA_VERSION);
    if version != SCHEMA_VERSION {
        // The projection is a pure, rebuildable cache of the log. An **older** schema
        // self-heals: drop the projection and replay under the current schema (doc 10
        // §6 — `full_rebuild` recreates `projection_meta`, so the version is reset to
        // current). A **newer** schema than this binary understands is a hard stop.
        if version < SCHEMA_VERSION {
            return full_rebuild(conn);
        }
        return Err(PvfsError::SchemaVersion {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }

    // Step 3 — verify the index agrees with the log at its applied point.
    if si > sl {
        return full_rebuild(conn);
    }
    if si > 0 {
        match log_store::read_event(conn, si)? {
            Some(row) if hex::encode(&row.chain_hash) == hi => {}
            _ => return full_rebuild(conn),
        }
    }

    // Unclean shutdown forces a full agreement check (spec §9.3 crash flag).
    if clean != "1" {
        return full_rebuild(conn);
    }

    // Step 4 — catch up.
    if si < sl {
        let chain = if si == 0 {
            genesis
        } else {
            let row = log_store::read_event(conn, si)?.ok_or_else(|| PvfsError::Corruption {
                db: "log.db".into(),
                detail: format!("missing event at seq {si}"),
                seq: Some(si),
            })?;
            let mut a = [0u8; 32];
            if row.chain_hash.len() != 32 {
                return Err(PvfsError::Corruption {
                    db: "log.db".into(),
                    detail: "chain hash wrong length".into(),
                    seq: Some(si),
                });
            }
            a.copy_from_slice(&row.chain_hash);
            a
        };
        replay_range(conn, &identity, chain, si + 1, sl)?;
    }
    Ok(identity)
}

// ---- replay-time author-authorization enforcement (doc 06 §3.3) -------------------
#[cfg(test)]
mod enforcement_tests {
    // `super::*` already brings params!, Connection, Event, PvfsError, log_store, …
    use super::*;
    use crate::engine::Engine;
    use crate::error::IntegrityReason;
    use crate::{crypto, identity, link, node};
    use k256::ecdsa::SigningKey;

    /// A validly-self-signed `NodeCreated` authored by `author_key`.
    fn forge_node_event(author_key: &SigningKey, label: &str) -> Event {
        let author = crypto::pubkey_bytes(author_key);
        let payload = node::folder_payload();
        let t = 1_000_000;
        let digest = node::compute_id_digest(
            node::TYPE_FOLDER,
            label,
            node::VISIBILITY_PUBLIC,
            &payload,
            false,
            0,
            t,
            &author,
        );
        Event::NodeCreated(node::Node {
            id: hex::encode(digest),
            node_type: node::TYPE_FOLDER.into(),
            label: label.into(),
            visibility: node::VISIBILITY_PUBLIC.into(),
            payload,
            is_temp: false,
            creation_nonce: 0,
            created_at: t,
            author,
            sig: crypto::sign_digest(author_key, &digest).unwrap(),
        })
    }

    /// Append a properly-chained event straight to `<dir>/log.db`, bypassing the
    /// engine — simulating a tampered/hostile log.
    fn append_to_log(dir: &std::path::Path, ev: &Event) {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute(
            "ATTACH DATABASE ?1 AS log",
            params![dir.join("log.db").to_str().unwrap()],
        )
        .unwrap();
        let max = log_store::max_seq(&conn).unwrap();
        let last = log_store::read_event(&conn, max).unwrap().unwrap();
        let prev = <[u8; 32]>::try_from(last.chain_hash.as_slice()).unwrap();
        let tx = conn.transaction().unwrap();
        log_store::append_event(&tx, &prev, max + 1, ev, 2_000_000).unwrap();
        tx.commit().unwrap();
    }

    fn foreign_key() -> SigningKey {
        identity::device_key(&identity::generate_mnemonic().unwrap(), "", 0).unwrap()
    }

    #[test]
    fn replay_rejects_event_from_unauthorized_key() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _m) = Engine::init(dir.path()).unwrap();
        engine.close().unwrap();

        append_to_log(dir.path(), &forge_node_event(&foreign_key(), "intruder"));

        // Reopen → catch-up replay hits the forged event → rejected.
        // `.map(drop)` discards the Ok(Engine) (which isn't Debug) so we can
        // assert/print on the Result.
        let outcome = Engine::open(dir.path()).map(drop);
        assert!(
            matches!(
                outcome,
                Err(PvfsError::Integrity {
                    reason: IntegrityReason::UnknownAuthor,
                    ..
                })
            ),
            "expected UnknownAuthor, got {outcome:?}"
        );
    }

    #[test]
    fn replay_accepts_event_from_authorized_member() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, m) = Engine::init(dir.path()).unwrap();
        let member = foreign_key();
        engine
            .authorize_member(&m, &crypto::pubkey_bytes(&member))
            .unwrap();
        engine.close().unwrap();

        append_to_log(dir.path(), &forge_node_event(&member, "guest"));

        // Member is authorized → replay accepts; forest opens cleanly.
        Engine::open(dir.path())
            .expect("authorized member's event must replay")
            .close()
            .unwrap();
    }

    #[test]
    fn revoked_member_cannot_author_after_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, m) = Engine::init(dir.path()).unwrap();
        let member = foreign_key();
        let member_pub = crypto::pubkey_bytes(&member);
        engine.authorize_member(&m, &member_pub).unwrap();
        engine.revoke_device(&m, &member_pub).unwrap(); // revoke last
        engine.close().unwrap();

        // Event authored after the revocation (later seq) must be rejected.
        append_to_log(dir.path(), &forge_node_event(&member, "after-revoke"));
        // `.map(drop)` discards the Ok(Engine) (which isn't Debug) so we can
        // assert/print on the Result.
        let outcome = Engine::open(dir.path()).map(drop);
        assert!(
            matches!(
                outcome,
                Err(PvfsError::Integrity {
                    reason: IntegrityReason::UnknownAuthor,
                    ..
                })
            ),
            "expected UnknownAuthor, got {outcome:?}"
        );
    }

    #[test]
    fn replay_rejects_aclset_from_non_admin_member() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, m) = Engine::init(dir.path()).unwrap();
        let root = engine.identity.root_node_id.clone();
        let member = foreign_key();
        let member_pub = crypto::pubkey_bytes(&member);
        engine.authorize_member(&m, &member_pub).unwrap(); // authorized, but no admin
        engine.close().unwrap();

        // Forge an AclSet on the root authored by the member: the author IS an
        // authorized device but lacks admin (`a`) on root → apply must reject.
        let t = 1_500_000;
        let (kind, id, rights) = (0u64, Vec::<u8>::new(), acl::ACL_R as u64); // grant `any` read
        let sig = crypto::sign_digest(
            &member,
            &crate::event::msg_acl_set(&root, kind, &id, rights, t, &member_pub),
        )
        .unwrap();
        append_to_log(
            dir.path(),
            &Event::AclSet {
                node_id: root,
                principal_kind: kind,
                principal_id: id,
                rights,
                set_at: t,
                author: member_pub,
                sig,
            },
        );

        let outcome = Engine::open(dir.path()).map(drop);
        assert!(
            matches!(
                outcome,
                Err(PvfsError::Integrity {
                    reason: IntegrityReason::UnknownAuthor,
                    ..
                })
            ),
            "expected UnknownAuthor (no admin), got {outcome:?}"
        );
    }

    #[test]
    fn replay_rejects_member_link_without_write() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, m) = Engine::init(dir.path()).unwrap();
        let root = engine.identity.root_node_id.clone();
        let member = foreign_key();
        let member_pub = crypto::pubkey_bytes(&member);
        engine.authorize_member(&m, &member_pub).unwrap(); // authorized, but no write grant
        engine.close().unwrap();

        // Forge a node (fine — an orphan) and a link placing it under root, both
        // signed by the member, who has no write on root.
        let t = 1_500_000;
        let mut n = node::Node {
            id: String::new(),
            node_type: node::TYPE_FOLDER.into(),
            label: "intruder".into(),
            visibility: node::VISIBILITY_PUBLIC.into(),
            payload: node::folder_payload(),
            is_temp: false,
            creation_nonce: 7,
            created_at: t,
            author: member_pub.clone(),
            sig: Vec::new(),
        };
        let nd = n.id_digest();
        n.id = hex::encode(nd);
        n.sig = crypto::sign_digest(&member, &nd).unwrap();
        append_to_log(dir.path(), &Event::NodeCreated(n.clone()));

        let mut l = link::Link {
            id: String::new(),
            parent_id: Some(root),
            child_id: n.id.clone(),
            link_type: link::LINK_CONTAINS.into(),
            link_nonce: 0,
            order_key: "n".into(),
            created_at: t,
            author: member_pub,
            sig: Vec::new(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        };
        let ld = l.id_digest();
        l.id = hex::encode(ld);
        l.sig = crypto::sign_digest(&member, &ld).unwrap();
        append_to_log(dir.path(), &Event::LinkCreated(l));

        // Replay: the orphan node is accepted; placing it under root is rejected.
        let outcome = Engine::open(dir.path()).map(drop);
        assert!(
            matches!(
                outcome,
                Err(PvfsError::Integrity {
                    reason: IntegrityReason::UnknownAuthor,
                    ..
                })
            ),
            "expected rejection of a no-write member link, got {outcome:?}"
        );
    }

    // Per-key tags (doc 10 §4): an authorized member may assign a tag under its own
    // authority *without* admin on the root — it only ever unlocks nodes that key
    // already controls. Replay accepts it.
    #[test]
    fn replay_accepts_member_tagged_under_own_authority() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, m) = Engine::init(dir.path()).unwrap();
        let member = foreign_key();
        let member_pub = crypto::pubkey_bytes(&member);
        engine.authorize_member(&m, &member_pub).unwrap(); // authorized, not admin
        engine.close().unwrap();

        let t = 1_500_000;
        let (tag, granted) = ("friends", true);
        let sig = crypto::sign_digest(
            &member,
            &crate::event::msg_member_tagged(&member_pub, tag, granted, t, &member_pub),
        )
        .unwrap();
        append_to_log(
            dir.path(),
            &Event::MemberTagged {
                member_pubkey: member_pub.clone(),
                tag: tag.into(),
                granted,
                set_at: t,
                author: member_pub,
                sig,
            },
        );

        // a non-admin member's own-authority tag replays cleanly
        Engine::open(dir.path()).expect("own-authority MemberTagged must replay");
    }

    // But an author who is *not* an authorized member at all is still rejected
    // (the active-author check at the top of `check_member_event`).
    #[test]
    fn replay_rejects_member_tagged_from_unauthorized_key() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _m) = Engine::init(dir.path()).unwrap();
        engine.close().unwrap();

        let stranger = foreign_key();
        let stranger_pub = crypto::pubkey_bytes(&stranger);
        let t = 1_500_000;
        let (tag, granted) = ("sneaky", true);
        let sig = crypto::sign_digest(
            &stranger,
            &crate::event::msg_member_tagged(&stranger_pub, tag, granted, t, &stranger_pub),
        )
        .unwrap();
        append_to_log(
            dir.path(),
            &Event::MemberTagged {
                member_pubkey: stranger_pub.clone(),
                tag: tag.into(),
                granted,
                set_at: t,
                author: stranger_pub,
                sig,
            },
        );

        let outcome = Engine::open(dir.path()).map(drop);
        assert!(
            matches!(
                outcome,
                Err(PvfsError::Integrity {
                    reason: IntegrityReason::UnknownAuthor,
                    ..
                })
            ),
            "expected rejection of a tag from a non-member, got {outcome:?}"
        );
    }

    #[test]
    fn replay_rejects_device_cert_from_non_admin() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, m) = Engine::init(dir.path()).unwrap();
        let member = foreign_key();
        let member_pub = crypto::pubkey_bytes(&member);
        engine.authorize_member(&m, &member_pub).unwrap(); // authorized, not admin
        engine.close().unwrap();

        // a non-admin member forges a DeviceAuthorized admitting some other key
        let victim = crypto::pubkey_bytes(&foreign_key());
        let t = 1_500_000;
        let idx = acl::MEMBER_DEVICE_INDEX;
        let sig = crypto::sign_digest(
            &member,
            &crate::event::msg_device_authorized(&victim, idx, t, &member_pub),
        )
        .unwrap();
        append_to_log(
            dir.path(),
            &Event::DeviceAuthorized {
                device_pubkey: victim,
                device_index: idx,
                authorized_at: t,
                author: member_pub,
                sig,
            },
        );

        let outcome = Engine::open(dir.path()).map(drop);
        assert!(
            matches!(
                outcome,
                Err(PvfsError::Integrity {
                    reason: IntegrityReason::UnknownAuthor,
                    ..
                })
            ),
            "expected rejection of a non-admin device cert, got {outcome:?}"
        );
    }
}
