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
// v3 (doc 13 Q-E1, 1.2): `acl` carries `expires_at` (0 = never); an expired grant
// is masked on the read path. Same drop-and-replay upgrade.
// v4: + regions (P7.0, doc 20 §2).
// v5 (P7.2a, doc 20 §2.3): physical region logs — `nodes.region_id`
// (fold-maintained, sticky for orphans), the extended `regions` row (baseline
// commitment + generation file + committed head), and per-log `applied_marks`
// replacing the single last_applied pair. Same drop-and-replay upgrade.
// v6 (P7.2c, doc 20 §2.5): cross-region moves — `pending_moves` (the pair
// tracker) and `purged_nodes` (resurrection tombstones). Same upgrade.
// v7 (P9.1, doc 22 §2): `chunk_manifests` — owner-attested chunk layouts
// that license serve-while-fetching. Same upgrade.
// v10 (D72 Part B): `links.label` — the name an EDGE gives its child, so a
// rename changes a link instead of minting a new node. Empty means "no link
// label yet", and readers fall back to the node's label, which is what lets
// the change roll while boxes are mixed.
// v9 (D71 W6): `idx_nodes_label` — identity-by-content matches a file by
// (label, exact size), and without an index that is a full scan of `nodes`
// per imported file. Migrated in place (CREATE INDEX, no replay).
// v8 (D71 W1): `folder_bindings.bound_by` — the device that bound the
// folder, projected from the `FolderBound` event's existing `author`. A
// binding names a directory on ONE machine, so scanning and watching must
// only ever touch this device's own. No new event, no wire change: the
// attribution was always in the signed log, just never folded. Same
// drop-and-replay upgrade, which back-fills it for free.
pub const SCHEMA_VERSION: u32 = 16;

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
  sig            BLOB NOT NULL,
  region_id      TEXT               -- P7.2a: owning region (NULL = top); sticky for orphans
);

CREATE TABLE IF NOT EXISTS links (
  id            TEXT PRIMARY KEY,
  parent_id     TEXT,
  child_id      TEXT NOT NULL,
  link_type     TEXT NOT NULL,
  link_nonce    INTEGER NOT NULL,
  order_key     TEXT NOT NULL,
  -- D72 Part B: the name this EDGE gives its child. Empty = none yet, and
  -- readers fall back to the child node's label. Outside the link's id
  -- preimage, exactly like order_key, so renaming never changes the edge.
  label         TEXT NOT NULL DEFAULT '',
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
  expires_at     INTEGER NOT NULL DEFAULT 0, -- (doc 13 Q-E1) ms epoch; 0 = never
  PRIMARY KEY (node_id, principal_kind, principal_id, authority)
);
CREATE TABLE IF NOT EXISTS regions (
  node_id        TEXT    NOT NULL PRIMARY KEY,  -- the region boundary (P7.0, doc 13 §B)
  marked_at      INTEGER NOT NULL,
  -- P7.2a (doc 20 §2.3): the physical-log generation. state_root NULL = not yet
  -- split (a legacy P7.0 mark; the writer splits it lazily at open).
  state_root     TEXT,                          -- hex canonical state commitment
  baseline_seq   INTEGER NOT NULL DEFAULT 0,    -- seq of the RegionBaseline row in its host log
  baseline_log   TEXT    NOT NULL DEFAULT '',   -- log id hosting the baseline ('' = top); immutable
  parent_log     TEXT    NOT NULL DEFAULT '',   -- where future heads/unmark author; reparented on enclosing unmark
  log_file       TEXT,                          -- generation file, relative to the data dir
  committed_seq  INTEGER NOT NULL DEFAULT 0,    -- last SubRegionHead the enclosing log attests
  committed_head TEXT    NOT NULL DEFAULT '',
  -- D125 (doc 26 phase 1): 'log' = a physical per-region event log (P7.2, as
  -- before); 'catalogue' = no event log at all — the region keeps a local
  -- index (region_entries) and publishes a signed manifest hash as its head.
  -- LAST on purpose: full_rebuild copies positionally, and ALTER ADD COLUMN
  -- appends, so a migrated table and a fresh one must agree on column order.
  kind           TEXT    NOT NULL DEFAULT 'log'
);

-- P7.2a: per-log replay positions ('' = the top log, else the region root id).
CREATE TABLE IF NOT EXISTS applied_marks (
  log_id     TEXT PRIMARY KEY,
  seq        INTEGER NOT NULL,
  chain_hash TEXT NOT NULL
);

-- P7.2c (doc 20 §2.5): one row per cross-region move half still awaiting its
-- counterpart. Cleared when both halves fold; surviving rows are tolerated on
-- replicas (an unfetched region) and are corruption on an owner.
CREATE TABLE IF NOT EXISTS pending_moves (
  removed_link_id TEXT PRIMARY KEY,
  node_id         TEXT NOT NULL,
  removed_at      INTEGER NOT NULL,   -- the shared move timestamp t
  out_seen        INTEGER NOT NULL DEFAULT 0,
  in_seen         INTEGER NOT NULL DEFAULT 0,
  src_region      TEXT NOT NULL DEFAULT '',
  dest_region     TEXT NOT NULL DEFAULT ''
);

-- P9.1 (doc 22 §2): owner-attested chunk layouts. Early serving trusts the
-- root INSTEAD of the whole-file gate, so rows land only via the admin-gated
-- event; consumers additionally match content_hash against the node payload.
CREATE TABLE IF NOT EXISTS chunk_manifests (
  file_id       TEXT PRIMARY KEY,
  content_hash  TEXT NOT NULL,
  chunk_size    INTEGER NOT NULL,
  manifest_root BLOB NOT NULL
);

-- P7.2c: purge tombstones — with per-region logs a purge and its node's
-- creation can replay in either order; the tombstone makes the outcome
-- order-free. Compaction (doc 11) is where this set eventually shrinks.
CREATE TABLE IF NOT EXISTS purged_nodes (
  node_id TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS member_tags (
  member_pubkey BLOB NOT NULL,
  tag           TEXT NOT NULL,
  authority     BLOB NOT NULL,       -- (doc 10) the MemberTagged author = the tag authority
  set_at        INTEGER NOT NULL,
  PRIMARY KEY (member_pubkey, tag, authority)
);

-- Registered rotation recovery keys (doc 15 §C5): each may author a RootRotated.
CREATE TABLE IF NOT EXISTS recovery_keys (
  recovery_pubkey BLOB PRIMARY KEY,
  registered_at   INTEGER NOT NULL
);

-- Secure-blob ledger heads (doc 12 §8.2): the CURRENT ciphertext hash per blob.
-- Last write wins by design — the log keeps the content-free transition chain;
-- the projection keeps only the present state. No content, ever.
CREATE TABLE IF NOT EXISTS secure_blobs (
  blob_id      TEXT PRIMARY KEY,
  content_hash BLOB    NOT NULL,     -- hash of the ciphertext bytes (doc 12 §8.4)
  size         INTEGER NOT NULL,     -- ciphertext length
  updated_at   INTEGER NOT NULL,
  author       BLOB    NOT NULL
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
  label         TEXT NOT NULL DEFAULT '',
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

-- D81: one folder, MANY roots. The primary key was folder_id alone, which made
-- the same library on two volumes inexpressible -- and, worse, made a second
-- bind silently REPLACE the first. Data and Data_ext (and feederbox, and any
-- future holder) are roots of one tree.
CREATE TABLE IF NOT EXISTS folder_bindings (
  folder_id   TEXT NOT NULL,
  source_uri  TEXT NOT NULL,
  recursive   INTEGER NOT NULL,
  auto_index  INTEGER NOT NULL,
  extensions  TEXT NOT NULL,
  hash_policy TEXT NOT NULL,
  bound_at    INTEGER NOT NULL,
  bound_by    BLOB NOT NULL DEFAULT x'',
  unbound_at  INTEGER,
  PRIMARY KEY (folder_id, source_uri)
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

-- D99 — nodes the mover has established nobody can serve. Derived state, so
-- it lives here and never in the log. Held only in daemon memory until D99,
-- which meant every restart re-attempted ~24k doomed fetches over the network
-- before relearning what it already knew: the holder's first pass after a
-- restart took eight hours and moved nothing.
CREATE TABLE IF NOT EXISTS fetch_unfetchable (
  file_id  TEXT PRIMARY KEY,
  noted_at INTEGER NOT NULL
);

-- D112 — files a scan found held NOWHERE, and WHEN it first found that.
--
-- Having no live location is NOT the same statement as nobody having these
-- bytes. On a fleet whose mover works OUTSIDE the catalog (cloudplow rclones
-- feederbox to the NAS and deletes the local copy), a file is routinely
-- location-less for as long as it takes the holder to notice and record it.
-- D105 unlinked on that signal alone, which would have taken files out of the
-- tree that the NAS was holding the whole time.
--
-- So the observation is recorded and the decision deferred: unlink only if the
-- file is STILL held nowhere a grace period later, and drop the row the moment
-- any location appears. Derived state, never in the log.
CREATE TABLE IF NOT EXISTS scan_unheld (
  file_id  TEXT PRIMARY KEY,
  since_ms INTEGER NOT NULL
);

-- D125 — a catalogue region's own index: what is on ITS disk, keyed by the
-- path inside its root. Files AND directories (a directory is an entry with
-- no bytes — Chris's empty-folder requirement, doc 26 §4). Derived state,
-- never in the log; the log learns only the manifest hash of a snapshot.
CREATE TABLE IF NOT EXISTS region_entries (
  region_id    TEXT    NOT NULL,
  rel_path     TEXT    NOT NULL,
  kind         TEXT    NOT NULL,
  size_bytes   INTEGER NOT NULL,
  mtime_ms     INTEGER NOT NULL,
  changed_ms     INTEGER NOT NULL,   -- max(mtime, ctime) on THIS box: the D112 settle signal; never in the manifest
  content_hash TEXT,
  quality      TEXT,
  seen_at      INTEGER NOT NULL,
  PRIMARY KEY (region_id, rel_path)
);
-- D125 — each published head of a catalogue region: the seq and manifest
-- hash that went into the top log as a SubRegionHead. commit_region_heads
-- reads the latest row here instead of opening a log file.
CREATE TABLE IF NOT EXISTS region_snapshots (
  region_id     TEXT    NOT NULL,
  seq           INTEGER NOT NULL,
  manifest_hash TEXT    NOT NULL,
  entries       INTEGER NOT NULL,
  published_at  INTEGER NOT NULL,
  PRIMARY KEY (region_id, seq)
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

-- D72 Part B: empty = fall back to the child node's label.
CREATE INDEX IF NOT EXISTS idx_links_parent_order ON links(parent_id, order_key) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_links_child        ON links(child_id)             WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_nodes_type         ON nodes(node_type);
-- D71 W6: identity-by-content looks a file up by label; without this every
-- imported file costs a full scan of `nodes`.
CREATE INDEX IF NOT EXISTS idx_nodes_label        ON nodes(label) WHERE node_type = 'file';
-- v11 (D72): identity-by-name resolves the LINK label first, so that branch
-- needs its own index or every scanned file costs a table scan.
CREATE INDEX IF NOT EXISTS idx_links_label        ON links(label) WHERE label <> '';
-- v12 (D76): what a media file IS, measured. Keyed by node because a distinct
-- file is a distinct node; `seq` keeps the newest measurement winning on
-- replay regardless of the order rows arrive in.
CREATE TABLE IF NOT EXISTS media_quality (
  node_id  TEXT PRIMARY KEY,
  quality  TEXT NOT NULL,
  source   TEXT NOT NULL,
  seq      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_locations_file ON file_locations(file_id) WHERE removed_at IS NULL;
-- D85 — locations are also looked up BY URI, and that had no index.
--
-- `orphaned_local_locations` asks whether any OTHER live node claims these
-- same bytes, which is a match on `o.uri = l.uri`. Unindexed that is a full scan
-- of every location per candidate row. On the live holder — 28k locations — it
-- pinned a core and read the catalog at 143 MB/s while producing nothing,
-- starving the hash backfill sharing the same database. Correctness had been
-- checked; cost had not.
--
-- Prefix matches on uri use it too.
CREATE INDEX IF NOT EXISTS idx_file_locations_uri  ON file_locations(uri)     WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tlinks_parent_order ON temp_links(parent_id, order_key) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_tlinks_child        ON temp_links(child_id)             WHERE removed_at IS NULL;
";

/// Every table a rebuild must carry from the scratch replay into the live cache.
///
/// D81 — HAND-MAINTAINED, AND THREE HAD BEEN FORGOTTEN. A rebuild drops the live
/// tables and copies these back; anything folded from events but absent here is
/// silently emptied by every replay. `media_quality` (schema 12, mine),
/// `recovery_keys` and `secure_blobs` were all missing — so a rebuild discarded
/// quality, recovery-phrase custody and the encrypted-content ledger, and said
/// nothing.
///
/// Found in production: feederbox replayed 24,586 `MediaQuality` events, ended
/// with `unknown_events: 0` — it had decoded every one — and a `media_quality`
/// table with ZERO rows.
///
/// `rebuild_copies_every_table` pins the list against the schema, so the next
/// table cannot be forgotten the way these three were.
pub const MAIN_OBJECTS: &[&str] = &[
    "nodes",
    "links",
    "file_locations",
    "device_keys",
    "acl",
    "regions",
    "applied_marks",
    "pending_moves",
    "purged_nodes",
    "chunk_manifests",
    "member_tags",
    "temp_nodes",
    "temp_links",
    "temp_file_locations",
    "folder_bindings",
    "pending_changes",
    "location_quarantine",
    "fetch_unfetchable",
    "scan_unheld",
    "region_entries",
    "region_snapshots",
    "scan_state",
    "projection_meta",
    "media_quality",
    "recovery_keys",
    "secure_blobs",
];

// ---- the fold lock ----------------------------------------------------------

/// F5.8 (doc 17 §7.9): ONE FOLDER AT A TIME. The writer flock is a shared
/// PROBE (`others_alive`), so nothing else serializes projection mutation
/// across engines — and the daemon, its jobs engine, and every CLI open all
/// fold. The maintenance paths span many transactions; a write landing
/// between a rebuild's segments moves the applied mark to tip and the
/// rebuild concludes early — the D69 torn cache. Every projection-mutating
/// critical section (`full_rebuild`, `catch_up_tail`, the write path's
/// append+fold tx) therefore holds a blocking EXCLUSIVE flock on
/// `fold.lock` for its duration. Lock order is always flock → SQLite tx,
/// so the two lock systems cannot deadlock. RAII: released on drop, and by
/// the kernel on crash.
pub(crate) struct FoldLock(#[allow(dead_code)] nix::fcntl::Flock<std::fs::File>);

/// How long to wait for another process's fold before giving up.
///
/// D86 — this wait used to be UNBOUNDED: one non-blocking attempt, a message,
/// then `LockExclusive`, which blocks until the holder releases. Forever, if it
/// never does.
///
/// That is survivable in a CLI and fatal in a FUSE mount. The mount's session is
/// single-threaded, so a handler parked on this lock stops answering everything
/// — `getattr`, `readdir`, the lot — and the filesystem is dead while its
/// process looks perfectly healthy: alive, sleeping, small. That is exactly how
/// the library mount came up after a reboot, with the daemon beside it busy
/// folding a backlog: unit `active`, `mountpoint -q` timing out, readers stuck
/// in uninterruptible sleep where not even `timeout` could kill them.
///
/// Bounded, it becomes a `Busy` — which every caller already treats as
/// transient and retries. A slow fold now costs a retry instead of a mount.
///
/// The budget is SMALL on purpose, and the arithmetic is the reason. The write
/// path retries `Busy` five times, so this bound multiplies: at 30s the lab
/// measured a single `rm` through the mount taking 148s, with the message
/// printed three times — bounded, but 148 seconds of a frozen filesystem is not
/// meaningfully better than forever to anything waiting on it.
///
/// The lock is held for the length of a fold, which is milliseconds in the
/// ordinary case. Five seconds is already far outside normal; patience beyond
/// that belongs to the caller's retry ladder, which can afford it because it is
/// not holding a FUSE session hostage while it waits.
const FOLD_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
const FOLD_LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(100);

pub(crate) fn lock_folds(data_dir: &std::path::Path) -> Result<FoldLock> {
    lock_folds_within(data_dir, FOLD_LOCK_WAIT)
}

/// Test-only view of the bounded wait: can the fold lock be taken within
/// `budget`? Takes it and lets it go again, so the "it gives up rather than
/// hanging" property can be asserted without reaching into crate internals.
#[doc(hidden)]
pub fn try_fold_lock_for_test(
    data_dir: &std::path::Path,
    budget: std::time::Duration,
) -> Result<()> {
    lock_folds_within(data_dir, budget).map(|_| ())
}

/// D100 — run the member-event rights check against a forest on disk.
///
/// Test-only, and it exists because the check is not reachable otherwise:
/// `check_member_event` needs a `Connection`, `Engine` exposes none, and the
/// two callers that reach it (`fold_one` on replay, `check_member_event_batched`
/// on live commit) both need a validly signed event to get that far. Signing is
/// not what these tests are about — WHICH RIGHT each event kind demands is.
pub fn check_member_event_for_test(
    data_dir: &std::path::Path,
    ev: &Event,
    as_of_ms: u64,
) -> Result<()> {
    let conn = Connection::open(data_dir.join("index.db")).map_err(map_db("open index"))?;
    check_member_event(&conn, ev, as_of_ms)
}

pub(crate) fn lock_folds_within(
    data_dir: &std::path::Path,
    budget: std::time::Duration,
) -> Result<FoldLock> {
    let path = data_dir.join("fold.lock");
    let deadline = std::time::Instant::now() + budget;
    let mut said = false;
    let mut waits = 0u32;
    loop {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| PvfsError::io("open fold.lock", e))?;
        match nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock) {
            Ok(l) => return Ok(FoldLock(l)),
            Err((_f, _)) => {
                if !said {
                    eprintln!("pvfs: waiting for another pvfs process folding this forest…");
                    said = true;
                }
                if std::time::Instant::now() >= deadline {
                    return Err(PvfsError::Busy {
                        op: "fold lock (another pvfs process is folding this forest)".into(),
                        retries: waits,
                    });
                }
                waits += 1;
                std::thread::sleep(FOLD_LOCK_POLL);
            }
        }
    }
}

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

/// A bounded retry for a write that can meet a lock, with the same policy the
/// durable append already uses (D120).
///
/// The append path has had this since a 28,000-file adoption died five minutes
/// in because one fold met one lock. Everything ELSE kept the original
/// behaviour of failing on the first BUSY — which is why the flake that finally
/// surfaced it carried `retries: 0`, a number that says plainly nobody had
/// tried. Safe for a single statement: BUSY means nothing was applied.
pub(crate) fn retry_busy<T>(mut op: impl FnMut() -> Result<T>) -> Result<T> {
    let mut attempt = 0;
    loop {
        match op() {
            Err(PvfsError::Busy { .. }) if attempt < 5 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(50 << attempt));
            }
            Err(e) => return Err(e.with_retries(attempt)),
            other => return other,
        }
    }
}

pub fn meta_set(conn: &Connection, k: &str, v: &str) -> Result<()> {
    retry_busy(|| {
        conn.execute(
            "INSERT INTO projection_meta (k, v) VALUES (?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, v],
        )
        .map_err(map_db("write projection_meta"))
    })?;
    Ok(())
}

pub fn create_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(INDEX_SCHEMA)
        .map_err(map_db("create index schema"))?;
    if meta_get(conn, "schema_version")?.is_none() {
        meta_set(conn, "schema_version", &SCHEMA_VERSION.to_string())?;
        meta_set(conn, "clean_shutdown", "1")?;
    }
    // Seed only when absent: INSERT OR IGNORE takes a write lock even when
    // the row exists, which made EVERY engine open contend with a busy
    // daemon's folds (found by the P9 fleet run). The probe is a plain read.
    let seeded: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM applied_marks WHERE log_id = ''",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("probe applied mark"))?;
    if seeded.is_none() {
        conn.execute(
            "INSERT OR IGNORE INTO applied_marks (log_id, seq, chain_hash) VALUES ('', 0, '')",
            [],
        )
        .map_err(map_db("seed applied mark"))?;
    }
    Ok(())
}

// ---- per-log applied marks (P7.2a) ------------------------------------------

pub fn applied_get(conn: &Connection, log_id: &str) -> Result<(u64, String)> {
    conn.query_row(
        "SELECT seq, chain_hash FROM applied_marks WHERE log_id = ?1",
        params![log_id],
        |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?)),
    )
    .optional()
    .map_err(map_db("read applied mark"))
    .map(|v| v.unwrap_or((0, String::new())))
}

pub fn applied_set(conn: &Connection, log_id: &str, seq: u64, chain_hash: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO applied_marks (log_id, seq, chain_hash) VALUES (?1, ?2, ?3)
         ON CONFLICT(log_id) DO UPDATE SET seq = excluded.seq, chain_hash = excluded.chain_hash",
        params![log_id, seq as i64, chain_hash],
    )
    .map_err(map_db("write applied mark"))?;
    Ok(())
}

/// Attached-db name for a log during replay/append: the top log keeps its
/// historical name; region logs attach under `r<region-root-id>`.
pub fn attach_name(log_id: &str) -> String {
    if log_id.is_empty() {
        log_store::TOP_LOG.into()
    } else {
        format!("r{log_id}")
    }
}

/// A region generation's file, relative to the data dir (doc 20 §2.3): named
/// at birth from the baseline row's host + seq, never renamed.
pub fn region_log_rel_path(region_root: &str, baseline_log: &str, baseline_seq: u64) -> String {
    let host = if baseline_log.is_empty() {
        "top".to_string()
    } else {
        baseline_log.chars().take(8).collect()
    };
    format!("regions/{region_root}/g-{host}-{baseline_seq}.db")
}

// ---- canonical region state (P7.2a, doc 20 §2.3 / doc 11 §6) ----------------

/// The deterministic commitment to a subtree's current logged state: fixed
/// section order, items canonically `Enc`-encoded and sorted by primary key,
/// section hashes folded under a domain tag. Membership is the contains-closure
/// under `root` computed from links (stopping at nested marks) — never from
/// `nodes.region_id`, so the mark-time compute (before the column exists) and
/// the replay-time verify (after) agree by construction. Local observations
/// (pending changes, quarantine, scan state) and forest-scoped tables are
/// excluded: only log-derived state is committed.
pub fn canonical_state_root(conn: &Connection, root: &str) -> Result<[u8; 32]> {
    use crate::encoding::Enc;
    let m = map_db("canonical state");
    conn.execute_batch(
        "DROP TABLE IF EXISTS temp.canon_members;
         CREATE TEMP TABLE canon_members (id TEXT PRIMARY KEY);",
    )
    .map_err(&m)?;
    conn.execute(
        "WITH RECURSIVE sub(id) AS (
           SELECT ?1
           UNION
           SELECT l.child_id FROM links l JOIN sub s ON l.parent_id = s.id
           WHERE l.link_type = ?2 AND l.removed_at IS NULL
             AND NOT EXISTS (SELECT 1 FROM regions r WHERE r.node_id = l.child_id)
         )
         INSERT INTO canon_members SELECT id FROM sub",
        params![root, crate::link::LINK_CONTAINS],
    )
    .map_err(&m)?;

    let mut sections: Vec<[u8; 32]> = Vec::with_capacity(7);
    let section = |domain: &str, sql: &str, encode: &mut dyn FnMut(&rusqlite::Row<'_>, &mut Enc) -> rusqlite::Result<()>| -> Result<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(domain.as_bytes());
        let mut stmt = conn.prepare(sql).map_err(&m)?;
        let mut rows = stmt.query([]).map_err(&m)?;
        while let Some(row) = rows.next().map_err(&m)? {
            let mut e = Enc::new();
            encode(row, &mut e).map_err(&m)?;
            h.update(&e.finish());
        }
        Ok(*h.finalize().as_bytes())
    };

    sections.push(section(
        "pvfs:regionstate:nodes:",
        "SELECT id, node_type, label, visibility, payload, creation_nonce, created_at, author, sig
         FROM nodes WHERE id IN (SELECT id FROM canon_members) ORDER BY id",
        &mut |r, e| {
            e.string(&r.get::<_, String>(0)?)
                .string(&r.get::<_, String>(1)?)
                .string(&r.get::<_, String>(2)?)
                .string(&r.get::<_, String>(3)?)
                .bytes(&r.get::<_, Vec<u8>>(4)?)
                .u64(r.get::<_, i64>(5)? as u64)
                .u64(r.get::<_, i64>(6)? as u64)
                .bytes(&r.get::<_, Vec<u8>>(7)?)
                .bytes(&r.get::<_, Vec<u8>>(8)?);
            Ok(())
        },
    )?);
    sections.push(section(
        "pvfs:regionstate:links:",
        "SELECT id, IFNULL(parent_id,''), child_id, link_type, link_nonce, order_key, created_at,
                author, sig, IFNULL(removed_at,0), IFNULL(superseded_by,''), IFNULL(suspended_at,0)
         FROM links WHERE parent_id IN (SELECT id FROM canon_members) ORDER BY id",
        &mut |r, e| {
            e.string(&r.get::<_, String>(0)?)
                .string(&r.get::<_, String>(1)?)
                .string(&r.get::<_, String>(2)?)
                .string(&r.get::<_, String>(3)?)
                .u64(r.get::<_, i64>(4)? as u64)
                .string(&r.get::<_, String>(5)?)
                .u64(r.get::<_, i64>(6)? as u64)
                .bytes(&r.get::<_, Vec<u8>>(7)?)
                .bytes(&r.get::<_, Vec<u8>>(8)?)
                .u64(r.get::<_, i64>(9)? as u64)
                .string(&r.get::<_, String>(10)?)
                .u64(r.get::<_, i64>(11)? as u64);
            Ok(())
        },
    )?);
    sections.push(section(
        "pvfs:regionstate:locations:",
        "SELECT file_id, uri, added_at, IFNULL(removed_at,0) FROM file_locations
         WHERE file_id IN (SELECT id FROM canon_members) ORDER BY file_id, uri",
        &mut |r, e| {
            e.string(&r.get::<_, String>(0)?)
                .string(&r.get::<_, String>(1)?)
                .u64(r.get::<_, i64>(2)? as u64)
                .u64(r.get::<_, i64>(3)? as u64);
            Ok(())
        },
    )?);
    sections.push(section(
        "pvfs:regionstate:acl:",
        "SELECT node_id, principal_kind, principal_id, authority, rights, set_at, expires_at
         FROM acl WHERE node_id IN (SELECT id FROM canon_members)
         ORDER BY node_id, principal_kind, principal_id, authority",
        &mut |r, e| {
            e.string(&r.get::<_, String>(0)?)
                .u64(r.get::<_, i64>(1)? as u64)
                .bytes(&r.get::<_, Vec<u8>>(2)?)
                .bytes(&r.get::<_, Vec<u8>>(3)?)
                .u64(r.get::<_, i64>(4)? as u64)
                .u64(r.get::<_, i64>(5)? as u64)
                .u64(r.get::<_, i64>(6)? as u64);
            Ok(())
        },
    )?);
    sections.push(section(
        "pvfs:regionstate:bindings:",
        "SELECT folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at,
                IFNULL(unbound_at,0)
         FROM folder_bindings WHERE folder_id IN (SELECT id FROM canon_members) ORDER BY folder_id",
        &mut |r, e| {
            e.string(&r.get::<_, String>(0)?)
                .string(&r.get::<_, String>(1)?)
                .u64(r.get::<_, i64>(2)? as u64)
                .u64(r.get::<_, i64>(3)? as u64)
                .string(&r.get::<_, String>(4)?)
                .string(&r.get::<_, String>(5)?)
                .u64(r.get::<_, i64>(6)? as u64)
                .u64(r.get::<_, i64>(7)? as u64);
            Ok(())
        },
    )?);
    sections.push(section(
        "pvfs:regionstate:blobs:",
        "SELECT blob_id, content_hash, size, updated_at, author FROM secure_blobs
         WHERE blob_id IN (SELECT id FROM canon_members) ORDER BY blob_id",
        &mut |r, e| {
            e.string(&r.get::<_, String>(0)?)
                .bytes(&r.get::<_, Vec<u8>>(1)?)
                .u64(r.get::<_, i64>(2)? as u64)
                .u64(r.get::<_, i64>(3)? as u64)
                .bytes(&r.get::<_, Vec<u8>>(4)?);
            Ok(())
        },
    )?);
    // Immediate nested regions appear as their identities + last attested
    // heads (Q-B1: their interiors are their own logs' business).
    sections.push(section(
        "pvfs:regionstate:nested:",
        "SELECT r.node_id, r.marked_at, r.baseline_seq, IFNULL(r.state_root,''),
                r.committed_seq, r.committed_head
         FROM regions r
         WHERE EXISTS (SELECT 1 FROM links l JOIN canon_members cm ON l.parent_id = cm.id
                       WHERE l.child_id = r.node_id AND l.link_type = 'contains'
                         AND l.removed_at IS NULL)
         ORDER BY r.node_id",
        &mut |r, e| {
            e.string(&r.get::<_, String>(0)?)
                .u64(r.get::<_, i64>(1)? as u64)
                .u64(r.get::<_, i64>(2)? as u64)
                .string(&r.get::<_, String>(3)?)
                .u64(r.get::<_, i64>(4)? as u64)
                .string(&r.get::<_, String>(5)?);
            Ok(())
        },
    )?);
    conn.execute_batch("DROP TABLE IF EXISTS temp.canon_members;")
        .map_err(&m)?;

    let mut e = Enc::new();
    for s in &sections {
        e.bytes(s);
    }
    let mut h = blake3::Hasher::new();
    h.update(b"pvfs:regionstate:v1:");
    h.update(&e.finish());
    Ok(*h.finalize().as_bytes())
}

// ---- fold rules (spec §9.2) -------------------------------------------------

/// Fold one event into the projection. `log_id` is the log the event lives in
/// ('' = top) and `seq` its position there — the region-event arms need both
/// (a baseline is identified by its own row position, doc 20 §2.3).
pub fn fold(tx: &Transaction<'_>, log_id: &str, seq: u64, event: &Event) -> Result<()> {
    let m = map_db("fold event");
    match event {
        // D72 Part A — an event kind this binary does not know.
        //
        // It changes nothing in the projection, because we have no idea what
        // it means. What we MUST NOT do is pass over it silently: a box that
        // skipped an event has a projection that is missing whatever that
        // event said, and reporting itself healthy would be a lie of exactly
        // the kind this project keeps getting bitten by.
        //
        // So it is counted, and the count is surfaced (`pvfs versions`). The
        // box can still serve — the log verifies, most of it folded — but it
        // knows, and says, that it does not fully understand its own forest.
        Event::Unknown { kind, .. } => {
            tx.execute(
                "INSERT INTO projection_meta (k, v) VALUES ('unknown_events', '1')
                 ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT)",
                [],
            )
            .map_err(&m)?;
            tx.execute(
                "INSERT INTO projection_meta (k, v) VALUES ('unknown_event_kinds', ?1)
                 ON CONFLICT(k) DO UPDATE SET v =
                   CASE WHEN instr(v, ?1) > 0 THEN v ELSE v || ',' || ?1 END",
                params![kind],
            )
            .map_err(&m)?;
        }
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
        Event::RootRotated {
            new_root_pubkey, ..
        } => {
            // Re-anchor authority: `identity_root_pubkey` is the CURRENT root of
            // the lineage (doc 15 §C2). Replay folds events in order, so every
            // subsequent authorization check sees the new root; a full rebuild
            // reconstructs the same head. `forest_id`/ids are untouched.
            tx.execute(
                "INSERT INTO projection_meta (k, v) VALUES ('identity_root_pubkey', ?1)
                 ON CONFLICT(k) DO UPDATE SET v = excluded.v",
                params![hex::encode(new_root_pubkey)],
            )
            .map_err(&m)?;
            // A rotation is a clean slate for recovery keys (doc 15 §C6a): the
            // old ones — including any that authored this rotation — no longer
            // rotate. Register fresh recovery keys under the new root afterwards.
            tx.execute("DELETE FROM recovery_keys", [])
                .map_err(&m)?;
        }
        Event::RecoveryKeyRegistered {
            recovery_pubkey,
            registered_at,
            ..
        } => {
            tx.execute(
                "INSERT OR IGNORE INTO recovery_keys (recovery_pubkey, registered_at) VALUES (?1, ?2)",
                params![recovery_pubkey, *registered_at as i64],
            )
            .map_err(&m)?;
        }
        Event::RecoveryKeyRevoked {
            recovery_pubkey, ..
        } => {
            tx.execute(
                "DELETE FROM recovery_keys WHERE recovery_pubkey = ?1",
                params![recovery_pubkey],
            )
            .map_err(&m)?;
        }
        Event::AclSet {
            node_id,
            principal_kind,
            principal_id,
            rights,
            set_at,
            expires_at,
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
                    "INSERT INTO acl (node_id, principal_kind, principal_id, authority, rights, set_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(node_id, principal_kind, principal_id, authority)
                     DO UPDATE SET rights = excluded.rights, set_at = excluded.set_at,
                       expires_at = excluded.expires_at",
                    params![node_id, *principal_kind as i64, principal_id, authority, *rights as i64, *set_at as i64, *expires_at as i64],
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
        Event::SecureBlobUpdated {
            blob_id,
            content_hash,
            size,
            updated_at,
            author,
            ..
        } => {
            // Last write wins (doc 12 §8.2): the projection holds only "now";
            // the transition chain lives in the log, content-free.
            tx.execute(
                "INSERT INTO secure_blobs (blob_id, content_hash, size, updated_at, author)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(blob_id) DO UPDATE SET content_hash = excluded.content_hash,
                   size = excluded.size, updated_at = excluded.updated_at, author = excluded.author",
                params![blob_id, content_hash, *size as i64, *updated_at as i64, author],
            )
            .map_err(&m)?;
        }
        Event::NodeCreated(n) => {
            // P7.2c tombstones: a purge and this creation can replay in either
            // order once logs are parallel — never resurrect a purged id.
            let purged: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM purged_nodes WHERE node_id = ?1",
                    params![n.id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(&m)?;
            if purged.is_some() {
                return Ok(());
            }
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
            // P7.2c: if a NodeMovedIn already folded referencing THIS link as
            // the moved-away home (the destination log replayed first), the
            // link enters the projection already removed at the shared move
            // timestamp — dense history, one-home never violated, and the
            // outcome is identical in either replay order (doc 20 §2.5).
            let moved_away: Option<i64> = tx
                .query_row(
                    "SELECT removed_at FROM pending_moves WHERE removed_link_id = ?1 AND in_seen = 1",
                    params![l.id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(&m)?;
            if let Some(t) = moved_away {
                tx.execute(
                    "INSERT INTO links
                     (id, parent_id, child_id, link_type, link_nonce, order_key, created_at, author, sig,
                      removed_at, superseded_by, suspended_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, NULL)
                     ON CONFLICT(id) DO UPDATE SET removed_at = excluded.removed_at",
                    params![
                        l.id,
                        l.parent_id,
                        l.child_id,
                        l.link_type,
                        l.link_nonce as i64,
                        l.order_key,
                        l.created_at as i64,
                        l.author,
                        l.sig,
                        t
                    ],
                )
                .map_err(&m)?;
                return Ok(());
            }
            // One-home invariant (spec §5.2): a node may have at most one active
            // `contains` link at any time. Enforce at fold so a tampered or
            // crafted log cannot violate the invariant on rebuild/replay — it is
            // already checked live by `Engine::link`, but that guard is bypassed
            // when replaying events written by another process or injected directly.
            if l.link_type == crate::link::LINK_CONTAINS && l.parent_id.is_some() {
                let already: Option<String> = tx
                    .query_row(
                        "SELECT id FROM links WHERE child_id = ?1
                         AND link_type = ?2 AND removed_at IS NULL LIMIT 1",
                        params![l.child_id, l.link_type],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(&m)?;
                if let Some(existing_id) = already {
                    // Skip the event entirely rather than returning a hard error
                    // so that a well-formed move sequence (LinkRemoved then
                    // LinkCreated in the same batch) can still fold correctly.
                    // A genuine double-home (two concurrent active links) is
                    // only possible if a `LinkRemoved` is missing; surface it
                    // as a corruption error.
                    if existing_id != l.id {
                        return Err(crate::error::PvfsError::Corruption {
                            db: "log.db".into(),
                            detail: format!(
                                "one-home invariant violated: node {} already has contains \
                                 home {} when applying link {}",
                                l.child_id, existing_id, l.id
                            ),
                            seq: None,
                        });
                    }
                }
            }
            // Link ids exclude created_at/author (doc 03 §3.2), so re-homing a
            // node under a former parent regenerates the SAME id — recreation
            // must REACTIVATE the soft-removed row (the same rule locations
            // have), or a move back to a previous parent silently loses the
            // home. Found by the P7.2c smoke round-trip.
            tx.execute(
                "INSERT INTO links
                 (id, parent_id, child_id, link_type, link_nonce, order_key, created_at, author, sig,
                  removed_at, superseded_by, suspended_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL)
                 ON CONFLICT(id) DO UPDATE SET
                   order_key = excluded.order_key, created_at = excluded.created_at,
                   author = excluded.author, sig = excluded.sig,
                   removed_at = NULL, superseded_by = NULL, suspended_at = NULL",
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
            // P7.2a: homing assigns the child its parent's region. A move
            // refreshes it harmlessly (cross-region moves are refused); an
            // orphan keeps its last region (doc 20 §2.3 — stickiness is what
            // routes its eventual purge into the right log).
            if l.link_type == crate::link::LINK_CONTAINS && l.parent_id.is_some() {
                tx.execute(
                    "UPDATE nodes SET region_id =
                       (SELECT CASE WHEN EXISTS (SELECT 1 FROM regions r WHERE r.node_id = ?1)
                               THEN ?1 ELSE (SELECT region_id FROM nodes WHERE id = ?1) END)
                     WHERE id = ?2",
                    params![l.parent_id, l.child_id],
                )
                .map_err(&m)?;
            }
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
        // D72 Part B — the label is the edge's, not the node's.
        Event::LinkRelabeled { link_id, label, .. } => {
            tx.execute(
                "UPDATE links SET label = ?1 WHERE id = ?2",
                params![label, link_id],
            )
            .map_err(&m)?;
        }
        // D76 — the LATEST measurement wins, and its provenance rides with it.
        // A probe supersedes an *arr's import-time figure; the re-encoder's
        // analysis supersedes both. Storing the source is what makes that
        // ordering auditable instead of implicit.
        Event::MediaQuality {
            node_id,
            quality,
            source,
            ..
        } => {
            tx.execute(
                "INSERT INTO media_quality (node_id, quality, source, seq)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(node_id) DO UPDATE SET
                   quality = excluded.quality,
                   source  = excluded.source,
                   seq     = excluded.seq
                 WHERE excluded.seq >= media_quality.seq",
                params![node_id, quality, source, seq as i64],
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
            // D112 — somebody holds these bytes again, so the unlink clock
            // stops. Cleared HERE, in the fold, and not in `add_location`,
            // because the location that matters usually belongs to ANOTHER BOX
            // and reaches this one as a followed event: the holder records the
            // copy cloudplow moved, and the ingest — which is the box counting
            // down — learns it only through the log.
            tx.execute("DELETE FROM scan_unheld WHERE file_id = ?1", params![file_id])
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
        Event::RegionMarked {
            node_id,
            marked_at,
            kind,
            ..
        } => {
            // The enclosing region: the marked node's home parent's region
            // (NULL/absent = top). Captured at mark time; reparented if the
            // enclosing region later unmarks.
            let enclosing: Option<String> = tx
                .query_row(
                    "SELECT n.region_id FROM links l JOIN nodes n ON n.id = l.parent_id
                     WHERE l.child_id = ?1 AND l.link_type = ?2 AND l.removed_at IS NULL
                     LIMIT 1",
                    params![node_id, crate::link::LINK_CONTAINS],
                    |r| r.get(0),
                )
                .optional()
                .map_err(&m)?
                .flatten();
            let enclosing = enclosing.unwrap_or_default();
            tx.execute(
                // D125: the kind is fixed at the first mark; a re-mark only
                // re-stamps (the engine refuses one on a catalogue region).
                "INSERT INTO regions (node_id, marked_at, parent_log, kind) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(node_id) DO UPDATE SET marked_at = excluded.marked_at",
                params![
                    node_id,
                    *marked_at as i64,
                    enclosing,
                    if kind.is_empty() { "log" } else { kind.as_str() }
                ],
            )
            .map_err(&m)?;
            // Assign the contains-closure (stopping at nested marks) its region.
            tx.execute(
                "WITH RECURSIVE sub(id) AS (
                   SELECT ?1
                   UNION
                   SELECT l.child_id FROM links l JOIN sub s ON l.parent_id = s.id
                   WHERE l.link_type = ?2 AND l.removed_at IS NULL
                     AND NOT EXISTS (SELECT 1 FROM regions r WHERE r.node_id = l.child_id)
                 )
                 UPDATE nodes SET region_id = ?1 WHERE id IN (SELECT id FROM sub)",
                params![node_id, crate::link::LINK_CONTAINS],
            )
            .map_err(&m)?;
        }
        Event::RegionUnmarked { node_id, .. } => {
            let enclosing: Option<String> = tx
                .query_row(
                    "SELECT parent_log FROM regions WHERE node_id = ?1",
                    params![node_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(&m)?;
            let enclosing = enclosing.unwrap_or_default();
            let enclosing_or_null: Option<&str> =
                if enclosing.is_empty() { None } else { Some(enclosing.as_str()) };
            // The former interior folds back into the enclosing region; nested
            // marked regions keep their own identity but future heads/unmarks
            // author one level up now.
            tx.execute(
                "UPDATE nodes SET region_id = ?1 WHERE region_id = ?2",
                params![enclosing_or_null, node_id],
            )
            .map_err(&m)?;
            tx.execute(
                "UPDATE regions SET parent_log = ?1 WHERE parent_log = ?2",
                params![enclosing, node_id],
            )
            .map_err(&m)?;
            tx.execute("DELETE FROM regions WHERE node_id = ?1", params![node_id])
                .map_err(&m)?;
            // The generation is over; its applied mark must not leak into a
            // future re-mark of the same node.
            tx.execute("DELETE FROM applied_marks WHERE log_id = ?1", params![node_id])
                .map_err(&m)?;
        }
        Event::RegionBaseline { node_id, state_root, .. } => {
            // The split (doc 20 §2.3): verify the commitment against the state
            // this projection holds at this replay position — every rebuild is
            // doc 11 §5's full verification — then stamp the generation.
            let computed = canonical_state_root(tx, node_id)?;
            if computed.as_slice() != state_root.as_slice() {
                return Err(PvfsError::Corruption {
                    db: "log.db".into(),
                    detail: format!(
                        "region baseline for {node_id} does not match the replayed \
                         state (committed {}, computed {})",
                        hex::encode(state_root),
                        hex::encode(computed)
                    ),
                    seq: Some(seq),
                });
            }
            let file = region_log_rel_path(node_id, log_id, seq);
            tx.execute(
                "UPDATE regions SET state_root = ?1, baseline_seq = ?2, baseline_log = ?3,
                   log_file = ?4, committed_seq = 0, committed_head = ''
                 WHERE node_id = ?5",
                params![hex::encode(state_root), seq as i64, log_id, file, node_id],
            )
            .map_err(&m)?;
            // A fresh generation replays from its own genesis — a leftover
            // applied mark from a previous generation of this region root
            // would silently skip the new log's rows.
            tx.execute("DELETE FROM applied_marks WHERE log_id = ?1", params![node_id])
                .map_err(&m)?;
        }
        Event::SubRegionHead { node_id, head_seq, head_hash, .. } => {
            tx.execute(
                "UPDATE regions SET committed_seq = ?1, committed_head = ?2 WHERE node_id = ?3",
                params![*head_seq as i64, hex::encode(head_hash), node_id],
            )
            .map_err(&m)?;
        }
        Event::ChunkManifestRecorded {
            file_id,
            content_hash,
            chunk_size,
            manifest_root,
            ..
        } => {
            tx.execute(
                "INSERT INTO chunk_manifests (file_id, content_hash, chunk_size, manifest_root)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(file_id) DO UPDATE SET content_hash = excluded.content_hash,
                   chunk_size = excluded.chunk_size, manifest_root = excluded.manifest_root",
                params![file_id, content_hash, *chunk_size as i64, manifest_root],
            )
            .map_err(&m)?;
        }
        Event::NodeMovedOut {
            node_id,
            link_id,
            removed_at,
            dest_region,
            ..
        } => {
            // The source half (doc 20 §2.5): remove the old home at the shared
            // move timestamp — unconditionally, so both fold orders converge on
            // the same value — and record/clear the pair.
            tx.execute(
                "UPDATE links SET removed_at = ?1 WHERE id = ?2",
                params![*removed_at as i64, link_id],
            )
            .map_err(&m)?;
            tx.execute(
                "INSERT INTO pending_moves (removed_link_id, node_id, removed_at, out_seen, dest_region)
                 VALUES (?1, ?2, ?3, 1, ?4)
                 ON CONFLICT(removed_link_id) DO UPDATE SET out_seen = 1, dest_region = excluded.dest_region",
                params![link_id, node_id, *removed_at as i64, dest_region],
            )
            .map_err(&m)?;
            tx.execute(
                "DELETE FROM pending_moves WHERE removed_link_id = ?1 AND out_seen = 1 AND in_seen = 1",
                params![link_id],
            )
            .map_err(&m)?;
        }
        Event::NodeMovedIn {
            link: l,
            removed_link_id,
            removed_at,
            src_region,
            ..
        } => {
            // The destination half: retire the old home if it's here already
            // (same shared timestamp either way), refuse a GENUINE double-home,
            // insert the new link, flip the node's sticky region.
            if !removed_link_id.is_empty() {
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT id FROM links WHERE child_id = ?1 AND link_type = ?2
                           AND removed_at IS NULL LIMIT 1",
                        params![l.child_id, crate::link::LINK_CONTAINS],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(&m)?;
                match existing {
                    Some(id) if id == *removed_link_id => {
                        tx.execute(
                            "UPDATE links SET removed_at = ?1 WHERE id = ?2",
                            params![*removed_at as i64, removed_link_id],
                        )
                        .map_err(&m)?;
                    }
                    Some(id) if id != l.id => {
                        return Err(PvfsError::Corruption {
                            db: "log.db".into(),
                            detail: format!(
                                "cross-region move-in for {} names {removed_link_id} but the \
                                 active home is {id}",
                                l.child_id
                            ),
                            seq: Some(seq),
                        });
                    }
                    _ => {} // source not replayed yet (or idempotent refold)
                }
                tx.execute(
                    "INSERT INTO pending_moves (removed_link_id, node_id, removed_at, in_seen, src_region)
                     VALUES (?1, ?2, ?3, 1, ?4)
                     ON CONFLICT(removed_link_id) DO UPDATE SET in_seen = 1, src_region = excluded.src_region",
                    params![removed_link_id, l.child_id, *removed_at as i64, src_region],
                )
                .map_err(&m)?;
                tx.execute(
                    "DELETE FROM pending_moves WHERE removed_link_id = ?1 AND out_seen = 1 AND in_seen = 1",
                    params![removed_link_id],
                )
                .map_err(&m)?;
            } else {
                // orphan adoption: there must be no active home at all
                let existing: Option<String> = tx
                    .query_row(
                        "SELECT id FROM links WHERE child_id = ?1 AND link_type = ?2
                           AND removed_at IS NULL LIMIT 1",
                        params![l.child_id, crate::link::LINK_CONTAINS],
                        |r| r.get(0),
                    )
                    .optional()
                    .map_err(&m)?;
                if let Some(id) = existing {
                    if id != l.id {
                        return Err(PvfsError::Corruption {
                            db: "log.db".into(),
                            detail: format!(
                                "cross-region adoption of {} but it has active home {id}",
                                l.child_id
                            ),
                            seq: Some(seq),
                        });
                    }
                }
            }
            // same reactivation rule as LinkCreated: a round-trip move
            // regenerates the original link id (doc 03 §3.2)
            tx.execute(
                "INSERT INTO links
                 (id, parent_id, child_id, link_type, link_nonce, order_key, created_at, author, sig,
                  removed_at, superseded_by, suspended_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, NULL, NULL)
                 ON CONFLICT(id) DO UPDATE SET
                   order_key = excluded.order_key, created_at = excluded.created_at,
                   author = excluded.author, sig = excluded.sig,
                   removed_at = NULL, superseded_by = NULL, suspended_at = NULL",
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
            // The single writer of the node's final region (doc 20 §2.5) — and
            // of its SUBTREE's: descendants created before the move carry the
            // old region. Source-first replay fixes them here (the CTE);
            // destination-first replay creates them later under an
            // already-flipped parent (homing inheritance) — both orders
            // converge. Nested marked regions keep their own identity.
            if let Some(parent) = &l.parent_id {
                tx.execute(
                    "WITH RECURSIVE dest(v) AS (
                       SELECT CASE WHEN EXISTS (SELECT 1 FROM regions r WHERE r.node_id = ?1)
                              THEN ?1 ELSE (SELECT region_id FROM nodes WHERE id = ?1) END
                     ),
                     sub(id) AS (
                       SELECT ?2
                       UNION
                       SELECT lk.child_id FROM links lk JOIN sub s ON lk.parent_id = s.id
                       WHERE lk.link_type = ?3 AND lk.removed_at IS NULL
                         AND NOT EXISTS (SELECT 1 FROM regions r WHERE r.node_id = lk.child_id)
                     )
                     UPDATE nodes SET region_id = (SELECT v FROM dest)
                     WHERE id IN (SELECT id FROM sub)",
                    params![parent, l.child_id, crate::link::LINK_CONTAINS],
                )
                .map_err(&m)?;
            }
        }
        Event::NodePurged { node_id, .. } => {
            tx.execute("DELETE FROM nodes WHERE id = ?1", params![node_id])
                .map_err(&m)?;
            tx.execute(
                "DELETE FROM file_locations WHERE file_id = ?1",
                params![node_id],
            )
            .map_err(&m)?;
            tx.execute(
                "INSERT OR IGNORE INTO purged_nodes (node_id) VALUES (?1)",
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
            author,
            ..
        } => {
            // `author` is the device that ran the bind — the one machine where
            // `source_uri` actually exists (D71 W1). Re-binding a folder from a
            // different box legitimately re-attributes it, so the upsert takes
            // the newest event's author, exactly like every other field.
            tx.execute(
                "INSERT INTO folder_bindings
                 (folder_id, source_uri, recursive, auto_index, extensions, hash_policy, bound_at, bound_by, unbound_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL)
                 ON CONFLICT(folder_id, source_uri) DO UPDATE SET
                   recursive = excluded.recursive,
                   auto_index = excluded.auto_index,
                   extensions = excluded.extensions,
                   hash_policy = excluded.hash_policy,
                   bound_at = excluded.bound_at,
                   bound_by = excluded.bound_by,
                   unbound_at = NULL",
                params![
                    folder_id,
                    source_uri,
                    *recursive as i64,
                    *auto_index as i64,
                    extensions,
                    hash_policy,
                    *bound_at as i64,
                    author
                ],
            )
            .map_err(&m)?;
        }
        Event::FolderUnbound {
            folder_id,
            unbound_at,
            ..
        } => {
            // Still means EVERY root — the meaning it has always had, and the
            // meaning every already-deployed box folds it with (D81).
            tx.execute(
                "UPDATE folder_bindings SET unbound_at = ?1 WHERE folder_id = ?2",
                params![*unbound_at as i64, folder_id],
            )
            .map_err(&m)?;
        }
        Event::FolderUnboundRoot {
            folder_id,
            source_uri,
            unbound_at,
            ..
        } => {
            tx.execute(
                "UPDATE folder_bindings SET unbound_at = ?1
                  WHERE folder_id = ?2 AND source_uri = ?3",
                params![*unbound_at as i64, folder_id, source_uri],
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
/// then fold. Used by both catch-up replay and full rebuild. `log_id` is the
/// log being replayed ('' = top): region logs are default-deny for
/// forest-scoped kinds — a tampered region file cannot smuggle in a device
/// certificate, rotation, or second genesis.
fn replay_one(
    tx: &Transaction<'_>,
    identity: &ForestIdentity,
    log_id: &str,
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
    // D72 Part A — an event we cannot parse cannot have its signature checked,
    // because we do not know which bytes were signed. `verify_sig` says so
    // honestly, and replay must not treat that honesty as a verification
    // FAILURE — doing so would refuse the whole forest, which is precisely the
    // behaviour this work exists to remove.
    //
    // Authorization is DEFERRED, not waived. The chain hash already binds the
    // event's bytes into the log's order, and the first binary that
    // understands the kind will verify it properly and reject it if it was
    // never authorized. Until then it changes nothing and is reported as
    // not understood.
    if !matches!(ev, Event::Unknown { .. }) {
        ev.verify_sig()?;
    }
    if !log_id.is_empty() {
        if let Event::ForestCreated { .. }
        | Event::DeviceAuthorized { .. }
        | Event::DeviceRevoked { .. }
        | Event::RootRotated { .. }
        | Event::RecoveryKeyRegistered { .. }
        | Event::RecoveryKeyRevoked { .. }
        | Event::MemberTagged { .. } = &ev
        {
            return Err(PvfsError::Corruption {
                db: format!("region log {log_id}"),
                detail: format!("forest-scoped event {} in a region log", ev.kind()),
                seq: Some(row.seq),
            });
        }
    }
    match &ev {
        Event::ForestCreated { .. } if row.seq != 1 => {
            return Err(PvfsError::Corruption {
                db: "log.db".into(),
                detail: "second ForestCreated event".into(),
                seq: Some(row.seq),
            })
        }
        // Device certificates: root- or admin-device-signed (doc 09 §2.2). Genesis's
        // device-0 cert is root-signed (no admin device exists yet). The "root"
        // is the CURRENT root of the lineage as of this position (doc 15 §C2), so
        // certs signed by a post-rotation root validate on replay.
        Event::DeviceAuthorized { author, .. } | Event::DeviceRevoked { author, .. } => {
            let root = current_root(tx, identity)?;
            check_device_cert(tx, &root, &identity.root_node_id, author, row.written_at)
                .map_err(|_| unauthorized(row.seq, ev.kind()))?;
        }
        // Root rotation (doc 15 §C2): author is the current root OR a registered
        // recovery key. First valid one in the log wins (a later one fails here
        // because the current root has moved on).
        Event::RootRotated { author, .. } => {
            let root = current_root(tx, identity)?;
            if author.as_slice() != root.as_slice() && !is_recovery_key(tx, author)? {
                return Err(unauthorized(row.seq, ev.kind()));
            }
        }
        // Recovery-key register/revoke (doc 15 §C5/§C6a): author = current root.
        // (Phrase-authenticated by construction — the companion never signs these.)
        Event::RecoveryKeyRegistered { author, .. } | Event::RecoveryKeyRevoked { author, .. } => {
            let root = current_root(tx, identity)?;
            if author.as_slice() != root.as_slice() {
                return Err(unauthorized(row.seq, ev.kind()));
            }
        }
        Event::ForestCreated { .. } => {} // genesis (seq 1), root-authored
        // D72 Part A — we cannot authorize an author we cannot parse, and
        // `author()` correctly reports none. Refusing here would reject the
        // whole forest, which is the behaviour this work removes.
        //
        // DEFERRED, NOT WAIVED, and the deferral is bounded: the event alters
        // nothing (the fold ignores it), it is counted and named in
        // `pvfs versions`, and the first binary that understands the kind
        // performs the full signature and authorization check — rejecting it
        // then if it was never authorized. An unauthorized event can therefore
        // sit in a log unnoticed by boxes too old to read it, but it can never
        // take EFFECT on one.
        Event::Unknown { .. } => {}
        // Every other event is device-authored: enforce the same author + ACL
        // rules used by live member writes, so a tampered or synced log can't
        // carry an event its author had no right to (doc 06 §4.3, doc 07 §5).
        // Expiry is judged as of the row's chain-protected `written_at`, so a
        // write that was in-rights when appended replays identically forever.
        _ => check_member_event(tx, &ev, row.written_at)
            .map_err(|_| unauthorized(row.seq, ev.kind()))?,
    }
    fold(tx, log_id, row.seq, &ev)?;
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
/// `as_of_ms` is the instant ACL expiry (doc 13 Q-E1) is judged at: the wall
/// clock for a live commit, the event row's chain-protected `written_at` on
/// replay — so a write authorized by a then-valid expiring grant still replays
/// after the grant lapses, and a rebuild is deterministic.
pub fn check_member_event(conn: &Connection, ev: &Event, as_of_ms: u64) -> Result<()> {
    require_active_author(conn, ev, as_of_ms)?;
    let author = ev.author();
    match ev {
        Event::AclSet { node_id, .. } => {
            require_right(conn, author, node_id, acl::ACL_A, "set acl", as_of_ms)?
        }
        // Region boundaries (P7.0, doc 13 §B): admin on the node — a region
        // maps to an authority; drawing or erasing its border is that tier.
        Event::RegionMarked { node_id, .. }
        | Event::RegionUnmarked { node_id, .. }
        | Event::RegionBaseline { node_id, .. }
        | Event::SubRegionHead { node_id, .. } => {
            require_right(conn, author, node_id, acl::ACL_A, "mark region", as_of_ms)?
        }
        Event::LinkCreated(l) => {
            if let Some(parent) = &l.parent_id {
                require_right(conn, author, parent, acl::ACL_W, "create link", as_of_ms)?;
            }
        }
        // P7.2c: each half of a cross-region move carries the same right its
        // in-region counterpart would — write on the parent it touches.
        Event::NodeMovedIn { link, .. } => {
            if let Some(parent) = &link.parent_id {
                require_right(conn, author, parent, acl::ACL_W, "move in", as_of_ms)?;
            }
        }
        Event::NodeMovedOut { link_id, node_id, .. } => {
            let row: Option<Option<String>> = conn
                .query_row(
                    "SELECT parent_id FROM links WHERE id = ?1",
                    params![link_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("acl link lookup"))?;
            match row.flatten() {
                Some(parent) => {
                    require_right(conn, author, &parent, acl::ACL_W, "move out", as_of_ms)?
                }
                None => require_right(conn, author, node_id, acl::ACL_A, "move out", as_of_ms)?,
            }
        }
        // D100 — every event that mutates a link goes through the same rule
        // `LinkRemoved` already used. Relabel, reorder, supersede, suspend and
        // unsuspend all reached the catch-all below and were allowed on nothing
        // but "is this key live?".
        Event::LinkRemoved { link_id, .. } => {
            require_link_write(conn, author, link_id, "remove link", as_of_ms)?
        }
        Event::LinkRelabeled { link_id, .. } => {
            require_link_write(conn, author, link_id, "relabel link", as_of_ms)?
        }
        Event::LinkReordered { link_id, .. } => {
            require_link_write(conn, author, link_id, "reorder link", as_of_ms)?
        }
        Event::LinkSuspended { link_id, .. } => {
            require_link_write(conn, author, link_id, "suspend link", as_of_ms)?
        }
        Event::LinkUnsuspended { link_id, .. } => {
            require_link_write(conn, author, link_id, "unsuspend link", as_of_ms)?
        }
        // Both ends: superseding writes the old link out and the new one in, so
        // holding rights over one half is not permission to move the other.
        Event::LinkSuperseded { old_link_id, new_link_id, .. } => {
            require_link_write(conn, author, old_link_id, "supersede link", as_of_ms)?;
            require_link_write(conn, author, new_link_id, "supersede link", as_of_ms)?;
        }
        Event::FileLocationAdded { file_id, .. } => {
            require_right(conn, author, file_id, acl::ACL_W, "add location", as_of_ms)?
        }
        // D100 — the exact counterpart of FileLocationAdded above, and it was
        // allowed unchecked. Retiring a location is how bytes stop being
        // findable; it is a write to the file by any reading.
        Event::FileLocationRemoved { file_id, .. } => {
            require_right(conn, author, file_id, acl::ACL_W, "remove location", as_of_ms)?
        }
        // Hard delete. Admin, not write — `unlink` is the write-tier act, and
        // this is the one that cannot be undone.
        Event::NodePurged { node_id, .. } => {
            require_right(conn, author, node_id, acl::ACL_A, "purge node", as_of_ms)?
        }
        // What a file IS (D76) is content about that node.
        Event::MediaQuality { node_id, .. } => {
            require_right(conn, author, node_id, acl::ACL_W, "record quality", as_of_ms)?
        }
        // Binding decides what a folder INGESTS from disk, and unbinding
        // strands every location under it (D97). Write on the folder.
        Event::FolderBound { folder_id, .. }
        | Event::FolderUnbound { folder_id, .. }
        | Event::FolderUnboundRoot { folder_id, .. } => {
            require_right(conn, author, folder_id, acl::ACL_W, "bind folder", as_of_ms)?
        }
        // P9.1 (doc 22 §2): attesting a chunk layout licenses EARLY serving,
        // which bypasses the whole-file gate — owner/admin tier only.
        Event::ChunkManifestRecorded { file_id, .. } => {
            require_right(conn, author, file_id, acl::ACL_A, "attest manifest", as_of_ms)?
        }
        Event::SecureBlobUpdated { blob_id, .. } => {
            // Advancing a blob's ledger is a write (doc 12 §8.2) — the same right
            // a content change needs, enforced identically live and at replay.
            require_right(conn, ev.author(), blob_id, acl::ACL_W, "update secure blob", as_of_ms)?
        }

        // ---- allowed here, each for a stated reason -------------------------
        //
        // D100: this match was `_ => {}`. A catch-all is DEFAULT-ALLOW, which
        // is the opposite of this system's posture, and it silently swallowed
        // eleven kinds that mutate the tree — including FileLocationRemoved and
        // NodePurged. Every variant is now named, so adding an event kind
        // FAILS TO COMPILE until someone decides what right it needs. That
        // decision should cost a build error, not a security review.

        // A bare node is unreachable and confers nothing: it has no parent to
        // inherit an ACL from and no link placing it anywhere. The gated act is
        // the `LinkCreated` that puts it somewhere, which needs write on the
        // parent. There is genuinely nothing to check rights AGAINST here.
        Event::NodeCreated(_) => {}

        // Per-key tags (doc 10 §4): any authorized member may assign a tag
        // under its OWN authority — and the authority IS the signed author, so
        // a member cannot forge a tag under another key. The active-author
        // check at the top of this function is therefore sufficient; the old
        // "admin on the forest root" requirement was over-broad (it existed
        // only because tags were unscoped) and is dropped. A key-scoped
        // membership only unlocks nodes whose `Tag` grant that same key
        // authored — i.e. nodes it controls.
        Event::MemberTagged { .. } => {}

        // Authorized by the CALLER, not here, and at both commit and replay:
        // device certs take the root-or-admin rule via `check_device_cert`,
        // root rotation the root-or-recovery-key rule, recovery keys the
        // current root (doc 15 §C2/§C5/§C6a). `fold_one` and `append_durable`
        // both match these ahead of dispatching here; reaching this arm means
        // a caller skipped its own gate, so nothing is asserted about them.
        Event::DeviceAuthorized { .. }
        | Event::DeviceRevoked { .. }
        | Event::RootRotated { .. }
        | Event::RecoveryKeyRegistered { .. }
        | Event::RecoveryKeyRevoked { .. } => {}

        // Genesis, seq 1, root-authored — there is no prior state to check.
        Event::ForestCreated { .. } => {}

        // D72 Part A: an author we cannot parse cannot be authorized, and the
        // fold ignores the event entirely. DEFERRED, NOT WAIVED — the first
        // binary that understands the kind runs the full check and rejects it
        // then. It can sit in a log unread; it can never take effect unread.
        Event::Unknown { .. } => {}
    }
    Ok(())
}

/// D100 — the rule `LinkRemoved` has always used, now shared by every event
/// that mutates a link: write on the link's parent, or admin on the node
/// itself for a root link (which has no parent to hold rights over).
///
/// A link that is already gone is a no-op and allowed: replay must be able to
/// re-apply a removal it has already folded without inventing a rights failure.
fn require_link_write(
    conn: &Connection,
    author: &[u8],
    link_id: &str,
    action: &'static str,
    as_of_ms: u64,
) -> Result<()> {
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
        require_right(conn, author, &target, needed, action, as_of_ms)?;
    }
    Ok(())
}

/// The active-unrevoked-device precheck shared by [`check_member_event`] and
/// its batch-aware variant. As-of-time, not current-state (P7.2a, doc 20
/// §2.3): tree replay applies parallel logs after the top log completes, so
/// "authored before the revocation" must be judged by the owner-stamped,
/// chain-bound `written_at` — the same instant every other check here already
/// uses. A live commit passes the wall clock, so a currently revoked key
/// still fails.
fn require_active_author(conn: &Connection, ev: &Event, as_of_ms: u64) -> Result<()> {
    let author = ev.author();
    let active: i64 = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM device_keys WHERE device_pubkey = ?1
               AND authorized_at <= ?2 AND (revoked_at IS NULL OR revoked_at > ?2))",
            params![author, as_of_ms as i64],
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
    Ok(())
}

/// Batch-aware variant of [`check_member_event`] for the live commit path
/// (P10.0, doc 23 §9.2): one prepared batch may place a child under a parent
/// created earlier in the same batch, or attest a file born in the same
/// batch. `born` maps each batch-created node to its batch parent; rights on
/// a batch-born node resolve at its nearest pre-existing ancestor. That is
/// exact, not approximate — a node that does not yet exist can have no ACL
/// entries of its own, so its effective rights ARE the inherited ones.
/// Replay needs no equivalent: it checks-and-folds event by event, so a
/// parent is always projected before its child's link is judged, and both
/// paths reach the same verdict.
pub fn check_member_event_batched(
    conn: &Connection,
    ev: &Event,
    as_of_ms: u64,
    born: &std::collections::HashMap<String, String>,
) -> Result<()> {
    if born.is_empty() {
        return check_member_event(conn, ev, as_of_ms);
    }
    let resolve = |node: &str| -> String {
        let mut cur = node.to_string();
        // The batch is finite and link-acyclic by construction; the bound is
        // pure defense.
        for _ in 0..256 {
            match born.get(&cur) {
                Some(p) => cur = p.clone(),
                None => break,
            }
        }
        cur
    };
    match ev {
        Event::LinkCreated(l)
            if l.parent_id.as_deref().is_some_and(|p| born.contains_key(p)) =>
        {
            require_active_author(conn, ev, as_of_ms)?;
            let target = resolve(l.parent_id.as_deref().unwrap());
            require_right(conn, ev.author(), &target, acl::ACL_W, "create link", as_of_ms)
        }
        // D85 — a location placed on a node BORN IN THIS BATCH.
        //
        // The hash-fill successor mints a node and moves every location onto it
        // in one write. Without this arm the location add resolved rights from
        // the new node's tree position — which does not exist yet at check time
        // — and the whole fill was refused with "author lacks the required
        // right", naming a node id that had never been written. Same shape as
        // the LinkCreated arm above, and it existed for the same reason.
        Event::FileLocationAdded { file_id, .. } if born.contains_key(file_id) => {
            require_active_author(conn, ev, as_of_ms)?;
            let target = resolve(file_id);
            require_right(conn, ev.author(), &target, acl::ACL_W, "add location", as_of_ms)
        }
        Event::ChunkManifestRecorded { file_id, .. } if born.contains_key(file_id) => {
            require_active_author(conn, ev, as_of_ms)?;
            let target = resolve(file_id);
            require_right(conn, ev.author(), &target, acl::ACL_A, "attest manifest", as_of_ms)
        }
        _ => check_member_event(conn, ev, as_of_ms),
    }
}

/// The **current** root of the lineage (doc 15 §C2): the latest `RootRotated`'s
/// key, else the genesis root. Read from `identity_root_pubkey` in
/// `projection_meta`, which the fold keeps current; falls back to the passed
/// genesis identity for forests predating the lineage (never rotated).
pub fn current_root(conn: &Connection, identity: &ForestIdentity) -> Result<Vec<u8>> {
    let hexk: Option<String> = conn
        .query_row(
            "SELECT v FROM projection_meta WHERE k = 'identity_root_pubkey'",
            [],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("read current root"))?;
    match hexk.and_then(|h| hex::decode(h).ok()) {
        Some(k) => Ok(k),
        None => Ok(identity.root_pubkey.clone()),
    }
}

/// Is `pubkey` a registered rotation recovery key (doc 15 §C5)?
pub fn is_recovery_key(conn: &Connection, pubkey: &[u8]) -> Result<bool> {
    let n: i64 = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM recovery_keys WHERE recovery_pubkey = ?1)",
            params![pubkey],
            |r| r.get(0),
        )
        .map_err(map_db("recovery key check"))?;
    Ok(n != 0)
}

/// A device certificate (`DeviceAuthorized`/`DeviceRevoked`) is valid when signed
/// by the identity root **or** by a device holding admin (`a`) on the forest root
/// (doc 09 §2.2). Shared by replay and the live admin-op commit.
pub fn check_device_cert(
    conn: &Connection,
    root_pubkey: &[u8],
    root_node_id: &str,
    author: &[u8],
    as_of_ms: u64,
) -> Result<()> {
    let by_root = author == root_pubkey;
    let by_admin = !by_root
        && effective_rights_at(conn, &Principal::Key(author.to_vec()), root_node_id, as_of_ms)?
            & acl::ACL_A
            != 0;
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
fn require_right(
    conn: &Connection,
    author: &[u8],
    node: &str,
    right: u8,
    action: &str,
    as_of_ms: u64,
) -> Result<()> {
    if effective_rights_at(conn, &Principal::Key(author.to_vec()), node, as_of_ms)? & right != right
    {
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
///
/// Evaluates expiry (doc 13 Q-E1) at the wall clock — the live-path entry point.
/// Replay and other as-of consumers call [`effective_rights_at`] directly.
pub fn effective_rights(conn: &Connection, principal: &Principal, node_id: &str) -> Result<u8> {
    effective_rights_at(conn, principal, node_id, crate::engine::now_ms())
}

/// [`effective_rights`] evaluated as of `as_of_ms`: a grant with a nonzero
/// `expires_at <= as_of_ms` is **inert** — masked exactly like a tag grant under
/// a revoked authority (doc 10 §9.2). The row stays for inspection (`acl ls`
/// flags it); compaction removes it (doc 11).
pub fn effective_rights_at(
    conn: &Connection,
    principal: &Principal,
    node_id: &str,
    as_of_ms: u64,
) -> Result<u8> {
    // An owner device short-circuits to full rights. Otherwise determine whether
    // the caller is an authorized member (so `Any` grants apply), which tags a
    // member key holds (so the node's `tag:` grants apply), and whether the key's
    // direct `key:` grants are live: a NEVER-authorized key keeps them (the
    // ephemeral guest-key path, doc 13 §E), but a REVOKED key is masked —
    // `DeviceRevoked` must contain a stolen member key on the read path too
    // (doc 06 §5), exactly like a dead tag authority (doc 10 §9.2). The lingering
    // ACL rows go inert, not removed (compaction reclaims them, doc 11).
    let (is_member, member_tags, key_grants_live): (bool, Vec<(Vec<u8>, String)>, bool) =
        match principal {
            Principal::Public | Principal::Tag(_) => (false, Vec::new(), true),
            Principal::Any => (true, Vec::new(), true),
            Principal::Key(pk) => match key_standing(conn, pk)? {
                KeyStanding::Active { owner: true } => return Ok(acl::ACL_RWA),
                KeyStanding::Active { owner: false } => (true, member_tags_of(conn, pk)?, true),
                KeyStanding::Never => (false, Vec::new(), true),
                KeyStanding::Revoked => (false, Vec::new(), false),
            },
        };
    // A `Tag` query reports only that tag's grants (no `public` floor).
    let include_public = !matches!(principal, Principal::Tag(_));
    let mut rights = 0u8;
    let mut cur = Some(node_id.to_string());
    let mut guard = 0u32;
    // D90: the orphan resume below may fire at most once per walk.
    let mut orphan_resumed = false;
    while let Some(n) = cur {
        if include_public {
            rights |= grant_for(conn, &n, 2, &[], &[], as_of_ms)?; // Public — applies to everyone
        }
        if is_member {
            rights |= grant_for(conn, &n, 0, &[], &[], as_of_ms)?; // Any — authorized members
        }
        match principal {
            Principal::Key(pk) => {
                if key_grants_live {
                    rights |= grant_for(conn, &n, 1, pk, &[], as_of_ms)?; // this specific key
                }
                // A tag the member holds unlocks only the node's `Tag` grants
                // authored by the *same* authority (doc 10 §3).
                for (authority, t) in &member_tags {
                    rights |= grant_for(conn, &n, 3, t.as_bytes(), authority, as_of_ms)?;
                }
            }
            Principal::Tag(t) => {
                // Inspection (`acl check tag:<name>`): report this name's grants
                // across every authority that set one.
                rights |= grant_for_tag_any_authority(conn, &n, t.as_bytes(), as_of_ms)?;
            }
            _ => {}
        }
        if rights & acl::ACL_RWA == acl::ACL_RWA {
            break; // already maximal — stop walking
        }
        cur = match contains_parent(conn, &n)? {
            Some(p) => Some(p),
            // D90 — running out of links means one of two very different
            // things, and treating them alike was the bug: either `n` IS the
            // forest root and there is genuinely nothing above it, or `n` is an
            // ORPHAN and the chain to the grants has been cut.
            //
            // Grants live at the root, so an orphan reached NONE of them: a node
            // became unwritable by its own author the moment its last live link
            // went, and the watcher could not retire the location of a file it
            // could plainly see was gone. An orphan is still IN the forest — it
            // should not fall off a cliff. The walk therefore resumes at the
            // root exactly once, so orphans are governed by the forest's own
            // grants like everything else.
            //
            // This is a widening, deliberately: anyone holding `w` at the root
            // can now act on any orphan. That is the same authority that already
            // covers every linked node in the tree, and an orphan has no claim
            // to be better protected than the tree it fell out of.
            None if !orphan_resumed => {
                orphan_resumed = true;
                match meta_get(conn, "forest_root_node_id")? {
                    // `n` was the root: a real end, not a cut chain.
                    Some(root) if root != n => Some(root),
                    _ => None,
                }
            }
            None => None,
        };
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
/// the dead row stays put (inspection flags it inert via `authority_active`) and is
/// physically removed by compaction's re-genesis (doc 11), not a signed sweep.
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

/// Whether a grant/membership **authority** is still live (doc 10 §9.2). An empty
/// authority (the `public`/`any`/`key` principals carry none) is not key-scoped, so
/// it is always "active"; a tag authority is active iff its key is a currently
/// authorized, unrevoked member. Inspection commands use this to flag grants that
/// have gone **inert** because their authority was revoked — the same condition
/// `member_tags_of` masks on the read path. (Physical removal of the dead rows is
/// left to compaction's re-genesis, doc 11.)
pub fn authority_active(conn: &Connection, authority: &[u8]) -> Result<bool> {
    if authority.is_empty() {
        return Ok(true);
    }
    Ok(device_status(conn, authority)?.0)
}

/// One inert tag grant found by the audit: `(node_id, tag_name, authority, rights)`.
pub type InertTagGrant = (String, String, Vec<u8>, u8);

/// One inert tag membership found by the audit: `(member_pubkey, tag, authority)`.
pub type InertMembership = (Vec<u8>, String, Vec<u8>);

/// Forest-wide authorization audit (doc 08 §4 item 14): every **tag grant** whose
/// authority is no longer a live member — `(node_id, tag_name, authority, rights)`.
/// These grants are inert (masked on the read path; flagged `[inert]` by `acl ls`).
/// Read-only; ordered for stable output.
pub fn inert_tag_grants(conn: &Connection) -> Result<Vec<InertTagGrant>> {
    let mut stmt = conn
        .prepare(
            "SELECT a.node_id, a.principal_id, a.authority, a.rights FROM acl a
             WHERE a.principal_kind = 3
               AND NOT EXISTS (SELECT 1 FROM device_keys dk
                               WHERE dk.device_pubkey = a.authority AND dk.revoked_at IS NULL)
             ORDER BY a.node_id, a.principal_id, a.authority",
        )
        .map_err(map_db("prepare audit grants"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                String::from_utf8_lossy(&r.get::<_, Vec<u8>>(1)?).into_owned(),
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, i64>(3)? as u8,
            ))
        })
        .map_err(map_db("query audit grants"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(map_db("read audit grant"))?);
    }
    Ok(out)
}

/// Forest-wide authorization audit (doc 08 §4 item 14): every tag **membership**
/// whose authority is no longer a live member — `(member_pubkey, tag, authority)`.
/// Inert (masked), the membership counterpart of [`inert_tag_grants`]. Read-only.
pub fn inert_memberships(conn: &Connection) -> Result<Vec<InertMembership>> {
    let mut stmt = conn
        .prepare(
            "SELECT mt.member_pubkey, mt.tag, mt.authority FROM member_tags mt
             WHERE NOT EXISTS (SELECT 1 FROM device_keys dk
                               WHERE dk.device_pubkey = mt.authority AND dk.revoked_at IS NULL)
             ORDER BY mt.member_pubkey, mt.tag, mt.authority",
        )
        .map_err(map_db("prepare audit memberships"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .map_err(map_db("query audit memberships"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(map_db("read audit membership"))?);
    }
    Ok(out)
}

/// One inert direct `key:` grant found by the audit: `(node_id, key, rights)`.
pub type InertKeyGrant = (String, Vec<u8>, u8);

/// Forest-wide audit (doc 08 §3.1 follow-on to item 14): every direct `key:`
/// grant whose key **was** a device/member and is now revoked. Such grants are
/// inert — masked at access time (doc 06 §5) — but the rows linger until
/// compaction. A **never-authorized** guest key is NOT reported: its `key:`
/// grants still apply (the ephemeral guest/public-link path, doc 13 §E), so
/// only keys with certs that are all revoked qualify. Read-only.
pub fn inert_key_grants(conn: &Connection) -> Result<Vec<InertKeyGrant>> {
    let mut stmt = conn
        .prepare(
            "SELECT a.node_id, a.principal_id, a.rights FROM acl a
             WHERE a.principal_kind = 1
               AND EXISTS (SELECT 1 FROM device_keys dk
                           WHERE dk.device_pubkey = a.principal_id)
               AND NOT EXISTS (SELECT 1 FROM device_keys dk
                               WHERE dk.device_pubkey = a.principal_id AND dk.revoked_at IS NULL)
             ORDER BY a.node_id, a.principal_id",
        )
        .map_err(map_db("prepare audit key grants"))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)? as u8,
            ))
        })
        .map_err(map_db("query audit key grants"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(map_db("read audit key grant"))?);
    }
    Ok(out)
}

/// One expired grant found by the audit:
/// `(node_id, principal, authority, rights, expires_at)`.
pub type ExpiredGrant = (String, crate::acl::Principal, Vec<u8>, u8, u64);

/// Forest-wide audit: every grant whose `expires_at` has passed (doc 13 Q-E1).
/// Expired grants are inert — masked by `effective_rights` — but the rows stay
/// listed until compaction; this surfaces them all in one place. Read-only.
pub fn expired_grants(conn: &Connection, as_of_ms: u64) -> Result<Vec<ExpiredGrant>> {
    let mut stmt = conn
        .prepare(
            "SELECT node_id, principal_kind, principal_id, authority, rights, expires_at
             FROM acl WHERE expires_at != 0 AND expires_at <= ?1
             ORDER BY node_id, principal_kind, principal_id",
        )
        .map_err(map_db("prepare audit expired"))?;
    let rows = stmt
        .query_map(params![as_of_ms as i64], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, i64>(4)? as u8,
                r.get::<_, i64>(5)? as u64,
            ))
        })
        .map_err(map_db("query audit expired"))?;
    let mut out = Vec::new();
    for r in rows {
        let (node, kind, id, authority, rights, expires_at) =
            r.map_err(map_db("read audit expired"))?;
        out.push((
            node,
            crate::acl::Principal::from_wire(kind, id)?,
            authority,
            rights,
            expires_at,
        ));
    }
    Ok(out)
}

/// `(authorized_and_unrevoked, is_owner_device)` for a key in `device_keys`.
/// A key's standing in the device-cert projection: never seen, currently
/// authorized (owner device or member), or revoked. Distinct from
/// `device_status` because the access path must tell "never authorized"
/// (guest key — direct `key:` grants apply, doc 13 §E) apart from "revoked"
/// (contained — all personal grants masked, doc 06 §5).
enum KeyStanding {
    Never,
    Active { owner: bool },
    Revoked,
}

fn key_standing(conn: &Connection, pubkey: &[u8]) -> Result<KeyStanding> {
    let idx: Option<i64> = conn
        .query_row(
            "SELECT device_index FROM device_keys WHERE device_pubkey = ?1 AND revoked_at IS NULL",
            params![pubkey],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("acl key standing"))?;
    if let Some(i) = idx {
        return Ok(KeyStanding::Active {
            owner: (i as u64) != acl::MEMBER_DEVICE_INDEX,
        });
    }
    let seen: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM device_keys WHERE device_pubkey = ?1 LIMIT 1",
            params![pubkey],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("acl key standing"))?;
    Ok(if seen.is_some() {
        KeyStanding::Revoked
    } else {
        KeyStanding::Never
    })
}

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

/// An expired grant (nonzero `expires_at <= as_of_ms`, doc 13 Q-E1) is masked
/// here — the read-path counterpart of the revoked-authority mask above.
fn grant_for(
    conn: &Connection,
    node_id: &str,
    kind: u64,
    id: &[u8],
    authority: &[u8],
    as_of_ms: u64,
) -> Result<u8> {
    let r: Option<i64> = conn
        .query_row(
            "SELECT rights FROM acl WHERE node_id = ?1 AND principal_kind = ?2 AND principal_id = ?3 AND authority = ?4
               AND (expires_at = 0 OR expires_at > ?5)",
            params![node_id, kind as i64, id, authority, as_of_ms as i64],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_db("acl lookup"))?;
    Ok(r.unwrap_or(0) as u8)
}

/// Union of a tag name's grants on `node_id` across every **live** authority that
/// set one — for inspection only (`acl check tag:<name>`), never for an access
/// decision (those resolve a specific `(authority, name)` via `grant_for`).
///
/// Grants whose authority is a revoked member are **excluded** (same liveness mask
/// as `member_tags_of`, doc 10 §9.2): such a grant is unsatisfiable — it can only be
/// met by a membership under the *same* authority, which is itself masked — so it can
/// never confer access. Excluding it keeps `acl check tag:` honest (effective, like
/// `acl check key:`), while `acl ls` still lists the row and flags it `[inert]`.
fn grant_for_tag_any_authority(
    conn: &Connection,
    node_id: &str,
    name: &[u8],
    as_of_ms: u64,
) -> Result<u8> {
    let mut stmt = conn
        .prepare(
            "SELECT a.rights FROM acl a WHERE a.node_id = ?1 AND a.principal_kind = 3 AND a.principal_id = ?2
               AND (a.expires_at = 0 OR a.expires_at > ?3)
               AND EXISTS (SELECT 1 FROM device_keys dk
                           WHERE dk.device_pubkey = a.authority AND dk.revoked_at IS NULL)",
        )
        .map_err(map_db("prepare tag grants"))?;
    let rows = stmt
        .query_map(params![node_id, name, as_of_ms as i64], |r| r.get::<_, i64>(0))
        .map_err(map_db("query tag grants"))?;
    let mut rights = 0u8;
    for r in rows {
        rights |= r.map_err(map_db("read tag grant"))? as u8;
    }
    Ok(rights)
}

/// The node's `contains` (home) parent, or `None` at the root / for an orphan.
pub fn contains_parent(conn: &Connection, node_id: &str) -> Result<Option<String>> {
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

/// Maximum region nesting depth for tree replay: each level holds one extra
/// ATTACHed log file, and SQLite's attach budget is small (doc 20 §2.3).
const MAX_REGION_DEPTH: usize = 8;

/// The chain-genesis seed for `log_id` ('' = top; else a split region, whose
/// seed binds the baseline row position + state commitment, doc 20 §2.3).
pub(crate) fn log_genesis(
    conn: &Connection,
    identity: &ForestIdentity,
    log_id: &str,
) -> Result<[u8; 32]> {
    if log_id.is_empty() {
        return Ok(log_store::genesis_seed(
            &identity.instance_id,
            &identity.forest_id,
        ));
    }
    let (baseline_seq, state_root): (i64, Option<String>) = conn
        .query_row(
            "SELECT baseline_seq, state_root FROM regions WHERE node_id = ?1",
            params![log_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(map_db("read region row"))?
        .ok_or_else(|| PvfsError::Corruption {
            db: format!("region log {log_id}"),
            detail: "no active region row for this log".into(),
            seq: None,
        })?;
    let root_hex = state_root.ok_or_else(|| PvfsError::Corruption {
        db: format!("region log {log_id}"),
        detail: "region is not split (no baseline)".into(),
        seq: None,
    })?;
    let root = hex::decode(&root_hex).map_err(|_| PvfsError::Corruption {
        db: format!("region log {log_id}"),
        detail: "bad state_root encoding".into(),
        seq: None,
    })?;
    Ok(log_store::region_genesis_seed(
        &identity.instance_id,
        &identity.forest_id,
        log_id,
        baseline_seq as u64,
        &root,
    ))
}

pub(crate) fn attach_log(
    conn: &Connection,
    data_dir: &std::path::Path,
    log_id: &str,
    rel_file: &str,
) -> Result<()> {
    let name = attach_name(log_id);
    let path = data_dir.join(rel_file).to_string_lossy().into_owned();
    conn.execute(&format!("ATTACH DATABASE ?1 AS {name}"), params![path])
        .map_err(map_db("attach region log"))?;
    conn.execute_batch(&log_store::log_schema(&name))
        .map_err(map_db("region log schema"))?;
    Ok(())
}

pub(crate) fn detach_log(conn: &Connection, log_id: &str) -> Result<()> {
    conn.execute(&format!("DETACH DATABASE {}", attach_name(log_id)), [])
        .map_err(map_db("detach region log"))?;
    Ok(())
}

/// Replay `log_id`'s rows up to `to` inside one transaction, starting from the
/// applied mark.
fn replay_segment(
    conn: &mut Connection,
    identity: &ForestIdentity,
    log_id: &str,
    to: u64,
) -> Result<()> {
    let db = attach_name(log_id);
    // IMMEDIATE: take the write lock before reading the applied mark. Two
    // concurrent opens (a replica's follow thread + a job pass, P5) both saw
    // the same mark under a deferred tx and double-applied the tail — the
    // loser detonated the one-home invariant as a phantom "corruption".
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(map_db("begin replay"))?;
    // Re-read under the lock: whoever held it before us may have caught up.
    let (applied, chain_hex) = applied_get(&tx, log_id)?;
    if applied >= to {
        return Ok(());
    }
    let mut chain = if applied == 0 {
        log_genesis(&tx, identity, log_id)?
    } else {
        let bytes = hex::decode(&chain_hex).unwrap_or_default();
        if bytes.len() != 32 {
            return Err(PvfsError::Corruption {
                db: format!("log {log_id}"),
                detail: "applied chain hash wrong length".into(),
                seq: Some(applied),
            });
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        a
    };
    for seq in (applied + 1)..=to {
        let row = log_store::read_event_in(&tx, &db, seq)?.ok_or_else(|| PvfsError::Corruption {
            db: format!("log {log_id}"),
            detail: format!("missing event at seq {seq}"),
            seq: Some(seq),
        })?;
        chain = replay_one(&tx, identity, log_id, &row, &chain)?;
    }
    applied_set(&tx, log_id, to, &hex::encode(chain))?;
    tx.commit().map_err(map_db("commit replay"))
}

/// Tree replay (doc 20 §2.3): replay one log root-down. Pauses at every
/// `RegionUnmarked` to replay that region's sealed generation first (after the
/// unmark, the former interior is enclosing scope again), verifies the sealed
/// tip against the final head commitment, then folds the unmark. Active child
/// regions replay after this log completes — routing keeps enclosing events
/// out of their interiors, which is what makes end-of-log safe for them.
/// The caller has already attached this log (the top log always is).
fn replay_log(
    conn: &mut Connection,
    data_dir: &std::path::Path,
    identity: &ForestIdentity,
    log_id: &str,
    depth: usize,
) -> Result<()> {
    if depth > MAX_REGION_DEPTH {
        return Err(PvfsError::Corruption {
            db: format!("region log {log_id}"),
            detail: format!("region nesting exceeds the replay bound ({MAX_REGION_DEPTH})"),
            seq: None,
        });
    }
    let db = attach_name(log_id);
    let tip = log_store::max_seq_in(conn, &db)?;
    loop {
        let (applied, _) = applied_get(conn, log_id)?;
        if applied >= tip {
            break;
        }
        let pause: Option<i64> = conn
            .query_row(
                &format!(
                    "SELECT MIN(seq) FROM {db}.events WHERE kind = ?1 AND seq > ?2 AND seq <= ?3"
                ),
                params![
                    crate::event::K_REGION_UNMARKED,
                    applied as i64,
                    tip as i64
                ],
                |r| r.get(0),
            )
            .map_err(map_db("scan for unmarks"))?;
        match pause {
            Some(u) => {
                let u = u as u64;
                if u > applied + 1 {
                    replay_segment(conn, identity, log_id, u - 1)?;
                }
                let row =
                    log_store::read_event_in(conn, &db, u)?.ok_or_else(|| PvfsError::Corruption {
                        db: format!("log {log_id}"),
                        detail: format!("missing event at seq {u}"),
                        seq: Some(u),
                    })?;
                let ev = Event::decode(&row.kind, &row.body)?;
                if let Event::RegionUnmarked { node_id, .. } = &ev {
                    let node_id = node_id.clone();
                    replay_sealed_child(conn, data_dir, identity, &node_id, depth)?;
                }
                replay_segment(conn, identity, log_id, u)?; // folds the unmark
            }
            None => replay_segment(conn, identity, log_id, tip)?,
        }
    }
    // Active split regions whose baselines live in this log.
    let children: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT node_id, log_file FROM regions
                 WHERE baseline_log = ?1 AND state_root IS NOT NULL AND log_file IS NOT NULL
                 ORDER BY baseline_seq",
            )
            .map_err(map_db("list child regions"))?;
        let rows = stmt
            .query_map(params![log_id], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(map_db("list child regions"))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("list child regions"))?
    };
    for (child, file) in children {
        if !data_dir.join(&file).exists() {
            continue; // marked but never written to — genesis-only, nothing to replay
        }
        attach_log(conn, data_dir, &child, &file)?;
        let res = replay_log(conn, data_dir, identity, &child, depth + 1);
        detach_log(conn, &child)?;
        res?;
    }
    Ok(())
}

/// The pause step: replay an unmarking region's sealed generation and verify
/// its tip equals the final head commitment folded just before the unmark.
fn replay_sealed_child(
    conn: &mut Connection,
    data_dir: &std::path::Path,
    identity: &ForestIdentity,
    child: &str,
    depth: usize,
) -> Result<()> {
    let region: Option<(Option<String>, Option<String>, i64, String)> = conn
        .query_row(
            "SELECT log_file, state_root, committed_seq, committed_head
             FROM regions WHERE node_id = ?1",
            params![child],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()
        .map_err(map_db("read region row"))?;
    let Some((log_file, state_root, committed_seq, committed_head)) = region else {
        return Ok(()); // no active row (legacy or tampered) — the fold alone decides
    };
    if state_root.is_none() {
        return Ok(()); // legacy P7.0 mark, never split: its events are all here
    }
    // P7.2b (doc 20 §2.4): a REPLICA that doesn't hold this generation treats
    // it as an unfetched region — the seal stays attested by the enclosing
    // log, its contents unverifiable until the log is fetched. Owner/writer
    // opens keep the strict refusal below (every generation must be present).
    let held = log_file
        .as_deref()
        .map(|f| data_dir.join(f).exists())
        .unwrap_or(false);
    if !held && crate::replica::marker_path(data_dir).exists() && committed_seq > 0 {
        return Ok(());
    }
    let committed_seq = committed_seq as u64;
    let (fin_seq, fin_chain) = match log_file {
        Some(file) if data_dir.join(&file).exists() => {
            attach_log(conn, data_dir, child, &file)?;
            let res = replay_log(conn, data_dir, identity, child, depth + 1);
            let applied = applied_get(conn, child);
            detach_log(conn, child)?;
            res?;
            applied?
        }
        _ => (0, String::new()),
    };
    let fin_chain = if fin_seq == 0 {
        hex::encode(log_genesis(conn, identity, child)?)
    } else {
        fin_chain
    };
    if fin_seq != committed_seq || fin_chain != committed_head {
        return Err(PvfsError::Corruption {
            db: format!("region log {child}"),
            detail: format!(
                "sealed generation tip (seq {fin_seq}) does not match the final \
                 head commitment (seq {committed_seq})"
            ),
            seq: Some(fin_seq),
        });
    }
    Ok(())
}

/// Full rebuild (spec §9.3 step 5): drop and recreate the index schema, then
/// tree-replay every log from its genesis seed. Temp tables start empty.
/// What this box could NOT understand in its own forest (D72 Part A):
/// `(count, kinds)`. Zero means it folded everything.
///
/// Surfaced by `pvfs versions` so "this box is behind" is a fact an operator
/// can read, not something they infer when the library looks wrong.
/// Same as [`unknown_events`], on a connection already open (the migration path
/// runs inside one).
fn unknown_events_conn(conn: &Connection) -> Option<(u64, String)> {
    let n: u64 = conn
        .query_row(
            "SELECT v FROM projection_meta WHERE k = 'unknown_events'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()?
        .parse()
        .ok()?;
    let kinds: String = conn
        .query_row(
            "SELECT v FROM projection_meta WHERE k = 'unknown_event_kinds'",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default();
    Some((n, kinds))
}

pub fn unknown_events(data_dir: &std::path::Path) -> Option<(u64, String)> {
    let conn = Connection::open(data_dir.join("index.db")).ok()?;
    let n: u64 = conn
        .query_row(
            "SELECT v FROM projection_meta WHERE k = 'unknown_events'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()?
        .parse()
        .ok()?;
    let kinds: String = conn
        .query_row(
            "SELECT v FROM projection_meta WHERE k = 'unknown_event_kinds'",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_default();
    Some((n, kinds))
}

/// The schema version recorded in a forest's projection on disk, without
/// opening an engine (D71).
///
/// Opening is what migrates or rebuilds the cache, so anything that wants to
/// *report* the state an upgrade is about to act on has to read it raw.
/// `None` = no forest here, or a projection too damaged to say.
pub fn on_disk_schema_version(data_dir: &std::path::Path) -> Option<u32> {
    let conn = Connection::open(data_dir.join("index.db")).ok()?;
    conn.query_row(
        "SELECT v FROM projection_meta WHERE k = 'schema_version'",
        [],
        |r| r.get::<_, String>(0),
    )
    .ok()?
    .parse()
    .ok()
}

// ---- projection migrations (D71) --------------------------------------------

/// Bring the cache forward one schema version at a time WITHOUT dropping it.
///
/// Most schema changes are additive: a new column whose value comes from event
/// kinds already in the log. Dropping all of `MAIN_OBJECTS` and replaying every
/// event to fill one column costs the entire log — on the D69 fleet owner that
/// is 59,365 events, and on the production media library it is minutes during
/// which that box is unavailable. A migration turns the common case into an
/// `ALTER` plus a targeted pass.
///
/// **A migration is only ever an optimisation.** Any failure, and any version
/// with no registered step, falls back to [`full_rebuild`], which is always
/// correct. So a migration is free to refuse — and MUST refuse rather than
/// guess. Returns a description of what it did, or `None` to mean "rebuild".
fn migrate_projection(
    conn: &mut Connection,
    data_dir: &std::path::Path,
    from: u32,
) -> Option<String> {
    // Region logs are attached and detached during replay; a migration reads
    // only the top log, so a forest with live region logs is refused outright
    // rather than half-migrated. (The media fleet has none — the fast path is
    // exactly where it is needed.)
    let has_regions: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM regions WHERE log_file IS NOT NULL",
            [],
            |r| r.get(0),
        )
        .unwrap_or(1);
    if has_regions != 0 {
        return None;
    }

    // A box that folded an event as `Unknown` and has SINCE gained the code to
    // read it cannot take the cheap door. Its projection is missing whatever
    // that event carried, and an ALTER adding an empty column does not recover
    // it — only a replay does.
    //
    // This is not a corner case. In a rolling upgrade every box except the
    // first is behind for a while, so every box except the first may have
    // ignored events it can now read. Migrating those in place would leave
    // them permanently, silently wrong.
    if let Some((n, kinds)) = unknown_events_conn(conn) {
        if n > 0
            && kinds
                .split(',')
                .map(str::trim)
                .filter(|k| !k.is_empty())
                .any(crate::event::is_known_kind)
        {
            return None; // slow door: replay, and learn what we ignored
        }
    }

    let _folds = lock_folds(data_dir).ok()?;
    let mut done: Vec<&'static str> = Vec::new();
    let mut v = from;
    while v < SCHEMA_VERSION {
        let step = match v {
            7 => migrate_v7_to_v8(conn).map(|_| "folder_bindings.bound_by from FolderBound"),
            8 => migrate_v8_to_v9(conn).map(|_| "idx_nodes_label"),
            9 => migrate_v9_to_v10(conn).map(|_| "links.label"),
            10 => migrate_v10_to_v11(conn).map(|_| "idx_links_label"),
            11 => migrate_v11_to_v12(conn).map(|_| "media_quality"),
            12 => migrate_v12_to_v13(conn).map(|_| "folder_bindings keyed (folder_id, source_uri)"),
            13 => migrate_v13_to_v14(conn).map(|_| "fetch_unfetchable"),
            14 => migrate_v14_to_v15(conn).map(|_| "scan_unheld"),
            15 => migrate_v15_to_v16(conn).map(|_| "regions.kind; region_entries; region_snapshots"),
            _ => return None, // no registered step — rebuild
        };
        match step {
            Ok(what) => done.push(what),
            Err(_) => return None, // anything unexpected → rebuild, never guess
        }
        v += 1;
    }
    meta_set(conn, "schema_version", &SCHEMA_VERSION.to_string()).ok()?;
    Some(done.join("; "))
}

/// v7 → v8 (D71 W1): `folder_bindings.bound_by`, filled from the author each
/// `FolderBound` event has always carried.
fn migrate_v7_to_v8(conn: &mut Connection) -> Result<()> {
    // Rebuilt, not ALTERed. `ALTER TABLE ... ADD COLUMN` appends the column at
    // the END, so a migrated table and a freshly created one would hold the
    // same values in a DIFFERENT column order — a divergence that is invisible
    // to every named query and then bites the first thing that copies the table
    // positionally (it broke the rebuild swap on a live 82k-event forest).
    // A migrated cache must be structurally identical to a rebuilt one.
    let have: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('folder_bindings') WHERE name = 'bound_by'",
            [],
            |r| r.get(0),
        )
        .map_err(map_db("inspect folder_bindings"))?;
    if have == 0 {
        let tx = conn.transaction().map_err(map_db("reshape bindings"))?;
        tx.execute_batch(
            "ALTER TABLE folder_bindings RENAME TO folder_bindings_v7;
             CREATE TABLE folder_bindings (
               folder_id   TEXT PRIMARY KEY,
               source_uri  TEXT NOT NULL,
               recursive   INTEGER NOT NULL,
               auto_index  INTEGER NOT NULL,
               extensions  TEXT NOT NULL,
               hash_policy TEXT NOT NULL,
               bound_at    INTEGER NOT NULL,
               bound_by    BLOB NOT NULL DEFAULT x'',
               unbound_at  INTEGER
             );
             INSERT INTO folder_bindings
               (folder_id, source_uri, recursive, auto_index, extensions,
                hash_policy, bound_at, unbound_at)
             SELECT folder_id, source_uri, recursive, auto_index, extensions,
                    hash_policy, bound_at, unbound_at FROM folder_bindings_v7;
             DROP TABLE folder_bindings_v7;",
        )
        .map_err(map_db("add bound_by"))?;
        tx.commit().map_err(map_db("reshape bindings"))?;
    }
    let db = attach_name("");
    let tx = conn.transaction().map_err(map_db("migrate v8"))?;
    {
        // Ascending seq, so the newest FolderBound for a folder wins — the same
        // last-writer-wins the fold's upsert applies.
        let mut stmt = tx
            .prepare(&format!(
                "SELECT kind, body FROM {db}.events WHERE kind = ?1 ORDER BY seq"
            ))
            .map_err(map_db("read folder binds"))?;
        let rows = stmt
            .query_map(params![crate::event::K_FOLDER_BOUND], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_db("read folder binds"))?;
        for row in rows {
            let (kind, body) = row.map_err(map_db("read folder binds"))?;
            if let Event::FolderBound {
                folder_id, author, ..
            } = Event::decode(&kind, &body)?
            {
                tx.execute(
                    "UPDATE folder_bindings SET bound_by = ?1 WHERE folder_id = ?2",
                    params![author, folder_id],
                )
                .map_err(map_db("fill bound_by"))?;
            }
        }
    }
    tx.commit().map_err(map_db("migrate v8"))?;
    Ok(())
}

/// The scratch projection a rebuild is built into before it replaces the live
/// one. Left behind only by a process that died mid-rebuild, and removed by the
/// next one — the live cache is never the casualty.
fn rebuild_scratch(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("index.rebuild")
}

fn clear_scratch(data_dir: &std::path::Path) {
    let p = rebuild_scratch(data_dir);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", p.display()));
    }
}

/// A connection whose `main` IS the scratch file, with the forest's log
/// attached exactly as a real engine has it — so the replay code folds into the
/// scratch unmodified, with no qualified-name surgery.
fn open_scratch(data_dir: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(rebuild_scratch(data_dir)).map_err(map_db("open rebuild db"))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(map_db("busy timeout"))?;
    let log_path = data_dir.join("log.db").to_string_lossy().into_owned();
    conn.execute("ATTACH DATABASE ?1 AS log", params![log_path])
        .map_err(map_db("attach log.db"))?;
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(
        Some(rusqlite::DatabaseName::Attached("log")),
        "journal_mode",
        "WAL",
    );
    conn.execute_batch(crate::log_store::LOG_SCHEMA)
        .map_err(map_db("create log schema"))?;
    Ok(conn)
}

/// v8 → v9 (D71 W6): the label index identity matching needs. Pure DDL, so the
/// migration is instant on any size of forest — no replay, nothing to fill.
fn migrate_v8_to_v9(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_nodes_label ON nodes(label) WHERE node_type = 'file';",
    )
    .map_err(map_db("create idx_nodes_label"))
}

/// v9 → v10 (D72 Part B): links carry a label. Added EMPTY, deliberately — an
/// empty link label means "fall back to the node", which is exactly the
/// behaviour a forest had before this column existed. Nothing to back-fill,
/// so the migration is instant on any size of forest.
fn migrate_v9_to_v10(conn: &mut Connection) -> Result<()> {
    let have: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('links') WHERE name = 'label'",
            [],
            |r| r.get(0),
        )
        .map_err(map_db("inspect links"))?;
    if have == 0 {
        conn.execute_batch("ALTER TABLE links ADD COLUMN label TEXT NOT NULL DEFAULT '';")
            .map_err(map_db("add links.label"))?;
    }
    // temp_links carries the same attribute for the same reason; a temp link's
    // label never becomes an event (it is not durable), so this column is the
    // only place it can live. Guarded like `links` above: a migration must be
    // safe to meet a projection that already has the column.
    let have_temp: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('temp_links') WHERE name = 'label'",
            [],
            |r| r.get(0),
        )
        .map_err(map_db("inspect temp_links"))?;
    if have_temp == 0 {
        conn.execute_batch("ALTER TABLE temp_links ADD COLUMN label TEXT NOT NULL DEFAULT '';")
            .map_err(map_db("add temp_links.label"))?;
    }
    Ok(())
}

fn migrate_v15_to_v16(conn: &mut Connection) -> Result<()> {
    // D125 — additive. `kind` is appended, which is also where the fresh DDL
    // puts it, so the layout test's positional-copy invariant holds. Every
    // existing region is a 'log' region and stays one; nothing is re-read.
    // Guarded like v9→v10's `links.label`: a cache that already carries the
    // column (a test rewind, a half-applied bump) must not be sent through
    // the slow door by a duplicate-column error.
    let have: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('regions') WHERE name = 'kind'",
            [],
            |r| r.get(0),
        )
        .map_err(map_db("migrate v15→v16: probe regions.kind"))?;
    if have == 0 {
        conn.execute_batch("ALTER TABLE regions ADD COLUMN kind TEXT NOT NULL DEFAULT 'log';")
            .map_err(map_db("migrate v15→v16: regions.kind"))?;
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS region_entries (
           region_id    TEXT    NOT NULL,
           rel_path     TEXT    NOT NULL,
           kind         TEXT    NOT NULL,
           size_bytes   INTEGER NOT NULL,
           mtime_ms     INTEGER NOT NULL,
           changed_ms     INTEGER NOT NULL,   -- max(mtime, ctime) on THIS box: the D112 settle signal; never in the manifest
           content_hash TEXT,
           quality      TEXT,
           seen_at      INTEGER NOT NULL,
           PRIMARY KEY (region_id, rel_path)
         );
         CREATE TABLE IF NOT EXISTS region_snapshots (
           region_id     TEXT    NOT NULL,
           seq           INTEGER NOT NULL,
           manifest_hash TEXT    NOT NULL,
           entries       INTEGER NOT NULL,
           published_at  INTEGER NOT NULL,
           PRIMARY KEY (region_id, seq)
         );",
    )
    .map_err(map_db("migrate v15→v16"))?;
    Ok(())
}

fn migrate_v14_to_v15(conn: &mut Connection) -> Result<()> {
    // D112 — purely additive, like v13→v14: a new cache table, no existing row
    // touched. Starting empty is the RIGHT start: every file already held
    // nowhere gets its grace clock set on the next pass that sees it, rather
    // than being unlinked immediately on an upgrade.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS scan_unheld (
           file_id  TEXT PRIMARY KEY,
           since_ms INTEGER NOT NULL
         );",
    )
    .map_err(map_db("migrate v14→v15"))?;
    Ok(())
}

fn migrate_v13_to_v14(conn: &mut Connection) -> Result<()> {
    // D99 — purely additive: a new cache table, no existing row touched. The
    // mover simply starts empty on first run and refills as it learns.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS fetch_unfetchable (
           file_id  TEXT PRIMARY KEY,
           noted_at INTEGER NOT NULL
         );",
    )
    .map_err(map_db("migrate v13→v14"))?;
    Ok(())
}

fn migrate_v12_to_v13(conn: &mut Connection) -> Result<()> {
    // D81 — widen the key so one folder can have many roots. Rebuilt rather
    // than ALTERed: SQLite cannot change a primary key in place, and every
    // existing row is already valid under the wider key, so nothing is lost.
    let tx = conn.transaction().map_err(map_db("migrate v12→v13"))?;
    tx.execute_batch(
        "CREATE TABLE folder_bindings_new (
           folder_id   TEXT NOT NULL,
           source_uri  TEXT NOT NULL,
           recursive   INTEGER NOT NULL,
           auto_index  INTEGER NOT NULL,
           extensions  TEXT NOT NULL,
           hash_policy TEXT NOT NULL,
           bound_at    INTEGER NOT NULL,
           bound_by    BLOB NOT NULL DEFAULT x'',
           unbound_at  INTEGER,
           PRIMARY KEY (folder_id, source_uri)
         );
         INSERT INTO folder_bindings_new
           SELECT folder_id, source_uri, recursive, auto_index, extensions,
                  hash_policy, bound_at, bound_by, unbound_at
             FROM folder_bindings;
         DROP TABLE folder_bindings;
         ALTER TABLE folder_bindings_new RENAME TO folder_bindings;",
    )
    .map_err(map_db("migrate v12→v13"))?;
    tx.commit().map_err(map_db("migrate v12→v13"))?;
    Ok(())
}

fn migrate_v11_to_v12(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS media_quality (
           node_id TEXT PRIMARY KEY, quality TEXT NOT NULL,
           source TEXT NOT NULL, seq INTEGER NOT NULL);",
    )
    .map_err(map_db("create media_quality"))
}

fn migrate_v10_to_v11(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_links_label ON links(label) WHERE label <> '';",
    )
    .map_err(map_db("create idx_links_label"))
}

pub fn full_rebuild(
    conn: &mut Connection,
    data_dir: &std::path::Path,
    reason: &str,
) -> Result<ForestIdentity> {
    // F5.8: the WHOLE drop-and-replay under the exclusive fold lock — a
    // write landing between two replay segments moves the applied mark to
    // tip and this rebuild would conclude early, half-built (the D69 tear).
    let _folds = lock_folds(data_dir)?;
    // punch C: the post-upgrade/crash rebuild can run minutes on a grown
    // forest — say so instead of looking hung.
    // D71: say WHY. A bare "rebuilding" line cost hours of diagnosis when the
    // lab owner replayed a 59k-event log every ~25s — the message read as the
    // one-time upgrade path while it was actually recurring.
    eprintln!(
        "pvfs: rebuilding the index from the signed log — {reason} \
         (large forests take a few minutes)"
    );
    let identity = decode_genesis(conn)?;

    // D71 — BUILD BESIDE, THEN SWAP.
    //
    // This used to drop the live tables and replay into them, so for the whole
    // replay every reader — the daemon's read views included — saw an EMPTY
    // cache and answered from it. On a large forest that is minutes of a box
    // confidently returning nothing, and a crash mid-replay left a half-built
    // cache behind as the real one.
    //
    // The replay now happens in a scratch database beside the live one, and the
    // result lands in a SINGLE transaction. Readers see the old cache for the
    // whole rebuild and the new one after one commit — never a partial. A
    // process that dies mid-rebuild leaves only the scratch, which the next
    // rebuild clears; the live cache was never touched.
    clear_scratch(data_dir);
    let built = (|| -> Result<()> {
        let mut fresh = open_scratch(data_dir)?;
        create_schema(&fresh)?;
        replay_log(&mut fresh, data_dir, &identity, "", 0)?;
        // Verify BEFORE it can become the live cache: a forest that fails this
        // must not have its old cache replaced by the bad one.
        check_pending_moves(&fresh, data_dir)?;
        fresh.close().map_err(|(_, e)| map_db("close rebuild db")(e))
    })();
    if let Err(e) = built {
        clear_scratch(data_dir);
        return Err(e);
    }

    // The swap — DDL included, all inside ONE transaction.
    //
    // The live tables are dropped and recreated here rather than emptied,
    // because the shape we are replacing may not be the shape we are building:
    // a rebuild triggered by a schema bump finds the OLD columns, and a table
    // that reached v8 through the migration has `bound_by` appended last while
    // a freshly created one has it before `unbound_at`. Recreating both sides
    // from the one `INDEX_SCHEMA` makes the copy order-independent by
    // construction — `SELECT *` across two differently-ordered tables silently
    // maps the wrong columns onto each other, which is exactly how this was
    // found (a live 82k-event forest, `NOT NULL constraint failed:
    // folder_bindings.bound_by`).
    //
    // SQLite's DDL is transactional, so readers still see the old cache until
    // the commit and the new one after it — dropping inside the transaction
    // costs nothing in visibility.
    let scratch = rebuild_scratch(data_dir).to_string_lossy().into_owned();
    conn.execute("ATTACH DATABASE ?1 AS fresh", params![scratch])
        .map_err(map_db("attach rebuild db"))?;
    let swapped = (|| -> Result<()> {
        let tx = conn.transaction().map_err(map_db("swap projection"))?;
        for t in MAIN_OBJECTS {
            tx.execute_batch(&format!("DROP TABLE IF EXISTS main.{t};"))
                .map_err(map_db("swap: drop old table"))?;
        }
        tx.execute_batch(INDEX_SCHEMA)
            .map_err(map_db("swap: recreate schema"))?;
        for t in MAIN_OBJECTS {
            tx.execute_batch(&format!(
                "INSERT INTO main.{t} SELECT * FROM fresh.{t};"
            ))
            .map_err(map_db("swap projection table"))?;
        }
        tx.commit().map_err(map_db("swap projection"))
    })();
    let _ = conn.execute_batch("DETACH DATABASE fresh");
    clear_scratch(data_dir);
    swapped?;

    meta_set(conn, "clean_shutdown", "0")?;
    Ok(identity)
}

/// P7.2c pairing enforcement (doc 20 §2.5): after replay, a move half whose
/// counterpart never folded is corruption on an **owner** (it holds every
/// log, so the pair must be complete) and tolerated on a **replica** (the
/// counterpart may live in an unfetched region). A live commit authors both
/// halves in one transaction, so owners only hit this on tampering.
fn check_pending_moves(conn: &Connection, data_dir: &std::path::Path) -> Result<()> {
    if crate::replica::marker_path(data_dir).exists() {
        return Ok(());
    }
    let orphan: Option<(String, String)> = conn
        .query_row(
            "SELECT removed_link_id, node_id FROM pending_moves LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(map_db("pending moves check"))?;
    if let Some((link_id, node_id)) = orphan {
        return Err(PvfsError::Corruption {
            db: "log.db".into(),
            detail: format!(
                "cross-region move of {node_id} (link {link_id}) has only one \
                 half — its counterpart event is missing"
            ),
            seq: None,
        });
    }
    Ok(())
}

/// The §9.3 startup check. Runs on every open, after both files are attached.
/// Returns the forest identity on success.
/// Identity + schema gate for a **read-only view** (doc 07 §6). The primary
/// writer engine already ran [`startup_check`] — verification, self-heal,
/// replay — so a reader only confirms it speaks the current schema and decodes
/// the genesis identity. Any mismatch is a hard error: a read view cannot (and
/// must not) rebuild.
pub fn read_view_check(conn: &Connection) -> Result<ForestIdentity> {
    let version: u32 = meta_get(conn, "schema_version")?
        .unwrap_or_else(|| SCHEMA_VERSION.to_string())
        .parse()
        .unwrap_or(SCHEMA_VERSION);
    if version != SCHEMA_VERSION {
        return Err(PvfsError::SchemaVersion {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    decode_genesis(conn)
}

/// `others_alive`: another writer engine currently holds the forest (the
/// live-writer flock, P7.2c close-out) — `clean_shutdown = 0` then means "a
/// writer is live", not "the last writer crashed", so this open catches up
/// instead of force-rebuilding (and can never lose a minutes-long lock race
/// against the live writer's folds). Every OTHER rebuild trigger (structural
/// damage, schema change, agreement mismatch) is unchanged.
pub fn startup_check(
    conn: &mut Connection,
    data_dir: &std::path::Path,
    others_alive: bool,
) -> Result<ForestIdentity> {
    // Step 1 — structural check, now on the CRASH PATH ONLY.
    //
    // `PRAGMA quick_check` reads and verifies every page, so it costs time
    // proportional to the FOREST rather than to the work. Measured on a
    // 1.7 GB forest: 42s for log.db, 2m04s for index.db — essentially all of
    // a ~2m45s startup, and pure I/O wait (0.7s of user time in 124s). It ran
    // on every open, so every title added made every restart slower.
    //
    // What stands in for it:
    //   - **index.db is a pure, rebuildable cache** of the log — the same
    //     property the schema-version branch below already leans on. Auditing
    //     a derived cache page-by-page earns little when the recovery is
    //     "discard and replay", so the cheap probes below stand in and ANY
    //     failure routes to `full_rebuild`, exactly where the scan pointed.
    //   - **log.db is hash-chained**, and step 3 verifies the chain at the
    //     applied point (3b does it per region log). A cryptographic chain is
    //     a stronger statement than SQLite's structural check, so the scan
    //     only earns its cost where we already distrust the file: an unclean
    //     shutdown, where we are about to REPLAY the log and want to know it
    //     is sound before trusting it.
    // Tables must exist before the meta reads below — but a FAILURE here is
    // NOT an error to the caller, and it is not yet a rebuild either.
    //
    // `INDEX_SCHEMA` indexes columns that older projections do not have:
    // `idx_links_label` joined it with D72 (2026-08-19) while `links.label`
    // itself only arrives at v10. Applying the whole DDL to a v7 cache
    // therefore fails on that index, and nothing is wrong with the forest —
    // the cache is simply older than the shape being asked of it.
    //
    // This used to be `create_schema(conn)?`, so a pre-v10 cache could not be
    // opened AT ALL by a post-D72 binary: the daemon exited 1 and systemd
    // restart-looped it on `no such column: label`, which reads as corruption
    // rather than as an upgrade wanting its migration. Found 2026-09-08, the
    // first time the pipeline's daemon stage had run since 14 August — the
    // three weeks in between are how long a hard failure on the ONE path
    // nothing exercises can sit in a green tree.
    //
    // The DDL is re-applied below once the migration ladder has added the
    // columns it indexes, which keeps D71's cheap door open for exactly the
    // forest that needs it most: an old, large cache, where the alternative is
    // replaying the whole log. Every statement is `IF NOT EXISTS`, so a
    // partial application leaves nothing to undo. If the second attempt fails
    // too, this routes to `full_rebuild` like every other probe here.
    let schema_ddl = create_schema(conn);
    let clean = meta_get(conn, "clean_shutdown")?.unwrap_or_else(|| "1".into());
    let crashed = clean != "1" && !others_alive;
    if crashed && !quick_check(conn, "log")? {
        return Err(PvfsError::Corruption {
            db: "log.db".into(),
            detail: "PRAGMA quick_check failed".into(),
            seq: None,
        });
    }

    // The cheap index probes. A read that fails here means the cache is
    // unusable — which is a rebuild, never an error to the caller.
    let Ok(identity) = decode_genesis(conn) else {
        return full_rebuild(conn, data_dir, "genesis unreadable in the cache");
    };

    // Step 2 — positions. Mark first, tail second: the tail is then the
    // fresher read, so a concurrent append can only make `sl` larger, which is
    // the harmless direction (step 4 catches up).
    //
    // Ordering alone does NOT make the comparison trustworthy, though — see
    // `racing_writer` below.
    let (Ok((si, hi)), Ok(sl)) = (applied_get(conn, ""), log_store::max_seq(conn)) else {
        return full_rebuild(conn, data_dir, "log position unreadable in the cache");
    };

    // A live writer can legitimately show the applied mark AHEAD of the log
    // tail, and it is not a race we can read our way out of: `log.db` and
    // `index.db` are separate WAL databases, and **SQLite cannot commit across
    // databases atomically when any of them is in WAL mode**. A writer that has
    // just folded event N therefore publishes the mark and the log event in two
    // separate commits, and another connection opening in between sees the mark
    // lead the tail.
    //
    // Measured on the D69 fleet lab (D71): the mark led by EXACTLY 1, about
    // four times a minute for as long as a serve job wrote beside the daemon —
    // and each phantom cost a full replay of a 59,365-event log, forever. The
    // owner is the box that runs `tier`, so this was the fleet's mover
    // spending its life rebuilding a cache that was never wrong.
    //
    // At rest (no live writer) `si > sl` still means exactly what it always
    // meant — a truncated or swapped log — and still rebuilds.
    let racing_writer = others_alive && si > sl;

    let version: u32 = match meta_get(conn, "schema_version") {
        Ok(v) => v
            .unwrap_or_else(|| SCHEMA_VERSION.to_string())
            .parse()
            .unwrap_or(SCHEMA_VERSION),
        // A cache whose DDL would not apply AND whose version cannot be read is
        // past reasoning about. Rebuilding is always correct, and returning an
        // error to the caller here would be the bug above in a new place.
        Err(e) if schema_ddl.is_err() => {
            return full_rebuild(conn, data_dir, &format!("the cache schema is unreadable ({e})"))
        }
        Err(e) => return Err(e),
    };
    if version != SCHEMA_VERSION {
        // The projection is a pure, rebuildable cache of the log. An **older** schema
        // self-heals: drop the projection and replay under the current schema (doc 10
        // §6 — `full_rebuild` recreates `projection_meta`, so the version is reset to
        // current). A **newer** schema than this binary understands is a hard stop.
        if version > SCHEMA_VERSION {
            return Err(PvfsError::SchemaVersion {
                found: version,
                supported: SCHEMA_VERSION,
            });
        }
        // D71: try the cheap door first. An additive change migrates in place
        // (an ALTER plus a targeted pass) instead of replaying the whole log,
        // which is the difference between a blink and minutes of a box being
        // unavailable. Refusal is always safe — it just means the slow door.
        match migrate_projection(conn, data_dir, version) {
            Some(what) => {
                // The ladder has now added the columns `INDEX_SCHEMA` indexes,
                // so finish applying it. A genuine v7 cache arrives here with
                // `idx_links_label` still uncreated.
                if let Err(e) = create_schema(conn) {
                    return full_rebuild(
                        conn,
                        data_dir,
                        &format!("the migrated cache still does not fit this schema ({e})"),
                    );
                }
                eprintln!(
                    "pvfs: projection migrated v{version} → v{SCHEMA_VERSION} ({what}) \
                     — no replay needed"
                );
            }
            None => {
                return full_rebuild(conn, data_dir, "projection schema is older than this binary")
            }
        }
    } else if let Err(e) = schema_ddl {
        // Current version, and the DDL still will not apply: the cache claims a
        // shape it does not have, which no migration step covers.
        return full_rebuild(
            conn,
            data_dir,
            &format!("the cache does not match the schema it claims ({e})"),
        );
    }

    // Step 3 — verify the index agrees with the top log at its applied point.
    // Both halves are skipped while a writer is racing us: the event at `si`
    // is simply not visible on this connection yet, so neither the position
    // nor its chain hash can be checked, and step 4's tail fold picks it up
    // once it lands. Skipping a check we cannot perform is right; replaying
    // the whole projection because we cannot perform it is not.
    if si > sl && !racing_writer {
        return full_rebuild(
            conn,
            data_dir,
            &format!("applied mark ({si}) is ahead of the log tail ({sl})"),
        );
    }
    if si > 0 && !racing_writer {
        match log_store::read_event(conn, si)? {
            Some(row) if hex::encode(&row.chain_hash) == hi => {}
            _ => return full_rebuild(conn, data_dir, "applied mark disagrees with the log chain"),
        }
    }

    // Unclean shutdown forces a full agreement check (spec §9.3 crash flag) —
    // unless the "unclean" flag simply reflects a LIVE writer (see above).
    if crashed {
        return full_rebuild(conn, data_dir, "unclean shutdown with no live writer");
    }

    // Step 3b (P7.2a) — every active region log agrees with its applied mark:
    // a foreign append while we were closed must not linger unfolded, and a
    // truncated or swapped file must not pass silently.
    let mut behind = si < sl;
    let region_rows: Vec<(String, Option<String>)> = {
        let mut stmt = conn
            // D125 — a catalogue region has no event log to agree with; its
            // head is a manifest hash and lives in region_snapshots.
            .prepare("SELECT node_id, log_file FROM regions WHERE state_root IS NOT NULL AND kind = 'log'")
            .map_err(map_db("list regions"))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(map_db("list regions"))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("list regions"))?
    };
    for (rid, file) in region_rows {
        let (ra, rh) = applied_get(conn, &rid)?;
        let path = match file {
            Some(f) => data_dir.join(f),
            None => {
                if ra > 0 {
                    return full_rebuild(conn, data_dir, "a region has an applied mark but no log file");
                }
                continue;
            }
        };
        if !path.exists() {
            if ra > 0 {
                return full_rebuild(conn, data_dir, "a region log file is missing");
            }
            continue;
        }
        let rconn = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(map_db("open region log"))?;
        let rtip: u64 = rconn
            .query_row("SELECT IFNULL(MAX(seq),0) FROM events", [], |r| {
                r.get::<_, i64>(0)
            })
            .map(|v| v as u64)
            .unwrap_or(0);
        if rtip < ra {
            return full_rebuild(conn, data_dir, "a region log is shorter than its applied mark");
        }
        if ra > 0 {
            let chain: Option<Vec<u8>> = rconn
                .query_row(
                    "SELECT chain_hash FROM events WHERE seq = ?1",
                    params![ra as i64],
                    |r| r.get(0),
                )
                .optional()
                .map_err(map_db("read region chain"))?;
            match chain {
                Some(c) if hex::encode(&c) == rh => {}
                _ => return full_rebuild(conn, data_dir, "a region log disagrees with its applied mark"),
            }
        }
        if rtip > ra {
            behind = true;
        }
    }

    // Step 4 — catch up (tree replay walks every log from its applied mark).
    // A tail fold that FAILS is the cache lying (a projection torn by a
    // concurrent folder, a crash between checkpoint writes, …) — the same
    // class as every probe above, and it routes the same way: discard the
    // cache and replay the whole log. A genuinely bad LOG still refuses
    // loudly — full_rebuild replays every event through the identical
    // verification. Found live by the D69 fleet: a torn membership table
    // passed the position probes, then refused the forest's own device at
    // fold-apply ("author not authorized") and bricked the owner, while a
    // cold rebuild of the very same log was perfect.
    if behind {
        if let Err(e) = catch_up_tail(conn, data_dir, &identity) {
            eprintln!(
                "pvfs: incremental fold failed ({e}); discarding the projection \
                 cache and replaying the full log"
            );
            return full_rebuild(conn, data_dir, "incremental fold failed");
        }
    }
    Ok(identity)
}

/// The Step-4 tail fold, separated so `startup_check` can route ANY of its
/// failures to `full_rebuild` (the projection is a cache; its fold must
/// self-heal, never brick).
fn catch_up_tail(
    conn: &mut Connection,
    data_dir: &std::path::Path,
    identity: &ForestIdentity,
) -> Result<()> {
    // F5.8: exclusive with every other folder for the whole multi-segment
    // walk. The guard drops on return — a failure routed to `full_rebuild`
    // by the caller re-acquires there, sequentially.
    let _folds = lock_folds(data_dir)?;
    replay_log(conn, data_dir, identity, "", 0)?;
    check_pending_moves(conn, data_dir)?;
    // Actives whose baseline lives in a sealed generation are unreachable
    // from the tree walk once the seal is applied (the pause is in the
    // past) — sweep their tails directly. Order-free: an active region's
    // tail depends only on its own baseline + log.
    let actives: Vec<(String, String)> = {
        let mut stmt = conn
            .prepare(
                "SELECT node_id, log_file FROM regions
                 WHERE state_root IS NOT NULL AND log_file IS NOT NULL",
            )
            .map_err(map_db("list regions"))?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(map_db("list regions"))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(map_db("list regions"))?
    };
    for (rid, file) in actives {
        if !data_dir.join(&file).exists() {
            continue;
        }
        attach_log(conn, data_dir, &rid, &file)?;
        let res = replay_log(conn, data_dir, identity, &rid, 1);
        detach_log(conn, &rid)?;
        res?;
    }
    Ok(())
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
        // A realistic append stamp — clearly after any authorize/revoke the
        // test performed, since replay judges membership as-of `written_at`
        // (P7.2a, doc 20 §2.3).
        let t = crate::engine::now_ms() + 60_000;
        log_store::append_event(&tx, &prev, max + 1, ev, t).unwrap();
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
            &crate::event::msg_acl_set(&root, kind, &id, rights, t, 0, &member_pub),
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
                expires_at: 0,
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

    /// One-home invariant (spec §5.2): replay rejects a second active `contains`
    /// link for the same child if the first was never removed. A crafted or
    /// corrupted log that tries to give a node two homes must be detected at
    /// rebuild/replay even if both links pass signature and author checks.
    #[test]
    fn replay_rejects_double_home_link() {
        let dir = tempfile::tempdir().unwrap();
        let (mut engine, mnemonic) = Engine::init(dir.path()).unwrap();

        // Derive the device key so we can sign the forged link with an
        // authorized key (bypassing the UnknownAuthor check and reaching
        // the one-home invariant check).
        let device_key = identity::device_key(&mnemonic, "", 0).unwrap();
        let device_pub = crypto::pubkey_bytes(&device_key);

        // Add a child node and an alternative parent under root.
        let root = engine.identity.root_node_id.clone();
        let child_id = engine
            .add_node(
                &root,
                crate::engine::NodeSpec {
                    node_type: node::TYPE_FOLDER.into(),
                    label: "child".into(),
                    payload: node::folder_payload(),
                    is_temp: false,
                    creation_nonce: None,
                },
            )
            .unwrap();
        let alt_parent = engine
            .add_node(
                &root,
                crate::engine::NodeSpec {
                    node_type: node::TYPE_FOLDER.into(),
                    label: "alt".into(),
                    payload: node::folder_payload(),
                    is_temp: false,
                    creation_nonce: None,
                },
            )
            .unwrap();
        engine.close().unwrap();

        // Forge a second `contains` link placing `child` under `alt_parent`
        // *without* removing the first home link — one-home violation.
        let t = 3_000_000u64;
        let nonce = 99u64;
        let link_digest =
            link::compute_id_digest(Some(&alt_parent), &child_id, link::LINK_CONTAINS, nonce);
        let bad_link = link::Link {
            id: hex::encode(link_digest),
            parent_id: Some(alt_parent.clone()),
            child_id: child_id.clone(),
            link_type: link::LINK_CONTAINS.into(),
            link_nonce: nonce,
            order_key: "z".into(),
            created_at: t,
            author: device_pub.clone(),
            sig: crypto::sign_digest(&device_key, &link_digest).unwrap(),
            removed_at: None,
            superseded_by: None,
            suspended_at: None,
        };
        append_to_log(dir.path(), &Event::LinkCreated(bad_link));

        // Rebuild must detect the double-home as a Corruption error.
        let outcome = Engine::open(dir.path()).map(drop);
        assert!(
            matches!(outcome, Err(PvfsError::Corruption { .. })),
            "expected Corruption for double-home link, got {outcome:?}"
        );
    }
}
