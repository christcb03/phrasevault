# PVFS — P0 Core Engine Buildable Spec (02)

Status: **Draft for review — refine before coding**
Date: 2026-06-07
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md), [01-core-engine-design.md](01-core-engine-design.md)
Scope: The exact, buildable specification for **P0** — encodings, schemas, projection rules, identity, and function signatures. Every foundational decision is already settled (design doc §9); this turns them into something we can implement without guesswork.

> How to read this: each section is meant to be reviewed on its own. Nothing here is code yet. Where a detail is still genuinely open, it is called out as **[OPEN]** so we can settle it before building.

---

## 1. What P0 delivers

A library crate (the kernel) plus a thin CLI that can:

- Initialize a data directory (create `log.db` + `index.db`, derive identity).
- Create a tree (a root `folder` node).
- Add `file` / `folder` nodes (and the `temp` variant of either) under a parent.
- Link and remove links between nodes.
- Walk a tree in sibling order; fetch a node; list a parent's children.
- Verify a node/link (recompute id + check signature).
- List orphans; purge (explicit hard delete).

No storage-backend byte reading, no WASM, no search, no mount, no networking (those are P1+).

---

## 2. Project layout (Rust)

A workspace with a kernel library and a CLI binary that depends on it:

```
pvfs/
  Cargo.toml                 # workspace
  crates/
    pvfs-core/               # the kernel library (everything in this spec)
      src/
        lib.rs
        encoding.rs          # §3  canonical binary encoding (PCE)
        node.rs              # §4  Node type, id derivation, sign/verify
        link.rs              # §5  Link type, id derivation, order_key
        event.rs             # §6  Event enum + encode/decode
        log_store.rs         # §7  log.db (append-only events)
        projection.rs        # §8/§9 index.db schema + fold rules
        identity.rs          # §10 passphrase -> keypair
        engine.rs            # §11 public API (the facade)
        walk.rs              # §12 tree traversal
        error.rs             # §13 error type
    pvfs-cli/                # thin CLI over pvfs-core (P1 grows this)
      src/main.rs
```

Key dependencies (pinned later): `blake3`, `k256` (secp256k1 ECDSA), `argon2`, `rusqlite` (bundled SQLite), `thiserror`. No async in P0.

---

## 3. Canonical binary encoding (PCE)

Everything that gets hashed or stored as an event body is serialized with one deterministic scheme, **PVFS Canonical Encoding (PCE)**. One logical value has exactly one valid byte sequence — this is what makes ids reproducible across platforms and (in P2) across languages.

Primitive rules:

| Type | Encoding |
|---|---|
| `u64` | exactly 8 bytes, little-endian |
| `bool` | 1 byte: `0x00` false, `0x01` true |
| `bytes` | `u32` little-endian length prefix, then the raw bytes |
| `string` | UTF-8 bytes, encoded as `bytes` above (length-prefixed) |
| `option<T>` | `0x00` for none; `0x01` then `T` for some |

A composite value is the concatenation of its fields **in the fixed order given by its spec** — no field names, no separators, no padding. There is no map/dict type in any preimage (avoids key-ordering ambiguity).

> [OPEN] String length cap. Propose rejecting any `string`/`bytes` longer than `2^32 - 1` (the prefix limit) and adding a sane soft cap on `label` (e.g. 4 KiB) at the API layer.

---

## 4. Node

### 4.1 Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string (hex) | BLAKE3 of the preimage (§4.2). 32 bytes → 64 hex chars. |
| `node_type` | string | `"file"`, `"folder"`, or a module type `"<ns>.<name>"`. |
| `label` | string | display name (filename/folder name). |
| `visibility` | string | `"public"` in P0. Reserved for the secure module later. |
| `payload` | bytes | type-specific (§4.3). |
| `is_temp` | bool | temp lifecycle flag. |
| `created_at` | u64 | unix ms. |
| `author` | bytes | secp256k1 compressed public key, 33 bytes. |
| `sig` | bytes | signature over `id` (§4.4), 64 bytes. |

### 4.2 ID derivation (preimage field order)

```
preimage = PCE(
  node_type : string,
  label     : string,
  visibility: string,
  payload   : bytes,
  is_temp   : bool,
  created_at: u64,
  author    : bytes,      // 33-byte compressed pubkey
)
id = hex( BLAKE3_256(preimage) )
```

`id` excludes `sig` (you can't hash a signature of the thing you're hashing). Any change to any preimage field yields a different `id` — immutability is structural.

### 4.3 Base-type payloads

- **folder** — `payload` is PCE of `{ }` for P0 (empty byte string; reserved for later display metadata and the **folder-binding descriptor** that drives auto-indexing, see design doc §8.5).
- **file** — `payload` is PCE of:
  ```
  content_hash : string   // BLAKE3 hex of bytes, or "" if not yet hashed (lazy)
  size_bytes   : u64
  mime_type    : string
  original_name: string
  locations    : list<string>   // URIs; list = u32 count prefix, then each string
  ```
  P0 stores locations; resolving/reading them is P1.
- **temp** — not a payload shape; `is_temp = true` on a `file` or `folder` (or, later, a module node).

> [OPEN] Confirm the `file` payload field set for P0. `locations` could alternatively be modeled as separate child nodes later; for P0 inline is simpler.

### 4.4 Signing & verification

- **Sign:** `sig = secp256k1_ECDSA_sign(identityPrivKey, id_bytes)` where `id_bytes` is the 32-byte BLAKE3 digest (signed as a pre-hashed message, deterministic nonces per RFC 6979). Compact 64-byte `r||s`.
- **Verify:** recompute `id` from the stored fields; if it differs from the stored `id`, reject (tampered). Then check `sig` against `author` over `id_bytes`. Either failure ⇒ invalid.

---

## 5. Link

### 5.1 Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string (hex) | BLAKE3 of preimage (§5.2). |
| `parent_id` | option<string> | `none` ⇒ child is a tree root. |
| `child_id` | string | target node id. |
| `link_type` | string | `"contains"`, `"ref"`, or `"<module>.<name>"`. |
| `order_key` | string | per-parent sort key (§5.3). **Not** in the id preimage. |
| `created_at` | u64 | unix ms. |
| `author` | bytes | 33-byte pubkey. |
| `sig` | bytes | signature over `id`. |
| `removed_at` | option<u64> | mutable state band (projection only). |
| `superseded_by` | option<string> | mutable state band. |
| `suspended_at` | option<u64> | mutable state band. |

### 5.2 ID derivation

```
preimage = PCE(
  parent_id : option<string>,
  child_id  : string,
  link_type : string,
  created_at: u64,
)
id = hex( BLAKE3_256(preimage) )
```

Deliberately **excludes** `author`, `order_key`, and the state band:
- excluding `author` makes the same logical link dedupable across authors (idempotent);
- excluding `order_key` and the state band lets a link be reordered, removed, suspended, or superseded **without changing its identity**.

### 5.3 order_key

- An opaque sortable string. Children of a parent are listed by `ORDER BY order_key`.
- Insert-at-end: append a key greater than the current max for that parent.
- Insert-between: pick a key strictly between two neighbors (**fractional indexing** over a fixed alphabet).
- Carried in the `LinkCreated` event (durable, replicated). Changing it emits `LinkReordered` (§6).

> [OPEN] Pick the order_key alphabet/scheme. Propose Base62 fractional keys (digits+letters), midpoint between neighbors, with a documented rebalance fallback if keys get pathologically long. This can be a small isolated module with its own tests.

---

## 6. Events (the canonical truth)

Each durable change is one event. Event bodies are PCE-encoded and stored in `log.db` (§7). `kind` is a string; the body layout is fixed per kind.

| Kind | Body fields | Meaning |
|---|---|---|
| `NodeCreated` | full node record (all §4.1 fields incl. `sig`) | a durable node was created |
| `LinkCreated` | full link record incl. `order_key` (state band = none) | a durable link was created |
| `LinkRemoved` | `link_id: string`, `removed_at: u64`, `removed_by: bytes`, `removal_sig: bytes` | soft-remove a link |
| `LinkReordered` | `link_id: string`, `new_order_key: string`, `author: bytes`, `sig: bytes` | change sibling order |
| `LinkSuperseded` | `old_link_id: string`, `new_link_id: string` | mark a link replaced |
| `LinkSuspended` | `link_id: string`, `suspended_at: u64` | block (e.g. integrity) |
| `LinkUnsuspended` | `link_id: string` | clear suspension |
| `NodePurged` | `node_id: string`, `purged_at: u64` | hard-delete tombstone |

Notes:
- **Temp nodes/links never appear as events.** They exist only in `index.db` temp tables (§8). This is the whole point of the temp carve-out.
- `removal_sig` / reorder `sig` are signatures over a defined message so a remove/reorder is itself attributable (message layout specified in the build-out, e.g. `BLAKE3("pvfs:linkremoved:v1:" + link_id + removed_at)`).

> [OPEN] Confirm the signed-message layout for `LinkRemoved` / `LinkReordered`. Propose domain-separated BLAKE3 over the mutated fields.

---

## 7. log.db — the canonical store

Single SQLite file, WAL mode. One table:

```sql
CREATE TABLE events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,  -- total order of durable changes
  kind       TEXT NOT NULL,
  body       BLOB NOT NULL,                      -- PCE-encoded event (§6)
  chain_hash BLOB NOT NULL,                      -- tamper-evident hash chain (see below)
  written_at INTEGER NOT NULL
);
```

- **Append-only:** only `INSERT`. Rows are never updated or deleted in P0 (compaction is P4-adjacent).
- `seq` provides the authoritative total order used for replay and (later) replication.
- Idempotency: before appending `NodeCreated`/`LinkCreated`, the engine checks the projection for the id; re-creating an existing id is a no-op (no duplicate event).

### 7.1 Hash chain (tamper / corruption evidence)

Each event stores a rolling hash that binds it to all prior events:

```
chain_hash[seq] = BLAKE3( chain_hash[seq-1] || kind || body )
chain_hash[0]   = BLAKE3( "pvfs:log:v1" )      // genesis seed, before any event
```

Because every event's hash depends on the entire history before it, **any silently altered, dropped, or reordered event breaks the chain** from that point forward. This is what lets the startup check (§9.3) detect corruption rather than just "is the index behind." The chain also gives replication a cheap way to confirm two instances share the same prefix of history (P4).

---

## 8. index.db — the projection

Single SQLite file, WAL mode. Disposable: deletable and rebuildable from `log.db`.

```sql
-- Durable, projected from the log:
CREATE TABLE nodes (
  id          TEXT PRIMARY KEY,
  node_type   TEXT NOT NULL,
  label       TEXT NOT NULL,
  visibility  TEXT NOT NULL DEFAULT 'public',
  payload     BLOB NOT NULL,
  created_at  INTEGER NOT NULL,
  author      BLOB NOT NULL,
  sig         BLOB NOT NULL
);

CREATE TABLE links (
  id            TEXT PRIMARY KEY,
  parent_id     TEXT,                 -- NULL = tree root
  child_id      TEXT NOT NULL,
  link_type     TEXT NOT NULL,
  order_key     TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  author        BLOB NOT NULL,
  sig           BLOB NOT NULL,
  removed_at    INTEGER,
  superseded_by TEXT,
  suspended_at  INTEGER
);

-- Ephemeral, never logged or replicated (mirrors nodes/links shape):
CREATE TABLE temp_nodes ( /* same columns as nodes */ );
CREATE TABLE temp_links ( /* same columns as links */ );

-- Replay / integrity bookkeeping (key/value):
CREATE TABLE projection_meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
-- Required keys:
--   'last_applied_seq'        -> highest event seq folded into this projection
--   'last_applied_chain_hash' -> the log's chain_hash at last_applied_seq (hex)
--   'clean_shutdown'          -> '1' set on graceful close, '0' set on open (crash flag)
--   'schema_version'          -> projection schema version (for migrations)

CREATE INDEX idx_links_parent_order ON links(parent_id, order_key) WHERE removed_at IS NULL;
CREATE INDEX idx_links_child        ON links(child_id)             WHERE removed_at IS NULL;
CREATE INDEX idx_nodes_type         ON nodes(node_type);
CREATE INDEX idx_tlinks_parent_order ON temp_links(parent_id, order_key) WHERE removed_at IS NULL;
CREATE INDEX idx_tlinks_child        ON temp_links(child_id)             WHERE removed_at IS NULL;
```

The `(parent_id, order_key)` index is what makes the per-parent ordered walk fast at any scale (design doc §3.4).

---

## 9. Write protocol & projection fold

### 9.1 Atomic durable write

Both files are opened on one `rusqlite` connection with `log.db` ATTACHed, so a single transaction spans both:

```
BEGIN IMMEDIATE;
  -- compute chain_hash = BLAKE3(prev_chain_hash || kind || body)
  INSERT INTO log.events(kind, body, chain_hash, written_at) VALUES (...);  -- append truth
  <apply fold rules below to index tables>                                  -- update projection
  UPDATE projection_meta SET v = <new seq>     WHERE k='last_applied_seq';
  UPDATE projection_meta SET v = <chain_hash>  WHERE k='last_applied_chain_hash';
COMMIT;
```

If the process dies before COMMIT, neither side changed (atomic). If it dies after COMMIT, both are consistent and `last_applied_chain_hash` matches the log tail.

### 9.2 Fold rules (event → index mutation)

| Event | Index mutation |
|---|---|
| `NodeCreated` | `INSERT OR IGNORE INTO nodes(...)` |
| `LinkCreated` | `INSERT OR IGNORE INTO links(...)`, `removed_at/superseded_by/suspended_at = NULL` |
| `LinkRemoved` | `UPDATE links SET removed_at=? WHERE id=?` |
| `LinkReordered` | `UPDATE links SET order_key=? WHERE id=?` |
| `LinkSuperseded` | `UPDATE links SET superseded_by=? WHERE id=?` |
| `LinkSuspended` | `UPDATE links SET suspended_at=? WHERE id=?` |
| `LinkUnsuspended` | `UPDATE links SET suspended_at=NULL WHERE id=?` |
| `NodePurged` | `DELETE FROM nodes WHERE id=?` (links to/from it already removed) |

### 9.3 Startup integrity check & recovery

Run on **every** `Engine::open`, before serving any request. It is cheap on the happy path and self-healing otherwise. (Yes — this is the log↔index agreement check; it both catches "the index fell behind after a crash" and "something got corrupted or dropped.")

**Step 1 — structural check.** `PRAGMA quick_check` on both files.
- `index.db` unreadable/corrupt ⇒ discard it and go to **full rebuild** (Step 5). The index is disposable, so this is always safe.
- `log.db` unreadable/corrupt ⇒ this is the truth; do **not** improvise. Return a fatal `Corruption { db: "log.db", .. }` error telling the operator to restore from backup/replica. (See §16 open item on partial-log salvage.)

**Step 2 — read positions.**
- From `index.db`: `last_applied_seq` (`Si`), `last_applied_chain_hash` (`Hi`), `clean_shutdown`.
- From `log.db`: `MAX(seq)` (`Sl`) and the `chain_hash` at `Sl`.

**Step 3 — verify the index agrees with the log at its applied point.**
- Read the log row at `seq = Si`; if its `chain_hash != Hi`, the index and log disagree about shared history ⇒ **full rebuild** (Step 5).
- If `Si > Sl` (index ahead of the truth — only possible via corruption or a restored-older log) ⇒ **full rebuild**.

**Step 4 — catch up (normal post-crash path).**
- If `Si < Sl`: replay events `Si+1 .. Sl` through the fold rules, recomputing and **verifying `chain_hash` at each step**. If a recomputed chain hash ever disagrees with the stored one, the log is internally broken ⇒ fatal `Corruption { db: "log.db", seq }`.
- If `Si == Sl` and chains matched in Step 3: the projection is current — done (fast path, O(1)).

**Step 5 — full rebuild.** Drop and recreate the `index.db` schema; replay all events `1 .. Sl`, verifying the chain from the genesis seed (§7.1). Temp tables start empty (temp never survives a rebuild, by design). Set `clean_shutdown = 0`.

**Crash flag.** On successful open, set `clean_shutdown = 0`; on graceful `close()`, set it to `1`. If it was already `0` at open (previous run crashed), force the chain verification in Steps 3–4 even on the `Si == Sl` fast path, so an unclean shutdown always triggers a full agreement check rather than trusting positions alone.

**Optional deep verify.** A `verify_full` mode (CLI flag / periodic) rebuilds into a throwaway index and asserts it matches the live one, and re-verifies every node/link signature. Not run on every startup (cost), but available for paranoia / audits.

---

## 10. Identity (passphrase-derived)

```
salt    = BLAKE3_256("pvfs:identity:v1:" + passphrase)         // 32 bytes
seed    = Argon2id(password = passphrase, salt = salt,
                   m = 65536 KiB (64 MiB), t = 3, p = 1, out = 32 bytes)
privKey = secp256k1 scalar from seed
          (if seed >= curve order or == 0 — astronomically rare —
           re-derive with seed = BLAKE3(seed) and retry)
pubKey  = secp256k1 compressed public key (33 bytes)  // this is `author`
```

- Argon2id is memory-hard (64 MiB, 3 passes) so the long-term key resists brute force.
- The domain prefix `pvfs:identity:v1:` keeps this key separate from any future derived key.
- Same passphrase ⇒ same `author` on any machine ⇒ replication and recovery work.
- **Handling:** passphrase enters at startup (P1 decides UX: prompt/env/protected file); `privKey` is derived once and held in memory for signing; the passphrase reference is then dropped. Optionally cache `privKey` in the data dir mode `0600` to skip re-derivation on restart (cache, not source of truth).

> [OPEN] Confirm Argon2id parameters (64 MiB / t=3 / p=1). These match prior practice and are a sound default; raising memory increases brute-force cost but also startup time on low-RAM devices.

---

## 11. Engine API (the public facade)

Signatures are illustrative Rust; names/shape open to refinement. All fallible calls return `Result<_, PvfsError>` (§13).

```rust
pub struct Engine { /* holds the rusqlite connection, identity, etc. */ }

pub struct NodeSpec {            // caller-provided inputs; engine fills id/sig/created_at
    pub node_type: String,
    pub label: String,
    pub payload: Vec<u8>,        // already PCE-encoded for the type
    pub is_temp: bool,
}

impl Engine {
    // Open or create the data dir (log.db, index.db), derive identity, run recovery.
    pub fn open(data_dir: &Path, passphrase: &str) -> Result<Engine>;

    // Create a tree: makes a root folder node + a root link (parent_id = None).
    pub fn create_tree(&mut self, label: &str) -> Result<NodeId>;

    // Create a node under `parent`, ordered at end of parent's children.
    pub fn add_node(&mut self, parent: &NodeId, spec: NodeSpec) -> Result<NodeId>;

    // Add an explicit link (e.g. a `ref` cross-link).
    pub fn link(&mut self, parent: &NodeId, child: &NodeId,
                link_type: &str, order: Option<&OrderKey>) -> Result<LinkId>;

    pub fn remove_link(&mut self, link: &LinkId) -> Result<()>;  // triggers temp-purge check
    pub fn reorder_link(&mut self, link: &LinkId, new_key: &OrderKey) -> Result<()>;

    // Reads (served from the projection):
    pub fn get_node(&self, id: &NodeId) -> Result<Option<Node>>;
    pub fn children(&self, parent: &NodeId) -> Result<Vec<Node>>;     // ordered
    pub fn walk(&self, root: &NodeId) -> Result<TreeWalk>;            // ordered iterator
    pub fn verify(&self, id: &NodeId) -> Result<bool>;               // recompute id + sig

    // Lifecycle:
    pub fn list_orphans(&self) -> Result<Vec<Node>>;
    pub fn purge(&mut self, ids: &[NodeId]) -> Result<()>;           // explicit hard delete
}
```

`add_node` / `link` choose the durable-vs-temp path from `spec.is_temp` / the parent/child temp flag: temp writes hit only `temp_*` tables, durable writes go through §9.1.

---

## 12. Tree walk

- `children(parent)`: query the right table(s) — `links` and `temp_links` — `WHERE parent_id = ? AND removed_at IS NULL AND suspended_at IS NULL ORDER BY order_key`, resolve `child_id` to nodes, return in order.
- `walk(root)`: pre-order traversal. Visit root, then for each child in `order_key` order, recurse if it is a `folder` (or has children). Yields `(node, depth)`.
- A tree may mix durable and temp nodes; the walk reads both tables and merges by `order_key`.

> [OPEN] Cycle safety. `contains` links should form a DAG; the engine should refuse to create a `contains` link that would introduce a cycle (check that `child` is not an ancestor of `parent`). Confirm this guard for P0.

---

## 13. Errors — rock-solid, detailed, actionable

Error handling is a first-class part of the kernel, not an afterthought. The goals: **never panic on bad data or I/O, never lose the underlying cause, and every error carries enough context to act on** (which operation, which id, expected vs. actual, the source error).

### 13.1 Principles

- **No panics in library code on recoverable conditions.** No `unwrap()` / `expect()` / array-index panics on data, input, I/O, or DB results. `panic!` is reserved strictly for true internal invariant violations (bugs), and even those are documented. The CLI catches and renders errors; it never lets a panic escape as the user experience.
- **Typed, structured errors.** One `PvfsError` enum via `thiserror`. Variants carry **fields** (ids, seqs, offsets, expected/actual), not just strings.
- **Preserve the cause chain.** Wrap lower-level errors with `#[source]` / `#[from]` so the full chain (e.g. `Sqlite → Open log.db → Engine::open`) is available. The CLI prints the chain.
- **Distinguish recoverable vs. fatal.** Recoverable (bad input, not found, busy/locked, conflict) vs. fatal (log corruption, integrity break). Fatal errors say what to do (e.g. "restore log.db from backup").
- **Reads miss with `Ok(None)`/empty**, not errors. Errors are for exceptional/invalid states only.
- **Context at boundaries.** Use `tracing` to log the operation + key fields at each public entry point; the returned error stays machine-usable.

### 13.2 The error type (illustrative)

```rust
#[derive(Debug, thiserror::Error)]
pub enum PvfsError {
    #[error("I/O error during {op}: {source}")]
    Io { op: String, #[source] source: std::io::Error },

    #[error("database error during {op}: {source}")]
    Db { op: String, #[source] source: rusqlite::Error },

    #[error("SQLite is busy/locked during {op} (retried {retries}x)")]
    Busy { op: String, retries: u32 },

    #[error("canonical-encoding error in {what} at byte {offset}: {detail}")]
    Encoding { what: String, offset: usize, detail: String },

    #[error("{kind} not found: {id}")]
    NotFound { kind: &'static str, id: String }, // when an op REQUIRES it to exist

    #[error("integrity violation on {kind} {id}: {reason}")]
    // e.g. recomputed id != stored id, or signature failed
    Integrity { kind: &'static str, id: String, reason: IntegrityReason },

    #[error("log chain broken at seq {seq}: expected {expected}, got {actual}")]
    LogChainBroken { seq: u64, expected: String, actual: String },

    #[error("corruption in {db}: {detail} — restore from backup/replica")]
    Corruption { db: String, detail: String, seq: Option<u64> },

    #[error("cycle detected: linking {child} under {parent} would create a loop via {path}")]
    CycleDetected { parent: String, child: String, path: String },

    #[error("identity derivation failed: {detail}")]
    Identity { detail: String },

    #[error("invalid input for {field}: {reason}")]
    BadInput { field: String, reason: String }, // empty passphrase, oversized label, bad URI, ...

    #[error("schema version mismatch: store is v{found}, engine supports v{supported}")]
    SchemaVersion { found: u32, supported: u32 },
}

#[derive(Debug)]
pub enum IntegrityReason { IdMismatch { expected: String, actual: String },
                           SignatureInvalid,
                           UnknownAuthor }

pub type Result<T> = std::result::Result<T, PvfsError>;
```

### 13.3 Specific handling rules

- **Verification** (`verify`, and replay in §9.3) returns the precise failure: id-recompute mismatch reports expected vs. actual hash; signature failure is distinct from a missing/blocked node.
- **SQLite `BUSY`/`LOCKED`** is retried with bounded backoff; if it persists it surfaces as `Busy { retries }` rather than a raw driver error.
- **Encoding** failures report *which* field and *byte offset* failed to decode — invaluable for diagnosing a malformed event body.
- **Transactions** roll back on any error inside the write path (§9.1); a failed durable write never leaves a half-applied projection.
- **`Corruption` / `LogChainBroken`** are fatal and refuse to silently "fix" the truth log; they instruct recovery from backup/replica.

### 13.4 CLI surface

The CLI maps `PvfsError` to: a clear human message, the full `#[source]` cause chain, and a **distinct process exit code per category** (e.g. input error vs. not-found vs. corruption) so scripts can branch. `--json` emits the structured error (variant + fields) for tooling.

---

## 14. Test plan (built alongside, not after)

The kernel is fully testable with no I/O beyond temp dirs. Minimum P0 tests:

1. **Encoding determinism** — PCE of a value is byte-stable across runs; round-trips encode→decode.
2. **ID stability** — a fixed node/link input always yields the same id; changing any preimage field changes the id; changing `order_key`/state band does **not** change a link id.
3. **Sign/verify** — valid sig verifies; tampering payload (without re-id) is caught; wrong author fails.
4. **Identity determinism** — same passphrase ⇒ same pubkey; different passphrase ⇒ different.
5. **Projection fold** — each event kind produces the expected index state.
6. **Atomic write + recovery** — kill between append and project (simulated) leaves a consistent state; replay catches the projection up; full rebuild reproduces identical projection.
7. **Temp lifecycle** — temp node/link never produce events; temp purges immediately when only root-linked; rebuild drops temp; durable node cannot depend on temp.
8. **Walk order** — children come back in `order_key` order; insert-between lands in the right place; large-fanout walk uses the index (no full scan).
9. **Orphans/purge** — orphan detection correct; purge writes tombstone and removes from projection.
10. **Cycle guard** — creating a cycle via `contains` is rejected.
11. **Startup integrity check (§9.3)** — happy path is a no-op when positions/chains agree; an index lagging the log is caught up by replay; a corrupted/dropped/edited event breaks the chain and triggers full rebuild (or fatal `LogChainBroken` if the log itself is internally inconsistent); an unclean `clean_shutdown` flag forces a full agreement check; a corrupt `index.db` is rebuilt from the log.
12. **Error contract** — verification reports expected-vs-actual; encoding errors report field + offset; SQLite BUSY retries then surfaces `Busy`; a failed durable write rolls back leaving no half-applied projection; no panic on malformed input/data.

---

## 15. Out of scope for P0 (reaffirmed)

Storage-backend byte reads (P1), WASM module host (P2), search/serve/HTTP (P3), native mount, remote/peer backends, sync/replication, and log compaction (P4). The spec is structured so none of these require revisiting the data model.

Two P1 contracts are already settled (design doc §6.3 and §8.5) so the P0 model accommodates them without change: the **managed-temp spool + startup cleanup sweep** (prevents orphaned temp bytes on disk after a crash/rebuild), and **bound-folder auto-indexing** (live watcher + reconciliation scan; new files indexed as pointers; soft-remove when a tracked file is deleted on disk).

---

## 16. Open items to settle before coding

These are the **[OPEN]** flags above, collected:

1. §3 — string/bytes length caps (and a `label` soft cap).
2. §4.3 — confirm the `file` payload field set for P0 (inline `locations` vs child nodes).
3. §5.3 — order_key scheme (propose Base62 fractional indexing + rebalance fallback).
4. §6 — signed-message layout for `LinkRemoved` / `LinkReordered`.
5. §10 — Argon2id parameters (propose 64 MiB / t=3 / p=1).
6. §12 — confirm the cycle guard on `contains` links for P0.
7. §9.3 — policy when `log.db` itself is corrupt (chain broken / unreadable): propose **salvage up to the last valid seq** and stop with a fatal error requiring explicit operator action (rather than auto-truncating the truth). Confirm.

Once these six are agreed, this becomes the implementation checklist and coding can begin.
