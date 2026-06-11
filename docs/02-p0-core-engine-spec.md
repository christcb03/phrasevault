# PVFS — P0 Core Engine Buildable Spec (02)

Status: **Ready to implement** (all §16 decisions settled)
Date: 2026-06-07
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md), [01-core-engine-design.md](01-core-engine-design.md), [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md)
Scope: The exact, buildable specification for **P0** — encodings, schemas, projection rules, identity, and function signatures. Every foundational decision is already settled (design doc §9); this turns them into something we can implement without guesswork.

> How to read this: each section is meant to be reviewed on its own. Nothing here is code yet. Pre-coding decisions are marked **Decided**; the checklist in §16 is complete.

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

> **Decided:** Hard cap any PCE `string`/`bytes` at **`2^32 - 1` bytes** — this is the u32 length-prefix limit in the encoding itself, not an extra arbitrary ceiling. Soft cap **`label` at 4 KiB** at the API layer. There is no practical drawback at this limit: metadata fields and URIs are tiny, and file *content* is never embedded in PCE (only hashes and pointers). Nothing in PVFS needs a single multi-gigabyte string field; large blobs live on storage backends and are referenced by hash/URI.

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
| `creation_nonce` | u64 | disambiguates same-ms creates (§4.2); API-supplied or engine-random. |
| `created_at` | u64 | unix ms (audit/display; part of id preimage). |
| `author` | bytes | secp256k1 compressed public key, 33 bytes. |
| `sig` | bytes | signature over `id` (§4.4), 64 bytes. |

### 4.2 ID derivation (preimage field order)

```
preimage = PCE(
  node_type      : string,
  label          : string,
  visibility     : string,
  payload        : bytes,
  is_temp        : bool,
  creation_nonce : u64,
  created_at     : u64,
  author         : bytes,      // 33-byte compressed pubkey
)
id = hex( BLAKE3_256(preimage) )
```

> **Decided:** `creation_nonce` prevents distinct nodes from colliding when all other fields match in the same millisecond. **`add_node`** returns `AlreadyExists` if the id exists with different content; identical replay/sync is idempotent (§7, §11).

`id` excludes `sig` (you can't hash a signature of the thing you're hashing). Any change to any preimage field yields a different `id` — immutability is structural.

### 4.3 Base-type payloads

- **folder** — `payload` is PCE of `{ }` for P0 (empty byte string; reserved for later display metadata and the **folder-binding descriptor** that drives auto-indexing, see design doc §8.5).
- **file** — `payload` is PCE of:
  ```
  content_hash : string   // BLAKE3 hex of bytes, or "" if not yet hashed (lazy)
  size_bytes   : u64
  mime_type    : string
  original_name: string
  ```
  **Locations are not in the payload or id preimage.** A file's identity (content hash + metadata) is separate from where its bytes live (ADR principle). Storage URIs are added/removed via **`FileLocationAdded` / `FileLocationRemoved` events** (§6), which replicate independently — a new replica is just another signed location event, not a new file node.
- **temp** — not a payload shape; `is_temp = true` on a `file` or `folder` (or, later, a module node). Temp file locations follow the same event shape but are written only to `temp_*` projection tables (never logged).

> **Decided:** Multiple locations per file from P0, via location events (not inline in the node payload). This matches replication (add URI without changing `file` node id) and soft-remove of individual replicas/locations.

### 4.4 Signing & verification

- **Sign:** `sig = secp256k1_ECDSA_sign(identityPrivKey, id_bytes)` where `id_bytes` is the 32-byte BLAKE3 digest (signed as a pre-hashed message, deterministic nonces per RFC 6979). Compact 64-byte `r||s`.
- **Verify:** recompute `id` from the stored fields; if it differs from the stored `id`, reject (tampered). Then check `sig` against `author` over `id_bytes`. Either failure ⇒ invalid.
- **Low-s:** reject signatures with `s` above half the curve order (anti-malleability). Required on all verify paths.

---

## 5. Link

### 5.1 Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string (hex) | BLAKE3 of preimage (§5.2). |
| `parent_id` | option<string> | `none` ⇒ child is a tree root. |
| `child_id` | string | target node id. |
| `link_type` | string | `"contains"`, `"ref"`, or `"<module>.<name>"`. |
| `link_nonce` | u64 | disambiguates multiple edges with same `(parent, child, type)`; default `0`. |
| `order_key` | string | per-parent sort key (§5.3). **Not** in the id preimage. |
| `created_at` | u64 | unix ms (audit; **not** in id preimage). |
| `author` | bytes | 33-byte pubkey. |
| `sig` | bytes | signature over `id`. |
| `removed_at` | option<u64> | mutable state band (projection only). |
| `superseded_by` | option<string> | mutable state band. |
| `suspended_at` | option<u64> | mutable state band. |

### 5.2 ID derivation

```
preimage = PCE(
  parent_id  : option<string>,
  child_id   : string,
  link_type  : string,
  link_nonce : u64,
)
id = hex( BLAKE3_256(preimage) )
```

Deliberately **excludes** `author`, `created_at`, `order_key`, and the state band:
- **Logical link id** — replaying the same edge from an owner log onto a replica yields the same id (idempotent sync);
- excluding `order_key` and the state band lets a link be reordered, removed, suspended, or superseded **without changing its identity**.

### 5.3 order_key

- An opaque sortable string. Children of a parent are listed by `ORDER BY order_key`.
- Insert-at-end: append a key greater than the current max for that parent.
- Insert-between: pick a key strictly between two neighbors (**fractional indexing** over a fixed alphabet).
- Carried in the `LinkCreated` event (durable, replicated). Changing it emits `LinkReordered` (§6).

> **Decided:** **Base62 fractional keys** (digits + upper/lowercase letters — pick one fixed alphabet and document it). Insert-at-end: append a key greater than the current max for that parent. Insert-between: midpoint between neighbors. If keys grow pathologically long, **rebalance** that parent's keys in one transaction (re-emit `LinkReordered` for affected links). Implement as a small isolated module with its own tests.

---

## 6. Events (the canonical truth)

Each durable change is one event. Event bodies are PCE-encoded and stored in `log.db` (§7). `kind` is a string; the body layout is fixed per kind.

| Kind | Body fields | Meaning |
|---|---|---|
| `NodeCreated` | full node record (all §4.1 fields incl. `sig`) | a durable node was created |
| `LinkCreated` | full link record incl. `order_key` (state band = none) | a durable link was created |
| `LinkRemoved` | `link_id: string`, `removed_at: u64`, `removed_by: bytes`, `removal_sig: bytes` | soft-remove a link |
| `LinkReordered` | `link_id: string`, `new_order_key: string`, `author: bytes`, `sig: bytes` | change sibling order |
| `LinkSuperseded` | `old_link_id: string`, `new_link_id: string`, `author: bytes`, `sig: bytes` | mark a link replaced |
| `LinkSuspended` | `link_id: string`, `suspended_at: u64`, `author: bytes`, `sig: bytes` | block (e.g. integrity) |
| `LinkUnsuspended` | `link_id: string`, `author: bytes`, `sig: bytes` | clear suspension |
| `FileLocationAdded` | `file_id: string`, `uri: string`, `added_at: u64`, `author: bytes`, `sig: bytes` | register a storage URI for a file node |
| `FileLocationRemoved` | `file_id: string`, `uri: string`, `removed_at: u64`, `removed_by: bytes`, `removal_sig: bytes` | soft-remove one URI from a file |
| `NodePurged` | `node_id: string`, `purged_at: u64`, `author: bytes`, `sig: bytes` | hard-delete tombstone |

Notes:
- **Temp nodes/links/locations never appear as events.** They exist only in `index.db` temp tables (§8). This is the whole point of the temp carve-out.
- Signed messages for mutable operations use domain-separated BLAKE3 preimages (signed with secp256k1 over the 32-byte digest, same as nodes/links):

| Operation | Message signed (`msg = BLAKE3(...)`) |
|---|---|
| `LinkRemoved` | `"pvfs:linkremoved:v1:" \|\| PCE(link_id, removed_at, removed_by)` |
| `LinkReordered` | `"pvfs:linkreordered:v1:" \|\| PCE(link_id, new_order_key, author)` |
| `LinkSuperseded` | `"pvfs:linksuperseded:v1:" \|\| PCE(old_link_id, new_link_id, author)` |
| `LinkSuspended` | `"pvfs:linksuspended:v1:" \|\| PCE(link_id, suspended_at, author)` |
| `LinkUnsuspended` | `"pvfs:linkunsuspended:v1:" \|\| PCE(link_id, author)` |
| `FileLocationAdded` | `"pvfs:filelocationadded:v1:" \|\| PCE(file_id, uri, added_at, author)` |
| `FileLocationRemoved` | `"pvfs:filelocationremoved:v1:" \|\| PCE(file_id, uri, removed_at, removed_by)` |
| `NodePurged` | `"pvfs:nodepurged:v1:" \|\| PCE(node_id, purged_at, author)` |

> **Decided:** every mutable event is signed. Replicas and replay **reject** events that fail signature verification. See [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md) §3.

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
- `seq` provides the **local total order** for this forest's log (one write leader per forest; see [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md)).
- **Idempotency (replay/sync):** before appending `NodeCreated`/`LinkCreated`, if the projection already contains the id with identical content, skip append (no-op). On replay, `INSERT OR IGNORE` into projection.
- **Idempotency (API):** `add_node` / `link` return **`AlreadyExists { id }`** if the id exists with **different** content; return **`Ok(id)`** if bytes match exactly. Never report success for a distinct create that was silently dropped.

### 7.1 Hash chain (tamper / corruption evidence)

Each event stores a rolling hash that binds it to all prior events:

```
chain_hash[seq] = BLAKE3( chain_hash[seq-1] || PCE(seq, kind, body, written_at) )
chain_hash[0]   = BLAKE3( "pvfs:log:v1" )      // genesis seed, before any event
```

Because every event's hash depends on the entire history before it, **any silently altered, dropped, or reordered event breaks the chain** from that point forward. This is what lets the startup check (§9.3) detect corruption rather than just "is the index behind." For **replicas**, prefix chain comparison verifies an exact copy of the **owner forest's** history — not multi-writer merge ([03-federation-trust-and-uris.md](03-federation-trust-and-uris.md) §4).

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

-- Storage URIs for file nodes (projected from FileLocation* events; NOT in node payload):
CREATE TABLE file_locations (
  file_id     TEXT NOT NULL,
  uri         TEXT NOT NULL,
  added_at    INTEGER NOT NULL,
  removed_at  INTEGER,                 -- NULL = active
  PRIMARY KEY (file_id, uri)
);

-- Ephemeral, never logged or replicated (mirrors nodes/links/locations shape):
CREATE TABLE temp_nodes ( /* same columns as nodes */ );
CREATE TABLE temp_links ( /* same columns as links */ );
CREATE TABLE temp_file_locations ( /* same columns as file_locations */ );

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
--   'instance_id'             -> owner instance id for this data dir (P0: one owned forest)
--   'forest_id'               -> forest id on the owner (UUID or slug)
--   'forest_root_node_id'     -> canonical root node id of the primary tree

CREATE INDEX idx_links_parent_order ON links(parent_id, order_key) WHERE removed_at IS NULL;
CREATE INDEX idx_links_child        ON links(child_id)             WHERE removed_at IS NULL;
CREATE INDEX idx_nodes_type         ON nodes(node_type);
CREATE INDEX idx_file_locations_file ON file_locations(file_id) WHERE removed_at IS NULL;
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
  -- compute chain_hash = BLAKE3(prev_chain_hash || PCE(seq, kind, body, written_at))
  INSERT INTO log.events(seq, kind, body, chain_hash, written_at) VALUES (...);  -- seq from AUTOINCREMENT
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
| `FileLocationAdded` | `INSERT OR IGNORE INTO file_locations(...)`, `removed_at = NULL` |
| `FileLocationRemoved` | `UPDATE file_locations SET removed_at=? WHERE file_id=? AND uri=?` |
| `NodePurged` | `DELETE FROM nodes WHERE id=?`; `DELETE FROM file_locations WHERE file_id=?` |

### 9.3 Startup integrity check & recovery

Run on **every** `Engine::open`, before serving any request. It is cheap on the happy path and self-healing otherwise. (Yes — this is the log↔index agreement check; it both catches "the index fell behind after a crash" and "something got corrupted or dropped.")

**Step 1 — structural check.** `PRAGMA quick_check` on both files.
- `index.db` unreadable/corrupt ⇒ discard it and go to **full rebuild** (Step 5). The index is disposable, so this is always safe.
- `log.db` unreadable/corrupt or chain broken ⇒ **stop** (Step 6). Do not auto-truncate or silently repair the truth log.

**Step 2 — read positions.**
- From `index.db`: `last_applied_seq` (`Si`), `last_applied_chain_hash` (`Hi`), `clean_shutdown`.
- From `log.db`: `MAX(seq)` (`Sl`) and the `chain_hash` at `Sl`.

**Step 3 — verify the index agrees with the log at its applied point.**
- Read the log row at `seq = Si`; if its `chain_hash != Hi`, the index and log disagree about shared history ⇒ **full rebuild** (Step 5).
- If `Si > Sl` (index ahead of the truth — only possible via corruption or a restored-older log) ⇒ **full rebuild**.

**Step 4 — catch up (normal post-crash path).**
- If `Si < Sl`: replay events `Si+1 .. Sl` through the fold rules, recomputing and **verifying `chain_hash` at each step**. If a recomputed chain hash ever disagrees with the stored one, the log is internally broken ⇒ fatal `Corruption { db: "log.db", seq }` → **Step 6** (operator recovery).
- If `Si == Sl` and chains matched in Step 3: the projection is current — done (fast path, O(1)).

**Step 5 — full rebuild.** Drop and recreate the `index.db` schema; replay all events `1 .. Sl`, verifying the chain from the genesis seed (§7.1). Temp tables start empty (temp never survives a rebuild, by design). Set `clean_shutdown = 0`.

**Crash flag.** On successful open, set `clean_shutdown = 0`; on graceful `close()`, set it to `1`. If it was already `0` at open (previous run crashed), force the chain verification in Steps 3–4 even on the `Si == Sl` fast path, so an unclean shutdown always triggers a full agreement check rather than trusting positions alone.

**Optional deep verify.** A `verify_full` mode (CLI flag / periodic) rebuilds into a throwaway index and asserts it matches the live one, and re-verifies every node/link signature. Not run on every startup (cost), but available for paranoia / audits.

**Step 6 — operator recovery when `log.db` is corrupt (never automatic).**

When Step 1 or Step 4 detects log corruption (`Corruption` / `LogChainBroken`), the engine **refuses to open** and returns a fatal error listing recovery options in order of preference. The operator chooses explicitly; nothing destructive runs without confirmation:

| Priority | Action | History preserved? |
|---|---|---|
| 1 | **Restore from backup** — replace `log.db` (and optionally `index.db`) from a known-good backup, then reopen | Yes (to backup point) |
| 2 | **Restore from replica** (P4) — pull events from a peer instance that shares a valid prefix | Yes (merged from peer) |
| 3 | **Salvage prefix** — explicit `--salvage-log --up-to-seq N` after operator verifies the last good event; truncates tail only | Partial (prefix only) |
| 4 | **Filesystem rebuild** — explicit `--recover-from-filesystem <bound-folder>…` as **last resort**: scan bound folders on disk, create a fresh tree with new file nodes + `FileLocationAdded` events; archives or replaces the corrupted log | **No** — prior log history is lost |

Filesystem rebuild requires a strong confirmation phrase (similar to factory reset). It is for catastrophic loss when backups and replicas are unavailable — the tree can be reconstructed from what still exists on disk, but signatures, cross-links, module metadata, and historical events are gone unless recovered elsewhere.

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

> **Decided:** Argon2id **64 MiB / t=3 / p=1** — memory-hard default suitable for desktop/server; ~1–2 s derivation on typical hardware.

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
    pub creation_nonce: u64,     // 0 = let engine assign random if caller doesn't care
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
                link_type: &str, order: Option<&OrderKey>,
                link_nonce: u64) -> Result<LinkId>;

    pub fn remove_link(&mut self, link: &LinkId) -> Result<()>;  // triggers temp-purge check
    pub fn reorder_link(&mut self, link: &LinkId, new_key: &OrderKey) -> Result<()>;

    // File locations (separate from node id; supports multiple URIs + replication):
    pub fn add_location(&mut self, file: &NodeId, uri: &str) -> Result<()>;
    pub fn remove_location(&mut self, file: &NodeId, uri: &str) -> Result<()>;  // soft-remove
    pub fn locations(&self, file: &NodeId) -> Result<Vec<String>>;               // active URIs only

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

> **Decided:** **Cycle guard in P0.** Before creating a `contains` link (`parent → child`), walk ancestors of `parent`; reject if `child` is already an ancestor (would create a loop). Applies only to `link_type = "contains"`, not to `ref` cross-links.

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

    #[error("corruption in {db}: {detail} — see recovery options (backup, replica, salvage, filesystem rebuild)")]
    Corruption { db: String, detail: String, seq: Option<u64> },

    #[error("cycle detected: linking {child} under {parent} would create a loop via {path}")]
    CycleDetected { parent: String, child: String, path: String },

    #[error("identity derivation failed: {detail}")]
    Identity { detail: String },

    #[error("invalid input for {field}: {reason}")]
    BadInput { field: String, reason: String }, // empty passphrase, oversized label, bad URI, ...

    #[error("{kind} already exists: {id}")]
    AlreadyExists { kind: &'static str, id: String }, // API create when id taken by different content

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
- **`Corruption` / `LogChainBroken`** are fatal and refuse to silently "fix" the truth log; they print the **Step 6 recovery ladder** (§9.3) and require explicit operator action.

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
11. **Startup integrity check (§9.3)** — happy path is a no-op when positions/chains agree; an index lagging the log is caught up by replay; a corrupted/dropped/edited event breaks the chain and triggers full rebuild (or fatal `LogChainBroken` / Step 6 recovery ladder if the log itself is internally inconsistent); an unclean `clean_shutdown` flag forces a full agreement check; a corrupt `index.db` is rebuilt from the log.
12. **Error contract** — verification reports expected-vs-actual; encoding errors report field + offset; SQLite BUSY retries then surfaces `Busy`; a failed durable write rolls back leaving no half-applied projection; no panic on malformed input/data.
13. **File locations** — add two URIs to one file node (two events); file node id unchanged; soft-remove one URI; replication scenario = second instance applies same `FileLocationAdded` events.
14. **Recovery ladder** — corrupt log refuses open with recovery options listed; `--salvage-log` and `--recover-from-filesystem` require explicit confirmation and produce expected outcomes (filesystem rebuild creates fresh tree, history not preserved).
15. **Signed mutable events** — all mutable event kinds verify; unsigned/tampered events fail replay and replica import.
16. **Link logical id** — same `(parent, child, type, link_nonce)` replays to same link id without `created_at` in preimage.
17. **Node creation_nonce** — distinct nodes never collide silently; API returns `AlreadyExists` on conflict.
18. **PVFS URI parse** — canonical and shorthand forms from [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md) §2.2 round-trip parse (no network fetch in P0).

---

## 15. Out of scope for P0 (reaffirmed)

Storage-backend byte reads (P1), WASM module host (P2), search/serve/HTTP (P3), native mount, remote/peer backends, **forest replica sync + remote append RPC** (P4), and log compaction (P4-adjacent). Federation **ownership model, URI grammar, and trust rules** are decided in [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md); P0 implements trust fixes and metadata hooks so P4 does not revisit encodings.

Two P1 contracts are already settled (design doc §6.3 and §8.5) so the P0 model accommodates them without change: the **managed-temp spool + startup cleanup sweep** (prevents orphaned temp bytes on disk after a crash/rebuild), and **bound-folder auto-indexing** (live watcher + reconciliation scan; new files indexed as pointers; soft-remove when a tracked file is deleted on disk).

---

## 16. Pre-coding checklist — all settled

All items below are **decided**; this spec is ready to implement:

1. §3 — PCE hard cap at u32 max length; **4 KiB** soft cap on `label`.
2. §4.3 / §6 — file identity excludes locations; **multiple URIs via `FileLocationAdded` / `FileLocationRemoved` events**.
3. §5.2 — **logical link id** `(parent, child, type, link_nonce)`; `created_at` not in preimage.
4. §4.2 — **`creation_nonce`** on nodes; API **`AlreadyExists`** vs idempotent replay.
5. §5.3 — **Base62 fractional `order_key`** + rebalance fallback.
6. §6 — **all mutable events signed** (table in §6).
7. §7.1 — **chain binds `seq`, `kind`, `body`, `written_at`**; one write leader per forest log.
8. §10 — Argon2id **64 MiB / t=3 / p=1**; **low-s** enforced on verify.
9. §12 — **`contains` cycle guard** in P0.
10. §9.3 Step 6 — log corruption: **stop**; recovery ladder (backup → replica → salvage → filesystem rebuild last).
11. [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md) — forest ownership, sync modes, **PVFS URI grammar**, P0/P4 split.

**Outstanding (not blocking P0):** see [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md) §6.
