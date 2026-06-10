# PVFS — Core Engine (Kernel) Design (01)

Status: **Draft for review — design only, no implementation yet**
Date: 2026-06-07
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md)
Scope: Phase **P0**, the first thing we build — the core engine that everything else plugs into.

---

## 1. Why this is the first thing we build

The core engine has no upward dependencies. The storage backends (P1) operate on its nodes; the WASM module host (P2) is meaningless until nodes, links, signing, and the catalog exist. It also pins down the data model and the trust guarantees the whole system rests on, so it is the right place to be most careful.

Guiding directive: **correct, solid architecture over speed to production.**

### In scope for P0

- The data model: **node**, **link**, and the per-parent **sibling order**.
- The three base node types: **file**, **folder**, **temp**.
- Content addressing (BLAKE3) and signing/verification (secp256k1).
- The persistence layer (SQLite catalog) and how records are written.
- Tree construction and the ordered **walk** (parent→child + sibling order).
- The lifecycle rules: soft-delete, orphan detection, and immediate **temp** purge.
- The local **identity** keypair used to sign what this instance creates.
- The internal engine API surface that the CLI (P1) and module host (P2) will call.

### Explicitly out of scope for P0 (later phases)

- Reading/resolving actual file bytes from storage backends → **P1**.
- The WASM module host and module ABI → **P2**.
- Search indexing/dispatch, serve/stream, HTTP adapter → **P3**.
- Native mount, remote/peer backends, sync/replication → **P4**.

---

## 2. Source of truth — DECIDED

**Decision: an append-only event log is the canonical source of truth. SQLite is a rebuildable projection (index) derived from the log. Temp data is the deliberate exception — it lives only in SQLite and is never written to the log.**

### The model

- Every durable change is recorded as an immutable **event** appended to the log: `NodeCreated`, `LinkCreated`, `LinkRemoved`, `LinkSuperseded`, `LinkSuspended`, `NodePurged`. History is never edited — even a removal is a new event. The log itself is stored as an append-only `events` table in its own SQLite file (`log.db`), so we get crash-safety for free (see §5).
- **The projection is a second SQLite file (`index.db`).** It is built by replaying the log and folding events into current state. It can be deleted and fully regenerated at any time; it is a cache for fast queries, not the truth.
- Because nodes and links are immutable and content-addressed, the log is conflict-free to replicate later (P4): syncing is just shipping events between instances.
- The log is **tamper-evident**: each event carries a rolling hash chained to all prior events, so any dropped, reordered, or altered event is detectable. On every startup the engine verifies the projection agrees with the log and rebuilds it from the log if they diverge (e.g. after a crash or corruption). See spec [02-p0-core-engine-spec.md](02-p0-core-engine-spec.md) §7.1 and §9.3.

This is the most robust foundation and makes the hardest future feature — multi-instance sync — nearly free. It matches the project directive (correct, solid architecture over speed).

### The temp exception (solves log churn)

Temp data is, by definition, **ephemeral, local, and not meant to be replicated or to survive a from-scratch rebuild.** So it does not belong in the durable truth log at all.

- A node with `is_temp = true` (and any link to/from it) is written **only to dedicated SQLite tables** (`temp_nodes`, `temp_links`). It **never emits a log event** — not on create, not on purge.
- Consequence: no matter how heavily an app developer leans on temp files (thousands created and purged per minute), the canonical log is untouched. High-churn temp activity only hits SQLite, which is built for exactly that kind of fast insert/delete.
- Trade-offs that follow naturally from "temp is ephemeral":
  - Temp data is **not replicated** to other instances (it is local scratch space).
  - A full **rebuild of SQLite from the log drops all temp data** — acceptable, because temp is never meant to be durable. (Temp does survive ordinary process restarts, since it is on disk in SQLite; it is only lost on an explicit index rebuild.)
  - A durable (logged) node may **not** depend on a temp node. Links between durable and temp nodes are themselves temp (SQLite-only), so replaying the log on another instance never produces a dangling reference.

This gives `temp` a crisp definition: **local, ephemeral scratch data that lives only in the index, never in the truth log.**

> **⚠ Note for module and app developers — temp is NOT replicated.**
> A node marked `is_temp` lives only on the instance that created it. It is **never synced or replicated to other PVFS instances**, and it does **not** survive a from-scratch index rebuild (though it does survive normal restarts). Use `temp` only for disposable, instance-local data (caches, previews, in-progress scratch). If data must persist, replicate, or be shared across instances, **do not** mark it temp.

### Compaction (noted, deferred)

The durable log grows over time (purged durable nodes leave tombstone events). Periodic **log compaction** — rewriting the log to drop superseded/tombstoned history — is a future concern (P4-adjacent), not part of P0. The temp carve-out above already removes the largest expected source of churn.

---

## 3. Data model

### 3.1 Node

A node is the immutable, content-addressed unit of information.

| Field | Meaning |
|---|---|
| `id` | Content fingerprint — BLAKE3 over the canonical preimage (see §4). Immutable identity. |
| `type` | Node type string. Core types: `file`, `folder`, `temp`. Module types are namespaced (e.g. `media.movie`). |
| `label` | Human-readable name (e.g. a filename or folder name). |
| `visibility` | `public` by default. Part of the id preimage. Encryption semantics belong to the `secure` module; the core just stores the value. |
| `payload` | Type-specific data. Plaintext bytes/JSON for base types; opaque (possibly module-encrypted) bytes otherwise. |
| `is_temp` | Temp flag (see §6.2). Part of the id preimage, so it is immutable like every other field. |
| `created_at` | Creation timestamp (unix ms). |
| `author` | secp256k1 public key (hex) of the creator. |
| `sig` | secp256k1 signature over `id`. |

Sketch (illustrative, not final):

```rust
struct Node {
    id: NodeId,           // BLAKE3 of canonical preimage
    node_type: String,    // "file" | "folder" | "temp" | "<module>.<name>"
    label: String,
    visibility: Visibility, // Public by default in P0
    payload: Payload,     // bytes; interpreted by type
    is_temp: bool,        // temp lifecycle flag (see §6.2)
    created_at: u64,
    author: PubKey,
    sig: Signature,
}
```

### 3.2 Base node type semantics

- **folder** — a container. May be the **root node** of a tree. Has child nodes via `contains` links. Payload is minimal (e.g. display metadata).
- **file** — a leaf describing one file. Payload carries `content_hash` (BLAKE3 of the bytes, may be empty until lazily computed), `size_bytes`, `mime_type`, and `original_filename`. **Storage URIs are not in the payload** — they are separate signed events (`FileLocationAdded` / `FileLocationRemoved`) so a file keeps the same node id when replicas or paths are added (replication-ready from P0). In P0 we *store* locations in the projection; *resolving/reading* bytes is P1.
- **temp** — **decided: `temp` is a flag, not a standalone type.** Any node — `file`, `folder`, or a module node type — can be marked temp. A temp node has the special lifecycle in §6 (immediate purge instead of orphan retention). Modeling it as a flag is what lets it compose as a sub-type onto any module's node (e.g. a `media.preview` that is also temp, or a transient cache entry). The flag is part of the node's content-addressed identity (see §4.1) so it cannot be silently toggled.

### 3.3 Link

A link is a typed, signed, directed edge. Its `id` is content-addressed, but a small **mutable state band** lives outside the id preimage so connections can change without rewriting the edge.

| Field | Meaning |
|---|---|
| `id` | BLAKE3 over `(parent_id, child_id, link_type, created_at)`. |
| `parent_id` | Source node, or `null` when the child is a tree root. |
| `child_id` | Target node. |
| `link_type` | Core: `contains` (hierarchy), `ref` (cross-reference). Modules may add their own. |
| `created_at`, `author`, `sig` | Same trust fields as a node. |
| *state band* | `removed_at`, `superseded_by`, `suspended_at` — mutable; not part of `id`. |

### 3.4 Sibling order — DECIDED: per-parent `order_key`

Per the ADR, the root does not link to every node. Children of one parent are ordered among **themselves** so they can be listed in sequence.

**Decision: each child link carries a sortable `order_key`. Ordering is scoped per parent — there is no global list.**

- Listing one folder's children = an indexed range scan on `(parent_id, order_key)`: the database jumps straight to that parent's children, already sorted, and reads only those rows. Cost is roughly `O(log N + k)` where `k` is that one parent's child count — independent of the total tree size.
- Walking a tree is hierarchical: visit a parent, fetch its ordered children, recurse into child folders. The root is never a single index over every descendant; it only orders its own direct children.
- Inserting between two siblings = choosing an `order_key` that sorts between their keys (**fractional indexing** — keys are values you can always find a new value between, e.g. lexicographic strings). No neighbor rows need updating.
- The `order_key` is plain data carried on the link itself (recorded in its `LinkCreated` event, so it is part of the durable log and replicates cleanly) — two instances never fight over linked-list pointers. It is **not** part of the link's content-addressed `id`, so reordering never changes link identity.
- The `(parent_id, order_key)` composite index in the projection is rebuildable from the log at any time.

*(Why not prev/next pointers: a linked list needs every insert/remove to rewrite neighbor rows and is fragile under replication. `order_key` gives the identical per-parent walk without that bookkeeping, and stays fast at any scale because lookups are indexed by parent.)*

---

## 4. Content addressing & signing

### 4.1 Canonical preimage

The node `id` must be reproducible byte-for-byte on any platform, so the preimage encoding has to be canonical.

```
id = BLAKE3( canonical_encode(type, label, visibility, payload, is_temp, created_at, author) )
```

- **Decided: strict length-prefixed binary encoding** (not JSON). `canonical_encode` is a deterministic serialization with fixed field order, fixed-width little-endian integers, and length-prefixed UTF-8 strings — exactly one valid byte sequence per node.
- Any change to any field yields a new `id` — immutability is structural, not enforced by a flag.
- Binary (rather than JSON) is required because P2 WASM modules may be written in other languages and must compute byte-identical ids; JSON's whitespace/key-order/number-format ambiguities would cause cross-language id mismatches.

### 4.2 Signing

- `sig = secp256k1_sign(author_privkey, id)`.
- Verification recomputes `id` from the record's fields and checks the signature against `author`. A node whose recomputed `id` differs from its stored `id`, or whose signature fails, is rejected — this is how tampering is caught.
- Links are signed the same way over their own `id`.

---

## 5. Persistence — log + projection

Two layers across **two separate SQLite files** (see §2):

1. **Canonical log — `log.db`** — a single append-only `events` table of immutable events. This is the truth. Durable nodes/links are created and changed only by appending event rows. SQLite gives us crash-safety (WAL) and atomic commits for free. `log.db` is never deleted by routine maintenance.
2. **Projection — `index.db`** — the queryable state, rebuilt by replaying `events` from `log.db`. It is disposable: it can be deleted and fully regenerated. It also holds the **temp tables**, which are never sourced from the log.

### Write path

- **Durable write:** in one transaction, append the event row(s) to `log.db` **and** apply the resulting state to `index.db`. (Attaching `log.db` to the `index.db` connection lets both commit atomically; on startup, if `index.db` is behind `log.db`'s tail, replay the missing events to catch up.)
- **Temp write:** write directly to the `temp_*` tables in `index.db` only. No event, no `log.db` touch.

```sql
-- log.db — the canonical truth
CREATE TABLE events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,  -- total order of durable changes
  kind       TEXT NOT NULL,    -- 'NodeCreated' | 'LinkCreated' | 'LinkRemoved' | ...
  body       BLOB NOT NULL,    -- canonical-encoded event payload
  written_at INTEGER NOT NULL
);
```

### SQLite projection schema (illustrative, not final)

```sql
-- Durable, projected from the log:
CREATE TABLE nodes (
  id          TEXT PRIMARY KEY,
  type        TEXT NOT NULL,
  label       TEXT NOT NULL,
  visibility  TEXT NOT NULL DEFAULT 'public',
  payload     BLOB NOT NULL,
  is_temp     INTEGER NOT NULL DEFAULT 0,  -- always 0 in this table; 1 only in temp_nodes
  created_at  INTEGER NOT NULL,
  author      TEXT NOT NULL,
  sig         TEXT NOT NULL
);

CREATE TABLE links (
  id            TEXT PRIMARY KEY,
  parent_id     TEXT,                      -- NULL = child is a tree root
  child_id      TEXT NOT NULL,
  link_type     TEXT NOT NULL,             -- 'contains' | 'ref' | '<module>.<name>'
  order_key     TEXT,                      -- sibling ordering (see §3.4)
  created_at    INTEGER NOT NULL,
  author        TEXT NOT NULL,
  sig           TEXT NOT NULL,
  removed_at    INTEGER,                   -- folded from LinkRemoved events
  superseded_by TEXT,                      -- folded from LinkSuperseded events
  suspended_at  INTEGER                    -- folded from LinkSuspended events
);

-- Ephemeral, SQLite-only, NEVER logged or replicated (see §2 temp exception):
CREATE TABLE temp_nodes (  /* same columns as nodes, is_temp = 1 */
  id TEXT PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
  visibility TEXT NOT NULL DEFAULT 'public', payload BLOB NOT NULL,
  is_temp INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL,
  author TEXT NOT NULL, sig TEXT NOT NULL
);
CREATE TABLE temp_links ( /* same columns as links */
  id TEXT PRIMARY KEY, parent_id TEXT, child_id TEXT NOT NULL,
  link_type TEXT NOT NULL, order_key TEXT, created_at INTEGER NOT NULL,
  author TEXT NOT NULL, sig TEXT NOT NULL,
  removed_at INTEGER, superseded_by TEXT, suspended_at INTEGER
);

CREATE INDEX idx_links_parent ON links(parent_id) WHERE removed_at IS NULL;
CREATE INDEX idx_links_child  ON links(child_id)  WHERE removed_at IS NULL;
CREATE INDEX idx_nodes_type   ON nodes(type);
```

Queries that walk a tree read from both the durable and temp tables (a tree can contain a mix); replication and log replay touch only the durable tables.

---

## 6. Lifecycle rules

### 6.1 Soft-delete & orphans (durable nodes)

- "Deleting" a connection appends a `LinkRemoved` event; the projection sets `removed_at`. The node and link history are never erased.
- A node is **orphaned** when it has no active inbound links.
- Orphans are retained for review; hard delete (purge) appends a `NodePurged` tombstone event and is a separate, explicit, opt-in operation.

### 6.2 Temp purge (the exception)

- A temp node (`is_temp = true`) is **never retained as an orphan** and **never touches the log**.
- The moment its only remaining active link is the one to its tree root (i.e. nothing else references it), the engine **purges it immediately** — a direct `DELETE` of its `temp_nodes` / `temp_links` rows. No event is written.
- This runs as part of link removal: whenever a link is removed, the engine checks whether any affected temp node now hangs only off its root, and deletes it in the same SQLite transaction.
- Because temp purges are plain local deletes (not events), heavy temp churn imposes no cost on the canonical log.

> Open: define precisely "linked to nothing except its tree root." Proposed: the node has exactly one active inbound link and that link's parent is a tree root, or the node itself is a direct child of the root with no other inbound refs.

### 6.3 Managed temp bytes & crash/rebuild cleanup (P1+ contract)

P0 does not write file bytes at all (byte I/O is P1), so there is nothing on disk to leak yet. But once PVFS writes its **own** managed bytes for a temp node (e.g. a transcode preview or in-progress download in P1+), those bytes could be orphaned on disk if a crash or index rebuild drops the temp node. The contract that prevents this is fixed now so the model does not have to change later:

- **One PVFS-owned temp spool directory** (e.g. `<data_dir>/tmp/`). PVFS writes managed temp bytes *only* here, each file named by its temp node id. PVFS never writes managed bytes elsewhere.
- **Startup reconciliation sweep.** On engine open (after recovery/rebuild), diff the spool directory against the live temp nodes: delete any spool file no temp node references, and drop any temp node whose backing file is missing. After a rebuild the temp tables are empty, so every stale spool file is swept. This makes crash/rebuild leaks self-healing.
- **External locations are never touched.** The sweep only ever deletes inside PVFS's own spool dir. A temp node that merely *points at* a user-owned `file://` path is a pointer; PVFS does not delete that file.

(The same content-addressed-store GC idea applies to durable managed bytes in P1, but those are tracked by the log and so are not at risk of being forgotten the way temp is.)

---

## 7. Identity — DECIDED: passphrase-derived

The signing identity is **derived deterministically from a passphrase**, not randomly generated per instance.

- **Derivation:** `identityPrivKey = Argon2id(passphrase, salt = BLAKE3("pvfs:identity:v1:" + passphrase))`, then `authorPubKey = secp256k1.publicKey(identityPrivKey)`. Argon2id is **memory-hard** (deliberately slow and RAM-heavy) so the long-term signing key resists brute force. The domain-separation prefix (`pvfs:identity:v1:`) ensures this key can never collide with a key derived for some other purpose.
- **Why passphrase-derived:** the same passphrase reproduces the **same identity on any machine**. This is what makes replication (P4) and recovery work — a user can stand up a new instance, enter their passphrase, and it authors nodes under the same identity. A random per-instance key could not be recovered or matched across machines.
- **Handling:** the passphrase is taken at startup (prompt, env var, or a protected config file — exact UX is a P1 concern), the key is derived once, and the passphrase reference is cleared from memory. The derived private key may be cached in the data dir (owner-readable only, mode 0600) to avoid re-deriving on every start; this is a convenience cache, not the source.
- This key is the `author` of every node/link the instance creates and the signer for them. Multi-user / per-tenant identities can layer on later without changing the node model (an author is just a public key).

---

## 8. Engine API surface (internal)

The functions the CLI (P1) and WASM host (P2) will call. Conceptual, names illustrative:

```
init_forest(data_dir) -> Forest
create_tree(forest, root_label) -> root_node_id
add_node(forest, parent_id, type, label, payload) -> node_id   // signs + content-addresses
link(forest, parent_id, child_id, link_type, order?) -> link_id
walk(forest, root_id) -> ordered iterator of (node, depth)
children(forest, parent_id) -> ordered [node]
get_node(forest, id) -> Node
verify(forest, id) -> bool                                     // recompute id + check sig
soft_remove_link(forest, link_id)                              // triggers temp-purge check
list_orphans(forest) -> [node]
purge(forest, node_ids)                                        // explicit hard delete
```

No domain logic (media/secure/config) appears here — those arrive as WASM modules in P2/P3.

---

## 8.5 Bound folders & auto-indexing (P1 design)

P0 has no scanning, but the model for picking up files added to a tracked folder is fixed now so the node shape does not change later.

- **Folder binding.** A `folder` node may be *bound* to a real directory. The binding is a small descriptor (recorded in the folder's payload — reserved empty in P0): `{ source_path, recursive, auto_index, extensions filter, hash_policy, on_disk_delete: 'soft' }`.
- **Auto pickup (decided).** Bound folders are indexed automatically by **two cooperating mechanisms**:
  1. a **live filesystem watcher** (OS notifications via the `notify` crate) that ingests changes in real time while the daemon runs, and
  2. a **reconciliation scan** on startup and on a schedule, which diffs the directory against the index. The scan is required because a watcher captures nothing that happens while PVFS is off and can drop events under load.
- **New files** are indexed as **pointers** (a `file` node + location URI), consistent with "PVFS indexes external files, it does not copy them," with lazy hashing by default.
- **On-disk deletion (decided: soft).** When a tracked file disappears from disk, PVFS **soft-removes the location/link and marks it unavailable** but keeps the node, its metadata, and any cross-references (surfaced for review). It does not cascade-delete by default, because PVFS does not own external bytes.
- A **manual scan** command remains available as the fallback when no daemon/watcher is running.

---

## 9. Decisions (all settled)

All foundational decisions are now settled:

1. **Source of truth** (§2) — **decided:** append-only event log is the truth; SQLite is a rebuildable projection; temp data is SQLite-only and never logged.
2. **`temp`: type vs flag** (§3.2) — **decided: flag**, so it can compose onto `file`, `folder`, and module node types.
3. **Log on-disk format** (§5) — **decided:** an append-only `events` table in a separate SQLite file (`log.db`), distinct from the disposable projection (`index.db`); free crash-safety and atomic append-and-project.
4. **Sibling order representation** (§3.4) — **decided:** per-parent sortable `order_key` (indexed by `(parent_id, order_key)`), not prev/next pointers.
5. **Canonical encoding** (§4.1) — **decided:** strict length-prefixed binary, for byte-identical ids across languages (P2 WASM modules).
6. **Identity source** (§7) — **decided:** passphrase-derived (Argon2id → secp256k1), so the same identity reproduces across machines for replication and recovery.
7. **File locations** (§3.2, spec §4.3/§6) — **decided:** URIs are **not** in the file node id preimage; multiple locations per file via **`FileLocationAdded` / `FileLocationRemoved` events** (replication adds URIs without changing file node id).
8. **Log corruption recovery** (spec §9.3 Step 6) — **decided:** stop on corrupt log; operator ladder: backup → replica → salvage → filesystem rebuild (last resort, history lost).

With these settled, the P0 spec ([02-p0-core-engine-spec.md](02-p0-core-engine-spec.md)) is the implementation checklist.
