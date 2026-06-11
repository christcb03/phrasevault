# PVFS — Federation, Trust, and URIs (03)

Status: **Decided for data model** (P4 implements protocols; P0 implements trust fixes + URI grammar + forest metadata hooks)
Date: 2026-06-10
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md), [01-core-engine-design.md](01-core-engine-design.md), [02-p0-core-engine-spec.md](02-p0-core-engine-spec.md)

This document locks decisions from the federation and trust review. It does **not** specify wire protocols (those belong to the sync/file-server layer, version `1.0.#`).

---

## 1. Forest ownership and multi-forest hosts

### 1.1 Not one forest per server

A **PVFS instance** (one running engine / data directory on a machine) may host **many forests**:

| Role | Who writes the log | Purpose |
|------|-------------------|---------|
| **Owned** | This instance (`owner_instance_id == local instance_id`) | Forests created here; canonical root owned by this server |
| **Replica** | **Owner instance only** (remote append or sync from owner) | Full immutable copy of another instance's forest log + projection |

Each forest has:

- **`instance_id`** — stable identity of the **owner** instance (survives DNS/IP changes).
- **`forest_id`** — unique id for that forest **on the owner** (UUID or slug).
- **`root_node_id`** — canonical root of the forest's primary tree.

**Write rule:** A forest's log is appended **only** on the owner instance — either locally or via an **authenticated remote append** API on the owner. Replicas on other machines do **not** merge independent writes into that log.

### 1.2 Log sync (clarified)

**Log sync** means an **immutable copy** (or tail follow) of a forest's event stream — **not** merging two active writers into one chain.

- Each forest keeps its **own** linear `seq` + `chain_hash` per log.
- Prefix chain comparison verifies: "this replica matches the owner's history up to seq *N*."
- There is **no multi-master CRDT merge** on a shared log.

P0 implements **one owned forest** per data directory. **Decided:** the forest's identity (`instance_id`, `forest_id`, `root_node_id`) is recorded durably as a signed **`ForestCreated` genesis event at seq 1** of the log, and the chain genesis seed binds `instance_id` + `forest_id` (spec §6, §7.1) — the `projection_meta` copies are a rebuildable cache. P4 adds additional owned forests and replica forests on the same host.

### 1.3 Sharing modes (P4)

**Mode A — Full forest replica**

- Instance B holds a read-only replica of owner A's forest F (complete log copy or ongoing tail sync).
- B's **owned** forest may add `ref` links or import views pointing at nodes in the replica catalog.

**Mode B — Selective import into B's owned forest**

- User picks nodes from a replicated (or remote) catalog.
- Optional: copy bytes into B's local PVFS store.
- B's owned log: `NodeCreated` (same **node id** when content + metadata + author match) + `FileLocationAdded` for local storage URI.
- **Crosslink on owner:** B calls A's API → A appends signed `FileLocationAdded` (replica URI) and/or `ref` on A's tree — writes go to **A's log only**.

**Mode C — Pointer-only (no byte copy, no log replica)**

- B's owned forest creates a local node (or link) and records a **PVFS catalog URI** (§3) pointing at A's node.
- No replication of A's log or files; read resolves via network to A (or B's replica if present).

### 1.4 Same node id across instances (dedupe)

For backup / redundancy, the **same content-addressed node id** is used on owner and replica when the file record is the same (same preimage → same id). Cross-forest linkage uses:

- **`ref` links** between trees/forests, and/or
- **`FileLocationAdded`** on each side for storage URIs (`file://…`, etc.).

The node id identifies the **logical file**; locations identify **where bytes live**.

---

## 2. URI classes

PVFS uses **two URI classes**. Do not conflate them.

### 2.1 Storage URIs (bytes)

Stored via **`FileLocationAdded`** on a file node:

| Scheme | Meaning |
|--------|---------|
| `file://…` | Local or mounted path |
| `https://…` | Remote object / HTTP gateway |
| (future) | Blob store, torrent infohash, etc. |

These answer: **"Where do I read the bytes?"**

### 2.2 PVFS catalog URIs (nodes)

Identify a **node in a forest on an owner instance**. Used for federation, sharing, and cross-links — **not** for embedding file content.

**Canonical form:**

```text
pvfs:<instance_id>/<forest_id>/tree/<root_node_id>/node/<node_id>
```

**Shorthand** (same target; resolver skips optional tree walk verification):

```text
pvfs:<instance_id>/<forest_id>/node/<node_id>
```

| Segment | Meaning |
|---------|---------|
| `instance_id` | Owner instance (who may append to this forest's log) |
| `forest_id` | Forest id on that owner |
| `root_node_id` | Tree root (container / entry point) — the root `folder` node id |
| `node_id` | Target node id (64 hex chars) |

**Grammar notes:**

- Scheme is `pvfs:` (opaque hierarchy; not `pvfs://` unless we also register a URL form later).
- Segments are path-like; ids are hex strings without extra encoding.
- **`instance_id` / `forest_id` as two segments** is preferred over a single compound string (easier routing and logging). A compound `forest_id` of `<instance_id>:<slug>` is allowed if documented consistently.
- **Reachability** (hostname, port, TLS) is **not** in the URI — resolved via config/discovery from `instance_id`.

**Optional P4 optimization (deferred):** content-hash routed alias `pvfs:…/file/<content_hash>` for "read from any replica" — not primary identity; node id remains canonical.

### 2.3 Read resolution order (P4)

1. Local storage URIs on the node (`file://…` on this instance).
2. Local replica of the node's forest (if present).
3. Resolve `pvfs:…` catalog URI → fetch from owner or replica instance.
4. Fail with actionable error.

---

## 3. Trust model fixes (P0)

These apply to **every** forest log, including replicas (replica must reject unsigned or invalid events when syncing).

### 3.1 Sign all mutable events

Every state-changing event carries **`author`** + **`sig`** over a domain-separated BLAKE3 message (see spec §6). No exceptions for replicated logs.

| Event | Signed |
|-------|--------|
| `LinkRemoved`, `LinkReordered` | yes (already) |
| `FileLocationAdded`, `FileLocationRemoved` | yes (already) |
| `LinkSuperseded`, `LinkSuspended`, `LinkUnsuspended`, `NodePurged` | **yes (added)** |

Unattributed `NodePurged` on a replicated catalog would be a silent wipe — unacceptable.

### 3.2 Link id — logical edge id

Link id preimage **excludes** `created_at` and **excludes** `author`:

```
preimage = PCE(parent_id, child_id, link_type, link_nonce)
link_nonce : u64   // default 0; increment for a second edge with same (parent, child, type)
```

**Rationale:** Same logical link replayed from an owner log onto a replica yields the **same link id** (idempotent sync). `created_at` remains on the link record for display/audit but is not part of id.

### 3.3 Node id — `creation_nonce`

Add **`creation_nonce: u64`** to the node id preimage (caller-supplied or engine-generated random). Prevents accidental id collision when two distinct nodes share all other fields in the same millisecond.

**API vs replay:**

| Path | Behavior if node id already exists |
|------|-------------------------------------|
| **`add_node` API** | Return **`AlreadyExists { id }`** — never silent success for a distinct create attempt |
| **Log replay / sync** | `INSERT OR IGNORE` — idempotent |

If an API call produces identical bytes to an existing node, return **`Ok(id)`** (idempotent success).

### 3.4 Hash chain binding

Include **`seq`** and **`written_at`** in the chain step (not only `kind` + `body`):

```
chain_hash[seq] = BLAKE3( chain_hash[seq-1] || PCE(seq, kind, body, written_at) )
```

Detects row reordering and timestamp tampering cheaply.

### 3.5 secp256k1 signature malleability

Keep **secp256k1** — it is the curve the BIP39/BIP32 identity scheme (spec §10) and the wider wallet ecosystem use. Verifier **must enforce low-s** (reject malleable signatures). Document in spec §4.4.

### 3.6 Identity root & device keys

Identity is a **BIP39 generated seed phrase** → **BIP32 hardened HD key tree** (spec §10): an **identity root key** (signs `ForestCreated` and device certificates only) and **per-device signing keys** (the everyday `author`). `DeviceAuthorized` / `DeviceRevoked` events in the forest log tie device keys to the root and provide stolen-device containment. This changes nothing about the sync model — replication copies signed events verbatim and accepts foreign authors — but it gives remote-append authorization (§6 item 4) its natural rule: *accept appends from device keys currently certified under the owner's identity root.*

---

## 4. Replication vs hash chain (why this still works)

| Concern | Resolution |
|---------|------------|
| Linear chain = single writer | **One write leader per forest log** (owner instance) |
| Two instances diverge | They have **separate logs** unless one is a **replica** of the other |
| "Sync is just shipping events" | True for **owner → replica** copy of the **same** forest |
| Multi-master merge | **Out of scope** — avoided by ownership model |

The sync/file-server layer (version `1.0.#`) implements transport, auth, and tail follow — not log merge.

---

## 5. P0 vs P4 implementation split

| Item | P0 | P4 |
|------|----|----|
| Trust fixes (§3) | Implement | — |
| URI grammar (§2) | Parse/store strings; no remote fetch | Resolver + RPC |
| `instance_id`, `forest_id` metadata | One default owned forest | Multi-forest + replicas |
| Full / selective sync | — | Protocols |
| Remote append to owner log | — | Authenticated API |

---

## 6. Outstanding questions (not blocking P0 kernel)

1. **`instance_id` assignment** — How is it chosen at first init (hostname slug, UUID, operator config)? How do peers discover `instance_id` → network address?
2. **`forest_id` format** — UUID vs human slug; whether compound `<instance_id>:<slug>` is ever used vs always two path segments in URIs.
3. **Failover writer** — If owner instance is down, can a replica be promoted to append? (Requires explicit protocol; default is **no**.)
4. **Remote append auth** — *Model decided (§3.6):* the owner accepts appends from device keys certified under its identity root; cross-instance grants (e.g. letting B's identity request `FileLocationAdded` on A's forest) still need a grant mechanism. Wire protocol in sync layer `1.0.#`.
5. **Selective log subscription** — Subset-of-forest event stream vs full forest only for Mode B imports.
6. **Content-hash URI** — Whether to add `pvfs:…/file/<hash>` read shortcut in P4 (optional optimization).

P0 coding may proceed with defaults: `instance_id` from config/env at init, `forest_id` = UUID, single owned forest, no remote append.
