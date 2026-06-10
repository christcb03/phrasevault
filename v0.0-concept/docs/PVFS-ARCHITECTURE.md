# PVFS — PhraseVault Filesystem Architecture

## Overview

PVFS is a content-addressed, multi-tree filesystem built on the PhraseVault forest DAG. It provides a virtual filesystem abstraction over arbitrary storage backends — local disk, NAS mounts, peer-to-peer nodes, IPFS, or BitTorrent — with deduplication, signed provenance, and a staged path toward a native `pvfs://` protocol for inter-node file transfer.

PVFS is the persistence layer beneath MediaForest. MediaForest sees it as a native-feeling filesystem. PVFS does not care about media metadata — that's MF's domain. PVFS cares about: files, where they live, who owns which trees, and what gets deleted when.

---

## Core Concepts

### Content-Addressed Files

Every file in PVFS is represented by a `pvfs.file` node whose ID is derived from `BLAKE3(type + label + visibility + JSON(payload) + created_at + author)` per the standard node ID scheme. The payload carries the `content_hash` (BLAKE3 of the file's raw bytes), which is the deduplication key.

Two different people ingesting the same file bytes will, if hashing is enabled, produce nodes with the same `content_hash`. The system can detect this and link both trees to the same underlying file node rather than duplicating storage.

**Note on lazy hashing:** Hashing large NAS libraries up front is impractical. The `ingest()` method accepts `computeHash: false` to register a file pointer immediately and defer hash computation. Hash-based dedup kicks in only once hashes are present.

### pvfs.location — Storage Backend Abstraction

A `pvfs.file` node has one or more `pvfs.location` children (via `member` links). Each location is a URI pointing to where the bytes actually live:

```
file:///mnt/media/movies/Inception.mkv       — local or NAS path
http://192.168.1.100:8080/files/<hash>       — PVFS Server v1 HTTP
pvfs://<pubkey>/<content_hash>               — PVFS Server v2 P2P
magnet:?xt=urn:btih:<infohash>&...           — BitTorrent
ipfs://<CID>                                 — IPFS
```

The filesystem layer resolves whichever location is fastest/available. The `pvfs.file` node itself is always the canonical identity — locations come and go.

### Multi-Tree Forest Structure

The forest is organized into trees, all of which link to shared `pvfs.file` nodes. No file data is copied between trees — trees hold links, not bytes.

**Primary tree** (`tree.root`, label: `"pvfs:primary"`)
A flat, insertion-ordered list of every file ever added. This is the "everything" view. It is the master tree for cascade delete decisions.

**Folder trees** (one `tree.root` per directory)
Mirror the filesystem directory hierarchy. A file under `/media/movies/2010s/` is linked from the `movies` tree root, then from the `2010s` subtree. Walking from the `movies` root gives you all movies. Walking from the `2010s` subtree gives you just that decade.

**Metadata trees** (genre, year, director, actor, quality, etc.)
Each unique metadata value becomes a `tree.root`. A file tagged `genre:Sci-Fi` is linked as a `cross` link from the Sci-Fi genre root. These trees are independent from the folder hierarchy — you can start from "Sci-Fi" and enumerate every matching file across all folders.

**Cross-linking the roots**
Every tree root carries a `cross` link to the primary tree root. This means you can always navigate back to the authoritative timeline, and the orphan detection algorithm only needs to walk from the primary tree root to determine reachability.

---

## Deletion Model

### Soft Delete / Reference Counting

Links are never physically removed from the DB. A soft-removed link has `removed_at` set and is treated as inactive by the walker and the orphan detector. Nodes remain in the DB forever unless explicitly pruned.

### Orphaned Files

A `pvfs.file` node is **orphaned** when it has no active (non-removed) inbound links from any tree. This is a structural property derived by walking the forest, not a flag on the node itself.

### Master Tree and Cascade Delete

The primary tree is the master tree. **`DELETE /pvfs/trees/primary/files/:fileNodeId`** (implemented) always cascade soft-removes **all** active inbound links to that `pvfs.file` node (primary `branch`, user `pvfs_ref`, media `file` links, etc.).

1. Every inbound link gets `removed_at` set (append-only; links are never physically deleted until purge).
2. The file becomes **orphaned** when no active inbound links remain.
3. **Local disk delete is separate:** if a `file://` location exists, the API returns a warning and paths until the client sends `confirm_local_delete: true`. Only `file://` paths are deleted — never `pvfs-local:` or remote URIs.

Future: per-tree `config.prune_policy` may gate cascade (e.g. opt-out on folder trees). Today cascade from primary is unconditional.

### Auto-Prune vs Manual Orphan Cleanup

The `PrunePolicyPayload` already exists in the type system:

```typescript
interface PrunePolicyPayload {
  target_id:          string | null   // null = forest default
  retain_orphan_days: number | null   // null = never auto-prune
  warn_before_days:   number | null
  auto:               boolean         // true = auto-delete orphans after retain_orphan_days
}
```

`auto: false` → orphans accumulate. **`GET /pvfs/orphans`** lists them; **`POST /pvfs/orphans/purge`** hard-deletes DB rows when the app explicitly requests it (never automatic).

`auto: true` + `retain_orphan_days: N` → **`POST /forest/prune`** (policy-driven) can hard-delete aged orphans via `pruner.ts`.

### Factory reset (entire server)

**`POST /admin/factory-reset`** (see [ADMIN-FACTORY-RESET.md](ADMIN-FACTORY-RESET.md)) clears all forest and PVFS metadata and the `pvfs/` blob store. It is **not** the same as per-file delete with `confirm_local_delete` — factory reset does **not** unlink `file://` paths on the host filesystem.

---

## pvfs:// P2P Protocol (Target Architecture)

### Server Identity

Each PVFS Server has a secp256k1 keypair. The public key is its persistent identity. The `pvfs://` URI scheme uses this identity:

```
pvfs://<server-pubkey-hex>/<content_hash>
```

### Peer Discovery

PVFS Servers announce themselves on the Hyperswarm DHT keyed by `BLAKE3("pvfs:" + content_hash)`. Any client that wants a file opens a connection to the swarm topic for that hash and gets a list of peers serving it.

### Chunk-Level Transfer

The `pvfs.file` payload will be extended with chunk metadata:

```typescript
interface PvfsFilePayload {
  content_hash:  string    // BLAKE3 of full file
  size_bytes:    number
  mime_type:     string
  original_filename: string | null
  // Chunk manifest (populated when file is hosted by a PVFS Server):
  chunk_size?:   number    // bytes per chunk, e.g. 524288 (512 KB)
  chunk_count?:  number
  chunk_hashes?: string[]  // BLAKE3 of each chunk
}
```

Each chunk is downloaded independently and verified against its hash before assembly. This enables:
- Resume after interruption
- Parallel multi-source download
- Streaming playback once initial chunks are verified
- Detection of corrupt/malicious peers at chunk granularity

### BitTorrent Integration

BitTorrent is a first-class `pvfs.location` type. A PVFS Server can generate a magnet link for any hosted file and seed it via a BT client. The `pvfs.file` content hash does not need to match the BT infohash — the location node carries the magnet URI and the PVFS layer verifies the bytes against `content_hash` after download regardless of source.

---

## Staged Implementation Plan

### Stage 1 — Tree Structure and Node Types ✅ (primary + user)

**Implemented:**
- Primary tree (`pvfs:primary`), user trees (`pvfs:user:{pubKey}`), `pvfs_ref` links
- `POST /pvfs/ingest`, primary backfill on startup, `GET /pvfs/trees/primary/walk`
- `getParentLinks()` for orphan detection

**Not yet:** folder trees, metadata trees (genre/year), cross-links between tree roots.

**Deliverable (met):** Ingest links every file into the primary tree; MediaForest can walk ordered inventory.

---

### Stage 2 — HTTP PVFS + Cascade Delete + Orphan API ✅ (v1)

**Implemented:**
- Fastify PVFS routes — see [PVFS-HTTP-API.md](PVFS-HTTP-API.md)
- `GET /pvfs/file/:id/stream` with byte ranges (serves `file://` and `pvfs-local:`)
- Persistent scan jobs (`pvfs_scan_jobs` in `forest.db`)
- Cascade delete from primary + optional confirmed `file://` disk delete
- `GET /pvfs/orphans`, `POST /pvfs/orphans/purge` (app-initiated only)

**Not yet:** `GET /files/:hash` content-addressed store, `orphaned_since` field, auto-prune cron, `http` location type for copied blobs.

**Deliverable (met):** MediaForest can register, stream, cascade-remove, and purge orphans through PVFS.

---

### Stage 3 — pvfs:// P2P (Hyperswarm + Chunk Transfer)

**Goal:** Two PVFS Server nodes can share files with each other. Client can download from multiple peers simultaneously with chunk-level verification.

**New pieces:**
- Server keypair generation and persistence (`server_key.json`, mode 0o600)
- Hyperswarm peer announcement on `BLAKE3("pvfs:" + content_hash)` topic
- Chunk manifest computed at ingest time, stored in `pvfs.file` payload
- Chunk download protocol: request chunk N, receive bytes, verify against `chunk_hashes[N]`
- `pvfs.location` type `peer` with `uri: pvfs://<pubkey>/<hash>` and `peer_id: <pubkey>`
- When a file is downloaded from a peer, create a local `pvfs.location` of type `http` (now hosted locally too), and create a `peer` location pointing back to the source
- Transfer manager: parallel chunk download from N peers, reassembly, final full-file verify

**Deliverable:** MediaForest instances can share files across the network without a central server. Partial downloads survive restarts.

---

### Stage 4 — BitTorrent and IPFS Location Types

**Goal:** Files that exist in the broader ecosystem (BT/IPFS) can be linked without the PVFS Server needing to host them. Download via BT/IPFS, verify against PVFS content hash.

**New pieces:**
- `pvfs.location` type `torrent` with `uri: magnet:?...`
- BT download adapter: drives a BT client, monitors download progress, verifies completed file against `pvfs.file.content_hash`
- `pvfs.location` type `ipfs` with `uri: ipfs://<CID>`
- IPFS adapter: fetch via IPFS gateway or local node, verify hash
- Seeding: PVFS Server can seed hosted files via BT to improve redundancy
- Magnet link generation: `POST /pvfs/file/:id/seed` → generates and seeds the file, returns magnet URI, creates a `torrent` location node

**Deliverable:** PVFS can act as a unified access layer over local files, peer nodes, BT torrents, and IPFS — whichever resolves first wins, all verified against the same content hash.

---

## API Surface (Staged)

**Stage 1 — Tree ops (no HTTP server yet)**
```
POST /pvfs/ingest          body: { path, mediaNodeId?, label?, computeHash? }
GET  /pvfs/file/:id        returns pvfs.file node
GET  /pvfs/tree/:rootId    walk tree from root, returns files
```

**Stage 2 adds**
```
GET  /pvfs/orphans                         list orphaned pvfs.file nodes
DELETE /pvfs/orphans                       bulk delete orphans
DELETE /pvfs/file/:id                      soft-delete + optional cascade
GET  /pvfs/file/:id/locations              all pvfs.location nodes for a file
GET  /files/:hash                          serve file bytes (PVFS Server)
POST /pvfs/upload                          ingest uploaded file into store
```

**Stage 3 adds**
```
GET  /pvfs/peers                           known PVFS peers
GET  /pvfs/file/:id/swarm                  peers currently announcing this file
POST /pvfs/file/:id/fetch-from-peer        trigger chunk download from peer
GET  /pvfs/transfers                       active chunk transfer status
```

**Stage 4 adds**
```
POST /pvfs/file/:id/seed                   seed via BT, create torrent location
POST /pvfs/file/:id/fetch-from-torrent     trigger BT download + verify
POST /pvfs/file/:id/fetch-from-ipfs        trigger IPFS fetch + verify
```

---

## Security Constraints

- Camera credentials, vault secrets: never in plaintext in repo — vault.yml only
- PVFS Server keypair (`server_key.json`): mode 0o600, owner-readable only
- Chunk verification is mandatory before assembly — corrupt/malicious peer data is rejected at chunk boundary
- `pvfs.location` URIs with `type: peer` are never trusted without hash verification of transferred bytes
- Forest nodes are immutable and signed — a node's content cannot be altered after creation
- Deletion is always soft at the forest layer; physical file deletion is a separate, logged operation tied to a `prune_record` node

---

## Open Questions

1. **Dedup across users**: If two users on the same PVFS Server ingest identical files, do they share the `pvfs.file` node? Currently no — node ID includes `author`. A content-hash index could detect the duplicate and share the location node, but the policy question (does user A own user B's node?) is unresolved.

2. **Folder tree granularity**: Should each path segment be its own `tree.root`, or just the leaf directories? Deep NAS hierarchies could create hundreds of roots. Lazy creation (root created on first file in that folder) is probably right, but the schema needs a folder→root index.

3. **Chunk size**: 512 KB is a reasonable default. Very large files (4K rips at 50+ GB) might benefit from larger chunks. Consider making it a per-file property rather than a global constant.

4. **Auto-prune vs MediaForest UI**: For Stage 2, the manual orphan review UI in MediaForest is the priority. Auto-prune can default to `auto: false` until the UI exists and users have confirmed they're comfortable with the delete semantics.
