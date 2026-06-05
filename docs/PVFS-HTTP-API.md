# PVFS HTTP API (implemented)

MediaForest consumer reference: [mediaforest `docs/PVFS-API-WISHLIST.md`](https://github.com/christcb03/mediaforest/blob/main/docs/PVFS-API-WISHLIST.md).

Deploy: push `main` → GHCR → Watchtower on presubuntu. See [DEPLOY.md](DEPLOY.md).

**Stream URL:** canonical path is `GET /pvfs/file/:id/stream` (wishlist alias `/pvfs/stream/:id` not added yet). Responses on `GET /pvfs/file/:id` include a `stream_url` field.

## Trees

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pvfs/trees/primary` | Primary root id + file count |
| GET | `/pvfs/trees/primary/walk?offset=&limit=` | Ordered file entries under `pvfs:primary` |
| GET | `/pvfs/trees/user/:pubKey` | User tree refs (`pvfs_ref` links) |
| POST | `/pvfs/trees/user/:pubKey/ref` | Body: `{ primary_file_node_id }` |

Primary tree label: **`pvfs:primary`**. User tree label: **`pvfs:user:{pubKeyHex}`**.

On server start, existing `pvfs.file` nodes are **backfilled** into the primary tree if missing.

## Files and locations

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pvfs/locations` | Flat list (MediaForest compat): `{ nodes: [{ id, payload: { uri, ... } }] }` |
| GET | `/pvfs/locations/by-uri?uri=` | Lookup by `file://` URI |
| POST | `/pvfs/file` | Create file node (auto-linked to primary) |
| GET | `/pvfs/file/:id` | File + location children + `stream_url` |
| POST | `/pvfs/file/:id/location` | Add `pvfs.location` child |
| GET | `/pvfs/file/:id/stream` | Byte-range streaming |
| POST | `/pvfs/ingest` | Body: `{ path, media_node_id?, label?, mime_type? }` — registers file + primary link |
| GET | `/pvfs/file/:id/verify?uri=` | BLAKE3 verify |

## Scan jobs (SQLite — `pvfs_scan_jobs` in `forest.db`)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/pvfs/scan` | Body: `{ path, dry_run?, extensions?, limit?, compute_hash? }` → `{ jobId }` |
| GET | `/pvfs/scan` | Recent jobs (summary, last 50) |
| GET | `/pvfs/scan/:jobId` | Job status + file list (survives server restart) |

## Primary tree removal (cascade + optional local disk delete)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pvfs/trees/primary/files/:fileNodeId/remove-preview` | Inbound links to soft-remove + local `file://` paths that would need confirmation |
| DELETE | `/pvfs/trees/primary/files/:fileNodeId` | Soft-removes **all** inbound links to the file (cascade). Body: `{ confirm_local_delete?: boolean }` |

Cascade always runs on DELETE. If the file has `file://` locations, the response includes `local_delete.required_confirmation: true` and paths until you call again with `confirm_local_delete: true` (deletes bytes on disk only for `file://`, never `pvfs-local:` or remote URIs).

## Orphans (app-initiated purge only)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/pvfs/orphans` | `pvfs.file` nodes with no active inbound links |
| POST | `/pvfs/orphans/purge` | Body: `{ file_node_ids?: string[] }` — hard-delete orphans from DB (optional id list; default all orphans) |

Auto-prune by age is still via `/forest/prune` and `config.prune_policy`. Orphan **purge** is never automatic.

## Link type

Added **`pvfs_ref`** for user-tree → primary file references (`src/forest/types.ts`).

## P1 (not blocking MediaForest)

| Method | Path | Notes |
|--------|------|--------|
| HEAD | `/pvfs/file/:id/stream` | Range probe for players |
| GET | `/pvfs/stream/:id` | Alias of stream path above |
| POST | `/pvfs/stream/:id/authorize` | Delegated browser token via MF session |

## Not yet implemented

- Folder / genre metadata trees (see `docs/PVFS-ARCHITECTURE.md`)
- `orphaned_since` on orphan list entries
- Distributed `pvfs://` peers
- Append-only forest replication API (Hypercore still in MediaForest interim)