# PVFS — P1 Storage Backends & Core FS Ops Spec (04)

Status: **Draft for review — open decisions marked [OPEN]**
Date: 2026-06-11
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md), [01-core-engine-design.md](01-core-engine-design.md), [02-p0-core-engine-spec.md](02-p0-core-engine-spec.md), [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md)
Scope: Phase **P1** — reading/resolving actual bytes, scanning real storage into trees, bound-folder auto-indexing, read-path integrity, and the managed-temp spool. Builds strictly on the P0 kernel; **no P0 encoding or schema changes**.

---

## 1. What P1 delivers

On top of the P0 kernel (`pvfs-core`):

- A **`StorageBackend` trait** with a **local filesystem backend** (`file://` scheme).
- **`scan`** — index a real directory into a tree (file nodes as pointers + location events; PVFS copies nothing).
- **`stat`** — node metadata joined with live backend info.
- **`cat`** — stream a file node's bytes, with **read-path integrity verification**.
- **`hash`** — compute/fill a file node's lazy `content_hash`.
- **Bound folders** — a folder tied to a real directory, kept current by a **live watcher** (daemon) plus a **reconciliation scan** (startup/schedule/manual). On-disk deletion soft-removes (design doc §8.5).
- **`pvfs serve`** — minimal daemon: filesystem watcher + scheduled reconciliation. No HTTP (that's P3).
- **Managed temp spool** — `<data_dir>/tmp/`, with the startup cleanup sweep (design doc §6.3).

Out of scope (reaffirmed): WASM host (P2), search/serve-HTTP (P3), mount/remote backends/sync (P4).

---

## 2. StorageBackend trait

Per ADR §5.3, concrete for P1:

```rust
pub trait StorageBackend {
    fn scheme(&self) -> &str;                                       // "file"
    fn stat(&self, uri: &str) -> Result<StatInfo>;                  // size, mtime, exists
    fn read_range(&self, uri: &str, range: Option<ByteRange>) -> Result<Box<dyn Read>>;
    fn write(&self, uri: &str, data: &mut dyn Read) -> Result<StatInfo>; // managed bytes only
    fn list(&self, uri: &str) -> Result<Vec<DirEntry>>;             // name, is_dir, size, mtime
    fn hash(&self, uri: &str) -> Result<String>;                    // BLAKE3 hex, streaming
}
```

- **Registry:** backends are looked up by URI scheme. P1 registers only `file`. Unknown scheme on read ⇒ `BadInput` (actionable: "no backend for scheme").
- **Local backend rules:** URIs are `file:///absolute/path` (RFC 8089, no host). Paths are canonicalized; symlinks are followed for reading but scan records the **symlink target's** stat and never recurses a symlinked directory twice (cycle-safe via canonical-path visited set).
- **`write` is for PVFS-managed bytes only** (temp spool now, content store later). PVFS never writes into user-owned scanned directories.

---

## 3. Folder binding

A `folder` node may be **bound** to a real directory; scan/watch keep it current.

Binding descriptor fields:

| Field | Type | Meaning |
|---|---|---|
| `source_uri` | string | `file:///...` directory |
| `recursive` | bool | descend subdirectories (default true) |
| `auto_index` | bool | watcher/reconciliation act on it (default true) |
| `extensions` | string | comma-list filter, `""` = all (e.g. `"mkv,mp4,srt"`) |
| `hash_policy` | string | `lazy` (default) \| `on_add` \| `never` |
| `on_disk_delete` | string | `soft` (only value in P1) |

> **[OPEN-1] Where does the binding live?** Design doc §8.5 said "in the folder's
> payload", but payload is part of the node's content-addressed id — editing a
> binding (e.g. adding an extension filter) would change the folder's id and
> orphan its subtree. Proposal: **bindings are events**, like file locations:
> `FolderBound { folder_id, descriptor…, author, sig }` /
> `FolderUnbound { folder_id, … }`, projected to a `folder_bindings` table.
> Same pattern already proven for locations; folder id stays stable across
> re-binding; replicates cleanly. Folder payload stays reserved-empty.

Constraints (either way): one active binding per folder; one binding per
`source_uri` per forest (two folders bound to the same directory would fight);
binding a folder requires the directory to exist and be readable.

---

## 4. Scan & reconciliation

`scan(folder)` brings a bound folder in line with its directory. The watcher
uses the same ingest path per event; reconciliation is just a full diff.

For each on-disk file passing the filter:

1. **Match** an existing file node by active location URI within this binding.
2. **New file** ⇒ create `file` node (payload per P0 §4.3: lazy `content_hash`
   unless `hash_policy = on_add`, `size_bytes`, guessed `mime_type`,
   `original_name`) + `FileLocationAdded(file://…)` + `contains` link under the
   mirrored folder path (subfolders become child `folder` nodes, created on
   demand, one per on-disk directory).
3. **Unchanged file** (same size + mtime as recorded) ⇒ no-op.
4. **Changed file** (size or mtime differs) ⇒ see **[OPEN-2]**.
5. **Disk-deleted file** (node has an active location under this binding but
   the path is gone) ⇒ **soft**: `FileLocationRemoved` for that URI. If that
   was the node's last active location, the node is additionally flagged
   `unavailable` in the projection (queryable; surfaced by `stat`/`ls`). The
   node, its metadata, and its links are kept (design doc §8.5) — PVFS does
   not own external bytes.

> **[OPEN-2] What happens when a file's bytes change on disk?** The file node's
> payload (hash/size) is immutable. Proposal — **same-node metadata refresh is
> impossible by design, so:** create a **new file node** (fresh payload),
> `LinkSuperseded` the old home link with a link to the new node (the old node
> keeps history/orphans for review), and move active locations to the new node
> (`FileLocationRemoved` old / `FileLocationAdded` new). Alternative: treat
> changed files as delete+add (simpler, loses the supersede trail).

Scan is **transactional per file** (a crash mid-scan leaves a valid partial
index; the next reconciliation completes it) and **idempotent** (event
idempotency from P0 §7 absorbs re-runs).

Scan stats are returned and printed: `added / unchanged / changed / removed / skipped`.

---

## 5. Read path — `cat` & integrity

`cat(node)` (engine: `open_bytes(node_id, range)`):

1. Collect active locations; resolution order (federation doc §2.3, P1 subset):
   local `file://` first; no other schemes in P1.
2. `stat` each candidate until one exists; none ⇒ `Unavailable` error listing
   tried URIs.
3. Stream bytes. **Integrity check (ADR §6):** if the node has a non-empty
   `content_hash` and the read is **full-file**, hash while streaming and
   compare at EOF; on mismatch the bytes already sent are followed by an error
   (CLI: non-zero exit, partial-output warning on stderr) and the location is
   **quarantined** (see [OPEN-3]). Range reads skip verification (can't hash a
   fragment) — documented.
4. Empty `content_hash` (lazy, never hashed) ⇒ serve without verification;
   `pvfs hash <node>` fills the hash (one streaming pass, emits the updated
   node? — no: hash lives in the payload… see [OPEN-2]; under the proposed
   event model `hash` creates the successor node exactly like a changed file).

> **[OPEN-3] What does a failed integrity check do, concretely?** Proposal:
> a **local quarantine table** (`location_quarantine(file_id, uri, reason,
> detected_at)`, projection-local, not an event — the byte corruption is a
> local observation, not forest history). Quarantined locations are skipped by
> resolution and shown by `stat`. `pvfs loc verify <file>` re-checks and lifts
> quarantine when bytes match again. Alternative: suspend via the existing
> signed `LinkSuspended`-style event — durable and replicated, but writes
> forest history for what may be a single bad disk.

---

## 6. Daemon (`pvfs serve`) & watcher

- `pvfs serve` runs in the foreground: a **`notify`-based watcher** on every
  bound folder with `auto_index`, plus a **reconciliation pass** at startup and
  every `reconcile_interval` (default 1h), plus the temp-spool sweep at start.
- Watcher events are debounced (default 2s) and fed through the same ingest
  path as scan steps 1–5.
- **Single writer:** the daemon takes an advisory lock file
  (`<data_dir>/serve.lock`). One-shot CLI commands remain usable while the
  daemon runs (SQLite WAL; writes serialize via busy timeout) — but only one
  daemon per data dir.
- A manual `pvfs scan` stays available when no daemon is running (design §8.5).

---

## 7. Managed temp spool (design doc §6.3)

- Spool dir: `<data_dir>/tmp/`. PVFS-managed temp bytes are written only here,
  one file per temp node, **named by the temp node id**.
- `Engine::open` sweep (after §9.3 recovery): delete spool files with no
  matching temp node; drop temp nodes whose `pvfs-tmp://` location points at a
  missing spool file.
- Temp spool locations use URI form `pvfs-tmp:///<node_id>` (resolved inside
  the spool dir only; the sweep and backend never touch paths outside it).
- External `file://` locations on temp nodes are pointers; never deleted.

---

## 8. Projection additions (index.db, rebuildable)

```sql
-- [OPEN-1] if bindings-as-events is accepted:
CREATE TABLE folder_bindings (
  folder_id   TEXT PRIMARY KEY,
  source_uri  TEXT NOT NULL UNIQUE,
  recursive   INTEGER NOT NULL,
  auto_index  INTEGER NOT NULL,
  extensions  TEXT NOT NULL,
  hash_policy TEXT NOT NULL,
  bound_at    INTEGER NOT NULL,
  unbound_at  INTEGER           -- NULL = active
);

-- local observations (NOT folded from events; survive rebuild = re-observed):
CREATE TABLE location_quarantine (
  file_id     TEXT NOT NULL,
  uri         TEXT NOT NULL,
  reason      TEXT NOT NULL,
  detected_at INTEGER NOT NULL,
  PRIMARY KEY (file_id, uri)
);
CREATE TABLE scan_state (        -- last seen size/mtime per (binding, uri)
  uri        TEXT PRIMARY KEY,
  size_bytes INTEGER NOT NULL,
  mtime_ms   INTEGER NOT NULL,
  file_id    TEXT NOT NULL
);
```

`location_quarantine` and `scan_state` are **local caches**: a full rebuild
clears them; the next reconciliation/verification repopulates them. New events
(if [OPEN-1] accepted): `FolderBound`, `FolderUnbound` — signed like all
mutable events, root-or-device authored, replicated.

---

## 9. CLI additions

```
pvfs bind <folder-id> <dir> [--no-recursive] [--no-auto-index]
                            [--extensions mkv,mp4] [--hash-policy lazy|on_add|never]
pvfs unbind <folder-id>
pvfs scan [<folder-id>]        # all bound folders if omitted
pvfs stat <node-id>            # node + locations + availability + quarantine
pvfs cat <node-id> [--range A-B] [-o FILE]
pvfs hash <node-id>            # fill lazy content_hash
pvfs loc verify <file-id>      # re-check quarantined/all locations
pvfs serve [--reconcile-interval 1h] [--debounce 2s]
```

Exit codes follow P0 §13.4; new condition: `Unavailable` (no readable
location) maps to exit 3 (not-found family).

---

## 10. Test plan additions

1. **Backend contract** — local backend stat/list/read_range/hash against a
   fixture dir; symlink cycle does not loop; no write outside spool.
2. **Scan** — fresh dir indexes fully (files, nested folders, filters);
   re-scan is a no-op; per-file transactionality (kill mid-scan, reconcile
   completes); scan stats correct.
3. **Pointer semantics** — scanned files get location events, bytes never
   copied; node id stable across location changes (P0 §14.13 extended).
4. **Disk deletion** — file removed on disk ⇒ location soft-removed, node kept,
   flagged unavailable; file restored ⇒ location re-added, flag clears.
5. **Changed file** — per [OPEN-2] resolution; old node retained for review;
   links updated; locations moved.
6. **Read path** — cat streams correct bytes; corrupted bytes detected
   (hash mismatch) ⇒ error + quarantine per [OPEN-3]; quarantined location
   skipped on next read; `loc verify` lifts quarantine after repair; range
   reads work and skip verification.
7. **Lazy hashing** — `hash_policy` honored; `pvfs hash` fills and persists.
8. **Watcher** — create/modify/delete on disk reflected while `serve` runs;
   debounce coalesces bursts; events while daemon stopped are caught by the
   startup reconciliation.
9. **Temp spool** — managed temp bytes only in `<data_dir>/tmp/`; crash leaves
   stale spool file ⇒ swept at next open; rebuild empties temp ⇒ spool emptied;
   external file:// of a temp node untouched by sweep.
10. **Daemon lock** — second `serve` refuses; one-shot CLI works alongside.

---

## 11. Open decisions to settle before coding

1. **[OPEN-1]** Folder binding storage: **events + projection table** (proposed)
   vs payload (breaks id-stability on re-bind).
2. **[OPEN-2]** Changed-file semantics: **new node + LinkSuperseded trail**
   (proposed) vs plain delete+add.
3. **[OPEN-3]** Integrity-failure handling: **local quarantine table**
   (proposed) vs signed suspend events in the log.
