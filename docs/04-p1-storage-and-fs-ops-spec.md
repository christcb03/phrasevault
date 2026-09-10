# PVFS — P1 Storage Backends & Core FS Ops Spec (04)

Status: **Implemented** — normative reference for P1 storage layer (see [INSTALL.md](INSTALL.md))
Date: 2026-06-11
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md), [01-core-engine-design.md](01-core-engine-design.md), [02-p0-core-engine-spec.md](02-p0-core-engine-spec.md), [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md)
Scope: Phase **P1** — reading/resolving actual bytes, scanning real storage into trees, bound-folder auto-indexing, read-path integrity, and the managed-temp spool. Builds on the P0 kernel; **no P0 encoding or schema changes**.

---

## 1. What P1 delivers

On top of the P0 kernel (`pvfs-core`):

- A **`StorageBackend` trait** with a **local filesystem backend** (`file://` scheme).
- **`scan`** — index a real directory into a tree (file nodes as pointers + location events; PVFS copies nothing).
- **`stat`** — node metadata joined with live backend info.
- **`cat`** — stream a file node's bytes, with **read-path integrity verification**.
- **`hash`** — compute/fill a file node's missing `content_hash`.
- **Bound folders** — a folder tied to a real directory, kept current by a **live watcher** (daemon) plus a **reconciliation scan** (startup/schedule/manual). On-disk deletion soft-removes the location, and takes the node out of the tree too once the file is held nowhere for a day (§11 item 4; design doc §8.5).
- **`pvfs serve`** — minimal daemon: filesystem watcher + scheduled reconciliation. No HTTP (that's P3). *(Since P5, doc 18: `pvfs serve` is the job supervisor; the P1 watcher lives on as the `watch` job.)*
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
| `hash_policy` | string | `on_add` (default since D94) \| `never` — `lazy` was removed in D94 and is refused at bind |
| `on_disk_delete` | string | `soft` (only value in P1) |

> **Decided — bindings are events** (supersedes design doc §8.5's
> payload note): `FolderBound { folder_id, source_uri, recursive, auto_index,
> extensions, hash_policy, bound_at, author, sig }` and
> `FolderUnbound { folder_id, unbound_at, author, sig }`, signed like every
> mutable event (domain prefixes `pvfs:folderbound:v1:` /
> `pvfs:folderunbound:v1:`), projected to the `folder_bindings` table (§8).
> Re-binding = `FolderUnbound` + new `FolderBound`; the folder's id never
> changes; bindings replicate and survive rebuilds. Folder payload stays
> reserved-empty.

Constraints (either way): one active binding per folder; one binding per
`source_uri` per forest (two folders bound to the same directory would fight);
binding a folder requires the directory to exist and be readable.

> **Decided (D71 W1) — a binding is scoped to the machine that made it.**
> `source_uri` names a path on exactly one box, so the binding's **author** (the
> device key `FolderBound` has always carried, never before folded) is projected
> as `folder_bindings.bound_by`, and everything that touches the directory
> filters on it: `scan(None)` and the watcher process **only this device's**
> bindings, and naming a foreign one explicitly is a clear error rather than a
> silent skip. `bindings()` still returns forest-wide truth — the listing shows
> the whole fleet and marks what belongs elsewhere.
>
> This is attribution, **not** absence-tolerance. A binding that *is* this
> machine's and whose directory has vanished still raises (§4's unmounted-source
> guard); weakening that into "skip anything missing" would let one unmounted
> NAS soft-remove every location beneath it.
>
> No new event, no wire change — the attribution was always in the signed log.
> Schema v8's drop-and-replay back-fills it.
>
> *Why it was needed:* on the D69 media fleet the `watch` job could not run on
> any replica at all — the watcher walked every binding in the forest and died
> registering a watch on the owner's directories, which do not exist on the
> ingest box.

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
4. **Changed file** (size or mtime differs) ⇒ **Decided: flag, don't auto-resolve.**
   The node is marked **`invalid: changed-on-disk`** in the local
   `pending_changes` table (§8). While flagged, the changed location is **not
   served** (`cat` skips it — the recorded fingerprint no longer vouches for
   those bytes, which may be a legitimate edit *or tampering*). The operator
   resolves explicitly via `pvfs resolve` (§9):
   - **`--replace`** — accept the new contents: create a new file node for
     them, move the location, and supersede the old home link
     (`LinkSuperseded`); the old node is kept as a reviewable orphan with its
     history.
   - **`--delete`** — treat it as untrusted: soft-remove the old node's links
     and locations (orphan it for review); with `--purge`, hard-delete it via
     the P0 purge protocol in the same step. The on-disk file is **never**
     touched (PVFS does not own external bytes).
   A binding-level auto-resolution policy (e.g. `on_change: replace` for
   media libraries that re-encode constantly) is a future option; P1 is
   manual-only.
5. **Disk-deleted file** (node has an active location under this binding but
   the path is gone) ⇒ **soft**: `FileLocationRemoved` for that URI. If that
   was the node's last active location, the node is additionally flagged
   `unavailable` in the projection (queryable; surfaced by `stat`/`ls`). The
   node, its metadata, and its links are kept (design doc §8.5) — PVFS does
   not own external bytes.

> ~~[OPEN-2]~~ **Decided** (§11 item 2) — same-node metadata refresh is
> impossible by design; changed bytes flag the node **`invalid:
> changed-on-disk`** and the operator resolves via `pvfs resolve --replace`
> (successor node + `LinkSuperseded` trail, locations moved) or
> `--delete [--purge]` (§4.4).

Scan is **transactional per file** (a crash mid-scan leaves a valid partial
index; the next reconciliation completes it) and **idempotent** (event
idempotency from P0 §7 absorbs re-runs).

### The settle window

A file that is still being written must NOT be catalogued: identity is by exact
size, so recording a half-copied file records a wrong size and then confidently
mis-identifies it ever after. The scan therefore DEFERS any file that changed
within `WATCH_SETTLE_MS` (15s) — counted as `settling`, never dropped, and
picked up by a later pass.

**The test is `max(mtime, ctime)`, not mtime.** mtime alone reads as "has it
stopped moving?" only for a writer that lets mtime advance — true of a local
copier like Sonarr, false of anything that back-dates the destination. rclone
preserves the SOURCE mtime, so a file that landed thirty seconds ago can carry
an mtime from two days back and clear the window on its first sighting.
Measured on the production holder (2026-09-08): arrivals whose mtime sat 41.8h
and 56.5h BEHIND their ctime, each catalogued mid-copy at a partial size, each
then failing the identity match against the node another box had already made —
which is where several hundred duplicate pairs came from.

ctime is set by the kernel on every content or metadata change and cannot be
back-dated from userspace (`utimes` moves mtime and atime, never ctime), so it
answers the question the window is actually asking: when did these bytes last
change *here*. A one-shot `pvfs scan` passes `settle_ms = 0` and indexes what is
on disk now; the window is the WATCHER's concern.

Scan stats are returned and printed: `added / unchanged / changed / removed /
skipped`, plus — as later milestones gave the scan more it could do and more it
had to explain — `relocated`, `settling`, `unreadable`, `empty_dirs`,
`unlinked` (nodes taken OUT OF THE TREE, distinct from `removed` locations,
D105), `pending_unlink` (held nowhere but inside the grace, D112) and
`ambiguous` (already catalogued more than once here, so nothing was added,
D113). A count that exists and is never printed is a count nobody can act on;
each of these was added because a scan was otherwise silent about something it
had decided.

---

## 5. Read path — `cat` & integrity

`cat(node)` (engine: `open_bytes(node_id, range)`):

1. Collect active locations; resolution order (federation doc §2.3, P1 subset):
   local `file://` first; no other schemes in P1 (P1 subset — doc 17 §7.2/§7.3
   has the current scheme set: `pvfs-tmp:///`, `pvfs-sync:///`,
   `pvfs-host://<pin>/` and candidate ordering).
2. `stat` each candidate until one exists; none ⇒ `Unavailable` error listing
   tried URIs.
3. Stream bytes. **Integrity check (ADR §6):** if the node has a non-empty
   `content_hash` and the read is **full-file**, hash while streaming and
   compare at EOF; on mismatch the bytes already sent are followed by an error
   (CLI: non-zero exit, partial-output warning on stderr) and the location is
   **quarantined** (see [OPEN-3]). Range reads over an **attested** file verify
   per 8 MiB chunk against the recorded manifest (since built: doc 22 §2);
   unattested files still skip range verification (can't hash a fragment).
4. Empty `content_hash` (lazy, never hashed) ⇒ serve without verification;
   `pvfs hash <node>` fills the hash (one streaming pass; per the §11 item 2
   decision the hash lives in the payload, so hashing creates a successor node
   exactly like a changed file).

> **Decided — local quarantine.** A failed check writes to the local
> `location_quarantine` table (§8) — corruption is an observation about *this*
> machine's view of the bytes, not forest history, so it is never a log event.
> Quarantined locations are skipped by resolution and surfaced by `stat` and
> `pvfs changes`. `pvfs loc verify <file>` re-hashes and lifts the quarantine
> when the bytes match again (e.g. after restoring from backup). An index
> rebuild clears the table; the next read/verify re-discovers any persisting
> corruption. (A future tiered escalation to a signed event for
> operator-confirmed tampering can layer on without model changes.)

---

## 6. Daemon (`pvfs serve`) & watcher

- `pvfs serve` runs in the foreground: a **`notify`-based watcher** on every
  bound folder with `auto_index`, plus a **reconciliation pass** at startup and
  every `reconcile_interval` (default 1h), plus the temp-spool sweep at start.
- Watcher events are debounced (default 2s) and fed through the same ingest
  path as scan steps 1–5.
- **Live-writer discipline** (since built): writer engines hold a shared
  flock on `<data_dir>/writer.lock`; a CLI open that finds a live writer
  catches up instead of crash-rebuilding. `serve.lock` is only the watcher's
  own single-instance lock — one daemon per data dir. One-shot CLI commands
  remain usable while the daemon runs (SQLite WAL; writes serialize via busy
  timeout).
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
-- bindings are events (FolderBound / FolderUnbound) — decided, §11 item 1:
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
CREATE TABLE pending_changes (   -- "invalid: changed-on-disk", awaiting resolve (§4.4)
  file_id     TEXT NOT NULL,
  uri         TEXT NOT NULL,
  old_size    INTEGER NOT NULL,
  old_mtime   INTEGER NOT NULL,
  new_size    INTEGER NOT NULL,
  new_mtime   INTEGER NOT NULL,
  detected_at INTEGER NOT NULL,
  PRIMARY KEY (file_id, uri)
);
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
(decided, §11 item 1): `FolderBound`, `FolderUnbound` — signed like all
mutable events, root-or-device authored, replicated.

---

## 9. CLI additions

```
pvfs bind <folder-id> <dir> [--no-recursive] [--no-auto-index]
                            [--extensions mkv,mp4] [--hash-policy on_add|never]
pvfs unbind <folder-id>
pvfs scan [<folder-id>]        # all bound folders if omitted
pvfs stat <node-id>            # node + locations + availability + quarantine
pvfs cat <node-id> [--range A-B] [-o FILE]
pvfs hash <node-id>            # fill a missing content_hash (a `never` binding, or pre-D94 nodes)
pvfs loc verify <file-id>      # re-check quarantined/all locations
pvfs changes                   # list nodes flagged invalid: changed-on-disk
pvfs resolve <node-id> --replace | --delete [--purge]   # operator decision (§4.4)
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
4. **Disk deletion** — file removed on disk ⇒ location soft-removed. **The node
   goes too, if the file ends up held NOWHERE and stays that way for
   `UNLINK_GRACE_MS` (24h)** — D105 as amended by D112. This clause used to end
   "node kept, flagged unavailable", which left production carrying 1,849 node
   records from a single removed folder, in no report an operator reads.

   Three conditions, and each earns its place. The mount must be PROVEN live by
   its `.pvfs-root` marker (D81), or an unmounted volume looks like a deletion.
   No other box may hold the file, or one box evicting its copy deletes the file
   for everyone. And the grace must expire, because "no live location" is a
   routine transient state on a fleet whose mover works outside the catalogue —
   between one box retiring its location and another recording its own, a file
   that exists has none at all. `pvfs missing` IS the pending list.

   A file restored inside the grace re-adds its location and the clock stops.
   Restored AFTER it, the node is gone and the bytes come back as a NEW node: a
   deletion is a decision, and `match_by_identity` joins only on nodes with a
   live containing link.
5. **Changed file** — modification flags the node (`pending_changes`) and the
   stale location is not served; `pvfs changes` lists it; `resolve --replace`
   creates the successor node + `LinkSuperseded` trail and clears the flag;
   `resolve --delete` orphans the old node (`--purge` hard-deletes); the
   on-disk file is never modified by either path.
6. **Read path** — cat streams correct bytes; corrupted bytes detected
   (hash mismatch) ⇒ error + quarantine per [OPEN-3]; quarantined location
   skipped on next read; `loc verify` lifts quarantine after repair; range
   reads work and skip verification.
7. **Hash policy** — `on_add` hashes at bind/scan; `never` leaves nodes unhashed and `pvfs hash` fills and persists; `lazy` is refused (D94).
8. **Watcher** — create/modify/delete on disk reflected while `serve` runs;
   debounce coalesces bursts; events while daemon stopped are caught by the
   startup reconciliation.
9. **Temp spool** — managed temp bytes only in `<data_dir>/tmp/`; crash leaves
   stale spool file ⇒ swept at next open; rebuild empties temp ⇒ spool emptied;
   external file:// of a temp node untouched by sweep.
10. **Daemon lock** — second `serve` refuses; one-shot CLI works alongside.

---

## 11. Decisions (all settled)

1. ~~[OPEN-1]~~ **Decided:** folder bindings are signed events
   (`FolderBound` / `FolderUnbound`) + `folder_bindings` projection (§3).
2. ~~[OPEN-2]~~ **Decided:** changed files are **flagged invalid, never
   auto-resolved**; operator chooses `resolve --replace` (successor node +
   `LinkSuperseded` trail) or `resolve --delete [--purge]` (§4.4). New files
   are simply indexed into the tree position mirroring their on-disk location.
3. ~~[OPEN-3]~~ **Decided:** hash-mismatch on read ⇒ **local quarantine**
   (§5), never a log event; `pvfs loc verify` lifts it when bytes are repaired.

**All P1 decisions settled — this spec is ready to implement.**
