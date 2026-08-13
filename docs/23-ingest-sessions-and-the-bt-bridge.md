# 23 — External-ingest sessions & the BitTorrent bridge (P10 candidate)

**Status: APPROVED (Chris, 2026-08-13) — the four §8 questions are decided
and folded into §3/§7 below.** Prerequisite reading:
doc 22 (the swarm + attested streaming — the machinery this generalizes),
doc 21 (attachment kinds), doc 13 (typed log-resident records).

## 1. The end state (Chris, 2026-08-13, requirements verbatim)

- **PVFS provides the API**; the BitTorrent engine lives in a **PVOS app**.
- The PVOS app accepts requests from **radarr/sonarr, manually downloaded
  .torrent files, magnet links, etc.** and manages the download queue.
- **Streaming starts as quickly as possible** — files play while their
  torrents are still downloading.
- **Seeding is managed from the PVOS app**, with max-seed-time / max-ratio
  set in its UI.
- Downloads land **into the media app's tree or other requested locations**.

## 2. Division of labor

| PVFS (this repo, arc P10) | The PVOS BT app (separate effort) |
|---|---|
| Ingest-session wire API on `pvfsd` | BitTorrent protocol: peers, DHT, trackers, uTP (embed a Rust engine, e.g. librqbit) |
| Catalog-at-add: files visible in the tree before bytes exist | Queue management, priorities, bandwidth caps |
| Partial storage + crash-safe resume (the `.swarmpart` discipline) | *arr intake — present a qBittorrent-compatible RPC so radarr/sonarr work unmodified |
| Verification, publish gate, hash-fill, attestation (all existing paths) | Piece (SHA-1) verification against the infohash |
| Streaming of in-flight files (mount + fleet swarm) | Seeding policy: max time / max ratio, per-torrent overrides |
| Ranged byte reads for seeding (P9.0's ranged `Cat` — already built) | UI |

Nothing BitTorrent-specific enters `pvfs-core`. The API is a general
**external-ingest seam**: the BT app is its first consumer, but an HTTP
download manager, a camera importer, or any bytes-producing app uses the
same five operations.

## 3. The ingest session (the P10 API)

All operations are member-signed daemon ops in the doc 07 §5 two-phase
style where they touch the log.

- **`IngestBegin`** `{ parent, files: [{rel_path, size}], origin }` — creates
  the catalog subtree immediately: a folder per multi-file torrent, one
  **unhashed pointer node** per file (name + size from the metainfo — the
  files appear in the tree, listable and placeable, before a byte arrives).
  `origin` is a typed **log-resident record** (doc 13 pattern —
  `pvos.download`): kind (`bittorrent`), the **infohash**, piece size, the
  subtree's root node id, added by whom, when — **one record per torrent,
  no file list inside it** (§8.2; the catalog nodes are the list). Returns
  a session id + per-file handles. Because downloads are log records, the
  whole fleet can see what's downloading.
  - *Space preflight (§8.3):* refuses when the declared total exceeds free
    space (with margin) at the partial destination; `allow_shortfall`
    overrides at the caller's risk.
  - *Authorization:* cataloging needs `w` on the parent. The **early-serve
    license** (§5) requires the origin record's author to hold `a` on the
    target subtree — the same bar as doc 22 §2's attestation, for the same
    reason: early bytes are trusted against the origin's hash chain instead
    of the whole-file gate.
- **`IngestWrite`** `{ session, file, offset }` + binary data frames (the
  `SecurePut` framing pattern) — bytes land in the file's sync-store
  partial. Out-of-order and duplicate writes are fine; the partial is
  sparse. **Disk-full is a clean pause, never poison** (§8.3): the write
  errors, the session stays resumable from the bitmap. *Same-box fast path
  (optimization, later):* `IngestBegin` may return the partial's local
  path to a caller with filesystem access.
- **`IngestVerified`** `{ session, file, ranges }` — the app reports byte
  ranges whose torrent pieces verified against the infohash. `pvfsd` then
  BLAKE3-hashes any 8 MiB PVFS chunks now fully covered by verified ranges
  and marks them in the file's **progress sidecar** (`.{id}.progress`, a
  chunk bitmap beside the partial) — the piece→chunk bridge, incremental
  and cheap. These chunk marks are what license streaming (§5).
- **`IngestCommit`** `{ session, file }` — the existing trust gate, reused
  whole: whole-file BLAKE3 over the partial → **hash-fill successor node**
  (the lazy-hash machinery — the pointer node graduates to a hashed one) →
  atomic publish into the store → `ChunkManifestRecorded` attestation →
  manifest sidecar. From here the file is indistinguishable from any other
  PVFS file: it tiers, mirrors, exports, swarms. When the session's **last
  file** commits, a **`pvos.download.closed`** record `{origin ref,
  outcome: complete}` closes the ledger entry (§8.4).
- **`IngestAbort`** `{ session, keep_catalog }` — partials and progress
  removed; catalog nodes kept as bare pointers or unlinked, caller's
  choice; a `pvos.download.closed` record `{origin ref, outcome: aborted}`
  is authored so the origin record never dangles (§8.4).
- **`IngestList`** — sessions with per-file progress, so the app re-attaches
  after either side restarts. Sessions are **deployment state** (a
  `sessions` file beside `placement`/`serve.jobs`); partials already survive
  restarts by the `.swarmpart` discipline, so resume is: re-verify the
  progress bitmap against the partial (a local read), continue. From P10.1
  it also reports per-file **hot ranges** — chunks a mount reader is
  currently waiting on — the demand signal the app maps to sequential
  piece priority (§8.1).

## 4. Streaming as quickly as possible (the requirement that shapes it)

Two consumers serve in-flight ingest bytes, both keyed off the progress
sidecar:

- **The mount** (P9.1 generalized): today the streaming mount tracks its
  own in-process fetches via `SwarmProgress`; it grows a second source —
  progress sidecars written by `pvfsd` for ingest sessions. A read waits
  until its covering chunks are marked, then serves from the partial.
  First playable bytes arrive as soon as the app has verified the pieces
  covering chunk 0 — for sequentially-prioritized torrent downloads (the
  app's choice), that is seconds into the download.
- **The fleet swarm** (emergent, free): ranged `Cat` learns to serve marked
  chunks of an *in-flight* partial. A box still torrent-downloading a file
  is already a verified seed for every other box's swarm fetch — media
  arrives on the download box and the living room box at the same time.

**Trust statement, explicitly:** early bytes are licensed by the chain
*admin-authored origin record → infohash → SHA-1 pieces → covered BLAKE3
chunks*. The final `IngestCommit` still records what actually arrived under
the catalog's own hash and attests the chunk layout — the permanent record
never rests on the torrent's hashes. A poisoned torrent yields exactly what
it would in any client: wrong bytes, honestly cataloged, deletable.

## 5. Seeding (app-managed, PVFS-agnostic by construction)

The app seeds by reading pieces back through **ranged `Cat`** — built in
P9.0, random-access, location-agnostic. That last property quietly solves
the hard case: after `IngestCommit`, the mover may migrate the bytes to the
central store and evict the local copy — and seeding never notices, because
the daemon resolves whatever location is live. Max-time/max-ratio live
entirely in the app's UI and state; PVFS holds no seeding policy.
*Guidance for the app:* torrent targets should be ordinary (in-place) or
mirror subtrees; migrate-kind staging works too, since post-migration reads
fall through to the central copy.

## 6. What PVFS deliberately does not do

No BitTorrent protocol, no queue, no *arr emulation, no seeding policy, no
UI, no bandwidth shaping. One seam, five-and-a-half operations, all trust
machinery reused from docs 04/22.

## 7. Phases (once approved)

| Phase | Deliverable | Done means |
|---|---|---|
| **P10.0** | Ingest sessions end to end: the six wire ops, sessions file, partials + progress sidecars, commit = hash-fill + attest + publish; space preflight + `allow_shortfall`; `pvos.download.closed` on commit and abort | smoke: a scripted fake downloader writes ranges out of order, verifies, commits; the file serves, tiers, exports; kill mid-ingest resumes from the bitmap; an oversized add refuses; abort + commit both leave closed records in the log |
| **P10.1** | In-flight streaming: the mount consults progress sidecars; ranged `Cat` serves marked chunks of partials; `IngestList` hot ranges (mount demand → app piece priority) | fleet phase K: owner ingests out of order while the edge's mount streams the early chunks and a third box swarm-pulls marked chunks mid-ingest; `IngestList` shows the hot range while the edge's reader waits |
| **App** | The PVOS BT app (separate effort, consumes this API) | out of scope here |
| **Validate** | pipeline both hosts + fleet, per phase | all green; honest §8 close-out |

## 8. Decisions (Chris, 2026-08-13)

1. **Sequential priority: the app's business — but the API reports demand
   back.** No "streaming intent" hint on `IngestBegin`; the API stays
   byte-agnostic. Instead, `IngestList` grows per-file **hot ranges** —
   chunks a mount reader is currently blocked on (the mount records live
   demand beside the progress sidecar; `pvfsd` reads it). The app maps hot
   ranges to sequential/high piece priority, so hitting play on a
   half-downloaded file reprioritizes its torrent automatically — no UI,
   no at-add guessing. Radarr-queued background downloads stay
   rarest-first. Lands with the streaming phase (P10.1).
2. **Origin record: one per torrent** (session-level), mirroring the
   torrent's own identity — the infohash covers the whole torrent and
   pieces are defined over its concatenated byte stream. The record
   carries the infohash, piece size, and the subtree's root node id —
   **not the file list** (events cap at 64 KB and a season pack would blow
   it; the catalog nodes created in the same commit *are* the file list).
   Accepted consequence: a region-scoped replica lacking the record's
   region can't verify the early-serve license and falls back to safe
   blocking reads.
3. **Refuse at add when the bytes can't land.** `IngestBegin` fails when
   the declared total exceeds free space (with margin) at the partial
   destination. An explicit `allow_shortfall` override exists for "space
   will free in time" — caller's risk, never the default. Independent of
   the check: **ENOSPC mid-session is a clean pause, never poison** —
   `IngestWrite` errors, the session stays resumable from the bitmap.
4. **No orphaned download records.** Every `pvos.download` origin record
   is closed by a **`pvos.download.closed`** record `{origin ref, outcome:
   complete | aborted}` — authored when the session's last file commits,
   or at `IngestAbort`. The ledger is self-contained: any box can
   distinguish in-flight from finished from abandoned by the log alone.
