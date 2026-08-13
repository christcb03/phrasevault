# 23 — External-ingest sessions & the BitTorrent bridge (P10 candidate)

**Status: DRAFT for Chris's review (2026-08-13).** Prerequisite reading:
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
  `pvos.download`): kind (`bittorrent`), the **infohash**, piece size, added
  by whom, when. Returns a session id + per-file handles. Because downloads
  are log records, the whole fleet can see what's downloading.
  - *Authorization:* cataloging needs `w` on the parent. The **early-serve
    license** (§5) requires the origin record's author to hold `a` on the
    target subtree — the same bar as doc 22 §2's attestation, for the same
    reason: early bytes are trusted against the origin's hash chain instead
    of the whole-file gate.
- **`IngestWrite`** `{ session, file, offset }` + binary data frames (the
  `SecurePut` framing pattern) — bytes land in the file's sync-store
  partial. Out-of-order and duplicate writes are fine; the partial is
  sparse. *Same-box fast path (optimization, later):* `IngestBegin` may
  return the partial's local path to a caller with filesystem access.
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
  PVFS file: it tiers, mirrors, exports, swarms.
- **`IngestAbort`** `{ session, keep_catalog }` — partials and progress
  removed; catalog nodes kept as bare pointers or unlinked, caller's choice.
- **`IngestList`** — sessions with per-file progress, so the app re-attaches
  after either side restarts. Sessions are **deployment state** (a
  `sessions` file beside `placement`/`serve.jobs`); partials already survive
  restarts by the `.swarmpart` discipline, so resume is: re-verify the
  progress bitmap against the partial (a local read), continue.

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
| **P10.0** | Ingest sessions end to end: the six wire ops, sessions file, partials + progress sidecars, commit = hash-fill + attest + publish | smoke: a scripted fake downloader writes ranges out of order, verifies, commits; the file serves, tiers, exports; kill mid-ingest resumes from the bitmap |
| **P10.1** | In-flight streaming: the mount consults progress sidecars; ranged `Cat` serves marked chunks of partials | fleet phase K: owner ingests out of order while the edge's mount streams the early chunks and a third box swarm-pulls marked chunks mid-ingest |
| **App** | The PVOS BT app (separate effort, consumes this API) | out of scope here |
| **Validate** | pipeline both hosts + fleet, per phase | all green; honest §8 close-out |

## 8. Open questions (for the review)

1. **Sequential priority signaling** — should `IngestBegin` accept a
   "streaming intent" hint the app maps to sequential piece priority, or is
   that purely the app's business? (Lean: app's business; the API stays
   byte-agnostic.)
2. **Origin record shape** — one record per torrent (session-level, listing
   files) or per file? (Lean: per session, mirroring the torrent's own
   identity; per-file rows fold from it in the projection.)
3. **Quota/placement at add** — should `IngestBegin` refuse when the target
   subtree's placement can't hold the declared sizes? (Lean: refuse loudly;
   a half-downloadable torrent helps no one.)
4. **The `pvos.download` record's lifecycle** — retained forever as
   provenance (it is log-resident) with the session's *deployment* state
   deleted at commit, or also a completion record? (Lean: add-record only;
   completion is evident from the hash-fill successor + attestation.)
