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

## 9. P10.0 build spec (turnkey)

### 9.1 Records are nodes — no new event kinds

The doc 13 pattern is literal: a typed record is a `NodeCreated` with a
custom `node_type` and an opaque payload. `pvos.download` and
`pvos.download.closed` are `AddNode`-shaped nodes, dot-labeled so listings
read clean:

- **Origin**: `node_type = "pvos.download"`, label
  `.pvos.download-<sid8>`, a child of the `IngestBegin` parent. Payload
  (JSON, well under the 64 KB daemon cap): `{"kind":"bittorrent",
  "infohash":"<hex>","piece_size":N,"root":"<node>","total_bytes":N}`.
  Author + timestamp ride the event itself — not duplicated. Routing:
  `NodeCreated`+`LinkCreated` under the parent resolves to the parent's
  region via the batch-homes walk — §8.2's consequence is structural.
- **Closed**: `node_type = "pvos.download.closed"`, label
  `.pvos.download.closed-<sid8>`, same parent. Payload
  `{"origin":"<origin-node>","outcome":"complete"|"aborted"}`. Batched
  into the last file's commit (or the abort) — one signed write, no
  second round-trip.

### 9.2 Catalog shape at add

Multi-file (or any `rel_path` with a `/`): one folder node (the torrent
name) under `parent`, intermediate folders as needed, one unhashed
pointer file node per entry (`FilePayload{content_hash:"", size_bytes}` —
the existing `AddFile` shape). Single bare file: the pointer node lands
directly under `parent`; the origin record's `root` is then the file node
itself. All of `IngestBegin` is **one prepared batch** (doc 07 §5): the
daemon returns preimages + the session layout, the client signs, the
standard `Commit` lands it. The session activates only when that commit
lands (the prepared-slot registry grows an optional activation hook).
Authority: `w` on `parent`, checked at prepare; intra-batch parentage
(files linking to the folder born in the same batch) resolves rights at
the nearest pre-existing ancestor.

### 9.3 Session state — deployment, never log

`<data>/ingest.sessions` (the `serve.rs` two-tier policy: corrupt at
startup = refuse, corrupt at reload = keep previous + warn):

```
pvfs-ingest-sessions 1
session <sid> <owner-pub-hex> <parent> <root> <origin-node>
file <sid> <node> <size> [<new-node>]
```

Per-file progress is a sidecar beside the partial —
`.{node}.progress` (safe from the tmp sweep, which only eats `.tmp`):

```
pvfs-ingest-progress 1
chunk 8388608
size <declared>
range <start> <end>          # app-verified bytes, coalesced
done <chunk-index> <64-hex>  # fully-covered chunks, BLAKE3'd at mark time
```

The bitmap is **authoritative, not cache** — which bytes the app's SHA-1
verification blessed is knowledge only the app had; the daemon persists
it at `IngestVerified` time. The `done` hashes are P10.1's serving
manifest for free. Partials use `swarm_part_path` (`.{node}.swarmpart`)
— sparse `set_len`, seek-and-write, survives the sweep and kill -9.

### 9.4 The six ops on the wire

| Op | Kind | Flow |
|---|---|---|
| `IngestBegin{parent,name,files,kind,infohash,piece_size,allow_shortfall}` | control | space preflight (`statvfs` on the store root: declared total + 256 MiB margin vs available; refuse unless `allow_shortfall`) → prepare batch → `IngestPrepared{session,root,origin,files[],prepared_id,preimages,result_id}` → client signs → standard `Commit` activates the session |
| `IngestWrite{session,file,offset}` + frames | data-plane (the `SecurePut` loop: zero-length frame terminates) | session-owner principal only; sparse partial created on first write; refuses past-EOF; ENOSPC = clean error, partial kept → `IngestWritten{bytes}` |
| `IngestVerified{session,file,ranges}` | control | merge ranges into the sidecar; hash newly covered chunks from the partial; reply `IngestProgress{bytes_verified,chunks_done,chunks_total}` |
| `IngestCommit{session,file}` | control | hash the partial (`hash_with_manifest`, no locks held) → prepared batch: successor events + `ChunkManifestRecorded` (+ closed record iff last file) → client signs → `Commit` → daemon publishes (`swarm_commit`: rename + sidecar) → `IngestCommitted{node}` (the successor id — handles re-identify) |
| `IngestAbort{session,keep_catalog}` | control | prepared batch: closed record (+ unlinks unless `keep_catalog`) → `Commit` → partials + sidecars removed, session dropped |
| `IngestList{}` | control | active-member gate; sessions + per-file `{node,size,bytes_verified,chunks_done,chunks_total,committed}` |

Commit ordering is load-bearing: `swarm_commit` hard-refuses unhashed
nodes and `attested_manifest_root` goes stale across successors — so
successor-then-attest-then-publish, always. A crash between the log
commit and the publish is recoverable: re-`IngestCommit` sees the node
already hashed and just re-publishes.

### 9.5 Authority

- Catalog writes: `w` on `parent` (prepare-time + `check_member_event`).
- The attestation inside commit: `a` on the file (existing
  `ChunkManifestRecorded` arm) — the app identity is admin-tier on its
  target subtree, the same bar the §4 early-serve license needs.
- `IngestWrite`/`Verified`/`Commit`/`Abort`: the session owner's
  principal only. `IngestList`: any active member.

### 9.6 Touch list

`pvfs-proto` (6 ClientMsg + 5 ServerMsg variants, `IngestFileWire`,
serde-default discipline) · `pvfs-core/src/ingest.rs` (sessions file +
progress sidecar IO) · `sync.rs` (`free_space_at`) · `engine.rs`
(`prepare_ingest_begin`, `prepare_ingest_commit`, `prepare_ingest_close`
— member-signed builders mirroring `prepare_add_node`; commit-time
authority for intra-batch parents) · `pvfsd` (`sessions` on `Daemon`,
`IngestWrite` in the data-plane pre-match, five `handle` arms, activation
hook on the prepared registry) · `pvfs-client` (six methods; the framed
one modeled on `secure_put`) · `pvfs-cli` (`pvfs ingest
begin|write|verified|commit|abort|list`, bare `pvfs ingest` = list,
prompts per the standing rule) · smoke §P10.0 (the fake downloader) ·
docs 07/USER-MANUAL touch-ups.

### 9.7 Smoke: the fake downloader (done means)

> Built and validated 2026-08-13 — close-out in §10.

Two-file "torrent" from `/dev/urandom` slices: begin (assert pointer
nodes + origin record in the tree) → oversized begin refuses / passes
with `allow_shortfall` → out-of-order `ingest write` slices → partial
`ingest verified` (progress rises; sidecar exists) → **kill -9 the
daemon mid-ingest, restart, `ingest list` shows the session with
progress intact** → finish writes + verify → commit file 1 (cat
roundtrip `cmp`s; manifest sidecar; `chunk_manifests` row via the
python3 sqlite3 probe) → commit file 2 (closed record, outcome
complete) → second session: begin, write, abort (partial gone, closed
record aborted, nodes unlinked). Then the standard pipeline bar: both
hosts green, clippy `-D warnings`, honest close-out here.

## 10. P10.0 close-out (honest, 2026-08-13)

**Validated:** 233 cargo tests + 366 smoke checks (22 new, the §9.7 fake
downloader) green on both hosts via the pipeline; clippy `-D warnings`
clean. The in-process e2e test (`pvfsd/tests/ingest.rs`) runs the whole
lifecycle: multi-node begin, out-of-order writes, incremental chunk marks,
commit re-identification with cat round-trip, closed records for both
outcomes, and the three refusals (no-rights begin, oversized begin,
past-EOF write). The smoke adds the kill -9 crash: restart reloads the
session and the bitmap answers `1 chunk, 6291456 B` exactly — resume state
is the sidecar, proven authoritative.

**Deviations from §9, recorded:**

- *"The file serves, tiers, exports"* — smoke proves serves (cat) and
  exports; tier is not exercised on an ingested file directly. Argument:
  after publish the file is a store-resident hashed file identical to any
  synced one (same layout, same sidecar), and tier/evict semantics are
  P8-validated on that shape. Fleet phase K (P10.1) can add the explicit
  cross-machine pass if wanted.
- The commit-freeze (writes refused while a commit's hash is trusted) is
  **in-memory with a TTL**, not persisted: a daemon restart drops it, and
  the crash-retry path compensates by re-verifying through `swarm_commit`'s
  full read. The normal path's publish skips the re-read on purpose — the
  daemon hashed those bytes moments earlier with writes frozen — keeping
  the writer lock O(1) instead of O(file).
- `IngestList` reports committed files as fully verified rather than
  reading their (deleted) progress sidecars.

**Latent defects found and fixed by this build:**

1. **`LinkSuperseded` was missing from `set_author_sig`** — the kind was
   owner-only until the member-signed hash-fill successor needed it, so the
   member's signature was silently dropped and commit failed "signature
   invalid". The 9-touchpoint event drill has a real 10th touchpoint:
   *is the kind in the member-signable `set_author_sig` set?*
2. **Live commits refused intra-batch parentage** that replay accepts:
   `commit_member_write` checks every event against the current projection,
   so a file linking under a folder born in the same batch was Forbidden
   live but fine on replay. Fixed with the batch-aware check
   (`check_member_event_batched`): rights on a batch-born node resolve at
   its nearest pre-existing ancestor — exact, since an unborn node can have
   no ACLs of its own. Replay is untouched; both paths reach one verdict.
3. Smoke-harness findings worth keeping: sqlite probes against a live
   daemon need read-only URIs + retries (a WAL race reads as a false zero),
   and a daemon restart must poll for an *answer* — the stale socket file
   from a kill -9 satisfies `-S` before the new daemon binds and while the
   crash rebuild runs. The P9.1 `M2PID` cleanup-registration gap noted in
   passing was also fixed.

**Not in P10.0 (P10.1's list, unchanged):** the mount does not yet consult
progress sidecars, ranged `Cat` does not serve marked chunks of in-flight
partials, and `IngestList` has no hot ranges — in-flight bytes are not yet
readable by anyone but the ingesting app. The `done <idx> <hash>` sidecar
lines are already the serving manifest P10.1 needs.

## 11. P10.1 build spec (turnkey)

**One seam serves everyone.** Every in-flight read — local mount, remote
mount, a fleet box pulling early chunks — goes through **ranged `Cat` on
the ingesting daemon**. That is where the partial and the authoritative
bitmap live, so it is where three things happen exactly once:

1. **The early-serve license** (§3): before serving an in-flight file,
   `do_cat` checks the session owner (= the origin record's author) holds
   admin on the file. No attestation exists yet by design; this is the
   §4 trust chain's enforcement point.
2. **The wait**: a request whose covering chunks are not yet marked
   blocks server-side (200 ms polls of the sidecar, 60 s cap, engine lock
   never held), then streams from the partial. `CatStart` is sent only
   when bytes are ready, so old clients interoperate unchanged.
3. **Demand feedback (§8.1)**: every wait registers its byte range in the
   daemon's ingest state; `IngestList` reports them as per-file
   **`hot` ranges** (additive wire field). Hitting play on a
   half-downloaded file surfaces in the app's next poll — the signal it
   maps to sequential piece priority. Ranges expire with the wait.

**The mount becomes a thin proxy for in-flight files.** `open` on an
unhashed pointer node with no local bytes dials the serving daemon — the
replica's recorded source on a replica mount, the forest's own
conventional socket (device-key-signed) on the owner box — and each
`read` forwards as a ranged `Cat`, which waits server-side. No local
partial, no second progress plumbing, license enforced in one place.
(`mount: ingest-stream` on stderr is the which-path-ran marker.)

**Deliberately not in P10.1:** full swarm-fetch of in-flight files
(parallel multi-holder pulls against a partial manifest) — the serving
seam is the same ranged `Cat` the swarm workers speak, so that
integration stays open without new wire ops. `ChunkManifest` still
answers only for on-disk bytes.

**Touch list:** `pvfs-proto` (`IngestFileWire.hot`, additive) ·
`pvfsd` (`do_cat` in-flight source + license + wait, hot-range registry,
`IngestList` reporting) · `pvfs-fuse` (proxy handles) · `pvfs-cli`
(`remote cat --offset --len`, `ingest list` prints hot) · e2e test
(blocked reader surfaces a hot range, unblocks on `IngestVerified`,
license-refusal negative) · smoke §P10.1 · fleet **phase K**: owner
ingests out of order; the edge blocks reading chunk 0, the hot range
shows in `IngestList`, the owner verifies chunk 0 and the edge's bytes
arrive correct; a third box pulls the already-marked chunk mid-ingest.

## 12. P10.1 close-out (honest, 2026-08-13)

**Validated:** 235 cargo tests + 369 smoke checks green on both hosts via
the pipeline, clippy `-D warnings` clean, and the two-machine fleet at
**89/89** — phase K ran the §11 arc on real machines: the owner ingested
out of order, the edge pulled the marked chunk mid-ingest bit-perfect,
its blocked read on the unmarked chunk surfaced as `hot [[0,4096]]` in
the owner's `IngestList`, verifying that chunk unblocked it with the
right bytes, a consumer FUSE mount proxied the in-flight file over the
LAN (`mount: ingest-stream`), and the commit closed the ledger with the
edge reading the finished file whole. The e2e test carries the
license-negative: a `w`-only member's session is refused early serving.

**Latent defect found and fixed by this phase's validation — the
P7.2b replica-ingest race.** Fleet phase H failed intermittently
(`PRIMARY KEY constraint failed`, twice in four runs): the follow job's
sweep and a manual `replica sync` legitimately ship the same tail
concurrently, and both `ReplicaStore::append` and `append_region` read
the tip *before* taking the write transaction. Fixed: immediate
transaction first (10 s busy wait), tip read inside it, and overlap rows
verified byte-identical against the stored chain then skipped — a
diverging row for an existing seq still refuses at its exact seq.
Regression test `overlapping_ship_is_a_verified_noop`. This bug predates
P10 (shipped with P7.2b); the fleet's tighter timing this phase surfaced
it.

**Harness findings, recorded for the next author:**
- The fleet's `jget` reads stdin; the smoke's takes args. Passing JSON as
  an argument to the fleet's makes it eat the rest of the heredoc and the
  block dies silently — phase K now documents the convention in place.
- A consumer mount opened right after `replica sync` replays the fresh
  tail before answering; phase K's directory poll needed 15 s, not 10.
- Phase K's `eval` harvests are defaulted so a failed sub-block degrades
  into readable FAILs instead of `set -u` aborts; G1's export and H's
  seal sync now capture their stderr into the fail message (that
  instrumentation is what converted "flaky" into the PK-race diagnosis).
- One pipeline play failure on presubuntu and one G1 export failure
  (run 2) did not reproduce and remain unattributed; both paths are now
  instrumented, so a recurrence will name itself.

**Scope note:** the chaos suite was not re-run — P10.1 touches no
crash/rebuild path (the replica append was transactional before and
after; the ingest wait loop holds no locks). The commit-freeze and
publish semantics are unchanged from §10.

## 13. P10.2 — the same-box fast path (requested by PVOS D62, 2026-08-13)

§3's parked "same-box fast path (optimization, later)" is promoted: the
D62 Torrents app gives torrent bytes exactly one home by pointing its
BT engine's storage at the ingest partial — no spool, no double disk.

**The change, additive:** `IngestFileWire` grows
`partial_path: Option<String>` (serde-defaulted — P10.0/P10.1 peers
interop unchanged), filled by `IngestBegin` and `IngestList` **only on
Unix-socket connections**. A TCP caller gets `None`: a server-internal
filesystem path is useless off-box and handing it out anyway would leak
layout to remote members — same-box capability, same-box answer. The
path is deterministic (`.{node}.swarmpart` beside the store destination),
returned before any byte exists; the session's activation pre-creates
the shard directory so the app's first `open(create)` just works.
`IngestWrite` stays, unchanged, for cross-box callers.

**Contract for direct writers:** create sparse, write at offsets, and
report ranges via `IngestVerified` exactly as before — the daemon still
hashes covered chunks from the partial and the commit still re-reads the
whole file, so the trust story is untouched (the bytes' author never
matters; the hashes do). Commit renames the partial away — the app's
storage layer must tolerate the file vanishing at commit (D62 records
this constraint on its side).

**Done means:** e2e — begin over the socket returns the path, bytes
written directly to it (out of order) mark chunks via `IngestVerified`
and commit round-trips bit-perfect; smoke drives one file of the fake
torrent purely through the fast path; pipelines green on both hosts;
PVOS (path-dependent on these crates) still builds.

> **P10.2 close-out (2026-08-13):** built as specified above — no
> deviations. 236 cargo + 372 smoke green on both hosts via the pipeline,
> clippy `-D warnings` clean; the e2e fast-path test writes directly at
> the returned path (tail-first), marks via `IngestVerified`, commits
> bit-perfect, and confirms the partial is renamed away at commit (the
> D62 storage-shim contract); the smoke drives one file of the fake
> torrent purely through the fast path; PVOS `cargo check`s clean against
> the changed crates (scratch tree — its own deploy copy was left alone).
> The B1 gate on the PVOS side is now open.
