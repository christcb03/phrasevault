# 22 — The swarm data plane: all-holder parallel reads (P9)

**Status: BUILD SPEC (2026-08-12) — implementation follows immediately; every
decision here is recorded before code, deviations land in §6 honestly.**
Prerequisite reading: doc 20 §6 (the promoted arc + Chris's requirement,
verbatim: reads pull **from every known holder in parallel, BitTorrent-style,
for the fastest possible read**), doc 21 §3.3 (mirror copies join the seed
set), doc 17 §7.3 (the F5.2 single-source Fetcher this upgrades).

## 1. Goal

One fetch, every holder: a file's bytes arrive as verified chunks pulled
concurrently from all reachable instances that hold them, into the same
chaos-validated sync-store sink used today. Falls out by construction:
**resumable transfers** (the recorded chaos caveat — a killed 3 GiB fetch no
longer restarts from zero) and, in a second phase, **serve-while-fetching**
mount reads (punch J).

## 2. The trust model — deliberately unchanged in P9.0

The catalog's content hash remains the ONLY trust anchor. Chunk manifests are
**computed from bytes and served unsigned** by any holder; per-chunk hashes
steer parallelism, early bad-holder rejection, and resume — nothing else. The
assembled file must still pass the existing whole-file verify-then-rename
gate before a byte is published or a location logged. A lying manifest or a
corrupt chunk therefore costs a retry, never integrity. Files without a
catalog hash fall back to today's single-stream path.

**Serving bytes EARLY is different**: handing a reader chunk N before the
whole file verifies means trusting the chunk layout itself. That requires the
owner to attest the manifest (a logged `ChunkManifestRecorded { file_id,
content_hash, chunk_size, manifest_root }` event; the manifest travels as a
sidecar and verifies against the root, chunks against the manifest — custody
closed). That is **P9.1**, where punch J's serve-while-fetching lands; P9.0
keeps the mount's block-until-verified behavior.

*P9.1 mechanics (2026-08-13, written at build start):*
- **Authorization is admin-tier** (replay requires `a` on the file, like
  region ops): early serving trusts the attested layout INSTEAD of the
  whole-file gate, so a write-tier member must not be able to attest — a
  bogus root would leak garbage bytes to early readers before the final
  verify caught it. The attestation also **binds the content hash** it
  describes; consumers check it against the node's payload before trusting.
- **Attested at hashing time**: wherever the engine computes a file's content
  hash from its bytes (scan under `on_add`, the lazy hash fill), it computes
  the chunk root in the same read and appends the attestation in the same
  commit. Files hashed before P9.1 carry no attestation and keep the
  blocking mount behavior (a re-scan/re-hash attests them).
- **No new wire**: the manifest ships as before; the TRUSTED root arrives
  with the log. A consumer verifies manifest-against-root, then
  chunks-against-manifest, and may serve each chunk the moment it lands.
- **The mount serves while fetching**: opening an unfetched attested file
  starts a background chunked fetch (chunked even with ONE holder — same
  wire cost, and it buys progress + resume); each `read` waits only for the
  chunks covering its range. Unattested files block-until-verified exactly
  as today.

## 3. Mechanics (P9.0)

- **Chunks**: fixed 8 MiB, BLAKE3 per chunk. A manifest = the ordered chunk
  hash list; `manifest_root = BLAKE3("pvfs:manifest:v1:" || concat(hashes))`.
- **Sidecars at the sink**: every sync-store ingest computes chunk hashes
  inline while streaming (near-free) and writes `<store>/<xx>/<id>.manifest`.
  Holders serving pre-existing bytes (bound dirs, central stores) compute and
  cache the sidecar on first request.
- **Wire (additive)**: `Cat` grows `offset`/`len` (`0,0` = whole file — old
  peers unchanged); new `ChunkManifest { node }` →
  `ServerMsg::ChunkManifest { size, chunk_size, hashes }`. A holder that
  cannot answer (old binary, no bytes) fails the request; the fetcher falls
  back to the single-stream path.
- **Seed set**: what the Fetcher already dials — the recorded source plus
  every instance-pinned holder in the file's locations. Doc 21 mirrors join
  as *intra-host* redundancy through their instance (a mirror store on
  another box surfaces as that box's pinned location); no new discovery
  mechanism in P9.0, honestly noted.
- **The swarm pull**: manifest from the first responsive holder; a sparse
  `.{id}.swarmpart` partial in the sync store; one worker per holder (their
  own connections), chunks handed out round-robin, each verified against the
  manifest on arrival and written at its offset; a failed chunk requeues for
  another holder, a dead holder leaves the pool. When all chunks land: the
  existing gate — whole-file hash verify, atomic rename, location logged.
  One holder or a two-chunk file = today's single-stream path (no regression
  surface for the common small case).
- **Resume, stateless**: `.swarmpart` partials are excluded from the startup
  tmp sweep. On a fresh fetch attempt the fetcher re-verifies existing chunks
  from the partial against the manifest (a local read) and fetches only the
  rest — kill -9 at any point costs only the in-flight chunks. The chaos
  suite grows a kill-mid-swarm scenario asserting byte reuse.
- **Report**: the fetch result carries per-holder chunk counts, so the fleet
  test can assert every seed actually contributed.

## 4. What this deliberately is not (P9.0)

No DHT/discovery (the instance registry is the world), no upload scheduling or
choke logic (holders are trusted-cooperative daemons on a LAN), no rarest-first
(round-robin is enough at fleet scale), no per-chunk wire signatures (§2), no
mount changes (P9.1).

## 5. Phases

| Phase | Deliverable | Done means |
|---|---|---|
| **P9.0** | sidecars at the sink, ranged `Cat` + `ChunkManifest` wire, the swarm Fetcher with resume | smoke: two local holders, swarm pull, both contribute; kill-resume keeps bytes; fleet phase J: 3 GiB from two real boxes faster than the best single stream, both seeds contribute; chaos: kill mid-swarm resumes |
| **P9.1** | `ChunkManifestRecorded` attestation + FUSE serve-while-fetching (punch J) | first mount read of an unfetched file streams as chunks verify; unattested files keep blocking behavior |
| **Validate** | pipeline both hosts + fleet + chaos, per phase | all green; honest §6 close-out |

## 6. Close-out

**P9.0 landed (2026-08-12)** — validated: 227 cargo tests + 339 smoke on both
hosts, clippy clean, fleet **72/72** including phase J on real hardware: a
1 GiB file as 128 chunks, **73 pulled from the owner across the LAN and 55
from the edge-local holder concurrently**, reassembled bit-perfect in ~20 s;
a kill -9 mid-swarm left the `.swarmpart`, and the retry **resumed 22/128
chunks** and completed from both holders. Findings, honestly:

- **The mover and the swarm interact exactly as doc 21 §3.3 predicted, and
  phase J proved it the hard way**: a second holder's `--here` location under
  a `central`-placed subtree is *retired by the tier job within seconds* (the
  §7.10 consolidation contract), collapsing the seed set to one. Durable
  swarm seeds are exactly the locations the mover never retires — doc 21
  **mirror** copies and in-place bindings. The fleet's swarm target lives in
  its own in-place binding for this reason.
- **Publishes must never re-read**: the first build computed the sidecar by
  re-reading the published file — a second 3 GiB read inside the edge's sync
  job that blew the fleet's timing windows. Chunk hashes are now computed
  inline as bytes stream (the sink), and a swarm publish reuses the manifest
  it verified against. Same lesson, smaller: the applied-marks seed row was
  an unconditional write on EVERY engine open; it is probe-then-insert now.
- **Workers get three strikes**: a holder mid-fold can transiently fail one
  chunk; retiring it on the first miss silently degraded a swarm to a single
  stream. Requeue-with-strikes keeps good seeds in the pool.
- Ops note: the fleet's G-phase 120-second windows are tight on the slow box
  when runs are stacked back-to-back; a clean run passes end to end.
- **P9.1 landed (2026-08-13)** — validated: 227 cargo + 344 smoke on both
  hosts, clippy clean, fleet **75/75**, with the arc-closing checks on real
  hardware: the edge's mount **served the first MiB of an unfetched 1 GiB
  file in ~2 s while the fetch was still in flight**, on the attested
  streaming path (punch J, retired). As built: `ChunkManifestRecorded`
  (admin-gated replay, binds the content hash; folded into
  `chunk_manifests`, schema v7) is authored wherever a content hash is
  computed from bytes — scan under `on_add`, resolve-replace, the lazy hash
  fill — in the same read (no second pass). The mount's open of an
  unfetched attested file spawns a background chunked fetch (chunked even
  with one holder) and each `read` waits only for its covering chunks via
  the shared `SwarmProgress`; unattested files keep block-until-verified.
  Files hashed before P9.1 attest on their next re-hash. Honest note: the
  single-box smoke cannot exercise serve-early (a same-host replica
  resolves the owner's `file://` path locally and rightly never fetches) —
  the fleet carries that proof; the smoke pins attestation shipping and
  read correctness. And pvos-test earned its keep once more: it has no
  `sqlite3` CLI, which taught the smoke to probe through python instead.
