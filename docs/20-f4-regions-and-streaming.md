# 20 — F4: region logs + the streaming mount (P7)

**Status: DESIGN (2026-08-11, authored overnight) — implementation follows the same
night; every decision here is a PROPOSAL for Chris's morning review, made explicit so
the build never blocked on an answer. Deviations land in §7 as phases close.**
Prerequisite reading: doc 13 §B (the *decided* region architecture), doc 17 §8
(F4's order), doc 11 (compaction — the per-region beneficiary), doc 03 §1.5/§6.

## 1. Goal

Two capabilities, in doc 17 §8's order:

1. **Region logs** (doc 13 §B): any node can be marked a region boundary; its subtree
   gets its own append-only signed log, parents commit child heads, and one root hash
   still attests the whole forest. Unlocks per-app replication ("ship the Photos
   region, not my life"), per-region compaction, and the future §A active-active.
2. **The FUSE streaming mount**: `pvfs mount <node> <dir>` — open-and-stream without
   prefetch; reads resolve locations live (local, sync store, read-through), so a
   consumer browses a pointer-mode library as a real filesystem. The materialized
   export stays the zero-dependency path.

Swarm transfer and standby failover stay design-notes here (§6) — deliberately not
built this pass.

## 2. Region logs — the shape (doc 13 §B, made concrete)

### 2.1 The build plan (rewritten 2026-08-11 after the merge decision)

P7.0 (logical regions) is BUILT. The interim P7.1 was struck (see §7 — its
sparse-sequence verification mode is machinery physical logs delete), so the arc
that remains is **P7.2: region replication on physical per-region logs**, built
directly. Chris confirmed 2026-08-11. The shape:

- **Storage.** The existing `log.db` IS the top region's log. A marked region gets
  `​.pvfs/regions/<region-root-id>/log.db` — same schema, its own dense chain.
- **Split at mark (PROPOSAL).** History is never rewritten: at `region mark`, the
  parent log records the mark (as today) plus a **baseline commitment** — a doc 11
  verifiable snapshot of the subtree state at that head. The region's log begins
  from that baseline; new region events append there. Replicating a region ships
  baseline + region log — never the parent's history. (Doc 11's snapshot mechanics
  were confirmed at build start: still design-only, so §2.3 builds the
  region-scoped subset directly.)
- **Head commitments.** Each region's log periodically (and at every parent-side
  op touching the region) records `SubRegionHead { region, seq, head_hash }` in
  its PARENT's log — the hash-linked tree of logs; the forest root hash still
  attests everything (doc 13 §B).
- **Replay** walks the tree root-down: parent log first, each committed child head
  verified against the child log's actual chain. Whole-forest `verify` externally
  unchanged.
- **Wire.** `LogInfo`/`LogRead`/`LogWait` grow an optional `region` scope;
  `pvfs replica add --region <node>` ships baseline + region log + the parent
  head-commitment path (the manifest proof). Region replicas serve/ACL-scope to
  the region; cross-region refs stay dangling-but-verifiable.
- **Cross-region moves (PROPOSAL — the doc 13 §B deferred question).** A move
  across a boundary = `LinkRemoved` authored in the source region + `LinkCreated`
  in the destination region, same author, each event carrying the other region's
  head hash at authoring time (the causal cross-reference). Replay accepts the
  pair only when both sides exist or the missing side is an unfetched region.
  Until this lands mid-arc, the P7.0 refusal stays.
- **Unmark = merge back:** the region log is sealed with a final head commitment;
  subsequent events author in the parent. Sealed logs remain for verification.

Sub-phases, each validated before commit, none half-landed:
P7.2a storage + split/merge + tree replay, single host; P7.2b wire + `replica add
--region` + scoped serving; P7.2c cross-region moves; P7.2d fleet-test region
phase across both machines. This is the deepest engine change since P0 — the
sub-phase gates are the safety mechanism.

### 2.2 Settled details (following doc 13 §B verbatim)

- Region = contains-closure under the marked node, minus nested regions (Q-B1 ✓).
- Marks are signed structural events in the PARENT's scope, admin-authored.
- Cross-region moves: **refused in P7.0–P7.1** (`mv` across a boundary errors with
  guidance) — the both-logs authoring question is P7.2's to answer (doc 13 §B
  deferred it; refusing beats guessing).
- ACL/tag grants inside a region travel with it (they're events on its nodes —
  Q-B4 falls out of the filter).

### 2.3 P7.2a build mechanics (2026-08-11, written at build start)

Doc 11 was confirmed at build start: **still design-only** (status "Proposed",
nothing implemented). So P7.2a builds the region-scoped subset of it — the
deterministic state commitment — and skips the archive half entirely: the
parent log keeps its full history untouched, so the mark-time baseline is a
**state snapshot commitment, not an event archive**. Doc 11's "checkpoint event
vs meta-operation" question resolves to *event* here (uniform with the model),
and its determinism constraint (§6) binds the canonical encoding below.

**Storage.** Region logs are separate SQLite files (same `events` schema) at
`regions/<region-root-id>/g-<enclosing>-<baseline-seq>.db` under the data dir,
ATTACHed on demand around each write transaction (never permanently — the
attach cap stays distant). The generation is named at birth and **never
renamed**: unmark just ends the generation (no active region row → nothing
routes there), so sealing is crash-free by construction, sealed logs remain in
place for verification, and a re-mark starts a fresh generation file. WAL like
the others; cross-file atomicity keeps the established posture: the log is
truth, the projection self-heals, and an unclean shutdown forces the full
agreement check.

**Region-log genesis.** `chain_hash[0] = BLAKE3("pvfs:regionlog:v1:" ||
Enc(instance_id, forest_id, region_root_id, baseline_seq, state_root))` —
identity, position, and content bound. The enclosing head hash is deliberately
NOT in the seed: unlike a doc 11 checkpoint (which replaces history), the
baseline event itself remains chain-bound in the enclosing log at
`baseline_seq`, so the parent linkage is already pinned there; repeating it in
the seed would add nothing.

**The baseline commitment.** `region mark` becomes one commit appending
`RegionMarked` + new event `RegionBaseline { node_id, state_root, at }` to the
enclosing region's log and creating the region log file. `state_root` is a
two-level hash over the subtree's canonical current state: fixed section order
(nodes, links, locations, ACL rows, bindings, secure blobs, nested-region
heads), items canonically `Enc`-encoded and sorted by primary key, section
hashes folded under a domain tag. Immediate nested regions appear **as their
head hashes**, not their interiors (Q-B1). Full rebuild recomputes the root
when it folds a `RegionBaseline` — at that replay position the projection *is*
the mark-time state — and errors on mismatch: every rebuild is doc 11 §5's
"full verification" for free.

**Event routing.** Every append already funnels through one engine path, so
routing lives there. Forest-scoped kinds (genesis, device certs, root rotation,
recovery keys, member tags) always author in the TOP log. Node-scoped kinds
route to their subject's region: links by their parent (containing) side,
locations/ACL/blobs/bindings by their node, `NodeCreated` **with its homing
link in the same batch**, marks/unmarks/baselines/heads to the *enclosing*
region. A batch may span logs (a bound-folder scan over a subtree holding a
nested mark splits cleanly); routes are computed against pre-transaction state
plus the batch's own links, before anything folds.

**Orphans stay put.** The projection's nodes gain a fold-maintained region
column (mark/unmark reassign the subtree; homing sets it at create). `region_of`
becomes a lookup instead of a containment walk, and — the point — a node
orphaned inside region R **stays R's**, so its later purge authors in R's log.
Without stickiness, an orphan's purge would route to the top log and tree
replay would fold the purge before the region log resurrects the node.

**Causal isolation is the invariant** that makes parent-then-children replay
sound: no event outside region R's log may touch R's interior. Enforced at
prepare time: cross-region `mv` stays refused (P7.2c lifts it), **adopting an
orphan across a boundary is refused too** (it *is* a cross-region move — the
orphan's history lives in its sticky region's log, and homing it elsewhere
would make replay order observable), and **purging a subtree that contains a
marked region is refused** ("unmark first" — the seal folds S's history into
R, then the purge is all-R).

**Tree replay.** Per-log applied marks replace the single
`last_applied_seq`/`chain_hash` pair (projection SCHEMA_VERSION 5 — one-time
rebuild on first open, the established pattern). Replay walks root-down: top
log first, then each **active** region log in mark order, recursing for nested
marks. One ordering subtlety is load-bearing: a **sealed** generation replays
at its *unmark position* in the enclosing log (replay pauses at
`RegionUnmarked`, replays the sealed generation, verifies its tip against the
final head commitment, then folds the unmark) — because once a region is
unmarked its former interior is parent scope again, and enclosing events after
the unmark may legitimately touch it. Active regions have the opposite
guarantee (routing keeps enclosing events out of their interior), which is
what lets them defer to end-of-log.
Ordering across parallel logs makes the membership check **as-of-time**
(`authorized_at ≤ t < revoked_at`) instead of current-state — the honest
trust-model note: "authored before revocation" is now judged by the
owner-stamped, chain-bound `written_at`, which is sound because revocation
defends against the revoked member (who cannot append at all), not against the
owner, who signs the chain and was always trusted for ordering.

**Head commitments in P7.2a** are appended at unmark (the final seal, in the
same commit, before `RegionUnmarked` — whose landed wire shape is unchanged),
at clean shutdown, and via an explicit engine call; the "every parent-side op
touching the region" trigger and the daemon's periodic job land with P7.2b,
where staleness starts to matter. Chain verification treats region rows beyond
the last committed head as tip extension — verified by chain + signatures now,
attested by the next commitment.

**Upgrade path.** A forest with pre-P7.2a marks (logical regions, one log)
splits **lazily at first writer open**: each marked-but-unsplit region gets the
baseline + fresh log then, with `prev_tip` = the current head — the mark and
the split are simply not the same instant for legacy regions. History is never
rewritten either way. **Explicit inter-phase hazard:** until P7.2b teaches the
wire region scope, replicas following a forest do not receive region-routed
events — mark no regions on fleet-replicated forests between the two phases;
the arc is not releasable half-way (why the release cut waits).

## 3. The FUSE mount — P7.3

- New crate `pvfs-fuse` (the `fuser` crate, pure Rust; runtime needs the distro's
  `fuse3` package — added to the pipeline prepare stage), CLI face `pvfs mount
  <target> <dir>` (foreground; `--daemon` later) + `pvfs umount <dir>`.
- **Read-only in P7.3**, deliberately: inode table from the projection (directories
  = folder nodes, files = file nodes with sizes from payloads), `open` resolves
  locations at first read — local path, sync store, else **read-through via the
  F5.2 Fetcher** streaming into the sync store while the read is served from the
  growing file (open-and-stream, no full prefetch for sequential reads).
- Writes, xattrs, and mtime fidelity: out of scope; the mount is the streaming
  *consumer* face (Plex reads, humans browse). Write semantics belong to a later
  arc if ever — the catalog write model is the CLI/daemon's.
- Serving daemons and the mount share the engine via a read view + the fetch pass;
  the mount never holds the writer lock across a stream.

## 4. Phases + turnkey checklist

| Phase | Deliverable | Done means |
|---|---|---|
| **P7.0** | region mark/unmark events + CLI + projection membership | mark, ls, unmark round-trip; replay preserves marks; cross-region mv refused; tests + smoke |
| **P7.2a** | physical region logs: storage + split/merge + tree replay | mark splits (baseline + new log), unmark seals; whole-forest verify unchanged; replay walks the tree |
| **P7.2b** | wire scope + `replica add --region` + scoped serving | a region replicates without the parent's history; manifest proof verifies; out-of-region refused |
| **P7.2c** | cross-region moves (paired events with head refs) | the P7.0 refusal lifts; replay accepts the pair |
| **P7.2d** | fleet-test region phase, both machines | ship one app's region to the edge; it follows/serves/exports scoped |
| **P7.3** | `pvfs-fuse` read-only streaming mount | mount a replica, `ls`/`cat` through the kernel, a pointer-mode file streams via read-through; pipeline gains the fuse dep; smoke mounts + reads |
| **P7.4** | §6 design notes only (swarm, failover) | doc section, no code |
| **Validate** | pipeline both hosts + fleet-test region phase + clippy, per landed phase | all green; honest §7 close-out of exactly what landed |

## 5. Overnight execution notes (for the morning review)

Order: P7.0 → P7.1 → P7.3 → (P7.2 only if the night is long enough — it will NOT be
half-landed; an unstarted P7.2 is recorded, a half-built one is reverted). Every
phase validates on presubuntu before its commit, as always.

## 6. Design notes for the deferred pair

- **Swarm transfer (PROMOTED to a wanted arc — Chris, 2026-08-11, via doc 21 §3):
  P9, after regions.** Reads pull **from every known holder in parallel,
  BitTorrent-style**: files get a BLAKE3 chunk manifest (chunked at the sync
  sink); the Fetcher's candidate list — source, registry-pinned holders, and
  doc 21 mirror copies — becomes a seed set, chunks are pulled concurrently from
  all of them, each chunk verified on arrival. Falls out for free: **resumable
  transfers** (the chaos caveat) and **serve-while-fetching** mount reads
  (punch J) — a read is served the moment its chunks land. Wants regions settled
  first so manifests can live per-region.
- **Standby failover (doc 03 §6 Q3):** explicit promotion only — a signed
  `WriterPromoted` event authored with the recovery phrase (never automatic), all
  replicas refuse the old writer's events after fold. Design compatible with
  region-scoped writers later (§A).

## 7. Close-out

- **P7.0 landed** (`616d058`, validated: 211 tests, 303 smoke, clippy clean): the
  region vocabulary end to end — signed mark/unmark events with admin-gated replay,
  the regions projection (schema v4), membership, CLI, and the cross-region mv
  refusal.
- **P7.1 deliberately NOT started — a design finding instead (2026-08-11, night):**
  implementing the filtered ship exposed that §2.1's interim demands
  **sparse-sequence replay** in the replica store: region rows arrive with seq gaps,
  so chain verification (which assumes dense rows) must grow a gap-tolerant mode
  used *only* by this interim — exactly the machinery physical per-region logs
  (P7.2) delete, since each region then owns a dense chain and the standard replay
  just works. PROPOSAL for review: **merge P7.1 into P7.2** — build region-scoped
  replication once, on real per-region logs, instead of shipping a throwaway
  verification mode for the single-log era. Per §5's rule (no half-landed phases),
  nothing of P7.1 was committed. **DECIDED (Chris, 2026-08-11): merged — build the
  final physical-log version directly; no interim attestation mode.**
- **P7.3 landed** (`7239d8a`, validated: 212 tests incl. a real kernel
  mount+read, 306 smoke incl. mounting a replica through the VFS, clippy clean):
  the pvfs-fuse crate (pure-Rust fuser; runtime dep = fusermount3, added to the
  pipeline prepare stage), `pvfs mount`/`umount` (Linux-gated), live byte
  resolution with verified read-through at open. As-built deviation: the first
  open of an unfetched file blocks for the verified fetch — serve-while-fetching
  is the recorded refinement, a natural companion to the swarm work (§6).
- **Also this night, before P7:** P6 landed whole (doc 19, `7c868c0`), a latent
  concurrent-fold race in projection catch-up was found by the smoke suite and
  fixed (`58adaa2`), and the tmp-sweep session's fix merged (`b24d8f8`).
- **P7.2a landed** (2026-08-11, validated: **219 cargo tests + 317 smoke on
  both hosts, clippy clean** — all 212 pre-existing tests pass unchanged on
  the physical-log engine, plus 7 new P7.2a tests and 11 new smoke checks
  covering split/routing/seal/generations/tree-rebuild/guards/legacy-split).
  Built to §2.3 with these as-built notes, honestly:
  - *Doc 11 confirmed design-only at build start* — §2.3's region-scoped
    subset (deterministic canonical `state_root`, commitment event, bound
    genesis) was built directly; the archive half was correctly unnecessary.
  - *Two invariants surfaced during the build and were specced before code*
    (§2.3 updated in place): sealed generations must replay **at their unmark
    position** (the pause), and **orphan adoption across a boundary is a
    cross-region move** — refused alongside `mv` until P7.2c. Orphan region
    stickiness (a fold-maintained `nodes.region_id`) is what makes purge
    routing sound; it also turned `region_of` O(1).
  - *Head-commitment cadence:* at unmark (the seal), at engine close, and via
    `Engine::commit_region_heads`; the "every parent-side op touching the
    region" trigger and the daemon's periodic job are deferred to P7.2b where
    wire staleness starts to matter. The daemon's SIGTERM path does not yet
    commit heads (its checkpoint is read-only) — same P7.2b item.
  - *Inter-phase hazard, sharper than predicted:* until P7.2b ships region
    logs, a whole-forest replica of a forest that marked **and unmarked** a
    region refuses to open — the seal cannot be verified without the sealed
    generation, and default-deny wins. Mark no regions on replicated forests
    until P7.2b lands (fleet-test and smoke flows verified unaffected).
  - *Membership checks became as-of-time* (`authorized_at ≤ t < revoked_at`)
    per §2.3. Marginal-exposure note recorded there: a data-dir attacker
    already holds `device.key`, so nothing new is reachable through it.
  - `RegionInfo`/`Engine::region_info` expose generation state engine-side;
    the CLI surface for it rides P7.2b with the wire scope.
- **Morning decisions for Chris:** (1) §7's P7.1→P7.2 merge proposal; (2) doc 19's
  packaging intent — 1.4.0 = P5 + P6 + fixes, with P7.0/P7.3 riding or waiting.
