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
  are the dependency to confirm first at build.)
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
- **Morning decisions for Chris:** (1) §7's P7.1→P7.2 merge proposal; (2) doc 19's
  packaging intent — 1.4.0 = P5 + P6 + fixes, with P7.0/P7.3 riding or waiting.
