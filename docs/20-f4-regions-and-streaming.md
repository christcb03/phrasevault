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

### 2.1 Vocabulary first, plumbing second (PROPOSAL)

Doc 13 §B is a storage architecture; landing it all at once would rewrite the log
store, replay, replication, and compaction in one motion. Proposed instead, two
steps that are each verifiable end-to-end:

- **P7.0 — logical regions.** Two new signed events in the (still single) forest
  log: `RegionMarked { node_id }` / `RegionUnmarked { node_id }` (owner/admin-
  authored, replayed like any structural event), a `pvfs region mark|unmark|ls`
  CLI, and projection state answering "which region does node X belong to"
  (nearest marked ancestor, forest root = the implicit top region). Everything
  downstream — region-scoped *replication* first of all — keys off this
  vocabulary while the bytes still live in one chain.
- **P7.1 — region-scoped replication over the single log.** `pvfs replica add
  --region <node>`: the daemon ships only events whose touched nodes fall inside
  the region (selective subscription, Q-B3), **plus** a per-batch **filtered-log
  proof**: the shipped rows' chain positions + the tip hash, so the replica can
  verify "these are real rows of the pinned chain, in order, none withheld
  *within the region*" — the Q-B2 answer for the single-log era: the proof is
  the owner's signed attestation of the filter (a `RegionTail { region, seq_set_hash,
  tip }` statement per batch) rather than a chain prefix. A region replica opens
  with `ls`/`cat`/ACLs scoped to the region; out-of-region refs are dangling-but-
  verifiable.
- **P7.2 — physical per-region logs (the doc 13 §B end state).** The log store
  becomes region-addressable (`log.db` per region under `.pvfs/regions/<region-id>/`),
  parents carry `SubRegionHead { region, head_hash, seq }` commitments, replay
  walks the tree of logs root-down, and region replication ships a real log +
  the parent head-commitment path (the manifest proof). Mark/unmark become the
  split/merge ops. **This phase only starts overnight if P7.0/P7.1 validate
  early**; it is the deepest engine change since P0 and does not rush well.

Rationale: P7.1 delivers doc 13 §B's *user-visible promise* (replicate one app's
region, verifiably) with the integrity argument moved from "chain prefix" to
"owner-signed filter attestation" — sound because the owner already signs every
row; the replica trusts the same key for the filter it trusts for the rows. P7.2
then swaps the substrate under an unchanged UX, and its verification strengthens
to structural (heads in parent logs) rather than attested.

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
| **P7.1** | region-scoped replication (filtered ship + attested proof) | `replica add --region` ships a strict subset, verifies, serves scoped; out-of-region access refused; two-machine check in fleet-test |
| **P7.2** | physical per-region logs + head commitments (STRETCH — only on early green) | tree-of-logs replay; whole-forest verify unchanged externally; region ship = real log + manifest path |
| **P7.3** | `pvfs-fuse` read-only streaming mount | mount a replica, `ls`/`cat` through the kernel, a pointer-mode file streams via read-through; pipeline gains the fuse dep; smoke mounts + reads |
| **P7.4** | §6 design notes only (swarm, failover) | doc section, no code |
| **Validate** | pipeline both hosts + fleet-test region phase + clippy, per landed phase | all green; honest §7 close-out of exactly what landed |

## 5. Overnight execution notes (for the morning review)

Order: P7.0 → P7.1 → P7.3 → (P7.2 only if the night is long enough — it will NOT be
half-landed; an unstarted P7.2 is recorded, a half-built one is reverted). Every
phase validates on presubuntu before its commit, as always.

## 6. Design notes for the deferred pair

- **Swarm transfer:** the Fetcher's candidate list is already multi-source; swarm =
  chunked fetch-by-hash (BLAKE3 tree chunks) from several holders at once, which
  also buys resumable transfers (the chaos run's one caveat). Wants the region work
  settled first so chunk manifests can live per-region.
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
  nothing of P7.1 was committed.
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
