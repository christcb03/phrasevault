# 24 — Fleet review + library re-genesis (D87)

**Status: REVIEW COMPLETE; D87 + D88 BUILT, DEPLOYED AND VERIFIED (2026-08-30); D89 BUILT.** Written 2026-08-29 after the
`.manifest` recursion incident. Scope asked for by Chris: a full review of what
PVFS does, every issue and change since the media forest was created, whether
replica write-routing and the identity model are right, and whether fixes we
applied to one operation were applied to its siblings.

Prerequisite reading: doc 17 §5/§7 (replica + write-through), doc 19
(write-through completeness), doc 11 (compaction), doc 22 (swarm/chunk
manifests).

---

## 0. The one finding that changes how everything else is read

**`main` is 80 commits stale, and the fleet does not run it.**

| | |
|---|---|
| `phrasevault-repo` @ `main` | `ec9eda3`, `v1.4-27` |
| `phrasevault-d71` @ `d71-scoped-bindings` | 80 commits ahead, **0 behind** |
| Deployed on feederbox | `pvfs 1.4.0`, built 2026-08-29 02:54 |

Both report version `1.4.0`. The version string is identical and the code is
not. The deployed binary writes a `MediaQuality` event kind that **does not
exist in `main`'s `Event` enum at all**, and the live log holds 24,585 of them.

Consequences, in order of severity:

1. Any work started from `main` is built on sand. The `.manifest` fix in this
   milestone was first written, tested (252 tests) and clippy-cleaned against
   `main` before this was noticed. That work was discarded and redone on
   `d71-scoped-bindings`; the test number was meaningless because it was the
   wrong suite.
2. `main` cannot safely be deployed to the fleet. It has no `MediaQuality`
   variant, so it would meet 24,585 events it cannot decode.
3. D76, D80–D86 exist only as commits on a long-lived branch. `git describe`
   says `v1.4-27` on a tree that is materially behind production.

**This is the highest-value fix in the document and it is process, not code:**
the branch the fleet runs must be the branch `main` points at. Everything below
was re-verified against `d71-scoped-bindings` after this was found.

---

## 1. The incident, and its actual root cause

### What happened

feederbox's `watch` job rescans its binding `/Media → file:///mnt/local/Media`.
`walk_disk` skips dotfiles, then applies the binding's extension filter **only
when it is non-empty**. This binding has no filter, so every file was content —
including PVFS's own `.manifest` sidecars. An adopted sidecar becomes a file
node; serving it calls `chunk_manifest()` → `manifest_for()`, which **caches by
writing `<name>.manifest`**; the next pass adopts that. One level per pass.

Measured before it was stopped: **23 levels deep, ~3,000 junk files**
(1,422 on feederbox, 1,570 on the NAS via cloudplow), **1,667 junk nodes** —
5.3% of the catalog. The depth histogram is a clean staircase, 89 files at
level 1 tapering to 1 at level 23: 89 files affected, ~23 scan passes.

### The root cause is a naming inconsistency, not a missing check

PVFS writes exactly three kinds of bookkeeping into the operator's content tree:

| Bookkeeping | Name | Walkers step over it? |
|---|---|---|
| Bound-root marker | `.pvfs-root` | yes — dotfile |
| Swarm partial | `.{id}.swarmpart` | yes — dotfile |
| **Chunk-manifest sidecar** | **`{file}.manifest`** | **no** |

Two of three follow the convention. The third does not, and the third is the one
that caused this. `walk_disk` has skipped dotfiles since forever, so the partial
and the root marker were never at risk — by construction, not by vigilance.

`advertise.rs` carried an `ends_with(".manifest")` guard for the sync-store walk,
which proves the hazard was already understood in one place and never
generalized. **A per-walker name check is the same shape of mistake as the one
that already existed and did not save us.** The real fix is to make the sidecar
a dotfile so no walker has to know anything.

### What is fixed in this branch

A shared `is_sidecar_name`/`is_sidecar_path` in `sync.rs`; an unconditional guard
in `walk_disk` placed *before* the extension filter; a refusal in
`write_manifest_sidecar` (the one choke point all callers pass through) so an
already-contaminated forest still serves those nodes and simply recomputes;
`advertise.rs` now asks the shared predicate.

This stops the loop. **It does not fix the naming inconsistency**, which is
carried forward as the real fix in §6.

### Disabling `watch` bounds the growth — it does not stop it

Measured after the fact, and worth recording because the first conclusion was
wrong. Disabling `watch` on feederbox stopped new **adoptions**, and the rate
fell from ~9 files per 10 minutes to 1 in 2 hours. It did not reach zero: a
6-level sidecar was written at 23:53, nineteen minutes after the job was
disabled.

The mechanism is the serve path, not the scan. The junk **nodes** are still in
the catalog; serving one calls `chunk_manifest()` → `manifest_for()`, which
caches by writing the next level down. Growth is therefore **bounded at one
level past the deepest catalogued node** rather than unbounded — it can no
longer compound, because compounding needs adoption.

This is the argument for fixing both ends rather than one. The `walk_disk`
guard stops adoption; the `write_manifest_sidecar` refusal stops precisely this
residual write. Either alone leaves a live path.

### Secondary defect, unfixed

`manifest_for` writes to disk as a side effect of a read. A getter that mutates
the filesystem is what converted a single bad adoption into unbounded growth.
The guard neutralises it; the shape remains.

---

## 2. Replica write routing — is it right?

**Yes, and the model is sound.** `Engine::append_durable` opens with a hard
`if self.replica { return Forbidden }` — a replica can never write its own log,
by construction rather than by convention. Mutations route to the source as
member-signed prepared writes (F5.0, doc 17 §7.1; doc 19 completed the op set
with `RemoveLocation`, `Link`, `Unlink`, `Reorder`). The daemon authorizes at
prepare time with the *caller's* key and commits. Reads resolve from any
authorized holder.

Two things worth recording because they look like bugs and are not:

- **A replica legitimately holds a binding.** feederbox has
  `/Media → file:///mnt/local/Media` despite being read-only, because D71 made
  bindings machine-local state in `.pvfs/bindings.local`, deliberately outside
  the log. Not a routing gap.
- **`bind`/`unbind`/`purge`/`quality` have no `prepare_*`.** For bind/unbind
  that is the D71 design above. For purge and quality it should be confirmed
  rather than assumed — see §5.

### The asymmetry that is real

23 `prepare_*` write-through paths against 33 local `append_durable` sites, and
30 event kinds. Routing coverage is a per-call-site decision, so every new
mutation has to remember to be routable. That is the same class of problem as
§1: correctness by vigilance rather than by construction.

---

## 3. Authority checks — the sibling-operation audit

This is the "did we apply the fix to the other operations" question, and the
answer is **no, twice.**

### 3a. The commit-side check does not mirror the prepare-side check

`commit_member_write` verifies each event's signature, checks device certs, and
otherwise calls `check_member_event_batched` → `check_member_event`, which ends
in a permissive `_ => {}`. `require_active_author` runs before the match, so
signature and active-unrevoked-device are always enforced. **Per-node rights are
not**, for every kind without an arm:

| Checked for per-node rights | Falls through to `_ => {}` |
|---|---|
| `AclSet`, `RegionMarked/Unmarked/Baseline`, `SubRegionHead`, `LinkCreated`, `NodeMovedIn/Out`, `FileLocationAdded`, `ChunkManifestRecorded`, `SecureBlobUpdated` | **`FileLocationRemoved`**, `LinkRemoved`, `LinkSuperseded`, `LinkReordered`, `LinkRelabeled`, `LinkSuspended/Unsuspended`, `NodePurged`, `MediaQuality`, `FolderBound/Unbound` |

Doc 19 documents `RemoveLocation`'s authority as "`w` on the file", and the
prepare path does enforce it (`engine.rs:3580`). So the **primary** gate is
correct and this is not an open door. But the two-phase shape hands a member a
prepared batch to sign — a member who constructs their own batch and submits it
to commit is checked only for signature and device liveness on those kinds.

Scoped honestly: in *this* forest all three grants are `rwa` on the root, so it
changes nothing operationally today. Against the stated default-deny posture, the
second gate should mirror the first.

### 3b. The batched-authority map covers 3 of ~30 kinds

`check_member_event_batched` maps batch-born nodes to their batch parents so
authority resolves at the nearest pre-existing ancestor. It has arms for
`LinkCreated`, `ChunkManifestRecorded`, and — added by D85 — `FileLocationAdded`.

D85's own commit message is the argument for this milestone:

> `check_member_event_batched` already existed for exactly this […] but it only
> covered LinkCreated and ChunkManifestRecorded. FileLocationAdded fell through
> to the unbatched check.

One arm was added for the operation that failed. Nothing asked whether the other
27 kinds had the same hole. That is the pattern to break.

---

## 4. State of the library

Measured on feederbox's replica, 2026-08-29.

### Hashing — lazy hashing should go, and D85 already started it

Of 29,542 file nodes: **2,491 hashed (8.4%), 27,050 unhashed (91.5%)**. D85
recorded 97.8% unhashed, so the scan-fill is working, slowly.

This is not cosmetic. From D85's commit, measured through the FUSE mount:
**115.8s to read 1MB of an unhashed file against 0.10s for a hashed one** — an
unhashed file has no chunk manifest, so a mount cannot stream it and blocks on a
whole-file fetch. Swarm serving, dedup and verified read-through do not apply to
91% of the library.

`HashPolicy::Lazy` did not defer the work, it skipped it, and nothing surfaced
that because nothing depended on it yet. D85 (`620beb6`, "the scan fills hashes
— no lazy library, no bulk backfill tool") is the right direction; removing the
`Lazy` variant outright finishes it.

### The log

241,662 events / 106 MB.

| Kind | Count |
|---|---|
| FileLocationAdded | 88,807 |
| FileLocationRemoved | 58,667 |
| LinkCreated / NodeCreated | 33,957 each |
| MediaQuality | 24,585 |
| LinkRemoved | 921 |
| LinkSuperseded | 722 |
| ChunkManifestRecorded | 22 |
| AclSet | 16 |

60,094 distinct location rows against 88,807 add events: ~28,700 locations were
added, removed and added again. **The log is dominated by files moving**, not by
our mistakes — the `.manifest` incident is ~6,461 events, **2.7%**. That is worth
saying plainly, because the instinct that the log is clogged with our churn is
mostly wrong.

### Residue

- **939 orphans**, including 38 Dragon Ball entries.
- **79 `file://` locations**, all `file:///mnt/nas-media/...` — the NFS path
  retired in D80. They sit *outside* the binding prefix, so the scan never
  touches them. They are stranded, not active.
- **3 separate "Dragon Ball" folders** under `/Media/TV` — D84 duplicate tree
  paths, still live.
- `scan_state` is **89% junk** (1,498 manifest URIs against 181 real).

---

## 5. The scan refusal — SOLVED (D89)

Recorded in full, including the wrong turns, because three plausible
explanations were tested and disproved before the right one, and the wrong ones
are cheap to repeat.

### The chain, proven end to end

1. `effective_rights_at` resolves authority by walking **`contains` parents**
   toward a grant (`projection.rs`), and `contains_parent` matches only
   `removed_at IS NULL` — a **live** link.
2. Every grant in this forest is at the **root**: three `key:` rows, `rwa`,
   nothing anywhere else.
3. So an **orphan** — a node whose last live `contains` link is gone — reaches
   no grant. The walk ends at the node itself, `rights = 0`, and default-deny
   refuses. **A node you authored, holding bytes you hold, becomes unwritable
   the moment it is unlinked.**
4. The scan's removal loop matches BOTH prefixes (D81: bare `file://` and
   pin-qualified `pvfs-host://<pin>/`), so it does reach these nodes.
5. `remove_location(...)?` propagated that refusal and **abandoned the entire
   pass** — so no later file reconciled, and the next pass met the same node and
   died in the same place. In the field: `watch` in backoff for hours while the
   tree drifted.

Live proof, 2026-08-30, under the fixed binary: node
`b91682ae…` — `Big Brother (US) - s28e20 - Episode 20.mkv`, authored by
feederbox's own key, holding a live `pvfs-host://` location on feederbox's own
pin — is an orphan, absent from the `/Media` walk, and refused. **95 orphans on
feederbox still hold live locations.** The same episode label has **two other
live nodes** under the same parent, which is D84 in the flesh: duplicate
resolution orphans a node, and orphaned nodes can never be cleaned up by the box
that owns them. 40 paths still carry duplicate live file nodes.

### What was wrong before, and why

- *"The owner refuses it."* No — `check_member_event` has no arm for
  `FileLocationRemoved`, so the commit side cannot be the refuser. The refusal
  is the **prepare**-side check.
- *"A batched-authority gap mirroring D85."* No — the removal targets a
  pre-existing node, so the `born` map never fires.
- *"The node is orphaned."* Right idea, **tested against the wrong sample**: 0 of
  the 17 vanished Dragon Ball Z nodes were orphans, so it was discarded. Those 17
  were never the failing set — the error naming `cc50859a…` was **stale**, left
  over from a job that had been in backoff for hours. A stale error read as a
  live one cost the most time of anything in this review.

### The fix, and the half deliberately not taken

**Taken:** the removal arm now quarantines and carries on, exactly as the ingest
arm ten lines above it already did — *"one file the catalog will never accept
must not stop the line"* (D71 W4). The rule existed and had simply never been
applied to retiring. `scan_state` is deliberately not cleared on refusal: the
location is still live, so a later pass or a repaired grant must be able to
retry. `needs_attention`/`quarantined` now say WHICH node and why, instead of
the whole pass dying silently.

**Then taken, on Chris's call (D90):** *"any tree needs to be able to remove
nodes for files that no longer exist — when the job watching for file changes
sees a change it must be able to make that update."* That settles it, and it
rules out the alternatives: author-retains-`w` ties authority to authorship
rather than to the forest, and keep-orphans-immutable needs a reaper that does
not exist and leaves the watcher unable to state a fact it can plainly see.

So **the walk resumes at the forest root exactly once** when it runs out of
links. Running out means one of two very different things — `n` IS the root
(a real end) or `n` is an orphan (a cut chain) — and treating them alike was the
bug. An orphan is still in the forest; it should not fall off a cliff.

This is a widening and is documented as one: anyone holding `w` at the root can
now act on any orphan. That is the same authority which already covers every
linked node, and an orphan has no claim to be better protected than the tree it
fell out of. The bound is real and tested — a member granted only on a
**subfolder** still gets nothing on an orphan, because the resume goes to the
root, not to "allow". Test: `an_orphan_resumes_at_the_root`.

### Still open

1. Whether `purge` and `quality` are routable from a replica, or local-only by
   design like bind/unbind.
2. The 40 duplicate live nodes and the 95 orphans holding live locations. The
   quarantine stops them wedging the scan; it does not clean them up.

---

## 5b. The holder's CPU — SOLVED (D88)

Reported as "the NAS hits CPU high enough to stall playback, but 90% of the time
it is fine". Both halves of that were true and the second was the clue.

**Measured, not assumed.** pvfsd held **93% of one core** with io at only 2.2% —
CPU-bound on BLAKE3, not disk-bound. And the library is not occasionally large,
it is *mostly* large: **1,161 movies, median 19 GB, p90 31 GB, max 70 GB, 833 at
or above 10 GB** — roughly 23 TB. TV episodes at 1–2 GB pass in seconds, which is
the 90% that felt fine; a 19 GB movie holds a core for a long stretch, which is
the 10% that stalled playback.

**The real cause was that we were using a quarter of the box.** `hasher.update`
is single-threaded and blake3 was pulled in without `rayon`. Worse, the read
buffer was 1 MiB — and BLAKE3 only parallelises WITHIN an `update` call, so
enabling rayon alone would have changed nothing. The buffer size *is* the width
of the hash. It is now a full swarm chunk, which is the boundary the manifest
already needed, so the read size and the hash width finally agree.

**Result on the holder, measured after deploy:** four rayon workers active, and
the job moved from **CPU-bound (0.93 cores, 2.2% io)** to **I/O-bound
(1.11 cores, 13–16% io)** at **153 MB/s**, with ~40% CPU idle. That is ~20% more
CPU, *not* 3–4×, because the disk now sets the pace — which is the outcome
wanted: hashing is off the critical path and the cores are free for playback.

**Priority.** busybox on QTS has **no `nice` applet, only `renice`**, so the
launcher sets it after start, and finds the pid the way the existing guard does
because `setsid` may fork. The whole daemon is reniced rather than only the hash:
serving is I/O-bound so it loses little, and the trade is the one wanted — fleet
transfers yield to whatever someone is watching.

**Consequence for §6.** This is the concrete price of dropping lazy hashing:
~23 TB read once, at 153 MB/s ≈ 42 hours of holder time. That is affordable
*only* because it is niced and one-time — which is exactly why the hash must be
recorded somewhere portable (`pvfs-manifest 2`) rather than paid again per
forest.

---

## 5c. Deployment record — 2026-08-30

Rolled owner → feederbox → holder (the D72 §9e order), each step verified by
**binary content**, not by a green recap.

| Box | Was | Now |
|---|---|---|
| owner `pvfs-owner` | pre-D86 | d88, `pvfsd-media` active |
| ingest `feederbox` | pre-D86 | d88, `pvfsd-replica` active, `watch` back on |
| holder `qnap` | D86 (ahead of the others) | d88, reniced 19, `watch` back on |

No schema migration: every box was already at projection schema 13.

**Verified after:** feederbox's local manifests fell 1499 → 1 (the rest drained
to the NAS via cloudplow) with **zero new recursive sidecars** once `watch`
resumed — the D87 guard holds under live load.

**Operational traps worth keeping.** `/tmp/pvfs` on these boxes is the SOCKET
directory: `scp`ing a file named `pvfs` there fails with a bare "dest open
failure". Stage to `~/d88`. The holder keeps `bin/{pvfs,pvfsd}.pre-d88` as the
rollback, and its ARM binary was test-run on the box *before* the swap, because
a wrong-arch binary there means a dead daemon and no systemd to notice.

---

## 6. The proposal — re-genesis without re-hashing

### Why it works

~~Node ids are content-addressed and link ids exclude `created_at`/`author`
(doc 03 §3.2, restated in doc 11 §2: *"Identities survive"*). A fresh forest
built from the same bytes mints **the same ids**. Re-genesis is therefore a
rebuild, not a rename-everything migration.~~

> **FALSE. Disproved by rehearsal, 2026-09-02 — see §16.** Two fresh forests
> over byte-identical libraries produced **completely different ids for every
> node**. The paragraph above misread its own source: doc 03 §3.2 says the
> **LINK** id preimage excludes `created_at` and `author`. **Node** ids include
> both, *and* a `creation_nonce` drawn from `rand::thread_rng()`
> (`crates/pvfs-core/src/node.rs`, `preimage()`). A random nonce makes
> reproduction impossible by construction — no amount of identical bytes can
> defeat it.
>
> Re-genesis is therefore exactly what this paragraph said it was not: a
> rename-everything migration. That does not kill it, but it changes the plan —
> see §16.

### What it buys

Rebuilding from current state emits roughly:

| | |
|---|---|
| NodeCreated + LinkCreated | 67,938 |
| FileLocationAdded (active only) | 29,010 |
| MediaQuality | 24,585 |
| **Total** | **~121,500 against 241,662 — half** |

Dropping the junk takes it to ~115,000. Every removal, supersede and re-add
disappears, because current state does not care how many times a file moved.
Per doc 11 this targets **disk and replay time, never read latency** —
`index.db` is already history-free.

Equally valuable: a re-genesis that replays into a clean log is a **full-fleet
consistency check**. The 3 Dragon Ball folders, the 939 orphans and the 79
strays would have to be resolved rather than carried.

### The gap that blocks the cheap version

**The sidecar does not record the whole-file hash.** It stores the header, the
chunk size, and the per-chunk hashes. For files under 8 MiB the single chunk
hash coincides with the file hash; above that it does not. So today's sidecars
**cannot** seed a fresh forest's `content_hash`, and re-genesis would re-read
every byte — exactly the cost this proposal exists to avoid.

### The design tension, and the resolution

A durable hash record wants to live next to the file: it travels with the media,
survives a move, survives a forest, needs no central index. That is precisely
what a sidecar is — and precisely what caused §1.

**Dotfiles resolve both at once.** `.{name}.manifest` (or `.pvfs-manifest/`
per directory) is portable, travels with the bytes, and is invisible to every
walker that already skips dotfiles — matching `.pvfs-root` and `.swarmpart`.
The change that prevents the incident is the same change that makes re-genesis
cheap.

---

## 7. Turnkey checklist

Ordered so each step is verifiable before the next.

### A — process (do first, blocks everything)
- [x] A1. **DONE 2026-08-30.** Fast-forward PVFS `main` to `d71-scoped-bindings`. **Verified safe
      2026-08-29:** `main` is 0 ahead and fully contained, so this is a
      fast-forward with no conflicts possible. The 80 commits span 2026-08-17
      to 2026-08-29 and cover **D71–D86**, the migration work included.
      A full ref audit found nothing orphaned: every dangling object is either
      pre-rebase residue whose subject is present in the branch, an old stash
      (2026-04-18, 2026-08-10), or a superseded clippy fix that clippy now
      passes without. Then merge `d87-sidecar-and-review` on top. Landed as `e533b14`; branches
      deleted, both repos down to `main` and in sync with origin.
- [x] A1b. **DONE 2026-08-30** (`c635beb`). **PVOS has the same drift, and it is NOT a fast-forward.**
      `d71-watch-ingest` is 90 ahead of `main` while `main` is 12 ahead of it —
      they diverged when `main` took the D70 merge on 2026-08-16 and the branch
      did not. A `merge-tree` dry run reports exactly **one** conflicting file:
      `deploy/ansible/fleet/fleet-lab.ini`. Note the irony: one of `main`'s 12
      commits is "sync by content, not mtime", which is the fix A4 below needs.
      Resolved by taking the branch's file (it comments out the row pointing at
      the PRODUCTION QNAP) but keeping main's `fleet_artifacts` — the branch
      default `phrasevault-arm/target` has NO builds in it, checked on the host.
- [ ] A2. Version strings must distinguish builds — `git describe` into
      `--version`, so `1.4.0` cannot mean two different binaries.
- [ ] A3. Fix the pipeline summary: it reads the last `test result:` line, which
      is always an empty doc-test block, so it reports **0 passed and exits 0**
      on a full green run. Aggregate instead.
- [ ] A4. **The pipeline can test stale binaries and report green.**
      `ansible.posix.synchronize` runs in archive mode, so it preserves the
      control machine's mtimes; cargo decides staleness by mtime. Source edited
      while a previous build was running arrives with an mtime *older* than the
      artifacts and is silently not rebuilt. Caught 2026-08-29: the run reported
      `p1_storage: 11 passed` against a tree holding 12 tests, and the two new
      regression tests never executed — exit code 0 throughout. Verified not a
      clock-skew issue (Mac and presubuntu agree within 2s). Fix by giving
      synced files fresh mtimes (`--no-times`, or touch the tree after sync).
      PVOS already fixed this class of bug ("sync by content, not mtime").

### B — the incident (fix in hand)
- [x] B1. Sidecar guard on the correct base — shared predicate, `walk_disk`
      guard before the extension filter, `write_manifest_sidecar` refusal.
- [x] B2. Regression tests ported to this base.
- [x] B3. Pipeline green + clippy `-D warnings` clean.
- [x] B4. **DONE** — rolled owner → feederbox → holder, `watch` back on, and
      confirmed: local manifests 1499 → 1, **zero** new recursive sidecars (§5c).
- [ ] B5. Delete the junk files (`-name "*.manifest.manifest"`, all
      exactly 89 bytes; keep the level-1 sidecars).
- [ ] B6. **Chris decided 2026-08-30: LEAVE them** for re-genesis to drop.
      Which makes E/F below load-bearing rather than optional.
      (was: decide the 1,667 junk nodes: unlink+purge (3,334 events, 1,667 interim
      orphans) or leave for compaction to drop for free.)

### C — the real fix
- [ ] C1. Make the sidecar a dotfile. Migration: accept both names on read,
      write only the new one, sweep the old.
- [ ] C2. `pvfs-manifest 2` — whole-file BLAKE3 in the header, so a sidecar can
      seed `content_hash`.
- [ ] C3. Stop `manifest_for` writing on read; make caching an explicit call.

### D — authority (from §3 and §5)
- [x] D0. **Scan no longer dies on one refusal** (D89). The removal arm
      quarantines and carries on, the way the ingest arm always has.
      `needs_attention`/`quarantined` name the node and the reason;
      `scan_state` is kept so a repaired grant can retry. Test:
      `an_orphan_can_reach_no_grant`.
- [ ] D0b. **Decide what an orphan may do** (§5, "the half not taken"):
      root-grant fallback, author-retains-`w`, or orphans stay immutable and
      something reaps them. Blocks cleaning the 95 orphans holding live
      locations and the 40 duplicate live nodes.
- [ ] D1. Mirror the prepare-side right into `check_member_event` for every kind
      now hitting `_ => {}` — `FileLocationRemoved` first.
- [ ] D2. Make the catch-all **deny** for mutating kinds, so a new event kind
      fails closed instead of silently unchecked.
- [ ] D3. Audit all 30 kinds against the batched map; add arms or prove N/A.
- [ ] D4. Reproduce the §5.1 refusal under the fixed binary and settle it.

### E — hashing
- [ ] E1. Remove `HashPolicy::Lazy`; binding a library hashes it.
- [ ] E2. Sidecar-seeded fill: read the hash from C2 rather than re-reading bytes.
- [ ] E3. Drive the remaining 27,050 unhashed files to zero, measured.

### F — re-genesis (only after C and E)
- [ ] F1. Measure doc 11's trigger — projection rebuild time, `replica add` on
      LAN — **on a copy, never on production feederbox**.
- [ ] F2. `pvfs forest regenesis <src> <dest>`: replay current state into a
      fresh log, seeded from sidecars, no re-hash.
- [ ] F3. Reconcile-or-fail on residue — duplicate paths, orphans, strays. The
      point is that it surfaces them.
- [ ] F4. Rehearse on the lab fleet before the media forest.

---

## 8. Decisions

### Settled 2026-08-30

1. **A1 — trunk.** `main`, both repos. Merged, branches deleted, origin in sync.
2. **B6 — leave the junk nodes.** Re-genesis drops them for free; unlinking
   would cost ~3,334 permanent log events and bury 924 real orphans under 1,667
   junk ones. This makes E/F load-bearing rather than optional.
3. **F1 — do not measure the compaction trigger.** Chris: a rebuild into a fresh
   forest is wanted regardless, and it is the better instrument — it exercises
   the same machinery and surfaces duplicates and orphans as failures instead of
   carrying them. Doc 11's trigger (a rebuild crossing ~1 min, `replica add`
   crossing a few minutes on LAN) stands unmeasured, by choice.
4. **Lazy hashing goes.** Confirmed by the numbers: 91.5% of the library was
   unhashed, so swarm serving and verified read-through did not apply to it.
   D85 began this; removing the `Lazy` variant finishes it.

### Still open

1. ~~**D0b — what may an orphan do?**~~ **SETTLED (D90): resume at the root.**
   A tree must be able to retire what no longer exists. The 95 orphans holding
   live locations can now be retired by the watcher itself.
2. **C1 — dotfile rename now or after re-genesis?** Doing it first means one
   migration instead of two, and it is the real fix for §1 rather than the guard.
3. **The evict pair in the smoke suite** (§3): change the test to the new truth,
   change its setup so tier does not pre-retire, or widen evict to reclaim
   retired own-host locations. Option three changes production eviction.
4. **A2–A4 — the pipeline can lie.** It reports "0 passed" on a green run and
   can test stale binaries at exit 0. Both bit this review.

---

## 9. D99 — the mover throws away what it learns

Found 2026-08-31 on the live holder, eight hours after a restart: `tier` had
**never completed a pass** (`last_ok_ms: null`), against 33,928 `stream failed`
and 1,204 `streamed but commit failed` lines in its log.

Two independent defects, one shared shape — **a discovery the system makes and
then discards.**

### 9a. A remote integrity violation is not recorded (the headline)

1,814 `integrity violation` lines come from **five files**, retried forever.
The cause is not subtle, and the numbers name it exactly:

| | `Piccolo's Return.mkv` |
|---|---|
| catalog says | 3,371,964,304 bytes |
| disk holds | 3,694,978,150 bytes |

The *arr stack grabbed a better encode and overwrote the path. PVFS still binds
the **old** content id there. The holder fetches, receives bytes that hash to
something else, correctly refuses the commit — and repeats, every pass, forever.

**PVFS already knows how to handle this. It just does it in one place and not
its sibling:**

- `Engine::read_verified` (`fs.rs`) — a local read whose bytes miss their hash
  calls `self.quarantine(id, &uri, "hash mismatch on read")`. Durable, visible
  in `loc ls`, liftable by `loc verify`.
- `Fetcher::fetch` (`fetch.rs`) — a **remote** stream whose bytes miss their
  hash calls `eprintln!`. Nothing durable. Nothing visible. Nothing to lift.

Same failure, same available remedy, applied once. This is exactly the pattern
the §1 review was meant to catch and did not.

**Why local drift detection does not cover it.** `walk_disk` *does* sense a
changed file and parks it in `pending_changes` for an operator decision (doc 04
§4.4) — 51 of them are waiting on the holder right now. But that check runs
against **a host's own disk**. The five poison files' bytes live on feederbox,
and three of them are no longer even on its local disk (cloudplow moved them, so
feederbox reads them back through `/mnt/unionfs` — the holder pulling its own
bytes in a circle). A holder can only discover that a *remote* location has
drifted at fetch time. That discovery is the only signal there is, and it is
thrown away.

**The fix.** On a commit failure that is `PvfsError::Integrity`, quarantine the
serving location — every location of that node whose URI carries the failing
candidate's pin. `ReplicaSource` keeps only the pin, not the URI it came from,
so the mapping is recovered from `engine.locations(id)` rather than by widening
a core type used elsewhere.

**What this deliberately does NOT do:** it does not re-hash and adopt the new
bytes. A file that changed underneath the catalog is exactly the case doc 04
§4.4 reserves for a human — corruption and an upgrade are indistinguishable to
the scanner, and silently adopting either would make the log ratify whatever
last overwrote the disk. Quarantine stops the bleeding and makes the choice
visible; `resolve --replace` remains the operator's.

### 9b. The mover forgets across restarts, and pays ~8 hours for it

`tier_unfetchable` is a `Mutex<HashSet<String>>` on the daemon's state struct.
In memory only. Every restart empties it, so the first pass afterwards must
re-attempt **every** doomed node over the network before the set is rebuilt.

The arithmetic matches the symptom: ~24k unreachable nodes at roughly a second
each of connect-and-be-refused is ~6.7 hours. The observed figure was 477
minutes and still climbing. D98 stopped the *within-session* retry storm and was
verified doing so; it just never survived a restart.

**The fix.** Persist the set in `index.db` beside `location_quarantine` — it is
derived state, so it belongs in the projection and never in the log. Load at
startup, save after each pass, and keep D98's 24-pass expiry so a repaired
catalog still recovers on its own.

**These two compose — but only because a third thing was fixed to make it so.**
9a quarantines a bad location; a node whose only location is quarantined stops
being a candidate; it then falls into 9b's memory and stops being asked for at
all. The five files stop costing anything, and stay visible.

That chain was broken in the middle when first written, and tracing it rather
than assuming it is what found the break: with every location quarantined,
`fetch` returned *"no reachable source holds this file"*, which D98's memory
does **not** key on — deliberately, since that wording also means "no instance
registered", an operator's problem to fix and the wrong thing to cache. So the
mover would have swapped one error repeated every pass for a different error
repeated every pass. `fetch` now tells the two apart and gives the
all-quarantined case the "no readable location" wording D98 already acts on.

### 9b-ii. The hazard the fix opened, and one it did not

Quarantining more locations makes any code that treats "has another location"
as "is safely held elsewhere" more dangerous. Two such places exist.

**`evict_pass` — fixed here, and it destroys files.** Its `live_elsewhere` test
read `engine.locations()`, which returns quarantined URIs. So: the NAS copy of a
file drifts and gets quarantined; feederbox's evict sees a location that is not
its own, calls the file safely held, and deletes the local copy — leaving only
the copy already known to be wrong. That is the same silent loss the size check
immediately below it was written for after a 1080p replacement was deleted in
the lab. D99 excludes quarantined URIs from that test.

**`retire_locations_under` — found, NOT fixed, deliberately.** Its guard is a
SQL `EXISTS`/`NOT EXISTS` pair over `file_locations` and has the same blind
spot. Three reasons it is left: it retires a catalog *record* and deletes no
bytes, so a rescan repairs it; the hazard predates D99, since `read_verified`
and `loc_verify` have always been able to quarantine; and the two queries are
complements, so editing one side without the other creates a location that
falls into neither set — a worse failure than the one being fixed, and not
something to land in the same pass as the fix it rides along with.

### 9c. Not in scope, and why

- **The 32 no-op pending changes.** Of 51 flagged, 32 show `N -> N bytes` — same
  size, flagged on mtime alone (rclone and cloudplow touch mtimes), and 23 of
  those are `.manifest` recursion nodes. Noise, not corruption, and it clears
  with re-genesis (§6). Worth its own decision, not this fix.
- **Adopting the new encode automatically.** See 9a — that is §4.4's call to
  make, and it belongs to a human.

## 10. D99 turnkey checklist

### A — the parity fix (9a)
1. `Engine::quarantine_location(id, uri, reason)` — a public wrapper over the
   existing private `quarantine`, so the client crate can reach it.
2. In `Fetcher::fetch`, match the commit error before stringifying it; on
   `PvfsError::Integrity`, quarantine every location of `id` whose URI parses to
   the failing candidate's pin.
3. ~~Same treatment in `swarm_fetch`.~~ **Deferred in D99 — and SUPERSEDED by
   D102 (§15).** The reasoning was that a swarm pulls chunks from *every*
   holder, so a whole-file mismatch cannot name which one served bad bytes, and
   blaming a pin would strand good holders. That holds for a real multi-holder
   swarm. It does not hold when there is exactly ONE candidate, which is the
   production shape — so the case D99 declined was the only one occurring, and
   the fallback re-downloaded 5.5 GB per pass to fail the same check. D102
   quarantines when `candidates.len() == 1`.
4. **`candidates()` must SKIP quarantined locations.** Found while implementing
   3, and without it the whole fix is cosmetic: `Engine::locations()` returns
   quarantined URIs on purpose — evict, reclaim and `loc_verify` all need to
   see them, and re-reading one is how a quarantine gets LIFTED — so recording
   the quarantine would have changed nothing about what the mover tried next
   pass. The filter belongs in the fetcher's candidate list and nowhere else.
5. Test: quarantining one location of a node bans exactly that one, leaves a
   second holder usable, and does not hide either from `locations()`.
   **Lab, not unit:** that a live peer serving wrong bytes ends up quarantined
   needs a real peer — the same gap D98's marking path has, recorded rather
   than papered over.

### B — the memory fix (9b)
6. Table `fetch_unfetchable (file_id TEXT PRIMARY KEY, noted_at INTEGER)` in the
   projection schema, additive.
7. Daemon loads it into `tier_unfetchable` at startup; writes back after each
   pass; the 24-pass clear truncates the table too.
8. Test: a daemon restart does not re-attempt a node already known unfetchable,
   and the 24-pass expiry still lets a repaired one back in.

### C — verification that would have caught this
9. **A successful fetch logs nothing today.** `fetch.rs` has an `eprintln!` on
   each failure branch and none on success, so "zero successes in the log"
   proved nothing and cost an hour of the wrong diagnosis. Log the success too.
10. Re-check on the live holder after deploy: `serve status` shows tier
   completing passes, and `loc ls` on the five names shows a quarantined
   location with its reason.

---

## 11. Review queue — open after D99 merged (2026-09-01)

Everything below is **found and verified, not fixed**. Items 1–9 came from an
independent review Chris commissioned; each carries the verdict from checking
it against the tree, because a second reader's report is a lead, not a finding.
Items 10–14 are what this workstream knows it left standing.

### Verified — security

**1. `check_member_event` fails OPEN, and wider than reported.** CONFIRMED, and
worse than the report said. `projection.rs:1789` ends the match with `_ => {}`,
so any kind not named passes on `require_active_author` alone — "is this device
key live?" and never "may this key do this to this node?". **19 of 32 event
kinds** land there, including `FileLocationRemoved`, `NodePurged`, `NodeCreated`,
`LinkRelabeled`, `LinkReordered`, `LinkSuperseded`, `LinkSuspended`,
`LinkUnsuspended`, `FolderBound`, `FolderUnbound`, `FolderUnboundRoot` and
`MediaQuality`. `LinkRemoved` right above it does the per-node rights match
properly, which is the shape the rest want.

This contradicts the standing posture — no authority outside explicit ACL
grants, **default-deny** — and a catch-all arm is default-allow. Caveat before
anyone writes the fix: some identity kinds in that list (`DeviceAuthorized`,
`DeviceRevoked`, `RootRotated`, `RecoveryKey*`, `ForestCreated`) may be
authorised on a different path, so each needs checking rather than a blanket
`require_right`. Tests must cover **both** live commit and projection replay —
the two paths judge separately and have diverged before.

### Verified — correctness

**2. `LIKE ?1 || '%'` with no `ESCAPE`.** CONFIRMED at **9 sites** in
`engine.rs`, including both halves of `retire_locations_under` — the function
D99 just touched. In SQLite `_` is a single-character wildcard, so a prefix
matches more than it names. Fleet paths carry underscores (`Data_ext`,
`CACHEDEV1_DATA`), so this is not hypothetical, and the operation it guards
REMOVES location records. Fix by escaping `_ % \` in the bound prefix, or by
`substr(uri, 1, length(?1)) = ?1`.

**3. `manifest_for` writes to disk on a read.** CONFIRMED — `sync.rs:418` calls
`write_manifest_sidecar` at :432. Split the getter from an explicit write at
adopt/verify time.

### Verified — the tooling that judges the code

**4. Pipeline and CI run different toolchains.** CONFIRMED. `ci.yml` pins
`1.96.0` and says in its own comment why floating on `@stable` was wrong;
`pipeline.yml:72` still installs `--default-toolchain stable`. So presubuntu
can pass a clippy that CI fails, in the direction that matters.

**5. CI clippy is not `--all-targets`.** CONFIRMED —
`cargo clippy --workspace -- -D warnings` leaves test code unlinted. The ad-hoc
runs this workstream does by hand ARE `--all-targets`, so the manual check is
stricter than the gate.

**6. `/tmp/pvfs-*-results.txt` is still one shared path.** CONFIRMED, and it is
the unfinished half of the build-slot fix: sessions now get
`/opt/pvfs-<session>/src` but still `tee` into the same two result files.
Verification reads those files, so concurrent sessions can read each other's
totals — the failure mode the slot fix exists to prevent, one directory over.

**7. `--version` reports 1.4.0 for every build.** CONFIRMED, and already written
up as a RULE in `VERSIONING.md` after `1.4.0` meant two materially different
binaries at once. Bake `git describe --tags --dirty` in via `build.rs`/vergen.
Until then, deploys are verified by grepping the binary for a string only the
intended build has — which is what this workstream does.

**8. `.gitignore` blanket-ignores `*.json`.** CONFIRMED (line 36, with
exceptions). Ignore by path instead, so a legitimate config cannot go missing
silently.

### Verified, but the recommendation is REJECTED

**9. Remap `hash_policy = lazy` to `on_add` in the loader.** The behaviour is
confirmed — D94 makes a `lazy` binding refuse to load. The proposed remedy is
the one Chris explicitly turned down: *"that isn't a real mode and it will be
confusing... I'd want to know if one gets left laying around trying to work in
a way it can't."* The refusal is the feature; it found a live `lazy` binding on
the NAS within minutes of shipping. A **one-shot migration that remaps and says
loudly what it changed** would satisfy both readings — silent reinterpretation
would not. Chris's call, not the reviewer's.

### This workstream's own leftovers

**10. The stall detector still measures the wrong thing.** D96 fixed a real bug
and is live, but "no pass has completed in N minutes" cannot describe a job
whose healthy pass takes days. It has now cried wolf three times, and it is the
detector the fleet monitoring of §5 would be built on.

**11. `watch` on the holder sits in `backoff`** — *"SQLite is busy/locked during
scan state (retried 0x)"*. Hashing advances regardless, so it recovers, but
`retried 0x` on a busy error is the wrong number for a retry path.

**12. ~~The D99 marking path is unproven end to end.~~ CLOSED 2026-09-01, in
production.** Within hours of the roll:

```
fetch: quarantined stale location
  pvfs-host://64b88868…/mnt/local/Media/TV/Reacher (2022)/Season 03/
  Reacher - s03e08 - Unfinished Business.mkv
```

A real peer, bytes that genuinely no longer match, a durable quarantine — the
proof no unit test could give, on one of the five files that started this.

**13. Two quarantine helpers now coexist.** `uri_quarantined(file, uri) -> bool`
in `engine.rs` and `quarantined_uris(id) -> Vec<String>` in `fs.rs`, from two
sessions that could not see each other. Same table, different shapes. Consolidate
when someone is next in that code.

**14. The CI watcher fix is unproven on GitHub.** `5a4711e` raises the poll
ceiling and prints the watcher's log on failure, but has not yet run on a GitHub
runner. If it still fails there, the output will finally say whether the daemon
was slow or refused to start.


---

## 12. D100 close-out — the queue, and what it cost

All fourteen items of §11 are addressed in `1405868`. Verified on presubuntu:
**103 suites, 481 tests, 377 smoke, 0 failed**, clippy `--all-targets -D
warnings` clean. Deviations, honestly:

### Corrections to §11 item 1 as reported

- **The identity kinds were never in the hole.** `DeviceAuthorized`,
  `DeviceRevoked`, `RootRotated` and the recovery keys are gated at BOTH commit
  and replay on a separate path (`check_device_cert`, current-root rules). They
  now sit in named arms saying so, rather than in a catch-all where "allowed"
  and "nobody looked" are indistinguishable.
- **The exposure was narrower than stated.** `prepare_remove_location` and its
  siblings already check rights, so the remote-member path was covered. The gap
  was replay and local commit — which is precisely where `fold_one`'s own
  comment promises "a tampered or synced log can't carry an event its author had
  no right to". For eleven kinds that promise was not kept.

### Verified against production, not just tests

This change could have been fleet-down: the new checks run on replay of a log
whose events predate them. A 148 MB copy of the owner's `log.db` (~241k events)
was replayed **with `index.db` absent**, so the entire log folded through the
new rules. It rebuilt a 116 MB projection with **zero rejections**.

A negative control ran too: with the six new checks neutered, all six denial
tests fail and the positive test still passes — the correct signature, since
removing a check allows everything.

### Done honestly, not fully

**§11 item 10 (the stall metric).** The blunt check now reports `overdue` and
states what it observed. It no longer asserts "the pass is stuck, not working",
a diagnosis it has no evidence for and got wrong all three times it fired. The
REAL fix — progress within a pass, so a long pass that is advancing can be told
from one that is wedged — needs a signal plumbed out of `scan_routed` and
`tier_pass`, a cross-crate API change that belongs in its own milestone. This
one stops the lying; it does not add the sense.

**§11 item 9 (lazy remap)** remains rejected, per Chris.

**§11 item 12 (the D99 marking path)** still needs a live peer. Production has
five files waiting.

### Two failures worth keeping

**The version fix did not work where it mattered, first time.** `build.rs` ran
`git describe` on the build host — which receives an rsync copy with `.git`
excluded. Every pipeline binary stamped itself `unknown`: useless on exactly
the builds that get deployed, which is the case VERSIONING.md wrote the rule
for. The playbook now resolves it on the control machine and passes it in.

**The build-slot fix filled the build host.** Each session slot is a full
source + target tree, ~6 GB. Three MERGED slots were never removed and
presubuntu reached 96G/96G — which is what failed two pipeline runs, not the
code. CLAUDE.md says to delete the slot on merge; the rule survived about a
day. **Reaping merged slots should be automatic, and is now the one open item
this milestone leaves behind.**

## 13. The production roll (2026-09-01) — what deploying it taught

D99+D100 rolled owner → ingest → holder, each verified before the next. Every
box MIGRATED 13→14 in place; no replay. Owner and ingest report
`v1.4-133-g82bd163`, the first deploy here whose binaries can prove which build
they are. The holder's `tier` went from `stalled` at 2,112 minutes with zero
completed passes to `idle`.

Three things only a real roll could show.

**The watchdog races the play.** `bin/watchdog.sh` (D83, written after the NAS
sat down for ten hours unnoticed) restarts pvfsd every 30s — inside the exact
window the play waits for it to exit, so the play concludes "still holding its
binary" forever. Neither knows the other exists. A NAS roll currently needs the
watchdog stopped by hand and RESTARTED afterwards; forgetting the restart
leaves the holder unsupervised, which is the outage D83 exists to prevent.
**Not yet fixed** — the play should bracket the swap itself.

**`Daemon up` passed by coincidence.** `grep -c listening pvfsd.log`, failing
unless the digit `1` appeared in the total — a count of every start the log had
ever held. It passes at 1 and 10–19, fails at 20 and 30. It failed this roll at
exactly 30 on a daemon that was up and serving. D101 asks instead whether the
daemon is running, matched on this mount's own argv.

**The play forced `sync` on, against the inventory.** The holder declares
`follow,tier` with sync deliberately off. Turning it on was not cosmetic:
`sync_pass` built its `Fetcher` with no `seed_unfetchable`, so D98's memory
never covered it and the not_found retry storm returned within minutes through
a job that had never been given the fix. D101 removes the forcing; D102 gives
`sync` the memory.

Two guards were RIGHT and stay: refusing when `media_node` was unset — before
the binary swap, not after — and refusing to overwrite a binary pvfsd still
held open. Both would have left the holder rolled but down.

## 14. Open after D102

Renumbered 2026-09-02; item 3 of the old list (D99's marking path end to end)
is CLOSED — it fired in production on Reacher s03e08 (§11 item 12).

**Code**

1. **The stall metric proper.** D100 stopped the detector asserting "stuck"
   with no evidence, but it still cannot tell a long pass that is ADVANCING
   from one that is wedged. That needs a progress signal out of `scan_routed`
   and `tier_pass` — a cross-crate API change, its own milestone (§12).
2. **A disabled job keeps its last status row.** After `serve disable sync` +
   SIGHUP the holder still reports `sync  idle  (last error: 82 fetch
   failures…)` while `serve.jobs` correctly lists only `follow, tier, watch`.
   Verified genuinely idle — the not_found count is static — so a reporting
   bug, not a runaway job. Same category as item 1: a status saying what it
   cannot support. The row should reset to `disabled` and drop the error.
3. **`watch` hits SQLite BUSY during scan state.** The retry count it reports
   is honest since D100; whether the retries are ENOUGH is a separate question
   nobody has asked.
4. **165 pending changes** on the holder, most flagged on mtime alone with no
   size change (rclone and cloudplow touch mtimes) and many of them
   `.manifest` recursion nodes. Noise that clears with the rebuild, but it
   buries the real drift among it.

**Tooling / operations**

5. **Automate build-slot reaping.** Each session slot is a full source + target
   tree (~6 GB); three MERGED ones went unreaped, presubuntu hit 96G/96G, and
   two pipeline runs failed in a way that read as a code error. CLAUDE.md says
   to delete them on merge; the rule lasted a day.
6. **The play should bracket the watchdog** around a NAS swap. It restarts
   pvfsd inside the 30s window the play waits for it to exit, so a roll needs
   the watchdog stopped and RESTARTED by hand — and forgetting the restart
   leaves the holder unsupervised, the exact outage D83 exists for (§13).
7. **`build-nas.sh` does not stamp `PVFS_BUILD`**, so QNAP binaries report
   `unknown` and can only be verified by content (VERSIONING.md).

**The big one**

8. **The rebuild** (§6) — re-genesis carrying the hashes forward, which also
   clears the D84 duplicate nodes, the manifest-recursion junk and most of
   item 4. Sidecar coverage is now ~96%, which was the precondition.

> 2026-09-09: an external review of the D102 merge was verified against
> D121 in [doc 26](26-d102-external-review-response.md). Items 1, 2, 6 and
> 7 above are restated there with their current state; item 5 closed with
> D121. Doc 26 §0 records the finding that reframes the mover's remaining
> WAN re-fetches: the holder's replica source is the owner, which holds no
> bytes.

## 15. D102 — the two gaps the roll itself found

Neither came from a test. Both came from reading production logs after D99 and
D100 were live.

**Swarm attribution.** D99 declined to quarantine on a swarm integrity failure
because a multi-holder swarm cannot attribute a bad chunk. True in general, and
irrelevant here: the holder pulls from one peer. The log showed
`swarm: resumed 663/663 chunks` — the file complete on disk and already proven
not to match — then a single-stream re-download of 5.5 GB across a WAN to fail
the identical check, every pass. D102 quarantines when there is exactly one
candidate, where attribution is not a guess.

**`sync` never had `tier`'s memory.** `sync_pass` built its `Fetcher` bare and
`sync_pull` never consulted the unfetchable set, so D98 and D99 covered `tier`
alone. Invisible while `sync` was off on the box that had the problem — and the
D99 roll turned it on (§13), bringing the entire not_found retry storm back
within minutes through a job that had simply never been given the fix. Both
jobs now share `fetch_unfetchable`.

**The pattern worth keeping:** every one of D99, D100, D101 and D102 is the
same shape — a fix applied at one site and not its siblings. `read_verified`
quarantined and `fetch` did not; `LinkRemoved` checked rights and eleven
siblings did not; `evict` learned about quarantine and `retire` did not;
`tier` got a memory and `sync` did not. Searching for the siblings is now the
cheapest review this project has.


## 16. The re-genesis rehearsal (2026-09-02) — the premise was wrong

Run on presubuntu against a synthetic library of four files deliberately larger
than the 8 MiB chunk size, so a whole-file hash and a single chunk hash differ
(below that they coincide and the test proves nothing).

**Q1: do node ids survive a fresh genesis? NO.** Two independent forests over
the same bytes agreed on node COUNT and on labels, and on nothing else. Every
id differed. The cause is in `node::preimage()`: the id covers
`creation_nonce`, `created_at` and `author`. The nonce is random; `created_at`
is a wall clock; `author` is the signing device. §6 read doc 03 §3.2's
statement about **link** ids as though it were about node ids.

**What that costs — MUCH LESS than first written.** The sentence here used to
read "anything holding a node id outside the log — PVOS bindings, exports, the
*arr hook's recorded ids, shares — points at nothing afterwards". That was
asserted, not checked. Checked (2026-09-07), the real set is small:

| holder | addresses by | survives re-genesis? |
|---|---|---|
| *arrs, rclone, anything on the mount | path + filename | **yes** — never sees an id |
| PVOS `MountBind` | a **tree path**, resolved to an id at call time (`mounts.rs:231`) | **yes** |
| PVOS regions / `folder_id` | read back from PVFS, not persisted | **yes** |
| `fleet-prod.ini` `media_node` | one node id | no — one line to re-point |
| `.pvfs/placement` on the owner and holder | the same id, 2–3 keys each | no — one file per box |
| `.pvfs/bindings.local` on the ingest and holder | the same id, 1–2 binding rows | no |
| **`pvfs-mount.service` on the ingest** | the forest **ROOT** id — a SECOND id | no |

This paragraph used to read "**a single node id — the Media folder — written
in one inventory line and one placement file per box**". **Measured against
the running fleet on 2026-09-08, that was wrong on all three counts:** there
are **two** distinct ids (the Media folder AND the forest root, the latter in
the ingest's `pvfs-mount.service`), spread over **six files**, in **ten**
key/row occurrences. The ingest carries no `placement` file at all — it holds
its id in `bindings.local`.

Still a small edit rather than a migration, and the conclusion survives. But
the enumeration is the thing a runbook needs to be exhaustive about, and it
was written from memory. Doc 25 §3 has the measured table.

What is genuinely lost is log CONTENT, which was already known and listed: ACL
grants, the 24,585 `MediaQuality` events (re-derivable by re-running the *arr
hook), tags, and locations held by other hosts.

**What still holds.** The hash work genuinely survives, which was the expensive
half: production shows `scan: hash from sidecar` at scale, and sidecar coverage
on the holder reached 96% before this was written. A re-genesis re-reads
metadata, not 40 TB of bytes.

**Q2: RESOLVED, and the answer was a bug (D103).** Sidecars were written by
`fill_hash_if_needed` — the path for files added *unhashed* — and by nothing
else. Both `on_add` paths, which are the ones a re-import takes, called
`hash_with_manifest` directly: they neither read a sidecar nor wrote one. The
record built to make re-genesis cheap did not apply to re-genesis.

So before D103, re-genesis would have re-read all 40 TB against 98% sidecar
coverage already on disk. D103 gives both `on_add` sites the same reuse-and-
record helper.

**How it was proved matters, because two obvious methods cannot.** Timing tells
you nothing — blake3 with rayon does 600 MB in about a second, so cold and warm
scans look alike. Making the bytes unreadable tells you nothing either: the
scan marks an unreadable file skipped *before* hashing, so the file never
reaches the code under test (that run reported `1 skipped, 1 unreadable`, which
confirmed the bug but could never confirm a fix). What works is a **sentinel
hash** in the sidecar that the bytes cannot produce, size left honest — if the
forest records it, it read the sidecar.

**A note on the rehearsal itself.** The first version suppressed setup errors,
so the forest was never built and every assertion compared empty to empty and
reported `ok` — a vacuous pass, the exact failure this document catalogues
elsewhere. The second compared `walk` output that turned out to be **labels,
not ids**, and would have "confirmed" the false premise. Both were caught by
noticing that counts looked impossible, not by the assertions.

### What this changes about the plan

1. ~~**Re-genesis needs an id-mapping story.**~~ Largely moot — see the table
   above. Non-native apps address by path and never see an id; PVOS resolves
   paths to ids at call time and persists none. Re-pointing `media_node` and
   the placement files is the whole of it.
2. **The compaction alternative deserves a second look** (doc 11). It targets
   the same problem — log size and replay time — WITHOUT changing identity, and
   the identity-preservation that made re-genesis look strictly better was
   imaginary.
3. **The cheap-hash property is real** — but it was not actually wired up until
   D103. Worth keeping either way.
4. **Quality, and anything else keyed by node id, can be CARRIED rather than
   lost.** Chris's suggestion, and the machinery already exists: `fs.rs:1846`
   does exactly this whenever hashing mints a successor id — read
   `media_quality(&old)`, then `set_media_quality(&new, …)`, re-signed as a
   fresh event for the new id rather than moved, because the log is
   append-only. A re-genesis can open the old forest read-only and, for each
   file it adds, carry the old record across matched **by path**. The same
   shape works for ACL grants. That shrinks "what is lost" to things genuinely
   tied to the old topology.


## 17. Open before the real re-genesis (2026-09-07)

D103 proved the cheap-hash property on live data: `TV/Reacher (2022)`, 67 GB,
30 files, **83 seconds** — 27 hashes reused from sidecars, 3 hashed fresh and
recorded, and `loc verify` confirmed a reused hash against the real bytes. The
live forest was untouched throughout.

That test was a **single-box forest**, and production is not one. What is still
open:

### Blocking

1. ~~**The fleet shape is untested.**~~ **TESTED 2026-09-07 on the lab pair —
   it works.** Owner `pvfs-lab-owner` built a fresh forest over 8 files (11
   nodes) and served it; `pvfs-lab-ingest` was enrolled `rwa`, took a replica,
   bound the SAME bytes at a DIFFERENT path, and ran `watch` as a daemon job.

   Result: **node count stayed 11 on both boxes**, and all 8 files ended with
   locations from both. `film1` carries three — the ingest's `file://` path,
   the owner's `file://` path, and the ingest's pin-qualified `pvfs-host://`.
   The `relocated` path works through replica → owner routing, which was the
   question that decided whether re-genesis is possible at all.

   **Two things the test taught that the runbook needs.** A replica REFUSES a
   bare `pvfs scan` — *"a replica has no local writer, so its scan must be
   routed to the owner — run it from the `watch` serve job"*. And `serve watch`
   in the foreground is not enough either: it arms inotify for NEW writes,
   while an existing library is picked up by the reconcile pass, so the routed
   import has to run as the `watch` DAEMON JOB. Both are exactly how
   production is configured, which is why neither shows up until you build a
   forest from scratch.

2. ~~**There is no re-genesis tool** (F2 was never built).~~ **The RUNBOOK is
   written — doc 25 (D107, 2026-09-08).** Still no tool: every step is a
   command an operator runs. What changed is that the order, the checks, and
   the two constraints the lab run taught are now written down, along with the
   measured list of everything that has to be re-pointed.

   Writing it turned up three traps, each of which would have cost a run:
   `library_node` is undefined in `fleet-prod.ini`, so the ingest bind task
   **silently skips** in production and a green play run binds nothing;
   `pvfs-mount.service` is **live on the ingest**, not "dead" as that file
   claims, and the play cannot re-point it because its vars are absent; and
   the external-id set is twice what §16 said (doc 25 §3).

   **NOT rehearsed end to end** — doc 25 §10. A runbook that has not been
   executed is a hypothesis.

3. ~~**The `MediaQuality` carry is designed, not built.**~~ **BUILT (D104):
   `pvfs forest carry-quality --from <old> [--dry-run]`**, matched by tree path
   and re-signed against the new ids.

   Dry-running it against a copy of the production log measured something more
   interesting than the tool: **of 24,585 recorded measurements, 119 are
   reachable from the forest root.** 581 sit on a node with a live containing
   link; the other 462 of those have live links to live parents whose chain
   never reaches the root. 34,269 nodes are reachable in total, against 56,155
   file nodes.

   So the quality data is not something re-genesis would destroy — **it is
   already gone**, stranded on superseded and disconnected nodes, and 119 is
   what there is to carry. The same numbers say the forest holds substantial
   disconnected structure: islands of live-linked nodes that no walk from the
   root can see. That is a stronger argument for re-genesis than the log size
   ever was.

4. ~~**No cutover plan for the mount.**~~ **Written (doc 25 §7) — and the
   premise was wrong.** "Sonarr, Radarr and rclone read through a mount
   pointed at a forest" was assumed, never checked. Checked 2026-09-08:
   mergerfs on the ingest has branches
   `/mnt/local=RW:/mnt/remote/nas=NC:/mnt/remote/nas2=NC` — **`/mnt/pvfs-root`
   is not among them**, nothing holds a file open on it, and no container
   mounts it. The *arrs read `/mnt/unionfs/Media`, which is local disk plus
   rclone. **PVFS is not in their read path**, so a forest swap is invisible
   to them and the library-vanished risk does not exist.

   What remains is re-pointing a mount unit nothing consumes, and restarting
   three daemons in roll order.

### Worth settling, not blocking

5. ~~**Rollback.**~~ **Defined: doc 25 §2 (six pass conditions) and §8
   (rollback).** The old forest is a different directory and its daemons are
   the ones still running, so rollback before cutover is doing nothing, and
   after cutover is re-pointing three units back.
6. ~~**F3's consistency check needs a before/after comparison.**~~ **Doc 25 §1
   is that step, with the commands.** Baseline re-taken 2026-09-08 on the live
   owner: **`missing` 1,894** (up from the 1,416 recorded here — it has grown),
   **`orphans` 25,602**, three `rwa` root grants. The islands count needs D106
   deployed to take at all.

### Already small — checked, not assumed

- **ACLs: three grants, all `rwa` at the root.** Trivial to re-establish.
- ~~**External node-id references: one id**~~ — **two ids, six files, ten
  occurrences** when finally measured rather than recalled (doc 25 §3). The
  extra one is the forest ROOT, in the ingest's `pvfs-mount.service`. Still
  small; the point is that "already checked" was not true of this line.
- ~~**Duplicate nodes (D84) should NOT recur.**~~ **FALSE, and it was being
  disproved while this line sat here.** They were being minted on every new
  arrival right up to 2026-09-08, and 588 groups were found the moment anything
  looked. The reasoning — "`match_by_identity` matches on name + size, so a
  second box relocates rather than re-adds" — inverted the truth: matching on
  SIZE is what fails, because the two nodes of a pair disagree about size, and
  that is the whole reason each pair exists.

  Two causes, both now closed. **D112**: rclone preserves the source mtime, the
  settle window trusted mtime, and the holder catalogued half-copied arrivals at
  a partial size. **D115/D117**: the scan matched on name AND size, so a file
  whose CONTENT changed was not a candidate at all and an *arr upgrade grew a
  node per version — with D115 a no-op on every replica until D117 taught its
  check that a location can be pin-qualified.

  The lesson worth more than the fix: this bullet is in a section headed
  "Already small — CHECKED, not assumed", and it was neither.


## 18. The islands — measured, and the mechanism (2026-09-07)

Found while dry-running D104's carry: 24,585 quality measurements, 581 on a
live-linked node, but only **119 reachable from the forest root**. The gap is
not an accounting quirk.

**Measured on the live owner index.** The first version of this table listed
"with a live link: 36,120" beside "reachable: 34,271" as though they were rival
totals, and omitted the largest group entirely — so the figures could not be
made to add up. Chris said so. They do add up; here is the whole forest:

| group | nodes | |
|---|---|---|
| reachable from the root | 34,279 | the live tree |
| live-linked but UNREACHABLE | 1,849 | the islands (1,358 files, 491 folders) |
| **no live link at all** | **25,602** | **the group that was missing** |
| **total** | **61,730** | 34,279 + 1,849 + 25,602 |

(36,120 was simply reachable + island, not a third category.)

**The 25,602 are not junk — they are the successor tax.** 25,589 are file
nodes, and **25,587 of them have a live twin under the same name**: they are
the PREDECESSORS left behind when a hash fill minted a successor. Exactly two
are genuinely gone, and one is `.manifest` residue. So roughly **41% of the
forest is superseded copies of files that are still there**, one per file
hashed — the cost of successor-per-fill, at library scale. It is the strongest
size argument for re-genesis, and it has nothing to do with the islands.

**One cause, one edge — and the removal was INTENTIONAL.** `Backups` was
unlinked on **2026-08-24 22:07 UTC**, when Chris moved the backups out of
`/Media`. Those files are supposed to be gone from the forest, and the top-level
unlink was the right call.

What went wrong is what it left. Unlink soft-removes THAT LINK and does not
cascade, so every node beneath — `Feederbox`, `Mac_iCloud_old`, `Mediabox` and
their contents — kept its own live link to its own live parent. The subtree
detached from the root in one operation and 1,849 node records stayed behind,
describing files that are no longer in the library at all.

**The removal mechanism DID work — every step but the last.** Chris asked
whether something should detect a file moved out of a bound folder and drop its
link. Something does, and it ran:

1. The scan noticed the files were gone and removed their **locations**. All
   1,849 island nodes now hold **zero live locations** — confirmed.
2. It deliberately does NOT remove the **link**. `walk_disk`'s removal arm calls
   `remove_location`, never unlink, because a scan cannot tell a deliberate
   deletion from an accident from an unmounted volume (doc 04 / D81).
3. `pvfs missing` reports exactly these — **715 of the entries in feederbox's
   current report are Backups files** — and says what to do:
   *"`pvfs missing --forget` unlinks them once you have decided."*
4. Nobody has run `--forget`.

So this is not a missing mechanism. It is an unrun command, and the design is
deliberate: the last step is a human decision by construction.

**The genuine gap is narrower than it first looked.** `missing` lists FILES, so
an operator sees 1,416 filenames rather than "the Backups subtree is detached
from the root; 1,849 nodes; run --forget". The 491 detached FOLDERS appear in no
report at all, and nothing says the subtree is unreachable — which is why this
sat for two weeks and was found during an unrelated investigation.

**A correction this forces.** Earlier analysis in this document read the ~1,272
photo-and-archive entries in `missing` as residue from an old, unrelated photo
root. They are not: they are the Backups island, reported correctly the whole
time and misread here.

**What it costs a live forest.** Nothing on disk: the bytes are untouched and
this is purely the catalog's shape. But `reclaim` trashes central bytes with no
live link, and these all HAVE live links — so the space they occupy is
invisible to the sweeper and will not come back. And it scales with one
command: unlinking a folder with 10,000 descendants strands 10,000 nodes while
the operator sees one success.

**For re-genesis this is an argument, not an obstacle.** A new forest is built
by walking directories on disk, so an island simply never appears — the 1,849
are dropped by construction. Better grounds for rebuilding than log size.

**The gap worth closing regardless:** nothing detects or reports a detached
subtree. Unlink's non-cascading semantics are defensible; the silence after is
not. A check that walks from the root — rather than asking about links — would
surface an island the day it forms instead of a fortnight later during an
unrelated investigation.

---

## 19. D106 — the island check, and a warning before the cut

Closes the gap §18 names. Two pieces: a report that finds a detached subtree,
and a word from `unlink` at the moment one is about to be created.

### 19.1 Why the existing checks cannot see this

Every check this system has asks a question **about a node**:

| check | question | answer for the 1,849 |
|---|---|---|
| `orphans` | has this node no live link? | no — it has one |
| `missing` | does nobody hold this file's bytes? | no — somebody does |
| `reclaim` | do these central bytes have no live node? | no — they do |

All three are local predicates, and a detached subtree is locally perfect: the
only broken thing is a single removed edge at the top, and no node inside it is
adjacent to that edge. The question has to be **about the graph** — *is there a
path from the root to here?* — and nothing asked it.

### 19.2 What "reachable" means here

**From every tree root, not "the" root.** A forest holds more than one tree —
`pvfs tree create` makes one, rooted by a live `contains` link with a NULL
parent, which is the same shape `forest init` gives the forest root — and
`walk` deliberately stays inside one tree. Seeding the walk from the forest
root alone therefore reports every *other* tree as detached. The first build
did exactly that; the CLI smoke suite caught it, having made a second tree
120 lines earlier and hung a ref-held file off it. The seed is now every live
NULL-parent `contains` edge.

From those seeds, reachability mirrors `walk()`, the engine's own pre-order
tree semantics (spec §12): **descend `contains` only, but count a `ref` child
of a reached folder as reached.** A ref child is listed when you browse its parent, so it is
plainly in the tree even though the walk does not descend it — flagging it
would be crying wolf on the very first run.

A link counts as live on the **same predicate `orphans` uses**: `removed_at IS
NULL`, nothing more. In particular a *suspended* link still traverses. That
symmetry is the point — the report is exactly the set difference between two
sets defined by the same edge test, so a node cannot fall into it because the
two halves disagreed about what a live edge is. Suspension is a deliberate,
recorded state with an operator behind it; treating it as detachment would
report a decision back to the person who made it.

Both `links` and `temp_links` traverse, for the same reason: `orphans` counts a
temp link as a live link, so the walk must be able to cross one or every staged
node would surface as an island.

### 19.3 Grouping — name the folder, not the children

The one-home rule makes `contains` a strict tree, so the ascent is unambiguous.
For each stranded node, climb live `contains` parents until either there is no
parent or the parent is reachable; that node is the island root. For the
production case every one of the 1,849 climbs to `Backups`, so the report is
**one line, not 1,849**.

The island root is normally *not* itself in the stranded set — its inbound link
is the one that was removed, so it has no live link at all and it is already an
`orphans` row. That is the useful part: `orphans` was reporting `Backups` all
along, in a list of 939, with nothing to say that this one had 1,849 nodes
hanging off it. The island report is what makes that row mean something.

`detached_at` comes from the retired edge itself — `MAX(removed_at)` over
removed `contains` links into the island root — so the report dates the cut.

It also *discriminates*, which matters on a replica. A node may be linked under
a folder that is itself linked into the tree later, so a replica caught up
between those two events shows a real, transient island. A cut has a removed
edge on record and a not-yet-synced edge does not, so the report says which it
is looking at rather than calling both a detachment.

### 19.4 The unlink warning

`unlink` stays non-cascading; §18 is right that the semantics are defensible.
What changes is that it counts the subtree first and says what it is about to
strand.

- **TTY, no `--yes`:** print the count, prompt `[y/N]`, default no.
- **Not a TTY, or `--yes`, or `--json`:** proceed, but print the warning.
  `prompt_line` *errors* without a TTY, so prompting unconditionally would turn
  every scripted folder unlink into a failure — including six in the smoke
  suite. A soft-remove is reversible by re-linking; a broken pipeline is the
  larger harm.
- Only for a live `contains` link to a node with at least one descendant. A
  file, a `ref`, or an empty folder is silent, as now.

### 19.5 Turnkey checklist

- [x] **A.** `Engine::list_islands()` → `IslandReport { nodes_total,
      reachable, live_linked, stranded, islands }` — the four numbers of §18's
      table plus the grouped rows.
- [x] **B.** `Engine::subtree_size()` → `SubtreeSize { nodes, files, folders,
      bytes }`, shared by the report and the unlink warning.
- [x] **C.** `pvfs islands` — human and `--json`. Always exit 0: a report,
      like `orphans` and `missing`, and the exit codes in this CLI mean
      *the command failed*, not *the forest has a finding*.
- [x] **D.** `pvfs unlink` warns and prompts per 19.4; `--yes` skips the prompt.
- [x] **E.** Tests: a clean forest reports nothing; unlinking a folder strands
      its subtree and the report names the folder with the right counts; nested
      islands group to the topmost; a `ref`-only child is not an island; the
      island root is the `orphans` row. Plus two the design did not foresee —
      a second tree is not an island, and a file held only by a `ref` from
      another tree is reachable (see 19.6). **9 tests**, and a CLI section in
      the smoke suite.
- [x] **F.** Pipeline green on presubuntu (`-e session=d105-islands`), clippy
      `-D warnings` clean.

### 19.6 Close-out

Built as designed. Four corrections, one of them the design's own fault.

**1. "The forest root" was the wrong seed — a forest has many trees.**

§19.2 as written said *walk from the forest root*, and the first build did. But
`pvfs tree create` makes a second tree, rooted by a live `contains` link with a
NULL parent — the same shape `forest init` gives the forest root — and `walk`
deliberately stays inside one tree (the smoke suite asserts exactly that:
"walk stays within one tree"). So a check seeded from one root calls every
other tree detached.

The CLI smoke suite caught it on the first run that reached it, and it caught
two shapes at once: `second-tree` itself, and `fifth-element.mkv`, a file whose
`contains` parent had been purged and which survives only on refs *from* that
second tree. Both reported as islands. Neither is one.

Fixed by seeding from every live NULL-parent `contains` edge. The check did not
weaken: a cut *inside* the second tree is still found, which is now a test.
Worth saying plainly — the unit tests did not find this, because they were
written from the same wrong sentence in the design. The end-to-end suite found
it because it was built by someone modelling a real forest, and a real forest
has more than one tree in it.

**2. The root has a live link.** `forest init` gives it a NULL-parent
`contains` link, so in a whole forest `live_linked` equals `nodes_total`, not
`nodes_total − 1` as the first test asserted. Only the test was wrong. The same
shape is what made correction 1 both possible and, once seen, obvious.

**3. `Link` does not carry `label`.** The projection has the column (D72) but
the struct does not map it, so `unlink_would_strand` reads it directly. It is
the name the operator sees; falling back to the node's label would have printed
the wrong one for any renamed edge.

**4. `detached_at` became one grouped pass.** `idx_links_child` is partial on
`removed_at IS NULL`, so asking for a *removed* edge by child id is a table
scan every time. One `GROUP BY child_id` over the retired `contains` edges
instead, so the cost no longer scales with how many islands a forest has.

**Scope held.** Unlink still does not cascade. `islands` still exits 0. Neither
is exposed over the daemon protocol, matching `orphans` and `missing`.

**One thing the design did not raise.** On a replica still catching up, a
folder linked into the tree *after* its children were populated shows as a real
island until the parent edge arrives. `detached_at` separates the two cases — a
cut has a retired edge on record, a not-yet-synced one does not — and the
report says which it is looking at instead of calling both a detachment.


## 20. The night the residue was cleared (2026-09-08) — close-out

Everything §17 and §18 catalogued as waiting for re-genesis to drop was
instead **fixed in place**, with the causes closed rather than outrun. This
section records what happened and, more usefully, what it cost to find.

### The numbers

| | before | after |
|---|---|---|
| `missing` | 1,913 | **0** |
| duplicate groups | 588 | **0** |
| islands | 1,849 nodes | **0** |
| manifest recursion on disk | 1,577 files | **0** (25,135 real sidecars intact) |
| `with a live link` vs `reachable` | 34,216 / 33,725 | **33,725 / 33,725** |

That last row is the one worth keeping. Those two numbers had never agreed.

### What `missing` actually was

Three causes, none of them "files that went away", and the mix is the lesson —
a single number had been standing in for three unrelated problems:

| cause | count | resolution |
|---|---|---|
| duplicate-pair halves | 506 | `pvfs duplicates --merge` (D113/D114) |
| the `Backups` island | 1,314 | `missing --forget`, then `islands --drop` for the 491 folders left behind |
| D80 NFS residue (`file:///mnt/nas-media`) | 96 | `--forget`; the mount has been gone since August |

### The chain of mistakes, in order

Worth reading as a sequence, because each fix exposed the next:

1. **D105 unlinked on "no live location"** — which on a fleet whose mover works
   outside the catalogue is a routine transient state. It went live on the
   ingest and was caught within the hour; nothing was lost. D112 put a day's
   grace behind it.
2. **The settle window trusted mtime**, which rclone back-dates. Half-copied
   files were catalogued at partial sizes and became duplicate pairs (D112).
3. **The merge that cleaned up the pairs was CREATING them.** It chose a keeper
   on the owner — a box that holds no media and so had to guess — and kept
   nodes whose size disagreed with disk, so the next scan could not match the
   real file and minted a fresh one. Chris: *"Can't the system just scan what
   is actually on disk where there is a question and keep the one that matches
   exactly what is actually there?"* That question produced D115.
4. **D115 was a no-op on every box that scans media**, because it compared a
   bare `file://` prefix against locations a replica writes pin-qualified. The
   measurement that would have caught it — 30,677 of 30,782 locations are
   `pvfs-host://` — had been on screen hours earlier (D117).

### What this does to the case for re-genesis

§16 argued the disconnected structure was *"a stronger argument for re-genesis
than the log size ever was."* That argument is gone. The duplicates, the
islands, the junk nodes and the manifest recursion — the things a rebuild was
going to clear for free — are cleared, and the mechanisms that produced them
are closed.

**And the cleanup itself grew the log.** Measured after the work: the log holds
**409,072 events**, against the ~241,000 this document records elsewhere.
Tonight's 1,445 unlinks, 617 merges, location moves and island drop cost
roughly 168,000 events — because unlink is a soft remove on an append-only log,
so tidying the forest is written INTO the thing whose size is the complaint.

That partially rebuilds the case this section just said had weakened. Clearing
residue in place fixes the tree and enlarges the log; only a rebuild or
compaction (doc 11) shrinks it. Worth stating plainly rather than leaving the
reader to notice the contradiction.

What remains is log size, replay time, and a deliberate clean baseline. Chris
(2026-09-08): *"I want to re-genesis more for a clean start without any baggage
from iterations and as a test to see how a fresh install would perform."* That
is a fair reason and a different one, and it should be stated as such rather
than inherited from an argument that no longer holds. Doc 11's compaction
targets the same log-size problem without changing identity.
