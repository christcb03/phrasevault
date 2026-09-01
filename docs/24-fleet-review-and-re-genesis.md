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

Node ids are content-addressed and link ids exclude `created_at`/`author`
(doc 03 §3.2, restated in doc 11 §2: *"Identities survive"*). A fresh forest
built from the same bytes mints **the same ids**. Re-genesis is therefore a
rebuild, not a rename-everything migration.

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
3. ~~Same treatment in `swarm_fetch`.~~ **Deliberately NOT done, on inspection.**
   The swarm assembles a file from chunks pulled from *every* holder, so a
   whole-file mismatch at `swarm_publish` cannot name which one served bad
   bytes — and since each chunk is already verified against the signed manifest
   during assembly, a whole-file failure there points at the manifest, not at a
   holder. Blaming a pin would strand good holders on the strength of a guess.
   The swarm already falls through to single-stream, which retries per-holder
   and *can* attribute the failure; production's log shows exactly that
   sequence. The single-stream fix therefore closes this path too.
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

**12. The D99 marking path is unproven end to end.** Unit tests cover the
pieces; a live peer serving wrong bytes does not. Production will exercise it
the moment D99 reaches the holder — five files are waiting.

**13. Two quarantine helpers now coexist.** `uri_quarantined(file, uri) -> bool`
in `engine.rs` and `quarantined_uris(id) -> Vec<String>` in `fs.rs`, from two
sessions that could not see each other. Same table, different shapes. Consolidate
when someone is next in that code.

**14. The CI watcher fix is unproven on GitHub.** `5a4711e` raises the poll
ceiling and prints the watcher's log on failure, but has not yet run on a GitHub
runner. If it still fails there, the output will finally say whether the daemon
was slow or refused to start.
