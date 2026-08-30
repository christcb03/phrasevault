# 24 — Fleet review + library re-genesis (D87)

**Status: REVIEW COMPLETE, BUILD NOT STARTED.** Written 2026-08-29 after the
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

## 5. Open questions — not answered by this review

Recorded honestly rather than papered over.

1. **Why the scan's location removal was refused.** The observed error was
   `forbidden: forbidden: remove location — you lack write (w) on cc50859a…`.
   Three hypotheses were tested and **all three failed**: (a) the owner refusing
   — the commit-side check has no arm for that kind, so it cannot be the
   refuser; (b) a batched-authority gap mirroring D85 — the removal targets a
   pre-existing node, so the `born` map would not fire; (c) the node being
   orphaned and therefore grant-unreachable — **0 of the 17 candidate nodes are
   orphans**. The error is also stale: the node it names is not in the current
   candidate set (17 vanished Dragon Ball Z S03 files). **Reproduce it under the
   fixed binary before theorising again.**
2. Whether `purge` and `quality` are routable from a replica, or local-only by
   design like bind/unbind.
3. Whether the D84 duplicate folders and the 79 `/mnt/nas-media` strays are one
   cause or two.

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
- [ ] A1. Fast-forward PVFS `main` to `d71-scoped-bindings`. **Verified safe
      2026-08-29:** `main` is 0 ahead and fully contained, so this is a
      fast-forward with no conflicts possible. The 80 commits span 2026-08-17
      to 2026-08-29 and cover **D71–D86**, the migration work included.
      A full ref audit found nothing orphaned: every dangling object is either
      pre-rebase residue whose subject is present in the branch, an old stash
      (2026-04-18, 2026-08-10), or a superseded clippy fix that clippy now
      passes without. Then merge `d87-sidecar-and-review` on top.
- [ ] A1b. **PVOS has the same drift, and it is NOT a fast-forward.**
      `d71-watch-ingest` is 90 ahead of `main` while `main` is 12 ahead of it —
      they diverged when `main` took the D70 merge on 2026-08-16 and the branch
      did not. A `merge-tree` dry run reports exactly **one** conflicting file:
      `deploy/ansible/fleet/fleet-lab.ini`. Note the irony: one of `main`'s 12
      commits is "sync by content, not mtime", which is the fix A4 below needs.
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
- [ ] B2. Regression tests ported to this base.
- [ ] B3. Pipeline green on `d71-scoped-bindings` + clippy `-D warnings`.
- [ ] B4. Deploy to feederbox, re-enable `watch`, confirm no regrowth.
- [ ] B5. Delete the ~3,000 junk files (`-name "*.manifest.manifest"`, all
      exactly 89 bytes; keep the level-1 sidecars).
- [ ] B6. Decide the 1,667 junk nodes: unlink+purge (3,334 events, 1,667 interim
      orphans) or leave for compaction to drop for free. **Recommend: leave.**

### C — the real fix
- [ ] C1. Make the sidecar a dotfile. Migration: accept both names on read,
      write only the new one, sweep the old.
- [ ] C2. `pvfs-manifest 2` — whole-file BLAKE3 in the header, so a sidecar can
      seed `content_hash`.
- [ ] C3. Stop `manifest_for` writing on read; make caching an explicit call.

### D — authority (from §3)
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

## 8. Decisions needed from Chris

1. **A1 — which branch is trunk?** Everything else waits on this.
2. **B6 — unlink the junk nodes, or leave them for compaction?**
3. **C1 — dotfile rename now, or after re-genesis?** Doing it first means one
   migration instead of two.
4. **F1 — measure the compaction trigger now**, or build re-genesis on the
   correctness argument regardless of the numbers?
