# The D102 external review, verified against main (26)

Status: **Response, 2026-09-09.** An outside reviewer read `main` at `4b58039`
(the D102 merge, schema 14) and produced a findings list. This document checks
every item against `main` at `906c39b` (D121, schema 15) and against the
production fleet, which has run `v1.4-190-gdcfb522` (D118) on all three boxes
since 2026-09-08 23:17. Verdicts first, then the fixes, grouped into three
proposed milestones. **This branch changes documents only**; the code
proposals in §6 are for Chris to accept, reorder, or drop.

Evidence conventions: `file:line` is `main` at `906c39b`. "QNAP log N" is a
line number in `/share/Data_ext/pvfs/pvfsd.log` on the holder (72,510 lines,
appended across restarts; the current run starts at line 72,478).

---

## 0. The finding that reframes both High items

**The holder's replica source is the owner, and the owner holds no bytes.**

`/share/Data_ext/pvfs/replica/.pvfs/replica` on the QNAP names
`tcp 192.168.1.120:7421`, pin `47e46c35…` — the owner VM, which keeps the log
and nothing else. `Fetcher::candidates` (`crates/pvfs-client/src/fetch.rs:220`)
appends that source to every file's candidate list, after the location-derived
holders. So in production a fetch ALWAYS has two candidates — feederbox from
the catalog, then the owner from the replica file — and the owner answers every
`cat` with `not_found: no readable location for file`
(`crates/pvfsd/src/lib.rs:896`).

Three consequences, all visible in the log:

1. **D102's one-candidate guard never fires.** `if candidates.len() == 1`
   (`fetch.rs:290`) is false on the only fleet it was written for. The single
   `quarantined stale location` line in the log (QNAP log 63470, Reacher
   s03e08, 2026-09-08) came from the D99 path in the single-stream loop
   (`fetch.rs:342`) — AFTER the swarm had already proven the bytes wrong
   (63445) and the single-stream loop had re-downloaded the whole file to
   fail the same check (63469). That is exactly the review's High #2, proven
   in production the day D102 reached the NAS.
2. **Every failed fetch ends on the owner's `not_found`.** The log holds
   42,570 `stream failed from` lines; 41,240 of them are the owner
   (`tcp:192.168.1.120:7421`). Each is a fetch that had already failed at
   feederbox for its own reason and was then asked of a box that could never
   answer.
3. **D98's memory is fed by the wrong signal.** `tier_pass` and `sync_pull`
   record a file as unfetchable when the LAST candidate's error contains
   `no readable location` (`fetch.rs:1123`, `fetch.rs:1642`). The last
   candidate is always the owner, and its error always contains that phrase.
   So a transient feederbox stream failure is recorded as "no holder has it"
   for up to 24 passes, and an integrity mismatch is recorded the same way —
   by accident, which is why the review's Medium "integrity mismatches never
   enter `fetch_unfetchable`" is true in the code and false on the fleet.

The review's proposed High #1 fix — "skip the source when its pin is only
represented by quarantined locations" — would change nothing here: the owner's
pin has no locations at all. The fix that matters is upstream of quarantine:
**the replica source is a fetch candidate only when the catalog gives it a
reason to be** (§6, D122 item 2).

---

## 1. Prior findings — re-checked

| Item | Verdict on `906c39b` |
|---|---|
| `check_member_event` fail-open | Fixed (D100). Not re-examined here. |
| CI `clippy --all-targets` | Fixed; D121 (`906c39b`) added the same lint to the pipeline's `test` tag. |
| `manifest_for` write-on-read | Fixed (D100). Not re-examined here. |
| Shared `/tmp/pvfs-*-results.txt` | Fixed. **The daemon journal is still shared** — `deploy/ansible/pipeline.yml:398` and `:458` name `/tmp/pvfsd-journal.txt` with no `{{ pvfs_suffix }}`. §4. |
| LIKE prefix wildcards (retire) | Fixed (`engine.rs:2298` uses `substr`). **`policy_for_uri` still uses LIKE** — `fs.rs:2051`. §3. |
| `.gitignore` blanket `*.json` | Fixed. Not re-examined here. |
| Persistent unfetchable | Fixed (schema 14; schema is 15 since D112's `scan_unheld`). |
| `evict_pass` / `retire_locations_under` quarantine | Fixed (`sync.rs:1214`, `engine.rs:2042`). |
| `--version` / `git describe` | `pvfs` and `pvfsd` stamped (D110). **`pvfs-companion` is still bare `1.4.0`** (`crates/pvfs-companion/src/main.rs:25`). The QNAP binary now reports `v1.4-190-gdcfb522` — not because `build-nas.sh` stamps it (it does not) but because it builds inside a git checkout, so `build.rs`'s `git describe` fallback happens to work. §3. |
| Pipeline rustup vs CI 1.96.0 | **Partial, unchanged by D121.** `pipeline.yml:95` still guards the install with `when: not cargo_stat.stat.exists`. presubuntu today: `rustc 1.96.0` from the `stable` CHANNEL, no pinned toolchain installed — equal to CI by coincidence until stable moves. §3. |
| Mover remote integrity quarantine | **Partial, and worse than reported** — §0. |
| `hash_policy=lazy` | By design (refused since D94, `fs.rs:80`). `docs/04` corrected in this branch (§7). The NAS has no lazy bindings — both `/Media` binds are `on_add`, forest-level and `bindings.local` agree. |

---

## 2. High — all four confirmed open

**H1. The replica source is always retried.** Confirmed: `fetch.rs:220-224`
pushes `self.source` unconditionally. Reframed by §0: in production the source
is not the quarantined pin, it is a box that has never held a byte. Fix: D122
item 2.

**H2. Fall-through to single-stream after a swarm whole-file mismatch.**
Confirmed: `fetch.rs:270-301` may quarantine, then `fetch.rs:300` runs the
single-stream loop regardless. Proven on the fleet (§0, item 1). Also
confirmed that the guard itself is dead in production. Fix: D122 items 3-4 —
attribute by which holders actually served chunks, not by how many candidates
there were, and after a quarantine recompute the candidate set instead of
falling through.

**H3. Disabling a periodic job does not stop it; the finish reports idle.**
Confirmed in three places:
- `crates/pvfsd/src/jobs.rs:852-858` — the `PERIODIC` arm of the supervisor
  only removes `next_due` for a disabled job; the live `Managed` in `running`
  is never signalled or drained. The `CONTINUOUS` arm directly above does
  both.
- `jobs.rs:281-288` — `mark_pass` sets `state = "idle"` unconditionally, so
  the pass that was already running overwrites the `disabled` that `reload`
  set at `jobs.rs:131`.
- `jobs.rs:133` — `reload` carries `last_error` across the transition, which
  is the `sync idle (last error: 82 fetch failures…)` row doc 24 §14 item 2
  already records.
- Only `tier` takes the cancel flag (`jobs.rs:506`); `sync`, `export`,
  `evict`, `reclaim` passes ignore the `stop` their `Managed` carries.
Fix: D123.

**H4. The mover's "already satisfied" ignores quarantine.** Confirmed:
both arms of `has_central` (`fetch.rs:1055-1100`) iterate
`engine.locations(&id)?` unfiltered, while `readable_path` (used only when
`has_central` is false) does exclude quarantined URIs via
`first_readable_location` (`fs.rs:2716`). A file whose only library copy has
been caught with wrong bytes counts as satisfied and is never re-fetched.
Fix: D122 item 6. Note the consequence once fixed: the fetch lands in the sync
store, placement finds the destination occupied, `location_owner` says the
occupant is this same node, and the D71 W5 "our own older copy" arm trashes
it and places the good bytes — the right outcome, and it needs a test that
says so.

---

## 3. Medium

| Item | Verdict | Where |
|---|---|---|
| Toolchain pin not enforced on existing hosts | **Open** (see §1 row). | `pipeline.yml:95`; presubuntu on `stable` |
| Daemon/companion version identity | Daemon fixed (D110); **companion open**. | `pvfs-companion/src/main.rs:25` |
| `export --fetch` has no unfetchable memory | **Open.** `export_pass` builds a bare `Fetcher` (`jobs.rs:451`); so do the CLI's one-shot `tier`, `sync`, `export --fetch` and `cat` (`pvfs-cli/src/main.rs:5179, 5524, 7020, 7055`). Only `sync_pass` and the `tier` job seed and persist, each with its own copy of the same ten lines. | D122 item 7 |
| `policy_for_uri` unescaped LIKE | **Open.** `?1 LIKE source_uri \|\| '/%'` at `fs.rs:2051`. The NAS binds `…/Data_ext/Media`, so the `_` wildcard is live in production; no sibling path differs at that character today, so the only cost is the one waiting to happen. The other LIKEs (`fs.rs:3051`, `engine.rs:2214/2298/2331`) match constant prefixes and are fine. | D124 item 1 |
| Quarantine lookup fail-open | **Open.** `unwrap_or_default()` at `fetch.rs:189`, `fetch.rs:246`, `sync.rs:1214`. A DB error reads as "nothing quarantined" in the three places quarantine is supposed to protect. | D122 item 1 |
| Integrity mismatches never enter `fetch_unfetchable` | **Open in code, masked on the fleet** (§0 item 3). | D122 item 5 |
| Pipeline slot reaping | **Fixed by D121** (`906c39b`): idle slots older than two days are reaped at report time. presubuntu is at 58 % with two slots (`/opt/pvfs` 25 G, `/opt/pvfs-roll` 624 M). | — |
| Stale docs | `docs/04` and `deploy/ansible/README.md` corrected in this branch (§7). `docs/08`'s header still says 2026-08-13, but D118 put a banner under it naming D117 and saying plainly that the body stopped tracking reality at D29 — honest as it stands. | — |
| Stall detector is "overdue", not progress | **Open by design** — doc 24 §14 item 1; needs a progress signal out of `scan_routed` and `tier_pass`. The QNAP shows `follow overdue` right now for exactly this reason. | deferred |
| No `prepare_purge` / `prepare_quality` | **Confirmed.** `WriteOp` has thirteen variants (`Mkdir … Mv`, `pvfs-proto`) and neither is among them; `Cmd::Purge` calls `engine.purge` directly (`main.rs:3843`) and `Cmd::Quality(Set)` calls `engine.set_media_quality` directly (`main.rs:2761`) with no `is_replica()` branch, unlike `Mv`/`Relabel` beside them. What a replica does on those two commands today was not traced here; at minimum, it does not route. | D124 item 7 |

---

## 4. Low

| Item | Verdict |
|---|---|
| Shared `/tmp/pvfsd-journal.txt` | Open — `pipeline.yml:398, 458`. Two-line fix (D124 item 4). |
| `rust-version = "1.75"` vs CI 1.96 | Open — `Cargo.toml:16`. Nothing builds with 1.75 to prove the claim. D124 item 5. |
| `is_sidecar_name` is `ends_with(".manifest")` | By design: v1 sidecars had no dot prefix and are still on disk. Keep; a coincidental `*.manifest` media file is skipped from the scan, which is the cheaper mistake. |
| Duplicate quarantine helpers / inline SQL in `stat_node` | Open — `fetch.rs:30` and `:45` differ only in the error type; `stat_node` (`fs.rs:2963`) and `first_readable_location` (`fs.rs:2716`) each spell the same two lookups. D124 item 6. |
| Watchdog vs NAS binary swap; `watchdog.sh` not in this repo | Both scripts live in the PVOS repo: `deploy/ansible/fleet/nas-watchdog.sh` and `deploy/ansible/fleet/build-nas.sh`. The QNAP's `bin/watchdog.sh` is byte-identical to `nas-watchdog.sh` (trailing whitespace aside). `fleet.yml` still does not bracket it — doc 24 §14 item 6, open. |
| `build.rs` git-describe cache misses tag-only changes | Confirmed: `rerun-if-changed` names `.git/HEAD` and `.git/index`; a new tag touches `refs/tags/` or `packed-refs`. D124 item 3. Pipeline builds are covered by `PVFS_BUILD`; the NAS build (§1) is not. |

---

## 5. The open questions, answered

1. **Is the production `ReplicaSource` the same peer as the quarantined pin?**
   No. It is the owner (`192.168.1.120:7421`), which serves no bytes. That is
   worse than either High item assumed — §0.
2. **Where do `build-nas.sh` and `watchdog.sh` live?** PVOS,
   `deploy/ansible/fleet/`. See §4.
3. **Do the five stale files still single-stream after D102?** D102 first
   reached the NAS on 2026-09-08 with the D118 build; from 2026-09-01 to then
   the holder ran D100. That D100 week (QNAP log 40945-63317) shows 211 swarm
   fallbacks, 206 commit failures and 10,105 owner `not_found`s. Since D102
   landed: one fallback, one commit failure, one quarantine — Reacher s03e08,
   the one event, and it took the single-stream path (§0) — and then nothing:
   the residue was cleared the same night (doc 24 §20), so there has been
   nothing to fetch. Not enough data for a rate; the one data point is High #2
   happening.
4. **Any live `hash_policy=lazy` bindings on the NAS?** None. `pvfs bindings`
   on the holder lists two `/Media` binds (`Data`, `Data_ext`), both
   `on_add`; `bindings.local` agrees.
5. **Cut a release past `v1.4`?** Chris's call. The fleet runs 190 commits
   past the tag with two schema bumps (14, 15) and a CHANGELOG `Unreleased`
   section that already reads as release notes. Recommendation: cut 1.5 once
   D122 has rolled, so the tag names a fleet that fetches correctly.

Two fleet facts recorded while checking, because the memory notes had them
wrong: the mover now runs on the **holder** (`tier` in the QNAP's
`serve.jobs`, pull-only), not the owner, whose only job is `reclaim`;
feederbox runs `follow, evict, watch`.

---

## 6. Proposed fixes — three milestones

Numbers are provisional (D105 was taken once already); renumber if a
concurrent session claims them.

### D122 — quarantine is consulted everywhere, and the source earns its place

The theme: every place that decides "where can the bytes come from" or "are
the bytes already here" asks the same question of the same table, fails
closed, and says what it learned in a type rather than a string.

1. **Fail closed on the lookup.** `Fetcher::candidates` returns
   `Result<Vec<ReplicaSource>, String>`; `quarantined_uris` errors propagate
   from `fetch`, `fetch_streaming` and `evict_pass`. Callers to touch:
   `fetch.rs:232`, `fetch.rs:1762`, `pvfsd/tests/f57_fleet.rs:130,147`.
2. **The source is a candidate only when the catalog says it could serve.**
   Push `self.source` only if the file has at least one non-quarantined
   location that is either a bare `file://` (host-implicit — the owner's own
   disk, the lab shape) or `pvfs-host://<source pin>/…`. A file whose
   locations are all pin-qualified to OTHER boxes gets no source candidate. On
   the production holder this removes the owner from every candidate list;
   on the D71 lab it changes nothing.
3. **Attribute a swarm mismatch by who served, not by how many could have.**
   `swarm_fetch_opts` already keeps per-holder chunk counts (`fetch.rs:521`).
   On a whole-file id mismatch, if exactly one holder contributed chunks,
   quarantine that holder's pin. Delete the `candidates.len() == 1` test.
4. **No fall-through onto doomed bytes.** After any quarantine inside
   `fetch`, rebuild the candidate list minus the quarantined pin. If it is
   empty, return the existing "no readable location … every known holder is
   quarantined" error; the single-stream loop runs only over what is left.
5. **A typed outcome.** `fetch` returns `Err(FetchError)` with
   `Permanent(String)` / `Transient(String)` (or a struct with
   `is_permanent()`); `tier_pass` (`fetch.rs:1123`) and `sync_pull`
   (`fetch.rs:1642`) stop matching on "no readable location". Permanent =
   every candidate was quarantined, or an id mismatch was attributed. A
   peer's `not_found` is permanent only when that peer was a catalog-named
   holder of the file — with item 2 in place, that is the only kind of peer
   left.
6. **`has_central` filters quarantined URIs** in both arms
   (`fetch.rs:1055-1100`), the same way `evict_pass` does at `sync.rs:1214`.
7. **One memory, one constructor.** `Fetcher::with_memory(engine, data_dir)`
   seeds from `unfetchable_load`; `Fetcher::persist_learned(engine)` saves
   only what this instance added. `sync_pass`, the `tier` job, `export_pass`
   and the CLI one-shots (`tier`, `sync`, `export --fetch`) all use them; the
   `tier` job keeps its 24-pass amnesia on top.
8. **Tests** (`crates/pvfs-client/tests/d122_*.rs`): source-not-a-holder
   yields no candidate; lab owner with bare `file://` still yields the source;
   one-holder swarm mismatch quarantines that pin and returns Permanent
   without a single-stream attempt (assert on the fake holder's request
   count); quarantined library copy → fetched, occupant trashed, good copy
   placed; a DB error in the quarantine lookup fails the fetch rather than
   proceeding.
9. **Verify on the fleet after the roll** (owner → ingest → holder, watchdog
   stopped and restarted per the runbook): the next id mismatch on the QNAP
   logs `quarantined stale location` BEFORE any `streamed but commit failed`
   line, and `stream failed from tcp:192.168.1.120:7421` never appears again.

### D123 — a disabled job stops, and says so

Closes doc 24 §14 item 2 and the review's High #3.

1. `PERIODIC` arm of `jobs::run`: a disabled job with a live pass gets
   `stop.store(true)` and moves to `draining`, exactly as `CONTINUOUS` does.
2. `sync_pass` and `export_pass` take the flag: `fetcher.set_cancel(flag)`
   (the swarm already honours it) and a `cancelled()` check between files in
   `sync_pull`. `evict_pass`/`reclaim_pass` check it between files.
3. `mark_pass` leaves `state = "disabled"` alone when the row is disabled;
   `reload` clears `last_error` on an enabled → disabled transition. A
   disabled job has no current error to report.
4. Test in `crates/pvfsd/tests/serve_jobs.rs`: disable during a pass — the
   row reads `disabled` within one tick, never flashes `idle`, `last_error`
   is `None`, and the pass thread has exited.

### D124 — hygiene, one small commit each

1. `policy_for_uri`: `substr(?1, 1, length(source_uri) + 1) = source_uri || '/'`
   plus a test with a sibling root that differs only at a `_`.
2. `pvfs-companion` gets the `build.rs` the other two binaries have and
   reports `1.4.0 (v1.4-…)`.
3. `build.rs`: add `rerun-if-changed` for `../../.git/refs/tags` and
   `../../.git/packed-refs`.
4. `pipeline.yml`: `/tmp/pvfsd-journal{{ pvfs_suffix }}.txt` at both
   mentions.
5. **One toolchain, one place.** Add `rust-toolchain.toml` (`channel =
   "1.96.0"`, `components = ["clippy"]`) so CI, the pipeline and a laptop all
   resolve the same compiler from the checkout; the `prepare` task then only
   needs rustup present (`rustup toolchain install` is idempotent — run it
   every prepare, not only when cargo is missing). Raise `rust-version` to the
   tested version or remove it. CI keeps its explicit pin with a comment
   naming the toml as the source of truth.
6. A shared `location_flags(id, uri) -> Result<(Option<String>, bool)>` for
   `stat_node` and `first_readable_location`; collapse `quarantine_stale` /
   `quarantine_stale_str` into one generic over `Display`.
7. `WriteOp::Purge { ids }` and `WriteOp::SetQuality { node, quality, source }`,
   D73-gated like `Relabel`; `prepare_purge` / `prepare_set_quality` on the
   engine; the two CLI arms route on `is_replica()`; a case each in
   `pvfsd/tests/p6_write_through.rs`. First, trace what a replica does today
   on those commands and write that down.
8. (PVOS repo) `fleet.yml` brackets the NAS watchdog around the binary swap —
   doc 24 §14 item 6.

---

## 7. What this branch changes

Documents only:

- This file.
- `docs/04-p1-storage-and-fs-ops-spec.md`: `hash_policy` default is `on_add`;
  `lazy` is refused (D94), not listed as an option.
- `deploy/ansible/README.md`: the toolchain is pinned to 1.96.0, not
  `stable`; the pin applies only when cargo is absent; the D121 `lint` and
  `reap` stages are in the tag table.
- `docs/24-fleet-review-and-re-genesis.md` §14: a pointer here.
