# 18 — Serve integration: the fleet runs itself (P5, doc 17's F0.1 + F3.1)

**Status: BUILT + FLEET-VALIDATED (P5.0–P5.4, 2026-08-10 → 08-11 — see §7 close-out).**
Prerequisite reading: doc 17 (the built federation arc; §9 Q5 is the identity finding
this milestone resolved — originally recorded in the since-retired HANDOFF.md).

## 1. Goal

The 1.3.0 fleet works end to end, but every recurring motion is a cron line or a
human: `replica sync && pvfs sync && pvfs export --prune` on consumers, `pvfs tier`
on the owner, `replica sync && pvfs evict` on the ingest box, `pvfs replica follow`
in a screen session. This milestone moves those loops into the long-running daemon
so a box, once configured, keeps itself fresh:

| Job | What it does today (by hand) | Runs where |
|---|---|---|
| **follow** | `pvfs replica follow` — long-poll the source, ingest, fold | any replica |
| **sync** | `pvfs sync` — fetch missing bytes for `sync`-placed subtrees | consumers/edge |
| **export** | `pvfs export --prune` after changes — keep the Plex view fresh | consumers |
| **tier** | `pvfs tier` — migrate placed subtrees into the central store | owner |
| **evict** | `pvfs evict` after a sync learns retirements | ingest/edge |

End state: zero cron entries in doc 17 §7.6's four-machine story. New episode lands →
cataloged (write-through, already built) → followers see it in seconds (F5.4, already
built) → consumers fetch + re-export, owner tiers, edge evicts — all as daemon jobs.

## 2. Shape: jobs live in `pvfsd` (proposed)

Doc 17 §2 sketched a separate `pvfs serve`; building it inside `pvfsd` looks strictly
better now, because the daemon already is the per-forest long-running process, already
holds the engine, and — decisive — F5.4's `LogWait` gives it **event-driven** triggers:
a replica daemon that runs *follow* internally knows the instant new events fold, which
is exactly when *sync* / *export* / *evict* should wake. A separate supervisor would
poll or duplicate the follow loop. `pvfsd@.service` and sd_notify (D57) carry over
unchanged.

- Jobs are **deployment state, never log events** (same rule as placement, doc 17 §6):
  a per-data-dir `serve.jobs` file; `pvfs serve enable|disable|ls [job]` edits it;
  `pvfsd` reads it at start and on SIGHUP.
  - *As-built note (P5.0, superseded by punch E 2026-08-11):* `pvfs serve` already
    existed — the P1 watcher. RESOLVED: the watcher is now the `watch` JOB (shared
    loop in `pvfs_client::watch`; ad-hoc foreground = `pvfs serve watch`), and bare
    `pvfs serve` prints job status (live when a daemon runs, configured otherwise).
    PVOS was checked — nothing invoked the bare form.
  - *Punch A (2026-08-11):* the runner watches `serve.jobs` itself (mtime, per
    tick) — `serve enable` takes effect within a second; SIGHUP remains a manual
    trigger.
  - *Punch F (2026-08-11, Chris):* `ServeStatus` is **member-gated** — job states
    and error strings are operational detail. `pvfs serve status` signs with the
    device key (owner boxes) or the client identity (enrolled boxes).
  - *Punch H (2026-08-11):* daemon commits and watch-job ingests nudge `tier`, so
    owner-side content migrates in seconds like everything else.
- Cadence: *follow* is continuous (the F5.4 loop, absorbed); *sync*/*export*/*evict*
  fire on fold + a slow safety interval; *tier* on interval (owner) + on local commits.
- One job runner, serialized per forest (the engine is single-writer locally anyway);
  per-job backoff on failure; last-run/last-error surfaced via `pvfs serve status`
  (reads the daemon over the socket) and the journal.
- **Open (Chris):** does `pvfsd` on an *owned* mount also get jobs (tier), or do we
  keep the owner's mover CLI-invoked and daemonize only replica-side jobs first?
  Proposal: owner tier job included, but P5 phases land replica-side first (§5).

## 3. What this deliberately is not

No new wire ops, no scheduling DSL, no multi-forest orchestrator: one daemon, one
forest, a handful of named jobs. Write-through completeness (`loc rm`, link ops) and
Mode B crosslinks stay on the standing list (doc 08 §3.4); F4 (region logs, FUSE) untouched.

## 4. THE input decision — job identity (doc 17 §9 Q5)

Background jobs dial other instances. Today **every** outbound connection signs with
the box's *client identity* (`~/.config/pvfs/identity.phrase`, the `whoami` key) —
`crates/pvfs-cli` `replica_client()` has no owner special case, and the forest
`device.key` never authenticates a network connection. The 2026-08-10 two-machine test
showed the consequence: on a private forest, the owner's own `tier` is a stranger to
its own edge box until the owner's client identity is `authorize-member`'d + granted
`r`. Three ways were on the table; **DECIDED 2026-08-10 (Chris): option (c)** — the model
stays, the friction goes:

- **(a) Document the grants.** Status quo mechanics; USER-MANUAL teaches the two-step
  per box. Pure default-deny; most setup friction; the surprise stays discoverable
  only at failure time.
- **(b) Owner engines dial with `device.key`.** Zero-setup for the owner's own boxes,
  but the forest's *admin* authority starts authenticating outbound connections to
  possibly-hostile daemons — least-privilege lost (the mover only needs `r`), and the
  device key graduates from log-signing to network-auth key (bigger exposure surface;
  would at minimum require domain-separated challenge signatures, verified, before
  build).
- **(c) Keep client-identity dialing; make the grants first-class.** A fleet-enroll
  step (e.g. `pvfs fleet enroll` run against the owner: authorize-member + `acl set r`
  for a box's client key in one visible, logged, revocable event) becomes part of box
  setup; serve jobs then run under exactly the authority the log shows they have.

Rationale for (c): the only option that keeps `device.key` off the network, keeps the
mover least-privilege, and removes the setup surprise — at the cost of one CLI helper,
zero change to the trust path. (a) was the same posture with worse ergonomics; (b)
traded the strongest key's isolation for convenience (c) provides more safely.

## 5. Phases + turnkey checklist

| Phase | Deliverable | Done means |
|---|---|---|
| **P5.0** | `serve.jobs` file + `pvfs serve enable/disable/ls/status`; `pvfsd` job runner skeleton (no jobs yet) | unit tests for config parsing; status over the socket |
| **P5.1** | *follow* absorbed into replica `pvfsd` (F5.4 loop internal; CLI `replica follow` stays for ad-hoc) | events authored on owner visible via serving replica daemon in seconds, no CLI process |
| **P5.2** | *sync* + *export* jobs (fold-triggered + interval; export targets from a `serve.exports` entry) | new file on owner → bytes + fresh Plex view on consumer, hands-free |
| **P5.3** | *evict* (edge) + *tier* (owner) jobs | HANDOFF's ingest story runs with zero cron: catalog → migrate → reclaim |
| **P5.4** | identity per §4's decision (enroll helper if (c)) + USER-MANUAL §7.9/§7.10 updates incl. the authorize-member finding | fresh box brought into a private fleet with documented steps only |
| **Validate** | pipeline (both hosts) + `deploy/fleet-test.sh` grown a **daemon-mode phase** (same 40 checks driven by jobs, not CLI loops) + clippy | all green on presubuntu + pvos-test |

Design-first close-out rule applies: deviations recorded here, honestly, when P5 closes.

## 6. Open questions

1. §4's identity decision (owner of record: Chris).
2. §2's owner-jobs question — daemonize tier now or later.
3. Export-target config shape: per-forest `serve.exports` vs arguments recorded by
   `pvfs export --keep-fresh`. (Lean: the latter — the export manifest already exists.)
4. Backoff/jitter numbers and whether *sync* failures should quarantine a candidate
   instance the way the Fetcher's dead-target set does within one pass.

## 7. Close-out (2026-08-11)

All five phases landed (P5.0 `50689da`, P5.1 `91f2718`, P5.2 `13615e4`, P5.3+P5.4
`d82e4f1`). Validated: **205 cargo tests + 286 smoke checks green on both hosts**
(presubuntu + pvos-test) through the full pipeline — release build, install, systemd
daemon stage — with clippy `-D warnings` clean throughout. `deploy/fleet-test.sh`
grew phase G (daemon mode) and passed **47/47**: the §7.10 ingest → tier → evict →
still-streams loop ran across two real machines entirely as serve jobs (fold-nudged,
zero cron), phase B now admits boxes via `pvfs fleet enroll`, tier moved 3 GiB over
the LAN at ~56 MB/s, and the post-evict stream-back verified bit-perfect at ~59 MB/s.

Deviations from the plan, honestly:
- `pvfs serve` already existed — the P1 **watcher** daemon. The job verbs nested
  under it (bare `pvfs serve` unchanged); unifying the watcher as a `watch` job
  stays open (§2 note).
- `tier` is interval-only (300 s, due immediately on enable/reload) — §2's
  local-commit nudge is deferred to the §6 list.
- Export config took the `serve.exports` shape (written by `export --keep-fresh`)
  rather than §6 Q3's manifest-only lean: the daemon needs a per-data-dir work list
  it can find without scanning the filesystem for export dirs.
- `ServeStatus` answers Info-tier (anon-readable operational metadata, like `Info`);
  revisit only if job rows ever carry content-derived detail.
