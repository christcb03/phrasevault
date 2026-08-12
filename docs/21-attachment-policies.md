# 21 — Attachment policies: three kinds of storage enrollment (P8)

**Status: BUILT + VALIDATED (P8, 2026-08-12 — see §5 close-out).**
Approved by Chris 2026-08-11; §3 resolved below. Supersedes the narrow
"sync --to migrator" question.

## 1. The requirement (Chris, verbatim intent)

When a storage space (a directory/disk) is enrolled into a tree, its **kind** is
chosen at enrollment:

1. **migrate** — serve the space's content as part of the tree AND move the bytes
   to another store (the space is staging: an ingest disk that stays empty).
2. **in-place** — serve the space's content as part of the tree; bytes never move
   (today's `pvfs bind`).
3. **mirror** — serve the space's content as part of the tree AND maintain a
   verified second copy elsewhere (the space's content gains a backup replica;
   nothing is retired or evicted).

## 2. Mapping to what exists

All three are `bind` + placement + mover composition — no new storage engine:

| Kind | Bind | Placement | Mover behavior |
|---|---|---|---|
| in-place | as today | none | untouched |
| migrate | as today | subtree placed `central --to <store>` | tier migrates + retires the space's locations; evict (same box) reclaims — exactly the §7.10 ingest flow, chosen at bind time |
| mirror | as today | NEW mode: `central-keep` | tier lands the verified central copy + logs it but **never retires** the source location; evict never touches it |

Proposed surface: `pvfs bind <folder> <dir> --kind in-place|migrate|mirror`
(default in-place; `--kind migrate|mirror` requires the tree to have a central
store placed, or takes `--to <store>` inline). The kind is recorded with the
binding (deployment state); the watch/tier/evict jobs read it — enrollment is
one command and the daemon does the rest.

## 3. Decisions (review of 2026-08-11)

1. Naming: `--kind in-place|migrate|mirror` as proposed.
2. `central-keep` is a placement mode (the mover already walks placements).
3. **Mirror copies serve reads — and more (Chris):** not only do both copies
   participate as read-through candidates (free, via the logged location), reads
   should eventually pull **from every known holder in parallel, BitTorrent-style,
   for the fastest possible read**. That is the swarm data plane — specified in
   doc 20 §6 (its own arc, P9, after regions): chunked fetch-by-hash where every
   logged location (mirrors included) is a seed. Doc 21's mirror kind is what
   *populates* the holder set; P8 ships with today's single-candidate read-through
   and inherits swarm reads automatically when P9 lands.
4. Regions: nothing special expected; confirm at P8 build.

## 4. Build shape (once approved)

P8.0 `--kind` recorded + in-place/migrate wired over existing machinery (mostly
plumbing + jobs); P8.1 `central-keep` mode + mirror semantics in tier/evict;
validate with a fleet-test phase (ingest disk drains; mirror survives source
deletion). Rough size: one evening.

## 5. Close-out (2026-08-12)

Built as §2's mapping promised — placement grew `central-keep`, the mover
walks both lists, `bind --kind` is enrollment sugar that records the
placement (prompting for the store when `--to` is omitted; a store inside the
bound space is refused). Validated: full pipeline on both hosts, the smoke
suite's new P8 section (11 checks: drain, retire, reclaim, mirror copy,
never-retire, never-evict, source-death survival), and fleet phase I.
Deviations and findings, honestly:

- **Single-box migrate needed a real semantic addition, not just plumbing**:
  §2's table said "tier migrates + retires the space's locations", but the
  mover only retired foreign `pvfs-host://` locations (the §7.10 two-box
  flow). A migrate-kind binding's own `file://` staging locations now retire
  too — with two safety rails found by the smoke suite: a staged copy never
  satisfies the "central copy exists" check (it would have retired the only
  live copy), and retired `file://` locations are evictable ONLY under a
  migrate-kind binding's source dir (a manual `loc rm` of an in-place path
  must never cost the user their file — draining is consent given at
  enrollment, not a property of retraction).
- **The mirror satisfaction test is store-specific**: any local copy
  satisfies a plain `central` root (the F5.3 owner-disk rule), but a mirror
  root is only satisfied by a copy IN ITS STORE — the source's own location
  satisfying it would have meant no second copy ever landed.
- Regions interaction (§3.4): confirmed nothing special — placement is
  deployment state, and the mover's logged location events route to each
  file's region like any other write.
- Punch J's swarm inheritance stands as designed: mirror copies are logged
  locations, so they join the P9 seed set with zero further work here.
