# 21 — Attachment policies: three kinds of storage enrollment (P8 candidate)

**Status: APPROVED (Chris, 2026-08-11) — §3 resolved below; build slot = P8, after
the region arc (doc 20 §2.1). Supersedes the narrow "sync --to migrator" question.**

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
