# 21 — Attachment policies: three kinds of storage enrollment (P8 candidate)

**Status: DESIGN DRAFT (2026-08-11) — Chris's requirements from the punch-list
review, mapped to machinery. NEEDS REVIEW before build; supersedes the narrow
"sync --to migrator" question (punch G).**

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

## 3. What needs deciding at review

1. Naming (`--kind` values above vs `staging|permanent|mirrored`…).
2. `central-keep` placement: new placement mode (proposed) vs a per-binding flag
   the mover consults. Lean: placement mode — the mover already walks placements.
3. Does *mirror* also imply the copy participates in read-through candidates
   (a second live location — it would, for free, via the logged location)? Lean: yes.
4. Interaction with regions (doc 20): a space enrolled into a marked region —
   nothing special falls out; confirm at build.

## 4. Build shape (once approved)

P8.0 `--kind` recorded + in-place/migrate wired over existing machinery (mostly
plumbing + jobs); P8.1 `central-keep` mode + mirror semantics in tier/evict;
validate with a fleet-test phase (ingest disk drains; mirror survives source
deletion). Rough size: one evening.
