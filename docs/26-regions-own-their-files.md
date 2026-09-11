# 26 — Regions own their files

**Status: DESIGN, for review. Argued out with Chris on 2026-09-09; nothing here
is built. Decisions marked SETTLED were agreed in that conversation; those
marked OPEN were not. The implementation plan is §10.**

Prerequisite reading: doc 13 §A (the write model, resolved 2026-06-21), doc 20
(region logs, built), doc 17 §7 (locations), doc 22 (the swarm), doc 24 §20 and
doc 25 §11 (why this is being proposed now).


## 0. The one-paragraph version

Every box catalogues its own files, in its own catalogue, and writes only its
own log. A file's identity is *where it is* — the region that holds it plus its
path inside that region — not a content hash, and not a node someone else
owns. The shared forest log stops carrying file events and carries only
**which regions exist and a signed hash of each one's current catalogue**. The
presentation layer unions the regions by relative path and shows one entry per
path with every copy behind it, admitting only copies whose bytes agree. What
disagrees is a conflict, decided by a rule rather than a person, and pushed to
monitoring rather than parked in a report.


## 1. Why — what the current model costs

The current model is **one node per logical file, with N locations attached**.
Every other property follows from that choice, and so does every problem doc 24
spent a fortnight on:

| symptom | root cause in the model |
|---|---|
| a replica cannot scan its own disk; every write routes to the owner | one writer per forest, because there is one node to write |
| 409,072 log events, 168,000 of them from a single night's cleanup | every location on every box is an event in the one shared log |
| 588 duplicate groups; two boxes each making a node for the same path | the identity rule (name + size) is trying to reconcile two boxes' views of one object |
| the merge that unlinked a real file (doc 24 §20) | the owner deciding which of two copies is "the" node, on a box that holds no media |
| the islands, the one-home rule, the folder collisions | folders are shared objects that need exactly one owner |

None of these are bugs in the code that implements the model. They are the
model. **A shared object with one owner, written to by N boxes, is a
coordination problem, and every fix so far has been coordination machinery** —
routing, settle windows, grace periods, contested-group refusals, keeper rules.

Doc 13 §A saw this coming and drew the line correctly in June: single-writer
per region keeps every integrity property; true multi-master needs a DAG and
merge semantics. This design stays on the right side of that line. Every region
has exactly one writer. It is just that different regions have different ones.


## 2. Identity — SETTLED

**A file is identified by `region + relative path`.**

- A **region** is one `device + mount` — a storage root on a specific box. The
  QNAP's `Data/Media` and `Data_ext/Media` are two regions, not one; the
  ingest's `/mnt/local/Media` is a third.
- The **relative path** is the path inside the region's root. `TV/Show (2020)/
  Season 01/ep01.mkv` on the ingest and the same string on the holder are the
  same *logical entry* held in two places. Absolute paths never leave the box.
- This is the key the filesystem already guarantees unique. No hashing is
  needed to know what a file *is*.

**The content hash becomes what it should have been all along: integrity and
transfer.** It verifies bytes, drives the swarm, and decides whether two copies
are the same. It no longer decides identity, which is where it kept going
wrong — a file whose bytes change is still the same file at the same path, and
the current model's inability to say so is the entire upgrade-in-place problem.

A file moved between regions is a delete in one and an add in the other. That
is what happened on disk, and the catalogue should say so.


## 3. Ownership — SETTLED

**A region is owned by exactly one box, which is the only writer of that
region's catalogue.** Nothing in another region's catalogue is ever written by
anyone but its owner. There is no routing, because there is nothing to route:
the ingest cataloguing the ingest's disk touches nothing the holder owns.

The forest still has an owner, but what the owner's log carries changes
completely (§5).

**What a region declares about itself** — OPEN in the details, settled in kind:

| field | notes |
|---|---|
| root | the absolute path on the owning box; never shared |
| owner key | the box's client identity, as today |
| drains? | per region, reusing D81's per-root DRAIN. A draining region is staging; a non-draining one is library |
| name | for the presentation layer and for humans |
| retention | see §7 — OPEN |


## 4. What a region catalogues — SETTLED

**Entries. Files AND directories.** A directory entry is an entry with no bytes.

This is the answer to the empty-folder question and it is not a special case:
a region that holds an empty `TV/Show (2020)/Season 02` records exactly that,
and the presentation layer shows an empty folder. Two regions both holding
`TV/Show (2020)/Season 01` is not a collision — it is two regions that both have
that directory, unioned at read time exactly as two regions holding one file
are.

What goes away is **folders as shared objects that need an owner**. That is the
part causing the islands, the one-home rule and the duplicate-folder mess. The
ability to have a folder — empty or otherwise — is untouched.

Per entry, the region records: relative path, kind (file/dir), size, mtime,
ctime, content hash (files, when known), and the D76 quality measurement when
one exists. The scan writes these rows locally, at disk speed, with no signing
per row. Sidecars stay exactly as they are — the hash cache beside the bytes,
which is what made the 2026-09-08 rehearsal import 152 GB in 26 seconds.


## 5. What the shared log carries — SETTLED (option 3)

Three options were weighed:

1. **A full signed PVFS log per region.** Per-event provenance, chain
   verification, verified log shipping — all built (doc 20 P7.2). Cost: an
   append + sign + fold per file event, confined to the owning region but still
   there.
2. **A plain local index, nothing signed.** Fastest and cheapest. Cost: no
   provenance or tamper evidence for the catalogue; replication needs
   inventing; history gone; the region machinery unused.
3. **A fast local index, plus a periodically published signed manifest.** The
   region catalogues locally at full speed; on a cadence it publishes a signed
   hash of its catalogue state as its head.

**Option 3 is settled for the media library.** Chris's original description was
option 3 — *"a blob storage that's in the log pointing to where the individual
trees are doing their own cataloging"* — and the mechanism to carry it is
already built: `SubRegionHead { region, seq, head_hash }` (doc 20 §2.2) is the
parent committing a child head. The shared log holds region marks and heads.
**It does not hold file events.** Log growth stops being a discipline and
becomes a property.

What is traded: provenance is per-snapshot, not per-event. The catalogue can
be proven authentic and current; it cannot prove who added one file at 14:32.
For a media library that is the right trade. The bytes stay hash-verified
regardless — this is only about the catalogue's own provenance.

**Snapshot cadence — OPEN.** Options: on every scan pass that changed
anything; on a timer; on demand. Cheap enough that "every pass that changed
something" is probably right.


## 6. The merged view — SETTLED, with one hard rule

**One logical entry per relative path, with every region's copy behind it.**
This is what the presentation layer shows and what the mount serves.

**Admission requires byte-identical copies.** The merged view admits exactly
one content hash per relative path. This is not taste; it is forced by the
swarm: chunk-level transfer fetches ranges from different peers and assembles
them, and two regions serving different bytes for one path would produce a
file assembled from two encodings — corrupt if unlucky, hash-failed if lucky.
"Read both at the same time in a swarm" is only safe when the bytes agree.

It is also forced by the operator's experience. Chris's scenario: a movie
plays badly partway through; two copies exist with different bytes; which was
served, and which should be fixed? If the system had pretended they were
redundant there is no answer. Refusing to merge them is what makes the
question answerable.

So: **same path, agreeing hashes** = redundancy. **Same path, disagreeing
hashes** = a conflict (§7). A copy without a hash is not admitted until it has
one — affordable now that sidecar coverage is ~99% on both production roots.


## 7. Conflicts — SETTLED in principle, OPEN in policy

**A conflict is decided by a rule, never left for a person.** This project has
already proved what "surfaced for an operator" means in practice: `missing`
sat at 1,913 for weeks; the Backups island sat a fortnight; doc 24 records
"Nobody has run `--forget`"; 588 duplicate groups existed the first time
anything asked. A set-and-forget system that resolves conflicts by reporting
them does not resolve them.

**7.1 Serving auto-resolves, always.** The D76 ladder (`media::choose`) picks
the served copy: quality, then a truncation guard, then size, then recency.
Deterministic — same inputs, same answer, on every box. The consumer is served
the winner, never the stale copy, so the confusing case never reaches them.
Nothing needs deleting for this to be true.

**7.2 Bytes are never deleted automatically on a non-draining region.**
Redundancy is the point of a non-draining region; the loser stays addressable
and fetchable. What to do about the *space* it takes is a retention policy
(7.4), not a judgement.

**7.3 By mount type:**

| | agreeing hashes | disagreeing hashes |
|---|---|---|
| **draining** region involved | one copy is redundant → the drained one goes | ladder picks the winner → it goes to the library region; the loser drains away. Self-resolving: there is an action |
| **non-draining** only | redundancy → serve nearest, or swarm across all | ladder picks the SERVED copy; both stay; conflict reported (7.5) |

The draining case is the easy one precisely because there is something to
*do*. The non-draining case only has something to *decide*, and 7.1 decides it.

**7.4 Retention — OPEN.** Per region: "keep newest N versions", "keep all",
"keep the ladder winner only". Explicit, declared, never inferred.

**7.5 Conflicts PUSH; they do not wait to be asked.** They go to D83's fleet
monitoring — the mechanism built after the NAS sat down for ten hours
unnoticed, for exactly this reason. A signal that arrives, not a report to
remember. They are also exposed **in band** in the presentation layer: the
served copy is the winner, and "N versions exist" is visible as an attribute of
the entry, so anyone touching the file can see it without knowing PVFS exists.


## 8. Replication — SETTLED, and it gets simpler

A region publishes a signed manifest hash as its head (§5). A replicating box
fetches the catalogue blob, checks its hash against the signed head, and
verifies the signature. Done. No fold, no replay, no chain walk for the
catalogue. Deltas are an optimisation: a 27,000-entry catalogue is a few
megabytes, so whole-snapshot replication is viable from day one.

Verified log shipping (doc 17) is *more* machinery than this needs. The
head-commitment path that carries the manifest is the part that is reused.

A box offline means that region's live catalogue is unavailable; the last
replicated snapshot still serves the merged view, marked stale by its age.
That is the correct behaviour for a library and it is what a filesystem does
when a drive is unplugged.

*Built as D129 (§10 phase 5). One precision on "stale": the log is the
reference. A copy is **stale** when the log attests a head newer than the one
held (the region's box published and this box has not fetched yet); a copy
whose box is offline is merely **old** — nothing newer is attested — and
`region ls` shows when it was fetched. Who serves the manifest is whoever
announced an endpoint and holds the file; nothing is special about the
owner, and the bytes are verified against the head before a row is written,
so a wrong box can waste a round trip and nothing else.*


## 9. What does NOT change

- **The log's integrity model.** Append-only, hash-chained, signed. The shared
  log is smaller and quieter; it is not different in kind.
- **ACLs and authority.** Region ownership is a grant like any other.
- **The swarm (doc 22).** Serves identical copies from N regions; this design
  makes "identical" a precondition rather than a hope.
- **Sidecars (D93/D103).** The hash cache beside the bytes, unchanged.
- **The D76 ladder.** Reused as the serving decision, unchanged.
- **Region logs (doc 20).** Head commitment is the carrier for §5. The
  per-region *event* log becomes optional — a region MAY keep one for
  provenance, but the media library will not.


## 10. Implementation plan

Phased so that each phase is buildable, testable and useful on its own, and so
that the current forest keeps working until the last phase.

**Phase 0 — spike (days). BUILT (PVOS D125 items 0–1).** `SubRegionHead`
carries a manifest hash for a region that has no log of its own once the
region row knows its `kind` (`log` | `catalogue`): five readers that presumed
a split log each grew a one-line predicate, and the shape held.

**Phase 1 — the region catalogue. BUILT (D125 items 2–5).** `region_entries`
(one row per file AND per directory, empty ones included, keyed by relative
path; size, mtime, `changed_ms`, hash from the sidecar when there is one,
quality) and `region_snapshots`, both projection-side. A binding on a
catalogue region's root writes rows and emits no node, link or location
event. The manifest is canonical bytes (`pvfs-region-manifest 1`, region,
seq, one tab-separated line per row in bytewise path order), hashed with
blake3, written to `regions/<id>/manifest.<seq>`; a pass that changed the
catalogue publishes seq+1 and ONE `SubRegionHead`, an unchanged pass publishes
nothing. Sidecar reuse carried over unchanged.

**Phase 2 — region ownership. BUILT, smaller than planned (D125 items 6–8).**
No declaration record: a region's owner IS an admin (`a`) grant on its root,
made in the same batch as the mark (`region mark --catalogue --owner
key:<hex>`), and the kind rides on `RegionMarked` as a trailing optional field
(byte-identical for log regions). The 28 `replica` gate sites stay as they
are — a replica still never appends locally; it publishes its head through
the forest owner with ONE routed op, `WriteOp::CommitRegionHead` (proto 4→5),
which the owner prepares under that grant and refuses for anyone else. A
catalogue region holds rows, never nodes: it is marked once, on an empty
folder, and refuses unmark and re-mark. *Still to run:* the two-box lab pair
(D125 item 9), the milestone's exit criterion.

**Phase 3 — the merged view. BUILT (PVOS D126).** `merged_view(dir)` and
`view_conflicts()` union every catalogue region's rows by relative path, one
level at a time in the manifest's bytewise order; a path is `Admitted` when
every known hash agrees (copies = hashed copies), `Unhashed` when none is,
`ConflictHashes`/`ConflictKind` otherwise — never merged, nothing deleted.
`pvfs view ls [dir]` / `pvfs view conflicts`. What phase 4 receives: the
conflict entries, each carrying every copy (region, size, mtime, hash) and,
for now, the newest copy as the description. The original spec follows.
Union region catalogues by relative path.
Admission by hash agreement. Conflict detection. Directory entries unioned.
*Testable alone:* two regions, overlapping paths, identical and differing
bytes; assert one entry per path, the right copies admitted, the conflict
flagged.

**Phase 4 — resolution. BUILT (PVOS D127).** `served_copy` (the D76 ladder
over a conflict's hashed copies), `region drain on|off` (a fleet-visible
`RegionDrainSet` in the log — a local flag would have let two draining boxes
trash each other's bytes), `resolve_conflicts` / `pvfs view resolve` (a
draining region's redundant or losing copy goes to that region's trash;
library regions are never touched; a winning draining copy stays and is
reported), a `resolve` serve job, and `conflicts: N` in `serve status`.
Retention (§7.4) and the push to D83 stay open. The original spec follows.
Ladder-based serving winner; drain behaviour; the
retention policy. *Testable alone:* every cell of the §7.3 table.

**Phase 5 — replication. BUILT (PVOS D129).** A catalogue travels as its
manifest — the exact bytes whose blake3 the log attests as the region's head
— fetched by a new wire request (`RegionManifest`, proto 7, read-gated on
the region) from whichever announced endpoint holds it, installed only when
it is the attested head (`Engine::install_region_snapshot`: a non-catalogue,
a locally bound region, a non-attested seq, a hash mismatch, a manifest
naming another region are each refused), into the same `region_entries`
the view reads; `region_fetched` (schema 18) records what is held.
`catalogue_status` and `ViewCopy.stale` say when the log attests a newer
head than the copy held; a box that is offline publishes nothing, so its
region is old, not stale — the §8 behaviour. The `catalogue` serve job
(60 s), `pvfs region fetch`, `region ls` head/held/stale, `stale: N` in
`serve status`. No deltas yet (§8: whole-snapshot is viable from day one).
Found on the way: since D125 the forest owner's heads tick re-attested
`(0, empty)` for every catalogue region another box owned; fixed. The
original spec follows.
Fetch-and-verify a region's catalogue by its signed
head; stale-by-age when the owner is offline.

**Phase 6 — the mount. BUILT (PVOS D130).** `pvfs mount --view <dir>`: the
same `pvfs-fuse` filesystem in a second mode — inodes are relative paths in
the merged view (`Engine::view_entry` for a lookup, `merged_view` for a
listing, cached 5 s), directories and admitted files shown, a hash conflict
shown as its served copy, unhashed files and kind conflicts not admitted
(§6) and so not shown. Bytes, in order: this box's own disk
(`local_path_for_hash` — a region it catalogues, size-checked), the hash
store (`sync/by-hash/`), else a read-through — `CatHash` on the wire (proto
8, read-gated on the region that holds the file) from the first announced
endpoint that serves it, into the hash store, served from the growing file
and verified whole before it is kept; a box that serves other bytes is
refused and named. Sequential and single-source: the parallel chunked pull
by hash — doc 22's swarm over N regions — is the next milestone. The
namespace is read-only. D82's unit gained `pvfs_mount_view`. The original
spec follows.
The FUSE mount (doc 20 §3, built) over the merged
view instead of the tree; the swarm over admitted copies. This is D82's
presentation layer, arriving on a model that can carry it.

**Phase 7 — monitoring.** Conflicts and capacity into D83, and in band.

**Phase 8 — migration.** The planned re-genesis (doc 25) becomes THIS: a fresh
start on the new model rather than a fresh start on the old one. The rehearsal
already proved the import is ~5 hours and metadata-bound. Nothing about the
current forest needs converting, because it is not being kept.

**Milestone numbers.** Doc 27 (the D102 review response, same day) proposes
D122–D124 for the fetch-path, disabled-job and hygiene fixes. Those numbers
stand; the phases here start at **D125**. Two of doc 27's items are
prerequisites rather than neighbours: D122 items 2–4 (the replica source is a
candidate only when the catalogue says it could serve; attribute a swarm
mismatch by who served) are exactly the candidate discipline §6 and phase 5–6
rely on, and are cheaper to land on the current model first.

**Sequencing note.** Phases 1–4 are the design; 5–7 are the delivery; 8 is the
cutover. Phases 1 and 2 could be built and tested on the lab pair before a
single production file is touched. The order of 3 and 4 could swap.


## 11. Open questions, collected

1. Snapshot cadence (§5).
2. Retention policy shape (§7.4).
3. The full set of what a region declares (§3).
4. "Nearest" for the swarm's copy selection — latency-measured, declared
   priority, or both.
5. Whether a region may keep a per-event log for provenance as an opt-in.
6. What the presentation layer shows for a conflict, concretely.
