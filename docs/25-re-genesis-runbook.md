# 25 — The re-genesis runbook

**Status: written 2026-09-08, NOT yet rehearsed end to end on the fleet.**
Doc 24 §17 lists "no re-genesis tool, and nobody has written the runbook" as
blocker 2. This is that runbook. It also settles blockers 4 (cutover), 5
(what "verified" means) and 6 (record the residue first), because all three
are answers this same document has to give.

What it is NOT: automation. F2 was never built and this does not build it.
Every step here is a command an operator runs, in an order that matters, with
a stated check after each. The two hard constraints come from the lab pair
run of 2026-09-07 (doc 24 §17 item 1), and neither is discoverable from the
code:

- **A replica refuses a bare `pvfs scan`** — "a replica has no local writer,
  so its scan must be routed to the owner — run it from the `watch` serve
  job". Only the owner can be scanned directly.
- **Foreground `serve watch` is not enough either.** It arms inotify for NEW
  writes; an existing library is picked up by the reconcile pass that runs on
  job start. So the routed import of a 40 TB library has to run as the
  `watch` **daemon job**, not a foreground command.

Read §3 before doing anything. It is the part that has been wrong in every
previous write-up of this plan.


## 0. Preconditions

| | why |
|---|---|
| D103 deployed on every box that will scan | before D103 the `on_add` paths neither read nor wrote sidecars, so a re-import re-reads all 40 TB. This is the property the whole plan rests on. |
| Sidecar coverage checked, not assumed | `pvfs sidecar-backfill --dry-run` on each holder. It was ~96% on the QNAP when last measured. Coverage is what makes the import metadata-speed rather than byte-speed. |
| D105 deployed | a scan on a marker-verified mount now unlinks files that are genuinely gone. On the FIRST scan after the roll this clears a backlog; do it before re-genesis so the old forest's residue counts (§1) are honest. |
| D106 deployed | `pvfs islands` is how §1 records the detached-subtree residue. Without it that number cannot be taken at all. |
| The recovery phrase for the OLD forest is in custody | rollback (§8) needs the old forest openable. |
| A maintenance window with cloudplow and the *arrs quiet | not strictly required — the old forest keeps serving throughout — but new arrivals during the window land in the old forest only, and have to be re-scanned after cutover. |

**Nothing here deletes the old forest.** It is a different directory on disk
and stays fully operational until §8 says otherwise. That is the rollback.


## 1. Record the residue FIRST (doc 24 §17 item 6)

Re-genesis silently drops the residue. That is the point of doing it — but
only if the residue was seen rather than merely gone. Take these on the
**owner**, before anything else, and keep the file:

```bash
cd /srv/pvfs/media
{
  date -Is
  echo "== info ==";     pvfs info
  echo "== missing ==";  pvfs --json missing  | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))'
  echo "== orphans ==";  pvfs --json orphans  | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))'
  echo "== islands ==";  pvfs islands
  echo "== bindings =="; pvfs bindings
  echo "== acl ==";      pvfs acl ls "$(pvfs --json info | python3 -c 'import json,sys;print(json.load(sys.stdin)["root_node_id"])')"
} | tee ~/regenesis-before-$(date +%Y%m%d).txt
```

Baseline measured 2026-09-08, for comparison when the real run happens:

| | count |
|---|---|
| `missing` — catalogued, held by nobody | 1,894 |
| `orphans` — no live link | 25,602 |
| islands — live-linked, unreachable | 1,849 at last count (doc 24 §18); re-take with D106 |
| root ACL grants | 3, all `rwa`, all `key:` principals |

The same commands run against the NEW forest after §6 are what "verified"
compares against.


## 2. What "verified" means — decide it HERE, not under pressure

Doc 24 §17 item 5 asks for this in advance. The bar:

1. **File-node count within 1% of the old forest's reachable count**, and no
   lower without an explanation. The old forest's reachable set is the honest
   comparand — not its total node count, which includes 25,602 orphans and
   1,849 stranded nodes that re-genesis is meant to drop.
2. **`pvfs islands` reports none.** A fresh forest has no excuse for one.
3. **`pvfs missing` is zero, or every entry is explained.** In a fresh forest
   built from a live library, an unheld file means a scan did not finish.
4. **A hash spot-check on 20 files across all three boxes** — `pvfs loc
   verify` against the real bytes, not against the sidecar that produced the
   hash. This is what catches a sidecar that was wrong before it was trusted.
5. **The mount serves bytes.** `cat` a file through `/mnt/pvfs-root` on the
   ingest and compare to the file on disk. A catalog that cannot stream is
   not a working forest.
6. **Both replicas converge on node count** within a `follow` cycle of each
   other. The lab run's pass condition was exactly this: 11 nodes on both
   boxes, and every file with locations from both.

Fail any of these and §8 is the answer, not a fix in place.


## 3. Every external reference to a node id — MEASURED, 2026-09-08

Doc 24 §16 said this was "a single node id — the Media folder — written in
one inventory line and one placement file per box". **That is wrong on all
three counts.** Checked against the running fleet:

| where | box | holds | value today |
|---|---|---|---|
| `fleet-prod.ini` → `media_node` | control machine | 1 line | `eff3125d…` (Media) |
| `/srv/pvfs/media/.pvfs/placement` | owner | `central-tree`, `staging-root` | `eff3125d…` |
| `/srv/pvfs/feeder/.pvfs/bindings.local` | ingest | 1 binding row | `eff3125d…` |
| **`pvfs-mount.service` → `ExecStart`** | **ingest** | **1 id** | **`6e81db94…` — the forest ROOT, a different id** |
| `…/pvfs/replica/.pvfs/placement` | holder | `sync-advertise`, `central-tree`, `library-root` | `eff3125d…` |
| `…/pvfs/replica/.pvfs/bindings.local` | holder | 2 binding rows | `eff3125d…` |

**Two distinct ids, six files, ten occurrences.** The forest root id in the
ingest's mount unit is the one every previous write-up missed.

Three things follow, and each is a trap:

- **`library_node` is NOT defined in `fleet-prod.ini`** (only in
  `fleet-lab.ini`). The ingest play's bind task is gated `when: library_node
  is defined`, so in production **it silently skips** — the live Media
  binding on feederbox was made by hand. After re-genesis it must be made by
  hand again, or the variable added. A play run that reports green will not
  have bound anything.
- **`pvfs-mount.service` is live but unmanaged.** `fleet-prod.ini` says the
  D82 union mount was "ROLLED BACK … and `pvfs-mount.service` is dead on the
  box". It is not dead — it is **active**, mounting the forest root at
  `/mnt/pvfs-root`. The play cannot re-point it because `pvfs_mount_node` and
  `pvfs_mount_point` are deliberately absent from the production inventory.
  Fix the unit by hand at §5, or add the vars.
- **Placement keys differ per box.** The owner has two, the holder three, the
  ingest has no placement file at all (it carries `bindings.local` instead).
  Copying one box's file to another re-points the wrong things.


## 4. The sequence

Owner first, always — forward compatibility covers the log and the wire only
degrades one way (D72 §9e / D73).

### Phase A — the new forest on the owner

```bash
# A new DIRECTORY. The old forest keeps running at /srv/pvfs/media.
sudo install -d -o chris -g chris -m 0755 /srv/pvfs/media2
cd /srv/pvfs/media2
pvfs forest init --no-import --alias media2
```

`--no-import` because the directory is empty and the tree is built
deliberately below. **`forest init` prints the recovery phrase exactly once.**
Move it to custody before the next command; the fleet play deliberately halts
here for the same reason.

Then the tree, and the id that everything in §3 will point at:

```bash
pvfs forest register /srv/pvfs/media2 --alias media2
NEW_ROOT=$(pvfs --forest media2 --json info | python3 -c 'import json,sys;print(json.load(sys.stdin)["root_node_id"])')
NEW_MEDIA=$(pvfs --forest media2 add "$NEW_ROOT" --kind folder --label Media)
echo "root=$NEW_ROOT media=$NEW_MEDIA"   # WRITE THESE DOWN — §5 needs both
```

**Check:** `pvfs --forest media2 ls "$NEW_ROOT"` shows exactly `Media`.

### Phase B — re-grant the ACLs

Three `rwa` grants at the root (§1). Take the three pubkeys from the old
forest's `acl ls` and re-issue them against the new root:

```bash
pvfs --forest media2 fleet enroll <pubkey> --rights rwa   # x3
pvfs --forest media2 acl ls "$NEW_ROOT"                   # check: 3 rows, rwa
```

Do this BEFORE the replicas are taken. A replica that cannot write routes its
scan to an owner that will refuse it, and the failure surfaces as a scan that
does nothing rather than as an authorization error.

### Phase C — the ingest (feederbox)

```bash
# on feederbox
pvfs instance add media2-src 192.168.1.120:7421 <owner-pin>
pvfs replica add /srv/pvfs/feeder2 --instance media2-src
cd /srv/pvfs/feeder2
pvfs bind "$NEW_MEDIA" /mnt/local/Media
```

**Do NOT run `pvfs scan` here.** It will be refused, correctly. Start the
`watch` job as a daemon job and let its reconcile pass do the import:

```bash
pvfs serve enable follow
pvfs serve enable watch
sudo systemctl start pvfsd-replica2       # or HUP an existing unit
```

**Check:** node count on the new forest climbs, and `pvfs scan`-style
progress appears in the journal as *routed* writes. `journalctl --user -u
pvfsd-replica2 -f | grep -E 'hash from sidecar|routed'`. If you see
`hash from sidecar` at volume, the cheap-hash property is working; if you see
full hashing, stop and check sidecar coverage before burning days of I/O.

### Phase D — the holder (QNAP)

Same shape, aarch64 binaries, no systemd:

```bash
# on the QNAP, via the start script
pvfs instance add media2-src 192.168.1.120:7421 <owner-pin>
pvfs replica add $NAS_HOME/replica2 --instance media2-src
cd $NAS_HOME/replica2
pvfs bind "$NEW_MEDIA" /share/CACHEDEV1_DATA/Data/Media
pvfs bind "$NEW_MEDIA" /share/CACHEDEV4_DATA/Data_ext/Media
pvfs place "$NEW_MEDIA" sync --advertise
pvfs serve enable follow
pvfs serve enable watch
pvfs serve enable tier
```

Two bindings, because the holder has two library roots (§3). `Data_ext` is
bound in place and read-only — catalogued and presented back, never a
placement target.

**Stop the NAS watchdog before touching the daemon, and RESTART it after**
(doc 24 §14 item 6). Forgetting the restart leaves the holder unsupervised,
which is the exact outage D83 exists to prevent.

### Phase E — carry the quality data

On the **owner**, once both scans have settled:

```bash
pvfs --forest media2 forest carry-quality --from /srv/pvfs/media --dry-run
pvfs --forest media2 forest carry-quality --from /srv/pvfs/media
```

Matched by tree path and re-signed against the new ids. Expect roughly **119
carried** out of 24,585 recorded measurements — the rest are already stranded
on superseded and disconnected nodes in the old forest, which is a finding
about the old forest, not a failure of the carry (doc 24 §17 item 3).


## 5. Re-point the external references

Only now, and all of them — §3 is the checklist. Both ids are needed:
`$NEW_ROOT` for the mount unit, `$NEW_MEDIA` for everything else.

1. `fleet-prod.ini`: `media_node=$NEW_MEDIA`.
2. Owner placement — `central-tree` and `staging-root` → `$NEW_MEDIA`.
3. Holder placement — `sync-advertise`, `central-tree`, `library-root` →
   `$NEW_MEDIA`. Written by `pvfs place … sync --advertise` in Phase D; check
   the file rather than trusting it.
4. `pvfs-mount.service` on the ingest — `--forest /srv/pvfs/feeder2` and
   `$NEW_ROOT` as the mount node. **By hand**: the play does not manage this
   unit in production (§3).
5. Add `library_node=$NEW_MEDIA` to `fleet-prod.ini` so the ingest bind stops
   being a manual step that a green play run hides.

**Check:** `grep -r "$OLD_MEDIA\|$OLD_ROOT"` across the inventory and every
box's `.pvfs/` returns nothing but the old forest's own files.


## 6. Verify

Run §2's six checks, and §1's commands against the new forest for the
comparison. Record the output next to the before-file. Do not proceed to §7
on a partial pass.


## 7. Cutover (doc 24 §17 item 4)

**The *arrs are not the problem they were assumed to be.** Checked on
feederbox 2026-09-08: mergerfs runs
`/mnt/local=RW:/mnt/remote/nas=NC:/mnt/remote/nas2=NC` — **`/mnt/pvfs-root`
is not a branch**, nothing holds a file open on it, and no container mounts
it. Sonarr, Radarr and rclone read `/mnt/unionfs/Media`, which is local disk
plus rclone to the NAS. **PVFS is not in their read path at all**, so a
forest swap is invisible to them and there is no library-vanished risk to
plan around.

What that leaves is genuinely small:

1. Stop the ingest's `pvfs-mount.service`, re-point it (§5 item 4), start it.
   `/mnt/pvfs-root` briefly disappears; nothing reads it.
2. Point the daemon units at the new directories — `pvfsd --mount
   /srv/pvfs/media2` on the owner, `/srv/pvfs/feeder2` on the ingest,
   `replica2` on the holder — and restart each in the same order as the roll:
   owner → ingest → holder.
3. Re-run the fleet play against the updated `fleet-prod.ini` and confirm it
   converges without changing anything unexpected.

The old daemons stop; the old forests stay on disk.

**Anything that arrived during the window is in the old forest only.** After
cutover, one `watch` reconcile pass on each box picks it up from disk — the
files are real and present, so this is an ordinary scan, not a migration.


## 8. Rollback

Available at every point up to §7, and cheap: the old forest is untouched and
its daemons are the ones still running. Before §7, rollback is doing nothing.

After §7:

1. Point the daemon units back at `/srv/pvfs/media`, `/srv/pvfs/feeder`,
   `replica`.
2. Restore `fleet-prod.ini` and the placement files from the before-file (§1).
3. Restore `pvfs-mount.service` to `$OLD_ROOT`.
4. Restart owner → ingest → holder.

**Do not delete the new forest on rollback.** It is the evidence for why the
attempt failed.

Delete the OLD forest only after the new one has run a full week including a
cloudplow cycle, a NAS reboot, and an *arr import — and after `pvfs islands`,
`missing` and `orphans` have been re-taken and are boring.


## 9. What is deliberately not carried

- **Node ids.** Every one changes; `creation_nonce` is random (doc 24 §16).
  §3 is the complete list of things that care.
- **The log's history** — 241k events. That is the point: the new log starts
  at genesis with no D84 duplicates, no manifest-recursion junk, and no
  superseded predecessors.
- **`missing` entries, orphans, islands.** §1 records them so the drop is
  seen.
- **Tags, and locations held by other hosts.** Re-derived by the scans.
- **ACL grants** — re-issued by hand in Phase B, not carried.


## 10. Open before this can be called rehearsed

1. **This has not been run end to end.** The lab pair proved the fleet SHAPE
   (doc 24 §17 item 1) over 8 files. Nothing has rehearsed the full sequence,
   and a runbook that has not been executed is a hypothesis.
2. **No timing estimate for the real import.** D103 measured 67 GB in 83s on
   one box against warm sidecars. 40 TB across two holders with 96% coverage
   has not been extrapolated, let alone measured.
3. **§7 assumes the mount has no consumers.** True on 2026-09-08 and checked;
   re-check on the day, because the D82 union mount being live-but-forgotten
   is exactly the kind of thing that changes without anyone recording it.
