# 29 — The cutover to the new model (doc 26 phase 8)

**Status: written 2026-09-11 (PVOS D137). Rehearsed only as its parts: the
D134 lab pair ran the play from a wiped forest through the receive → drain →
purge loop; the D128/D135 rehearsals covered the owner move and the NAS
supervisor. The whole sequence has not yet been run on the live fleet — §10
says what that costs.** Doc 25 remains the record of the old-model
re-genesis and of what a rehearsal teaches; this document replaces its
sequence, not its lessons.

## 0. What is different this time, in one paragraph

Doc 25 rebuilt the old forest: every file became a node again, every box
re-imported through routed writes, and §3 of that document had to hunt
down every external reference to a node id. On the new model (doc 26) the
shared log carries **marks, heads and grants** and nothing per file. Each
box catalogues its own disk locally at disk speed (sidecars make the hash
free), publishes a manifest hash as its region's head, and every box fetches
every other box's catalogue by that head. So the cutover is: a fresh forest,
one catalogue region per box, bind, let the watch jobs run, verify the
merged view, switch the units. No import. No carry. Almost nothing outside
the forest names a node id any more, because the units mount the **view**
and the inventory names regions by **label**.

## 1. Preconditions

| | why |
|---|---|
| Every box on **D135 or later** — the roll of D125–D135 done first, box by box (proto 8 sits inside the compatible window), by the fleet roll runbook | D125 (catalogue regions), D129 (fetching catalogues), D130 (the view mount), D133 (receive), D134 (the play), D135 (the supervisor) are all needed on every box |
| The **aarch64 build** of that same main for the QNAP, tested under qemu (memory: `qnap-arm-build`) | the holder is the box that matters most and the one the pipeline does not build for |
| Sidecar coverage checked **per root** on both holders' roots (`pvfs sidecar-backfill --dry-run`), ~99% as on 2026-09-08 | the new model's scan hashes what has no sidecar; coverage is the difference between minutes and days |
| The **old** forest's recovery phrase in custody; the new one's will be, the moment `forest init` prints it | rollback needs the old forest openable |
| The D135 supervisor **rehearsed once on the real QNAP** (stop the daemon by hand; the owner brings it back within five minutes) | the cutover's first NAS restart should not be the first time the channel is used |
| A window with cloudplow and the arrs quiet | not required — the old forest keeps serving — but arrivals during the window are catalogued by the new forest's first watch pass, not the old one's |
| The QNAP's clock on NTP — it was **139 s behind** the VMs on 2026-09-11 (D138) | the owner stamps its own health record, so supervision is unaffected; log correlation across boxes and the mtime of received files are not |
| **Decide the view mount** | doc 25 §7 found PVFS is not in the arrs' read path (mergerfs reads local + rclone). Whether the new forest's view goes into the union is D82's open decision, made separately; nothing here depends on it |

**Nothing here deletes the old forest.** It is a different directory and
its daemons keep serving until §7; that is the rollback.

## 2. What "done" means — decide it here

The merged view on every box lists the same set of file paths as the union
of the two holders' roots and feederbox's staging root, with:

- `pvfs view conflicts` empty except for pairs the ladder resolves (a
  staging upgrade waiting for `receive`), and none of kind `file vs folder`;
- `pvfs serve status` on every box: `conflicts 0` (or the expected few),
  `stale 0`, every job enabled and clean;
- `pvfs fleet health` on the owner: every box up, no action pending;
- a file written on feederbox lands on the NAS's library root by itself,
  its staging copy drains, and the view shows one copy — the D134 lab loop,
  on the real boxes, once.

Record the old forest's counts first (doc 25 §1's commands still apply):
`missing`, duplicates, islands, and the plain file count under each root
(`find <root> -type f ! -name '.*' | wc -l`) — the last one is the number
the view must match.

## 3. What is NOT carried, and why that is fine

- **Node ids.** Files have none on the new model. The only ids that survive
  are region ids, and the play derives them from labels.
- **The log** (409k events at last count). The new one starts at genesis and
  stays small: marks, heads, grants, drains.
- **D76 quality measurements.** They were per node; catalogue rows carry a
  `quality` column the watch fills from what it can measure, and the ladder
  falls through to size and recency where it is empty. `forest
  carry-quality` does not apply. Re-measurement is a later item, not a
  cutover step.
- **Locations, tags, placement.** Re-derived: a catalogue region's rows are
  its locations; placement is the per-box `placement` file the play writes.
- **ACL grants** — re-issued by the play (`fleet enroll --rights rwa`, one
  per box) as before.

## 4. The sequence

The play does most of it (D134). Two inventory files coexist during the
transition: `fleet-prod.ini` (the old forest, unchanged, still serving) and
`fleet-prod2.ini` (the new forest on new directories, units and ports). The
same boxes, the same binaries.

### Phase A — the inventory for the new forest

Copy `fleet-prod.ini` to `fleet-prod2.ini` and change only:

```
[all:vars]
owner_addr=<owner ip>:7431          # a NEW port; the old daemon keeps 7421
owner_alias=media2

[fleet_owner:vars]
pvfs_mount=/srv/pvfs/media2
pvfs_listen=0.0.0.0:7431
pvfs_announce=<owner ip>:7431
pvfs_unit=pvfsd-media2
# catalogue too (D138): without it the owner's own region ls holds no head
# and serve status reports every region stale, forever
pvfs_serve_jobs=reclaim,health,catalogue

[fleet_ingest:vars]
pvfs_replica=/srv/pvfs/feeder2
pvfs_listen=0.0.0.0:7432
pvfs_announce=<feederbox>:7432
pvfs_unit=pvfsd-replica2
pvfs_serve_jobs=follow,watch,catalogue,resolve
# the new model, instead of library_node:
pvfs_region=staging
pvfs_region_drains=true
pvfs_region_retention=7
library_path=/mnt/local/Media
pvfs_mount_point=/mnt/pvfs-view
pvfs_mount_view=true

[fleet_nas:vars]
nas_home=/share/CACHEDEV4_DATA/Data_ext/pvfs2
pvfs_listen=0.0.0.0:7433
pvfs_announce=<nas>:7433
pvfs_serve_jobs=follow,watch,catalogue,receive
pvfs_supervise=true
# D138: no local watchdog in the NEW home — the owner supervises it; the old
# watchdog keeps guarding the old daemon, and the play no longer touches it
nas_watchdog=false
# the new model, instead of media_node:
pvfs_region=library
library_path=/share/CACHEDEV1_DATA/Data/Media
pvfs_region_receives=true
```

`fleet_artifacts` points at a live pipeline slot of the rolled build (slots
are deleted at merge — set it on the day). The 7431 forward at home (doc 82's
ingress note) must exist before Phase C, exactly as 7421 does today.

### Phase B — the owner

```bash
ansible-playbook -i fleet-prod2.ini fleet.yml --tags owner
```

It halts once: **the recovery phrase**. Move it to custody, delete the
file, run again. The play registers the forest, mints the pin, enables the
jobs, announces, and starts `pvfsd-media2` on 7431 beside the old daemon.
**Check:** `pvfs --forest media2 fleet health` says "no announced peers"
(nothing else yet) and `systemctl is-active pvfsd-media pvfsd-media2` are
both `active`.

### Phase C — the ingest (feederbox)

```bash
ansible-playbook -i fleet-prod2.ini fleet.yml --tags ingest
```

The play enrols the box, takes the replica, creates and marks `staging`
under the new root owned by feederbox's key (on the owner, daemon down for
the write, restarted after), waits for the mark to follow, binds
`/mnt/local/Media` to it, sets it draining with a 7-day retention, enables
the jobs, and starts `pvfsd-replica2` on 7432. The `watch` job then
catalogues `/mnt/local/Media` — a local scan, sidecars reused — and
publishes head 1 through the owner.

**Check:** on feederbox, `cd /srv/pvfs/feeder2 && pvfs --json region ls`
shows `staging` as `local: true`, `drains: true`, `head ≥ 1`, and `entries`
equal to the file count under `/mnt/local/Media`. On the owner, `region ls`
shows the same head. If `entries` stays at 0 for more than a settle window
(15 s) plus one pass, read the journal for `hash from sidecar` lines: full
hashing at volume means a coverage gap — stop and backfill.

### Phase D — the holder (QNAP)

```bash
ansible-playbook -i fleet-prod2.ini fleet.yml --tags nas
```

**The old daemon and its watchdog are left alone** — since PVOS D138 the
play kills and restarts only the processes of the `nas_home` it is given
(as first written it stopped every pvfsd and every watchdog on the box; the
three-box lab caught it before this phase ever ran). The new home runs
without a local watchdog (`nas_watchdog=false`): the owner supervises it.
The play pushes the aarch64 binaries to the new `nas_home`, enrols, takes the replica, creates and marks `library`
owned by the NAS's key, binds `Data/Media`, declares it receiving, enables
`follow,catalogue,receive`, starts the daemon on 7433, installs the
supervise script and the forced-command key, and registers the channel on
the owner.

**The second root is by hand.** The play declares one region per box
(D134's open item); `Data_ext/Media` is a second library region on the same
holder — catalogued and presented, never a placement target:

```bash
# on the owner (daemon-down write, as the play does it)
sudo systemctl stop pvfsd-media2
cd /srv/pvfs/media2
R=$(pvfs --json info | python3 -c 'import json,sys;print(json.load(sys.stdin)["root_node_id"])')
EXT=$(pvfs add "$R" --kind folder --label library-ext)
pvfs region mark "$EXT" --catalogue --owner key:<nas pubkey> </dev/null
sudo systemctl start pvfsd-media2
# on the QNAP, once its follow job has the mark (region ls shows kind catalogue)
cd $NAS_HOME/replica && pvfs bind "$EXT" /share/CACHEDEV4_DATA/Data_ext/Media --hash-policy on_add
```

Both regions are catalogued by the holder's `watch`, which is why it is in
the job list above (a box with a region needs it — the D134 lab found this
on the owner, D138 put it in the example).

**Check:** `region ls` on the QNAP: `library` and `library-ext` both
`local: true`, heads ≥ 1, entries equal to each root's file count;
`receives: true` on `library` only. On the owner, `fleet health` lists the
holder up and supervised.

### Phase E — the fleet fetches, and the view is whole

Within a minute of each head (the `catalogue` job's cadence), every box
holds every catalogue. **Check on every box:** `pvfs view ls` at the root
shows the union; `pvfs serve status` says `stale: 0`; `pvfs view
conflicts` is empty or names only staging upgrades. Compare the view's
file count with §2's recorded totals.

### Phase F — one file through the loop, on the real boxes

Allow for the cadences before judging it: a file lands on the holder
~6.5 min after it settles in staging (receive 300 s + catalogue 60 s +
settle 15 s) and leaves staging ~5 min after that (resolve 300 s) — 380 s
and 687 s measured in the D138 lab for a 3 MB file.

Copy one small file into `/mnt/local/Media/…` on feederbox. Within: a
settle window + a watch pass (feederbox catalogues it), a minute (the
owner and the NAS fetch the head), the receive cadence (5 min; or `pvfs
view receive` on the QNAP now), the file is on `Data/Media` with a
sidecar; the NAS's watch publishes; feederbox's `resolve` (5 min cadence;
or `pvfs view resolve`) trashes its copy; the view shows one copy. That is
§2's last line, and the moment the new forest is doing the old forest's
job.

## 5. Re-point the external references

Shorter than doc 25 §3, because the model removed most of them:

1. `fleet-prod.ini` **becomes** `fleet-prod2.ini` (keep the old one as
   `fleet-prod.ini.old` until §8).
2. The ingest's `pvfs-mount.service` — the play templates it from the new
   inventory in `--view` mode; nothing names a node id.
3. Nothing in `placement`, `serve.jobs` or the units carries an id of the
   old forest; the region ids are the new forest's, written by the play.

**Check:** `grep -r "<old root id>\|<old Media id>"` across the inventory and
every box's new `.pvfs/` returns nothing.

## 6. Verify

§2, in full, recorded next to the before-file. Do not proceed to §7 on a
partial pass.

## 7. Cutover

The arrs do not read PVFS (doc 25 §7, re-check on the day). What is left:

1. Stop the old daemons in roll order — owner (`pvfsd-media`), ingest
   (`pvfsd-replica`), holder (its old start script's daemon, watchdog
   stopped by pid) — and disable the old units. The new ones are already
   serving on their own ports.
2. If the view is to be in the union (D82's decision): mount
   `/mnt/pvfs-view` and add it as a branch; otherwise leave it as it is.
3. Run the play against the new inventory once more and confirm it changes
   nothing but the deliberate always-run steps.
4. Restart the NAS watchdog for the NEW daemon's start script, or retire it
   in favour of the supervisor once the supervisor has brought the holder
   back at least once for real.

**Anything that arrived during the window** is on feederbox's disk; the new
forest's watch already catalogues that disk, so it is simply in the
staging region and flows through §4 F on its own.

## 8. Rollback

Before §7: nothing to do; the old forest never stopped. After §7: start
the old units in roll order, restore `fleet-prod.ini`, stop the new units.
Keep the new forest's directories as the evidence. Delete the OLD forest
only after the new one has run a full week with a cloudplow cycle, a NAS
reboot (the supervisor's first real `start`), and an arr import — and
after §2's counts have been re-taken and are boring.

## 9. Rehearsal

**Phases B–D and F ran on the three-box lab on 2026-09-11 (PVOS D138):**
VMs 300/301 as owner and ingest, the real QNAP as holder in a lab home
beside the production daemon, main `0abfce1` on all three (the holder's
first aarch64 run on real QTS), one file through the loop, and the owner
restarting the killed holder daemon in 2 min 20 s. Two play defects and
two of the amendments above came out of it. **Still un-rehearsed:** §7 and
§8 (the switch and the rollback), and a roll of a forest with history —
the three-box lab is where both go next.

Then run §4 on that lab with a subset before the real boxes. Then the live fleet over one show's directory,
as doc 25 §11 did, before the whole library. The 2026-09-08 rehearsal's
numbers (152 GB in 26 s from sidecars) are the expectation for the scan;
the fetch-and-verify of a 27,000-row manifest is a few megabytes.

## 10. Open

1. **The play declares one region per box.** The holder's second root is a
   hand step (§4 D). Making `pvfs_region` a list is a small follow-up.
2. **The `watch` job on the NAS** is not in the inventory example's job
   list for the holder; §4 D adds it. The example should carry it once the
   holder has a region.
3. **Quality re-measurement** on the new model (§3).
4. **§7 and §8 have not run anywhere** — the switch and the rollback are
   the untested half; §4 B–D and F have (§9).
5. **A drain leaves the sidecar behind** (D138): after `resolve` trashes a
   losing staging copy its `.<name>.manifest` stays in the staging root, and
   `.pvfs-trash` lives there too. On feederbox that is one orphan dotfile
   per moved file. PVFS follow-up: the drain takes the sidecar with the file.
