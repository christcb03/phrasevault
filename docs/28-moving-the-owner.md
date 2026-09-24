# 28 — Moving the owner (D128; PVOS D182)

**Status: D128 wrote this runbook on 2026-09-10 (lab pair). PVOS D182
(2026-09-23) made it one prompted run (`promote.sh`), added the fence that
stops a stale or replaced owner, promotion through the companion, a standby
owner, and dated copies of the log. Rehearsed on the lab pair
(`deploy/d182-owner-pair.sh`); on the lab fleet and the live fleet as D182's
checklist records — until the live drill has run, this is "rehearsed", not
"proven".** The sibling of doc 25: that one rebuilds a forest, this one keeps
it and changes which box may append to it.

## 1. What an owner is, and why it can move

The owner is the forest's one writer: every box dials it to publish, it
appends to the log, everyone else follows (doc 03 §1, doc 69 §9 in PVOS).
It holds no bytes. Its authority is not the box — it is a device certificate
on the log, signed by the root key the recovery phrase derives. So a replica,
which already holds the whole verified log, becomes the owner when the root
signs a `DeviceAuthorized` for it and a `DeviceRevoked` for the old box. The
forest id, every node id, every grant, every region head: unchanged. Nothing
is copied anywhere.

Never automatic (doc 20 §6, doc 03 §6 Q3): no job, no watchdog, no quorum
promotes. Home Assistant says the owner is down (PVOS D182: within ten
minutes); a person promotes. (Automatic failover is on the roadmap as an
opt-in for other users — doc 08, the availability track.)

**What an owner outage stops** (PVOS D183). Not the daily path: every box
keeps cataloguing its own regions, hands its heads to its peers directly as
signed claims, and each installs the others' catalogues — views, `receive`
and the drain move on — while the heads published meanwhile commit when the
owner is back, one row per region (doc 26 §8). What stops is the owner's own:
admin changes (grants, region marks, drain flags, enrolment — and revocation:
all of them log events), the NAS's supervision, the health observer and its
notifications, and the HA feed. So promotion is for an owner that is gone,
not one that is down for a reboot.

## 2. The standby, and the fence

**The standby** (PVOS D182) is a follower kept for exactly this: its own
daemon and directory (production: `mediabox-standby`, `/srv/pvfs/media2-standby`,
port 7435 on mediabox — bare metal, off the PVE host that carries the owner's
VM), `follow` only, announced so the owner's health job probes it; the page
shows its lag, and it makes the daily dated copy of the log (§7). Promoting it
leaves the fleet's shape unchanged: an owner that holds no bytes, in a daemon
of its own. Any follower can be promoted by hand; `promote.sh` promotes only a
standby, because a holder's replica would make one daemon owner and holder.

**The fence** (PVOS D182) is what makes a move safe to get wrong. A follower
only ever copies the owner, so a follower that holds MORE of the log than the
owner proves the owner stale — restored from an older image or copy, or
replaced by a promotion while it was away. Such an owner fences itself and
writes nothing:

- every routed write carries the writing replica's tip; an owner behind it
  fences before preparing anything;
- the owner's health job reads every peer's tip every two minutes;
- an owner's daemon hears its peers (its first health pass, 30 s at most)
  before it listens — so a zombie that boots after a promotion meets the
  promoted fleet's longer logs before any write can reach it.

A fenced owner opens and serves reads, refuses every append (daemon, CLI,
mount, jobs: `Engine::append_durable_with` is the one choke point), says so in
`serve status`, sends one `owner_fenced` (critical) and then nothing but its
daily check-in, and its HA collector posts nothing. `pvfs forest fence`
shows it and, asked, lifts it. A follower on ANOTHER branch (its chain
differs at its own tip) is refused and reported (`peer_diverged`); the owner
keeps writing. A follower whose source is behind it says so (`follow` error),
instead of calling itself up to date.

## 3. Before you start

- The root: the companion on this Mac (it holds the seed in its vault and
  asks you to approve each root signature — doc 14), or the recovery phrase,
  from custody. The phrase is on no box, and `promote.sh` never sees it.
- A standby that is at the owner's tip (the page shows it; `pvfs forest tip`
  on each box says it).
- The new owner reachable by the fleet on its port: feederbox dials the owner
  from outside (WireGuard, `wg0`), and the NAS and mediabox on the LAN.
- `deploy-respects-active-work` (memory): a planned move waits for an ingest
  session in flight to finish.

## 4. The move: `promote.sh`

```bash
cd deploy/ansible/fleet
./promote.sh
```

Bare, it asks (the inventory, which standby, the signer, and each
confirmation). Each step refuses rather than guesses; if one refuses, read
why, do not force.

1. **Look.** Every box's `pvfs forest tip`, as a table. Refuses when the
   target is behind another box (promoting it would fork the forest), or when
   two boxes disagree at one seq (the forest has forked already: a person
   decides which branch is the forest).
2. **Prepare.** The old owner, if it answers, is stopped and **disabled**, and
   its HA collector with it (a planned move — the drill). The target, still
   following, must reach the old owner's last seq. Then the target's daemon
   is stopped (promotion refuses a directory a daemon holds open). A dead
   owner is skipped: step 1 has shown the target holds the longest log among
   the boxes that answered.
3. **Sign — the one step a person does.**
   - *Companion:* the companion's socket is forwarded over SSH (as `pvfs ssh`
     does) and `pvfs forest promote --via-companion` runs on the target; the
     companion asks you to approve two root signatures — admit the target's
     new device (a key made on the target), revoke the old owner's. Its
     prompt names the forest and the devices.
   - *Phrase:* the script prints one command to run in another terminal —
     `ssh -t <target> pvfs forest promote <dir>` — which asks for the phrase
     there.
   Either way: every check and signature first, then `DeviceAuthorized` and
   every `DeviceRevoked` in ONE append (D128's two appends could half-finish).
   The default device index is the next never used; the default revocation is
   every live owner device other than the new one. The replica marker is kept
   as `.pvfs/promoted-from`.
4. **Verify.** The target says owner, not fenced; `follow` is turned off on
   it.
5. **The inventory.** The target moves into `[fleet_owner]` and `owner_addr`
   follows; the old owner goes to `[fleet_retired]` (out of every fleet
   group). A dated backup first; the diff shown and confirmed. The file is
   written through its link (worktrees link `fleet-prod.ini`, D155).
6. **The owner's role:** `fleet.yml --tags owner --limit <target>` — the
   owner's jobs, notify, the HA collector, `fleet announce`, the daemon.
7. **Point.** `promote.yml -e phase=point`: every follower's registry row
   and marker re-pointed and its daemon restarted (follow reads its marker
   once, at start); the NAS's supervision moved to the new owner's key; then
   every box must reach the new owner's tip. **No binary is touched** — a
   promotion must not become a roll.

It prints how long it took, and what is left by hand: Home Assistant's
quiet-owner page names VM 310 (edit it while the owner is elsewhere), and the
old box.

By hand (no Ansible), per doc 28's first edition: quiet the writers, `pvfs
replica sync`, stop the old owner, compare `pvfs forest tip` on every box,
`pvfs forest promote <mount>` (asks companion or phrase), `pvfs forest
register <mount> --alias <alias>`, start the new owner with `--listen`, and on
every replica `pvfs instance add <alias>-src <new-owner>:<port> <pin>` +
`pvfs replica repoint <mount> --instance <alias>-src` + restart.

## 5. Verify

- `pvfs forest tip` on every box: the same seq and hash, the new owner saying
  owner.
- The log carries the pair at the seqs promotion printed (`"revoked"` lists
  the old device).
- A region head is attested after the move (`pvfs region ls` on the new
  owner shows a head moving); `pvfs fleet health --now` shows every box; the
  page's feed is fresh and its owner row is the new box.

## 6. The old box

Its device is revoked in the canonical chain, and since D182 it fences itself
the moment it can see any box that followed the promotion — so a forgotten
unit that starts writes nothing. Still: its unit stays disabled (step 2 does
it when the box answers); the box stays cold until the new owner has been
through a full ingest cycle; then destroy it, or make it a replica of the new
owner in a FRESH directory (`pvfs replica add` — its old `.pvfs` is not
reused), or the next standby (`fleet.yml --tags standby` with a new host row).
Delete the old `.pvfs` only after that.

## 7. Dated copies of the log, and restoring one

Followers protect against losing a box; they faithfully copy whatever the
owner writes, a bad build's events included. A dated copy is the way back to a
known-good log. `pvfs forest backup [<mount>] --to <dir> --keep <days>` takes a
consistent copy beside a running daemon (`VACUUM INTO`), counts it only once a
full replay of it verifies (chain, signatures, authorization from seq 1),
names it `<forest>-<YYYYMMDD-HHMM>-seq<N>` with a `manifest.json`, prunes this
forest's older copies, and records its result in `backup-state.json`, which
`serve status` reports. Production: `pvfs-log-backup.timer` daily at 3:30 AM
Eastern on the standby (mediabox) and on feederbox (off-site), 30 days kept,
in `/srv/pvfs/log-backups`; about 3 MB a copy.

`pvfs forest restore <copy> <mount>` makes a replica directory from a copy,
verified the same way, following what the copied box followed. Two uses:

- **A damaged follower** is simpler to re-seed from a live owner (`replica add`
  into a fresh directory); a copy is for when that is not possible.
- **Every live log damaged** (a build that broke `log.db` on every box it
  reached): restore the newest good copy on the box that should own, and
  `pvfs forest promote` it. That rolls the forest back to the copy's seq:
  every follower now holds a longer, different chain and must be re-seeded
  (`replica add` into a fresh directory); each region republishes its head at
  its next pass, since the catalogues live on the boxes, not in the log.

## 8. Rollback

- Before the signing (step 3): start the old owner again (and enable its unit
  and collector); nothing has changed.
- After: there is no undo, only another move. The old box becomes a replica
  (or the standby) of the new owner (§6) and can be promoted back by the same
  run. Every move leaves one certificate pair in the log; the chain never
  breaks. Moving back revokes the device that is live at the time (D182: the
  first edition's default, "device 0", would have revoked nobody).

## 9. What built this

D128: `Engine::promote`, `pvfs forest promote`, `pvfs replica repoint`, the
fleet play's re-point in both replica roles, `deploy/d128-promote-pair.sh`.
PVOS D182: `Engine::promote_with_root_signer` (one append, phrase or
companion), `pvfs forest promote --via-companion` and its defaults, the fence
(`pvfs_core::fence`, the tip on `PrepareWrite`, `log`/`fenced` in `serve
status`, the health job's verdicts, the listener held for the first health
pass), `pvfs forest tip|fence|backup|restore`, the follower's *behind* error,
`owner_fenced`/`peer_diverged` and their clears, the standby role, `promote.sh`
+ `promote.yml`, the page (PVOS `deploy/homeassistant/pvfs-fleet.yaml`
`pvfs_owner_quiet`), `deploy/d182-owner-pair.sh`.
