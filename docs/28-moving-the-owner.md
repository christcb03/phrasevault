# 28 — Moving the owner (D128 runbook)

**Status: written 2026-09-10 with D128; rehearsed on the lab pair
(`deploy/d128-promote-pair.sh`), not yet on the live fleet.** The sibling of
doc 25: that one rebuilds a forest, this one keeps it and changes which box
may append to it.

## 1. What an owner is, and why it can move

The owner is the forest's one writer: every box dials it to publish, it
appends to the log, everyone else follows (doc 03 §1, doc 69 §9 in PVOS).
It holds no bytes. Its authority is not the box — it is a device certificate
on the log, signed by the root key the recovery phrase derives. So a replica,
which already holds the whole verified log, becomes the owner when the phrase
signs a `DeviceAuthorized` for it and a `DeviceRevoked` for the old box. The
forest id, every node id, every grant, every region head: unchanged. Nothing
is copied anywhere.

Never automatic (doc 20 §6, doc 03 §6 Q3): no job, no watchdog, no quorum
promotes. D83 may one day *say* the owner is down; a person promotes.

## 2. Before you start

- The recovery phrase, from custody. It is on no box.
- The new box is already a replica of the forest and follows it: enrolled on
  the owner with `rwa` (replication needs admin), `pvfs replica add`, pvfsd
  with `follow`. The ingest role of the fleet play does exactly this.
- The new box is reachable by the fleet on the owner port (7421 in
  production): feederbox dials the owner from outside, so the forward or VPN
  that points at the old VM must point at the new box before step 5.
- `deploy-respects-active-work` (memory): check the old owner is not mid-import
  before stopping it — an ingest session in flight is the thing to protect.

## 3. The move

Each step refuses rather than guesses; if one refuses, read why, do not force.

1. **Quiet the writers.** Every write goes through the owner, so stop the
   jobs that publish: on feederbox `pvfs serve disable watch` (or stop
   `pvfsd-replica`), on the QNAP stop `tier` (or the daemon — the watchdog
   bracket applies, see the fleet README). Reads keep working everywhere.
2. **Bring the new box to the tip.** On it: `pvfs replica sync <mount>`.
3. **Stop the old owner.** `sudo systemctl stop pvfsd-media` on the old VM,
   then `sudo systemctl disable pvfsd-media` — it must never start there
   again (§5).
4. **Check the tips match.** On both boxes:
   ```bash
   python3 -c "import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute('select max(seq) from events').fetchone()[0])" <mount>/.pvfs/log.db
   ```
   Different numbers mean a write landed between 2 and 3: start the old
   owner again, repeat from 2.
5. **Promote.** On the new box, with its pvfsd stopped (promotion refuses a
   dir a daemon holds open):
   ```bash
   pvfs forest promote <mount>
   ```
   It lists the forest's devices, refuses while the old owner's address
   still answers (`--force` only if that address now belongs to something
   else), asks for the phrase, takes device index 1 by default (pass
   `--device-index` for a free one if 1 is taken — it refuses a taken
   index), and revokes device 0, the key `forest init` made on the old VM
   (`--revoke <hex>` to name another; `--keep-old-device` only when that
   key is destroyed with its box). The replica marker is kept as
   `.pvfs/promoted-from`. Then `pvfs forest register <mount> --alias media`.
6. **Start the new owner.** Move the box into `[fleet_owner]` in
   `fleet-prod.ini`, set `owner_addr` to it, and run the owner role of the
   fleet play (`--tags owner`): unit with `--listen`, serve jobs, `fleet
   announce`. Its transport pin is new — the play reads it from the box.
7. **Re-point the fleet.** Run the ingest and NAS roles (`--tags ingest`,
   `--tags nas`). Since D128 both compare the registered `media-src` row
   with the inventory's address and the owner's pin, replace it when they
   differ, run `pvfs replica repoint` on the replica, and restart the daemon
   (the follow job reads the marker once, at start). By hand, per box:
   ```bash
   pvfs instance add media-src <new-owner>:7421 <new pin>
   pvfs replica repoint <mount> --instance media-src
   ```
   then restart pvfsd. `repoint` refuses a source that serves another forest.
8. **Re-enable the writers** from step 1.

## 4. Verify

- On every replica `pvfs replica sync <mount>` succeeds and the tips agree
  (step 4's one-liner).
- The log carries the pair, at the seqs promotion printed: `select kind from
  events where seq > <tip before>` shows `DeviceAuthorized`, `DeviceRevoked`.
- feederbox's watch job publishes a head the new owner attests (`pvfs region
  ls` on the owner shows the catalogue region's head moving); the QNAP's tier
  pulls (`pvfs serve status`).
- `<mount>/.fleet/endpoints/<new pin>` exists on a replica once the new owner's `fleet announce` has been folded; `pvfs fleet versions` shows every box.

## 5. The old VM

Its device is revoked in the canonical chain, so anything it appends is a dead
branch every replica refuses — but it would still *write* it locally and
report success. So: the unit stays disabled; the VM stays cold until the new
owner has been through a full ingest cycle; then either destroy it or make it
a replica of the new owner (`pvfs replica add` into a fresh dir — its old
`.pvfs` is not reused). Delete the old `.pvfs` only after that.

## 6. Rollback

- Before step 5: start the old owner again; nothing has changed.
- After step 5: there is no undo, only another move. The old box becomes a
  replica of the new owner (§5) and can be promoted back by the same
  procedure. Every move leaves one certificate pair in the log; the chain
  never breaks.

## 7. What D128 built for this

`Engine::promote` (`recover` + marker kept + revoke, refusing a non-replica or
an open one), `pvfs forest promote`, `pvfs replica repoint`, the fleet play's
re-point in both replica roles, and the lab pair script above, which walks
this whole runbook on presubuntu + pvos-test: refusal while the old owner
answers, promotion, a write on the new owner, the old box rejoining as a
replica and seeing it, one chain.
