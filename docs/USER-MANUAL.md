# PVFS User Manual

PhraseVault File System — a content-addressed, cryptographically-signed file system you own.
This manual covers everyday use of the `pvfs` command-line tool and sharing forests between users.

> Status: covers **PVFS 1.4** (forests, ACLs/tags, full daemon read/write/admin, secure blobs,
> companion, key replacement, federation + replicas, serve jobs, regions, the streaming mount,
> attachment kinds, and the swarm data plane) **and what main has added since, unreleased**, up to
> the build the media fleet runs (`v1.4-495`, rolled 2026-09-27): ingest sessions (§7.12) and the
> **region model** — each box catalogues its own disk, the merged view and its mount, the mover,
> the trash, copies of the log and moving the owner (§7.13). Future work is under
> [Roadmap](#11-roadmap).

---

## 1. What is PVFS?

PVFS organizes your files as a **forest** — a tree of *nodes* (folders and files) backed by an
append-only, signed event log. Unlike a normal directory:

- Every change is **signed** with your key and recorded in a tamper-evident log.
- Files are **content-addressed** (identified by a BLAKE3 hash), so identical content is recognized
  anywhere.
- A forest can be **registered** on a host so apps and other users can find it, **shared** with
  fine-grained per-folder permissions, and accessed over a network via federation (§7.4/§7.7).

Your real files stay where they are on disk; PVFS *indexes and binds* them into the forest.

---

## 2. Concepts & terms

| Term | Meaning |
|------|---------|
| **Forest** | One signed tree of nodes; the unit you create, own, and share. |
| **Mount** | The directory a forest lives in (e.g. `~/media`). Holds your files plus `.pvfs/`. |
| **`.pvfs/`** | Hidden engine state (the log, the index, your device key). Owned by you, mode `0700`. |
| **Node** | A folder or file in the tree, identified by a 64-hex id. |
| **Device key** | The per-machine key that signs your changes. Derived from your recovery phrase. |
| **Recovery phrase** | 24 words shown once at `forest init`. Write it down — it regenerates your keys. |
| **Member** | Another user authorized to access your forest, identified by their public key. |
| **Daemon (`pvfsd`)** | A process you run that lets other users reach your forest over a socket. |

---

## 3. Installation

See [INSTALL.md](INSTALL.md). In short, you get two binaries: `pvfs` (the CLI) and `pvfsd` (the
daemon). The examples below assume both are on your `PATH`.

---

## 4. Quick start

```bash
# create a forest in ~/media (run as your normal user, never with sudo)
cd ~/media
pvfs forest init
#   → prints the forest id, root node id, and your RECOVERY PHRASE (write it down!)
#   → offers to import the existing files in ~/media into the forest

# see what's in the tree
pvfs ls ~/media            # children of the forest root
pvfs walk ~/media          # the whole tree

# register it host-wide so it shows in `pvfs ls` and can be served (one-time, needs sudo)
sudo pvfs forest register ~/media --alias media
pvfs ls                    # lists registered forests
```

`forest init` never needs root; it refuses to run as raw root so your data is never owned by
`root`. Only **registration** (writing the host registry under `/etc/pvfs`) uses `sudo`.

---

## 5. Ownership & permissions

PVFS follows ordinary filesystem ownership:

- **You own the forest you create.** `.pvfs/` and its contents are yours (`device.key` is `0600`,
  the rest of `.pvfs/` is `0700` — private to you).
- **Unshared = private.** Until you explicitly share, only you can read a forest. Other users go
  through your daemon (§7), which denies by default.
- **Run your own daemon.** The forest's owner runs `pvfsd` for it (and the apps that use it). There
  is one daemon per owning user — no shared privileged service.

If a forest's `.pvfs/` ever ends up owned by the wrong account (e.g. a mistaken `sudo`), repair it:

```bash
sudo pvfs forest fix-permissions ~/media     # reassigns .pvfs/ back to you
```

Importing respects read permission: `forest init` / `pvfs scan` **skip files you can't read** and
report them, so your forest never references content you can't actually open.

---

## 6. Working with the tree

```bash
ROOT=$(pvfs --json info | python3 -c 'import json,sys;print(json.load(sys.stdin)["root_node_id"])')

pvfs add "$ROOT" --kind folder --label photos          # add a folder
pvfs add "$PHOTOS" --kind file --label pic.jpg --size 12345
pvfs node <node-id>                                    # show one node
pvfs loc add <file-id> file:///data/pic.jpg            # record where bytes live
pvfs bind <folder-id> /data/photos                     # bind a real directory…
pvfs scan <folder-id>                                  # …and index it
pvfs verify <node-id>                                  # recompute id + check signature
```

Most commands take a **node id** (64-hex), a `pvfs://` URI, or an absolute path under a mount.

### 6.1 Present a tree to non-PVFS apps (`pvfs export`)

Any app that reads ordinary directories (a media server, a backup tool, `rsync`) can consume a
PVFS tree via a **materialized export** — files from every bound location appear as one hierarchy:

```bash
pvfs export ~/media/library /srv/plex-library          # symlinks (default)
pvfs export ~/media/library /srv/copyset --mode copy   # hash-verified real copies
pvfs export ~/media/library /srv/plex-library --prune  # drop entries that left the tree
```

Point Plex (or anything else) at the export directory. Re-running refreshes it in place: unchanged
entries are left alone, removed nodes are pruned (`--prune`) or reported as stale. The export
directory is marked with a `.pvfs-export` manifest and is owned by the export — `pvfs` refuses to
export into a non-empty directory it didn't create. Files with no local bytes yet, secure blobs,
and folder refs are skipped with a per-entry reason. `--mode hardlink` serves apps that refuse
symlinks (same filesystem only); `--mode copy` streams through the verified read path, so a
corrupted location can never land bytes in the export (it gets quarantined instead, like any read).

### 6.1b Three ways to enroll a space (`pvfs bind --kind`, doc 21)

When you bind a directory, its **kind** decides what happens to the bytes:

```bash
pvfs bind <folder> /mnt/library                                  # in-place (default): bytes stay put
pvfs bind <folder> /mnt/ingest  --kind migrate --to /tank/store  # staging: the disk drains itself
pvfs bind <folder> /mnt/photos  --kind mirror  --to /tank/backup # backup: a verified second copy
```

- **in-place** — today's bind, unchanged.
- **migrate** — the space is staging. The mover (`pvfs tier`, or the daemon's
  `tier` job) lands a verified copy in the store, retires the staged location,
  and `evict` reclaims the bytes — an ingest disk that stays empty, enrolled
  with one command.
- **mirror** — the mover keeps a verified second copy in the store and **never
  retires anything**: the source keeps serving, the copy is a live backup (if
  the source dies, reads fall through to the mirror), and every mirror copy is
  a swarm seed today (doc 22). Omit `--to` and the command asks.

The kind is placement state under the hood (`pvfs place … central|central-keep`
work too); the store may not live inside the bound space.

**A binding belongs to the machine that made it.** The catalog is shared, but
`/mnt/library` is a path on one box and nowhere else — so `pvfs scan` (with no
folder) and the `watch` job only ever touch the bindings **this** machine bound.
`pvfs bindings` still lists the whole forest and marks the rest
`[bound on another machine: …]`; naming a foreign one explicitly
(`pvfs scan <folder>`) says so rather than pretending. Bind a directory on the
box that actually has it.

One thing this deliberately does *not* do: skip a binding merely because its
directory is missing. If a directory **this** machine bound has vanished — an
unmounted NAS — the scan still fails loudly, because silently treating it as
empty would soft-remove every location under it.

### 6.2 The live mount (`pvfs mount`, Linux)

Where an export materializes a snapshot, `pvfs mount <node> <dir>` presents the tree as a **live
read-only filesystem** (FUSE): browse with `ls`, open files with anything. Bytes resolve at open —
local path, sync store, or a verified fetch from a serving holder — so a pointer-mode library
streams on demand. Files whose chunk layout the owner has attested (automatic for anything hashed
since P9.1) **stream while they fetch**: playback starts as soon as the first chunks verify, with
the fetch continuing behind the reads. Unattested files fetch fully first — the safe default.
`pvfs umount <dir>` (or Ctrl-C on the foreground mount) releases it. Needs the distro's `fuse3`
package.

### 6.3 Regions (`pvfs region`)

A **region** makes a subtree its own replication and audit unit:

```bash
pvfs region mark <node>      # the subtree becomes a region
pvfs region ls [node]        # list boundaries / show which region a node is in
pvfs region unmark <node>    # fold it back into the enclosing region
```

Since P7.2a, a mark is physical: the region gets **its own signed log** under the data dir
(`regions/<id>/g-*.db`), created by one commit that also records a verifiable **baseline** of the
subtree's state at that instant. From then on everything inside the region authors in its log; the
enclosing log periodically attests the region's head, so one root hash still covers the whole
forest, and every rebuild re-verifies each baseline against the replayed history. `unmark` seals
the region's log in place (kept for verification) and returns the subtree to the enclosing log;
re-marking later starts a fresh generation.

What you'll notice day to day: nothing — reads, writes, and **moves across region boundaries**
all behave identically. A cross-boundary `mv` (or re-homing an orphan into another region)
authors one half in each region's log — a paired, causally cross-referenced protocol
(doc 20 §2.5) — and the node's region membership (with its whole subtree's) follows the move.
The one deliberate refusal left: **purging a subtree that still contains a region boundary**
(`unmark` first — a purge cascade is one region's business).

Everything above is a **log region**: it holds nodes and has its own signed log. A region can
instead be a **catalogue region** (`pvfs region mark <node> --catalogue --owner key:<box>`): it
holds no nodes at all, and the box that owns it catalogues a directory on its own disk — the
region model the media fleet runs, §7.13.

---

## 7. Sharing a forest with other users

Sharing is **mediated by your daemon** and controlled by **per-node ACLs**. Nothing is shared by
file permissions; collaborators never get your keys.

### 7.1 The three access tiers

| Principal | Who it grants |
|-----------|---------------|
| `public` | anyone, even unauthenticated — use for "share to everyone" |
| `any` | any authorized member of the forest |
| `tag:<name>` | any member holding that **tag** (e.g. `tag:media_users`) — see §7.6 |
| `key:<hex>` | one specific member |

Rights are `r` (read), `w` (write — create/modify children), `a` (admin: manage ACLs on a subtree).
Grants **inherit down** the tree. You (the owner) always have full rights.

### 7.2 Grant read access — step by step

**On the member's machine**, they find their identity:
```bash
pvfs whoami            # prints: client identity : key:028f...
```

**On your machine** (the owner), authorize that key and grant rights:
```bash
# 1. authorize the member's key — signed by your admin device, no recovery phrase
pvfs device authorize-member --pubkey 028f...

# 2. grant them read on a subtree (by node id)
pvfs acl set <photos-node-id> key:028f... r

# 3. see / check grants
pvfs acl ls    <photos-node-id>
pvfs acl check <photos-node-id> key:028f...
```

To share something with everyone on the host, grant `public` instead:
```bash
pvfs acl set <node-id> public r
```

### 7.3 Serve the forest

Run the daemon as yourself — it binds a conventional socket automatically
(`$PVFS_SOCKET_DIR/<forest_id>.sock`, default `/tmp/pvfs/…`):
```bash
pvfsd --mount ~/media          # (--socket <path> to override)
```

### 7.4 The member reads it

Point at the forest with `--forest` (an alias or mount path) — no socket path needed:
```bash
# authenticated as their identity (signs a challenge):
# node args everywhere accept ids, pvfs:// URIs, and absolute paths
pvfs remote --forest media ls   <photos-node-id>
pvfs remote --forest media stat <node-id>
pvfs remote --forest media info

# or anonymously (only sees `public` grants):
pvfs remote --forest media --anon ls <node-id>
```
(`--socket <path>` still works for an explicit socket.)

The daemon checks the caller's rights on every request and returns only what they may read.

**Across the network** (another machine): start the daemon with a listen address and it serves the
same protocol over TLS — no CA, no certificates to buy. The daemon prints a **transport pin** (also
in `<mount>/.pvfs/nettls/pin`); a client that pins it gets a private, verified channel, and still
authenticates as itself per connection:

```bash
# server
pvfsd --mount ~/media --listen 0.0.0.0:7420
#   pvfsd: listening on 0.0.0.0:7420 (transport pin 4f2a…)

# client — remember the server once (the pin IS the trust decision)…
pvfs instance add homeserver 192.168.1.10:7420 4f2a…
# …then use it like any forest
pvfs remote --instance homeserver ls <node-id>
pvfs remote --instance homeserver cat <file-id> > local-copy
# (or one-off: pvfs remote --connect 192.168.1.10:7420 --pin 4f2a… info)
```

A wrong or changed pin fails the connection before a byte of protocol is spoken. Rotating the
server's TLS material (delete `nettls/`) mints a new pin — clients re-pin explicitly.

### 7.5 Members writing (creating folders)

A member granted **`w`** on a subtree can create folders there over the daemon. Each change is
**signed by the member's own key** — the daemon never signs on their behalf:

```bash
# owner: grant write — while pvfsd runs, this auto-routes through it and takes effect live
pvfs acl set <node-id> key:028f... rw

# member: create a folder under that node
pvfs remote --socket … mkdir <node-id> my-folder
#   → created <new-node-id>
```

> **Note:** Admin changes take effect **immediately**. While `pvfsd` is running, `pvfs acl set` /
> `tag add` / `device authorize-member` auto-route through it, so the next request sees the new
> grant — no restart needed. (When no daemon is running, they apply directly to the forest.)

### 7.6 Tags (sharing with a group)

Instead of granting every friend individually, share content with a **tag** and give people the
tag. Two independent dials:

- **Share a node with a tag:** `pvfs acl set <node> tag:media_users r`
- **Give a member the tag:** `pvfs tag add <member-pubkey> media_users`

Now everyone holding `media_users` can read anything tagged `media_users` (with inheritance down
the tree). A new friend? `pvfs tag add <their-key> media_users` — done. Un-share? Remove the node's
tag grant, or drop the member's tag with `pvfs tag rm <key> media_users`. Inspect with
`pvfs tag ls <key>`.

**Tags belong to the key that sets them.** A tag is identified by *(who granted it, the name)*, not
the name alone — so two apps can both use `friends` in the same forest without colliding, and a tag
only opens a node when the **same key** granted both the node's tag and the member's tag. Any
authorized member may manage tags under its own authority (you don't have to be a forest admin), and
that authority can only widen access to nodes it already controls. If a member's key is revoked,
every tag it granted stops working immediately. `acl ls` / `tag ls` show ` (by <key>)` so you can
see which key a tag belongs to, and mark a now-dead grant `[inert: authority revoked]` (its rights
read `-` — what's actually in effect). To sweep a whole forest for such dead grants, run
`pvfs audit`.

### 7.7 Replicating a forest to another machine

A **replica** is a full, verified, read-only copy of a forest — its signed log shipped and
re-verified locally, its catalog rebuilt from it. Use it to carry your library to a second machine
(the media-server case), or to hold a proven backup of the metadata:

```bash
# on the source machine — serve with a network listener (§7.4)
pvfsd --mount ~/media --listen 0.0.0.0:7420      # prints the transport pin

# on the replica machine — pin the server, then replicate
pvfs instance add homeserver 192.168.1.10:7420 <pin>
pvfs replica add ~/media-replica --instance homeserver
#   replica of <forest-id> (214 events, verified)

pvfs replica sync ~/media-replica                # pull what's new, any time
pvfs replica follow ~/media-replica              # …or follow live: new events in seconds
pvfs export <node> /srv/plex-library --mode symlink   # replicas export like any forest
```

Three things to know:

- **Replication is an owner/admin capability.** The connection's identity needs **admin (`a`)
  rights on the forest root** — your own devices qualify automatically; grant `a` at the root to
  delegate it. A full log holds the whole forest's history, so it is deliberately not a member read.
- **A replica is proven, not trusted.** Ingest checks the hash chain row by row, and opening the
  replica replays the entire log through the same verification the owner's engine uses — chain,
  every signature, every authorization. A tampered ship fails loudly, at the exact event.
- **Replicas are read-only.** The owner's instance stays the forest's only writer; local writes and
  writes via a replica's daemon are refused. ACLs answer identically on a replica (the grants are
  in the log), and file bytes read through wherever the recorded locations resolve.
- **Fetches swarm (P9.0, doc 22).** When two or more registered holders have a
  file, `pvfs sync` / self-healing `cat` / the daemon's `sync` job pull it as
  parallel verified chunks from ALL of them at once, and a killed transfer
  resumes where it left off. Nothing to configure: holders come from the
  instance registry and the file's logged locations (mirror copies included),
  and verification is unchanged — the catalog hash still gates every publish.
- **Regions ship too.** A replica mirrors the source's per-region logs (§6.3): `add`, `sync`, and
  `follow` all discover and pull every region generation, each chain-verified against the baseline
  the enclosing log committed. `pvfs replica add <dir> --region <node>` scopes the replica to one
  region — the small top log plus that region's generations; other regions' contents simply stay
  unfetched (still attested by their heads). The scope note that matters: `--region` saves **bytes**,
  not rights — the top log still requires forest-root admin; region logs alone gate on admin of the
  region's root.

### 7.8 Pointer or sync — pulling bytes local

By default a replica holds the **catalog**; file bytes stay wherever their recorded locations
point (a *pointer*). For content you actually stream — a media library — tell the replica to keep
its own verified copies:

```bash
pvfs place <library-node> sync        # policy: keep this subtree's bytes local
pvfs sync                             # fetch everything missing, verified
pvfs sync <node>                      # …or one subtree right now, policy or not
pvfs export <library-node> /srv/plex-library --fetch   # fetch + materialize in one go
```

`pvfs sync` finds every file under the placed subtrees with no readable local bytes and fetches
it, **hashing while it arrives** — a corrupted or truncated transfer is discarded and reported per
file; wrong bytes never land. Each file is fetched from the best reachable holder: an instance the
registry knows to hold it (a `pvfs-host://` location, §7.9), else the replica's source. Fetched
files live in a managed store inside the forest's `.pvfs/` (put the replica's mount on the disk
you want filled), show up in `stat` as a `pvfs-sync://` location, and serve through `cat`, the
daemon, and `pvfs export` like any other bytes. **`pvfs cat` self-heals too**: reading a file with
no local bytes fetches it on demand and then serves it — a catalog entry is enough. Placement is
per-machine deployment state — two replicas of the same forest can pin different subtrees. Re-run
`pvfs sync` any time (idempotent); `pvfs place <node> pointer` returns a subtree to catalog-only.

**Become a holder the fleet can dial (F5.5).** Plain `sync` keeps your copies
private. Add `--advertise` and every verified fetch is also **logged as this
box's location** — any box that registered you (`pvfs instance add`) then
fetches those bytes straight from you, even with the source down:

```bash
pvfs place <library-node> sync --advertise   # needs a transport pin (pvfsd --listen once)
pvfs sync                                    # fetch + advertise (idempotent, catches up old fetches)
```

Leaving is honest too: place the subtree back to `pointer` and the next
`pvfs evict` **retracts each advertisement before deleting its bytes** — and
never deletes a copy that is the file's only live location.

The full media flow, end to end:

```bash
# media box:
pvfs instance add homeserver <addr> <pin>
pvfs replica add ~/media --instance homeserver
pvfs place <library-node> sync
pvfs sync
pvfs export <library-node> /srv/plex-library
# cron / after new episodes land on the server:
pvfs replica sync ~/media && pvfs sync && pvfs export <library-node> /srv/plex-library --prune
```

### 7.9 Writing from a replica (write-through)

A replica isn't a dead end for changes — it just isn't the writer. `pvfs add`, `pvfs loc add`, and
the admin commands (`acl`/`tag`/`device`, secure ops) on a replica mount **write through to the
source**: the operation travels member-signed to the owner's daemon (exactly like `pvfs remote`),
lands in the owner's log, and is pulled straight back so your own `pvfs ls` sees it immediately.
Your client identity needs the relevant rights on the owner's forest (`w` to create, admin for
grants), and the source must be reachable — there is no offline write queue, by design: the owner
stays the forest's only writer, so there is never anything to merge.

This is what makes an **ingest box** work: a machine that downloads new media can hold a replica,
catalog each finished file into the owner's forest the moment it lands (`pvfs add` +
`pvfs loc add --here <path>`), and every other replica picks it up on its next sync. `--here`
records an **instance-qualified location** — `pvfs-host://<the-box's-pin>/<path>` — so the catalog
knows *which machine* holds the bytes (the box needs a transport pin: run `pvfsd --listen` once).
Any machine that registered the box (`pvfs instance add`) fetches from it on demand.

**Admitting a box — one step.** An ACL grant alone does not confer authorship: the owner must
also authorize the box's client identity as a *member*, or its writes are refused at ingest
(`author not authorized` — default-deny working as designed). `pvfs fleet enroll` does both in
one visible, logged, revocable step: it prompts for the box's key (`pvfs whoami` on that box)
and grants `r` (consumer), `rw` (ingest), or `rwa` (replicator) at the root. This is **the
settled identity model** (doc 18 §4): every outbound connection — the mover's pulls and
read-through included — authenticates as that box's client identity, never the forest device
key (which never dials). The creating box enrolls itself: since just after 1.4 (on main)
`pvfs forest init` self-enrolls its own client identity with read, so a private
forest's own mover works from birth — other boxes still enroll via `fleet enroll`.
Revoke any time:
`pvfs acl set <root> key:<pubkey> ""`.

### 7.10 Tiered storage: migrate to a central store, reclaim the edge

The ingest box shouldn't hold the bytes forever. On the **owner**, declare the central store and
run the mover; on the **edge**, reclaim space once the catalog says it's safe:

```bash
# owner (e.g. the NAS):
pvfs place <library-node> central --to /volume1/media-store
pvfs tier          # migrate: verified copies land in the store, get logged,
                   # and only then are the edge's locations retired

# ingest box:
pvfs replica sync ~/media    # learn the retirements
pvfs evict                   # delete local bytes — only ever when the catalog
                             # records another live location; reports bytes freed
```

`pvfs tier` treats files already on the owner's own disks as satisfied in place; everything else
is fetched (locally or by read-through), streamed through the verified read path into a
node-id-addressed store, and recorded in the log as a real location. Retirement strictly follows a
live central copy — a failed migration never retires anything — so consumers keep streaming
throughout: before migration they read through to the ingest box, after it to the central copy.
The store is mover-managed (don't bind or scan it); browse the library through `pvfs export`.

**The mover attests (F5.6).** A file cataloged without a hash (an ingest box's
`pvfs add` + `loc add --here`) is verifiable by nobody — so when `tier`
migrates it, it fills the hash and attests the chunk manifest from the bytes
it just fetched, and the central copy lands under the new, attested id. From
then on every box can stream, heal, and verify it. Files already satisfied in
place are deliberately left alone — hash a library in bulk only when you ask:
`pvfs loc hash <file>` (owner-side).

**Let the store's machine serve it (F5.5).** When the store directory lives on
another box (the NAS, NFS-mounted here), tell the mover so it logs each store
copy as THAT machine's location — consumers then fetch store bytes straight
from the NAS instead of hairpinning through you:

```bash
pvfs place <library-node> central --to /mnt/nas/media-store \
     --served-by nas:/share/media-store   # the same directory as the NAS sees it
```

The instance must already be registered (`pvfs instance add nas …`); the two
paths naming the same directory is your assertion — the command says it back
so it is a decision, not an accident.

The complete media pipeline, all four machines:

```text
ingest box:  radarr/sonarr → pvfs add + loc add --here   (cataloged in seconds)
everyone:    replica sync / read-through                  (available immediately)
owner NAS:   pvfs tier                                    (bytes migrate home)
ingest box:  pvfs replica sync && pvfs evict              (3 TB stays free)
```

### 7.11 The fleet runs itself — daemon jobs (doc 18)

Every recurring loop above can run inside `pvfsd` instead of cron. Jobs are per-box
deployment state (`serve.jobs`, edited by `pvfs serve enable|disable`, reloaded on
SIGHUP or restart); `pvfs serve status` shows live state — running/idle/backoff, the
last success, the last error:

```bash
# any replica: fold owner events within seconds (the F5.4 follower, in-daemon)
pvfs serve enable follow

# consumers: fetch bytes for sync-placed subtrees when content changes
pvfs serve enable sync

# consumers: record an export once, then let the daemon keep the view fresh
pvfs export <library-node> /srv/plex-library --mode symlink --prune --keep-fresh
pvfs serve enable export        # pvfs serve exports lists what's kept fresh

# the owner: run the mover on an interval
pvfs serve enable tier

# the ingest box: reclaim retired bytes as the folds arrive
pvfs serve enable evict
```

A follow fold nudges sync, export, and evict immediately (a fetching sync re-nudges
export), with a 5-minute safety interval and a catch-up pass at daemon start behind
it — so the §7.10 pipeline converges in seconds end to end with zero cron entries.
Jobs dial with the box's client identity: enroll it first (§7.9).

#### Watching the fleet (D131, D135, D142, D146)

`pvfs serve status [--json]` answers for one box. Each job row carries its
state, `last_ok` (the last success) and `last_error` — cleared by the next
success, so a present error means the last run failed. The states: `running`,
`idle`, `backoff` (a transient failure; the job retries by itself), `error`
(the thread exited; the supervisor restarts it), `disabled`, `stalled` (a
pass in flight far past its own typical length — evidence), `overdue` (no
pass finished lately — for the pass-based jobs usually just a long pass).
`follow` is continuous: its `last_ok` is refreshed every few seconds while it
is current with its source, so an `overdue` follow really has not been able
to confirm for 15 minutes (D146).

On the owner, the `health` job (`pvfs serve enable health`) polls every
announced peer every two minutes:

```bash
pvfs fleet health            # every peer: up, or down since when; job errors; free space
pvfs fleet health --now      # poll first
pvfs fleet supervise <pin> --ssh user@<holder> --key ~/.ssh/pvfs-supervise   # restart a silent holder
pvfs fleet notify http://<ha>:8123/api/webhook/pvfs-fleet --format ha --label '<holder-ip>=the NAS'
pvfs fleet notify --test     # one test event
pvfs fleet notify --off
```

Formats: `ha`, `slack`, `discord`, `ntfy`, `json`. Events are transitions
only — a peer down or back, a restart sent, a job error that has persisted
about four minutes, a fenced owner (§7.13), a hung follower, and a line when
a problem clears — plus a daily heartbeat, each carrying one plain sentence. Doc 30 is the whole story, with a Home Assistant build as the worked
example.

---

### 7.12 External-ingest sessions — downloads land as they arrive (doc 23)

A downloader app (the PVOS BitTorrent app is the first) hands its bytes to
PVFS **while they download**: the files appear in the tree immediately as
size-only pointers, bytes stream into a crash-safe partial in any order, and
the commit runs the same hash-fill + attestation gates as every other file.
Every session is book-ended in the signed log by a `pvos.download` record
(kind, infohash, subtree root) and a `pvos.download.closed` record
(`complete` or `aborted`) — the fleet can always tell in-flight from
finished from abandoned.

```bash
# catalog a "torrent" now — one signed commit, no bytes yet
pvfs ingest begin MEDIA --name pack --infohash <hex> \
  --file "Season 1/e01.mkv:1073741824" --file "extras.txt:4000"

# bytes land sparse, out of order, resumable (kill -9 safe)
pvfs ingest write <session> <node> --offset 8388608 --from part2.bin

# the app reports which byte ranges its piece hashes verified;
# fully covered 8 MiB chunks are marked (the P10.1 streaming license)
pvfs ingest verified <session> <node> --range 0-16777216

pvfs ingest            # bare = list sessions with per-file progress
pvfs ingest commit <session> <node>   # hash-fill + attest + publish
pvfs ingest abort <session> [--keep-catalog]
```

The daemon refuses an `ingest begin` whose declared sizes exceed the store's
free space (pass `--allow-shortfall` to accept the risk), and a full disk
mid-download pauses the session cleanly instead of poisoning it. The app
identity needs write on the target folder, and admin on it for the
attestation that commits carry. Note: committing re-identifies the node (the
pointer gains its content hash) — `ingest commit` prints the successor id.

**In-flight files stream (P10.1).** While a session is live, verified
chunks already serve: `pvfs remote cat <node> --offset --len` returns
marked bytes immediately and *waits* for unmarked ones (the daemon holds
the request until the app verifies them), and a FUSE mount — local or on a
replica — proxies reads of in-flight files the same way, so a video starts
playing while its torrent downloads. Every waiting reader shows up in
`pvfs ingest list` as a **HOT** byte range: that is the downloader app's
cue to prioritize those pieces (sequential mode when someone hits play).
Early serving requires the session opener to hold admin on the target —
the same bar as the commit attestation.

### 7.13 The region model — each box catalogues its own disk (doc 26)

§7.7–§7.11 describe the **node model**: every file is a node in the forest's
log, and every box that writes routes its writes to the owner. It still works,
and a small private forest is simplest that way. A fleet of boxes that each
hold part of a large library runs the **region model** instead — the media
fleet has since its cutover on 2026-09-12 (doc 29):

| | node model (§7.7–§7.11) | region model |
|---|---|---|
| a file is | a node in the log, with locations | a row in the catalogue of the region that holds it: the region plus the path inside it |
| who writes it | the owner, for every box | the box whose disk it is on, locally, at disk speed |
| the forest log carries | every file event | which regions exist, who owns each, grants, drain flags, and one signed head per region |
| bytes move by | `tier` and `evict` | `receive` and `resolve` |
| programs read | `pvfs export`, `pvfs mount <node>` | the merged view: `pvfs view`, `pvfs mount --view` |

The content hash still verifies every byte and decides whether two copies are
the same file; it no longer decides what a file *is*.

#### Regions, heads and catalogues

A **catalogue region** is one folder of the forest, marked once, owned by one
box (an admin grant on its root), and bound on that box to a directory. That
box's `watch` job catalogues the directory — a row per file and per folder,
with its size, mtime and content hash (read from the sidecar beside the file
when there is one) — and after every pass that changed something it
publishes a hash of the whole catalogue as the region's next **head**, signed
by its key. Every other box's `catalogue` job notices the new head within a
minute, fetches the catalogue from whichever box announced it, checks it
against the head, and installs it. No box ever writes another box's
catalogue.

Setting one up (PVOS's fleet play does these steps; by hand):

```bash
# on the owner, with its daemon stopped — marks are not routed yet
pvfs add <root-id> --kind folder --label library
pvfs region mark <folder-id> --catalogue --owner key:<the holding box's pubkey>

# on the holding box — a replica that follows the owner — once the mark has arrived
pvfs bind <folder-id> /srv/media/library --hash-policy on_add
pvfs serve enable watch        # catalogue the directory as it changes
pvfs serve enable catalogue    # fetch the other regions' catalogues
```

Bare, `region mark` asks for `--catalogue` and `--owner`. A catalogue region
holds rows, never nodes: mark it on an empty folder; it cannot be unmarked or
marked again. A file without a hash is not shown to anyone (below); with the
default hash policy, `on_add` (which the play also passes explicitly), a file
with no sidecar is hashed when it is catalogued.

The watch starts a pass 2 s after the last change, at most 30 s after the
first however many keep coming, and in full every hour. It ignores changes to
what its walk passes over: PVFS's own names (`.pvfs-*` folders such as the
trash and partial downloads, sidecars) and litter such as `.DS_Store`. A
pass commits its rows in batches as it goes, so a restart costs at most a
batch; a file it cannot read is skipped and named, and its old row kept.

```bash
pvfs region ls        # on the library's box
#   7ea45c8e…  catalogue  drains  head 3120  held 3120  1204 rows
#   fe38175f…  catalogue  head 4410  live  27290 rows  receives
pvfs region entries <folder-id>   # the rows, and the last head this box published
pvfs region fetch                 # fetch now what this box is behind on (the job does it every minute)
```

`region ls` says, for each region: its head; `live` (this box catalogues it),
`held N` (a fetched copy at head N) or `not fetched`; how many rows; `STALE`
when the log attests a newer head than the one held (an offline box's region
is old, not stale: nothing newer exists); `drains` and `receives` (below).

**When the owner is down**, nothing daily stops: each box keeps cataloguing,
publishes its heads locally and hands them to its peers directly, signed
(`region ls`: `(N published here, pending the owner)` on its own box,
`(provisional; log M)` on the others), and when the owner is back each
region's newest head is committed in one row. What waits for the owner is
what only the log can say: grants, marks, drain flags, enrolments and
revocations.

#### The merged view

The **view** is one entry per path across every catalogue region this box
holds. Copies whose hashes agree are one entry with several copies behind it:
a read uses this box's own copy when it has one, and a box with none reads
through by hash from a box that has. Two regions holding **different** bytes
at one path is a **conflict**, never merged: the D76 ladder (quality, then a
guard against truncated files, then size, then recency) decides which copy
is served, both stay, and the conflict is counted in `serve status`. A file
with no hash yet is not in the view at all.

```bash
pvfs view ls                        # the top level: every region's root
pvfs view ls "TV/Andor (2022)/Season 01"
#   file  4987012345  2  admitted           TV/Andor (2022)/Season 01/…E01….mkv
#   file  5120334455  0  conflict:hashes:2  TV/Andor (2022)/Season 01/…E02….mkv
pvfs view conflicts                 # two hashes at one path, or a file against a folder
```

The columns are kind (`file`, `dir`), size, copies (hashed copies that
agree; 0 for a folder or a conflict), state (`admitted`, `unhashed`,
`conflict:hashes:N`, `conflict:kind`) and path.

#### The view as a filesystem (`pvfs mount --view`)

```bash
pvfs --forest media mount --view /mnt/pvfs/Media --allow-other --cache-mode stream
```

Any program can read the view as a directory tree: Plex, Sonarr and Radarr
do. A file's bytes come from this box's own disk when it holds a copy, else
they are read through by hash from a box that does, in pieces as the reader
asks, and verified: small files before their last piece is served, large
ones as a whole before they are kept.

- `--cache-mode keep` (the default): a file read through is completed in the
  background and kept, up to `--cache-max` (500G) and `--cache-age` (1d),
  least recently read first.
- `--cache-mode stream`: nothing kept — pieces more than 64 MiB behind the
  reader are dropped, and the file at its last close. For a media server on
  the same network.
- `--allow-other` lets other users read it (root, mergerfs, containers); it
  needs `user_allow_other` in `/etc/fuse.conf`.

What the view accepts, because a media manager importing an upgrade needs it:
**delete** a file (the box that holds each copy at that path moves it to its
region's trash — every copy, on every box), **rename** a file or a folder,
**`mkdir`** and **`rmdir`** (done by the box that holds the files, on its own
disk); `chmod`, `chown` and `touch` are accepted and ignored. What it refuses:
creating or writing a file. New bytes arrive on a region's own disk and are
catalogued there.

Restarting the daemon does not end a stream open through the mount;
restarting the mount does. So a mount may stay on an older build across an
upgrade and move when nothing is open. `pvfs versions` says, for each running
mount, whether this build would break it.

#### Moving bytes: staging drains into the library

A box that downloads (the **ingest** box) holds a **staging** region; a box
with the library disks holds a **library** region that receives. Two
declarations:

```bash
pvfs region drain <staging-region> on       # on the owner, daemon stopped: fleet-wide, a log event
pvfs region receive <library-region> on     # on the library's box: local to it
pvfs region receive <library-region> on --parallel 2 --streams 4   # files at once, ranges per file
```

And two jobs, each every five minutes:

- **`receive`**, on the library's box, pulls by content hash every file the
  view shows only on staging — and the staging copy of a conflict, which is
  the newer import — into its receiving region. A library copy it replaces
  goes to the library's trash.
  `pvfs serve receive-plan` asks the running daemon what is left to pull;
  `pvfs view receive --dry-run` works it out without one.
- **`resolve`**, on the staging box, moves a staging copy to the staging
  trash once a library region holds the same bytes and that region's box
  serves the file's last piece back matching. A staging folder goes once it
  is empty and the library holds it. `pvfs view resolve --dry-run` says what
  would go.

With those cadences a file that lands in staging reaches the library's disk
within about seven minutes, and leaves staging within about five more (doc 29
§4 F).

#### The trash

Nothing the fleet deletes by itself is gone at once. `resolve`, `receive`'s
replacements and deletes through the view move the file, with its sidecar,
into its region's `.pvfs-trash`, in a folder per day, on the disk of the box
that holds it. Every daemon purges its own regions' trash past their
retention every five minutes (7 days unless `pvfs region retention <region>
<days>` says otherwise). Run these on the box that holds the region:

```bash
pvfs trash ls                                   # every region on this box: day, days left, size, path
#   fe38175f0a1b  library  /share/Data/Media  — 3 file(s), 9.1 GB; kept 7 day(s)
#     2026-09-27 (20723)  purged in 4 d  4.2 GB  Movies/…/….mkv
pvfs trash ls "TV/Andor (2022)"                 # a file or a folder
pvfs trash restore "TV/Andor (2022)/Season 01"  # back where it was; never over a file that is there
pvfs trash restore "Movies/…" --from 20720      # an older day (the number ls shows)
```

`pvfs trash put <path> --region <id>` moves **one** region's copy to its
trash, from any box (it asks the box that holds the region), and only while
the copy is still the file with that hash — for when two regions hold
different bytes at one path and one of them is being kept. Bare at a
terminal, `restore` and `put` list what there is and ask. `--from <file>`
gives `put` a list (`region<TAB>path<TAB>hash` per line).

#### The owner: its log, copies of it, and moving it

The forest still has one owner: the box that appends to the log. It may hold
regions of its own like any other box.

```bash
pvfs forest tip                          # this box's copy of the log: seq and hash; owner, or replica of whom; fenced?
pvfs forest backup --to /opt/pvfs/log-backups --keep 30   # a dated copy, counted only once a full replay verifies it
pvfs forest restore <copy> <new-dir>     # a replica directory from a copy, verified the same way
```

**Moving the owner** (doc 28) is never automatic. Any box that holds the
whole log can become the owner — every box that follows does. Stop the old
owner if it still runs, check with `forest tip` that the new one has the
longest log, stop the new one's daemon, then on it:

```bash
pvfs forest promote /opt/pvfs/media --via-companion    # bare, it offers a running companion, else asks for the phrase
```

It admits a new device for this box and revokes the old owner's, in one
append signed by the forest's root: the companion asks you to approve both
signatures. It refuses while the recorded owner still answers (`--force`
overrides). Start this box's daemon with `--listen`, and point every other
box at it:

```bash
pvfs instance add media-src <new-owner>:<port> <pin>
pvfs replica repoint <its forest dir> --instance media-src
# then restart that box's daemon
```

PVOS's `promote.sh` does all of it, step by step, asking at each.

**The fence.** A box that holds more of the log than the owner proves the
owner stale — restored from an older copy, or replaced by a promotion while it
was away. Such an owner stops writing and says so (`fenced` in `forest tip`
and `serve status`). `pvfs forest fence` shows it and, asked, lifts it: only
when this box really is the forest's writer.

#### Root certificates bound to their forest (`bind-certs`)

One recovery phrase is one root key in every forest made from it. Until a
forest is bound, its certificates — device admissions and revocations, root
rotations, recovery keys, member tags — do not name the forest, so one signed
for another forest with the same root would verify in this one too.

```bash
pvfs forest bind-certs
```

From then on every such certificate must be signed for this forest; one
signed for another is refused (those already in the log stay valid). The
owner's own device signs the binding — it only takes authority away, so no
companion prompt. It shows the fleet first and asks, because every box that
reads the forest must understand bound certificates (protocol 14 or later).
A box that is gone for good would be counted forever: remove its records with
`pvfs fleet forget <pin>` first. It cannot be undone. A forest made by a
build that has this command is born bound.

#### The jobs

| job | what it does | in the media fleet |
|---|---|---|
| `follow` | keeps this box's copy of the log current with its source | every box but the owner |
| `watch` | catalogues the folders bound on this box as their files change, and in full hourly | every box that holds a region |
| `catalogue` | fetches and installs other boxes' catalogues when their heads move (every 60 s) | every box |
| `resolve` | trashes staging copies once the library holds the same bytes | the ingest box |
| `receive` | pulls by content hash what only staging holds into the receiving regions | the library's box |
| `health` | on the owner, polls every announced box every 2 minutes, restarts the ones it supervises, sends alerts (§7.11) | the owner |
| `reclaim` | trashes bytes whose node is no longer linked anywhere (node model) | the owner, with nothing to do |
| `sync`, `export`, `tier`, `evict` | the node model's mover and views (§7.8–§7.11) | — |

`pvfs serve enable --help` lists the same. `pvfs serve status` shows each
job's state, and also the view's conflicts, stale catalogues, whether the
box is fenced, the free space of every disk it stores on, its trash, its
running mounts and its last log copy. `pvfs fleet versions` shows what every
box runs (release, protocol, schema), read from the catalog.

**The media fleet (2026-09-30)** — the worked example the design docs use:

| box | role | regions | jobs |
|---|---|---|---|
| mediabox | owner (`/opt/pvfs/media`, alias `media`) and Plex's box | `mediabox-local`, `mediabox-local2` | `reclaim,health,catalogue,watch` |
| feederbox | ingest | `staging` (drains) | `follow,watch,catalogue,resolve` |
| the NAS | library | `library` (receives), `library-ext` | `follow,watch,catalogue,receive` |

## 8. Secure blobs (encrypted-at-rest storage)

A **secure blob** is a node whose bytes are **encrypted so the server can never read them**, and
which you can **truly delete** — unlike normal files, whose content is kept forever in the log. It's
meant for private app data: a messenger's message store, secrets, anything the host must not see.

Two things make it different from a normal file:

- **The bytes are one opaque encrypted blob** you overwrite in place. Old versions are discarded —
  real deletion, not soft-delete.
- **The log records only a signed hash of the ciphertext** (never the content), so PVFS can prove
  *that* it changed and *who* changed it, but never *what* it says.

By default the bytes are encrypted with the **companion envelope**: a random key encrypts the
content, and that key is wrapped to your **encryption key** (held by the companion, derived from
your phrase). The daemon stores and serves only ciphertext — **without your companion attached, the
server holds inert bytes.**

```bash
# create a secure store (storage is managed for you — no path needed).
# Works while the daemon is running: apps make new stores on the fly.
NODE=$(pvfs secure create <parent> my-secrets --json | sed -n 's/.*"created":"\([^"]*\)".*/\1/p')

# write to it (encrypted via your companion by default); old bytes are discarded
echo "top secret" | pvfs secure put "$NODE" -

# read it back (verified against the signed ledger, then decrypted via the companion)
pvfs secure cat "$NODE"

# who it's encrypted for, when it last changed, its size
pvfs secure status "$NODE"

# check the on-disk bytes still match the signed ledger
pvfs secure verify "$NODE"

# share it with someone else's key (re-wraps the content key; no re-encryption)
pvfs secure grant "$NODE" <their-pubkey-hex>
```

**Bringing your own encryption.** Apps that manage their own keys (the Messenger does) pass `--raw`
to `put`/`cat` to store and retrieve bytes verbatim — PVFS then treats the blob as opaque and does
no envelope work.

**Durability & recovery — what survives, and what doesn't.** A secure blob is deliberately split:
its *structure* is in the signed log, its *content bytes* are not.

| Event | What happens |
|-------|--------------|
| Reboot / crash mid-write | Safe. Bytes are fsynced then atomically renamed into place; the ledger event is in the write-ahead log. The worst case — a crash between writing bytes and recording the ledger — is a **detectable** mismatch that `secure verify` flags and a fresh `put` repairs. Never silent corruption. |
| Rebuilding the index | Full recovery. The node, its location, and every signed hash replay from the log. |
| New machine / `pvfs recover` | Structure and your decryption key both come back (the log replays; keys re-derive from your phrase). **But the ciphertext bytes live outside the log** — if the disk holding them is gone and the blob wasn't replicated, the bytes are unrecoverable. The log will tell you exactly what was lost (which hash, what size, when) but can't resurrect it. |
| Deleting / overwriting | The old bytes are discarded on purpose — that's the whole feature. **Crypto-shredding** (throwing away the content key) is the real erasure; physical remanence on disks, backups, or replicas is out of PVFS's hands. |

So: everything *provable* about a secure blob survives anything. The one thing that can be lost is
the encrypted content itself — which is exactly the trade a disappearing-messages store wants.
Anything you can't afford to lose should be replicated (the daemon happily replicates ciphertext it
can't read).

---

## 9. Recovery & devices

- Your **recovery phrase** (shown once at `forest init`) regenerates your keys. Store it safely.
- Move a forest to a new machine: copy the whole mount (including `.pvfs/`), then
  `pvfs recover --mnemonic "<phrase>"` to re-derive this machine's device key.
- Revoke a lost/compromised key: `pvfs device revoke --pubkey <hex>` (signed by your admin device;
  add `--mnemonic "<phrase>"` to root-sign). Its already-signed history stays valid.

Your **recovery phrase** is needed only for recovery — admitting/revoking members is signed by your
everyday admin device, not the phrase (doc 09 §2.2).

**If your seed is compromised — rotating the root (doc 15).** Because your identity is the *log*, not
the key, you can replace the root key while keeping your forest, its id, and all its history:

```bash
# one-time: register an offline recovery key so you can rotate even if every
# machine is compromised. Authorize with your current phrase (typed/piped);
# it prints a SECOND phrase to keep on paper.
echo "<current recovery phrase>" | pvfs forest recovery-key --forest <alias|mount>

# rotate the root: authorize with your current phrase OR the recovery phrase;
# it prints a fresh recovery phrase and re-anchors authority to a new key.
echo "<authorizing phrase>" | pvfs forest rotate-root --forest <alias|mount>

# retire an old recovery key without rotating (e.g. you shredded the paper):
echo "<current phrase>" | pvfs forest recovery-key --forest <alias|mount> --revoke <pubkey>
```

A rotation **clears all recovery keys** (register fresh ones under the new root afterwards), so a
stale or compromised recovery key never survives a rotation. After a rotation the old seed can no
longer authorize anything; device/identity keys derived from the old seed keep working until you
revoke and re-admit them, so do that next in a compromise.

A single lost identity key (not the whole seed) is cheaper: `pvfs identity replace` swaps it and
re-issues your grants under the new key, printing a handoff for forests where you're a member (they
run `pvfs member replace <file>`).

---

## 9.5 Upgrading a fleet without stopping it

`pvfs versions` reports what matters before an upgrade:

```bash
pvfs versions            # bare works; --json for scripts
```
```
pvfs             : 1.4.0
wire proto       : 15 (talks back to 3)
projection schema: 20 (this binary)
this forest      : 19 — will upgrade on next open (per-box cache; the fleet does not need to stop)
build            : v1.4-495-gc17ae29 (mount compat 1)
opening it here  : migrates in place from v19 (…)
```

`opening it here` says what the first open on this build would do: nothing,
migrate in place, or rebuild from the log (and why). Outside a forest the
forest lines say `(no forest here)`; beside a running view mount a
`running mount` line says whether it keeps working under this build (§7.13).

Read the first three lines like this:

- **projection schema** — the local cache in `index.db`. It is rebuildable from
  the log and **every box has its own**, so a schema-only change is a *per-box*
  concern. Upgrade one machine at a time; the others keep serving throughout,
  and readers simply fall through to them. The fleet never has to stop.
- **wire proto** — how boxes talk to each other. A change here is **fleet-wide**:
  mixed versions have to negotiate, so plan it deliberately rather than rolling
  it machine by machine.
- **pvfs** — the release; **build** names the exact commit, which is what to
  compare between boxes while main runs ahead of the last release.

`pvfs fleet versions` answers the same for every box at once, from what each
announced: "the fleet is UNIFORM" when all agree.

Within a single machine, everything sharing a data dir (`pvfsd`, the CLI, any
`pvosd`) must move together: an older binary refuses a newer projection, and a
read-only view cannot rebuild one. So per box: stop them, install, open the
forest once while it is quiet, start them again.

Opening on a newer binary does the upgrade. An **additive** change migrates in
place — sub-second even on a large forest — and says so:

```
pvfs: projection migrated v7 → v8 (folder_bindings.bound_by from FolderBound) — no replay needed
```

Anything it cannot migrate safely falls back to replaying the log, which is
always correct but costs time proportional to the log (~30 s for 80k events),
and likewise says so. Both messages name their reason; a rebuild that keeps
*recurring* is a bug worth reporting, not the one-time upgrade path.

A replay is built **beside** the live cache and swapped in at a single commit,
so readers keep getting correct answers from the old cache for the whole
rebuild rather than an empty one — and a rebuild that fails, or a machine that
loses power halfway through, leaves the old cache intact. It needs room for a
second copy of the index while it runs.

---

## 10. Command reference (summary)

| Command | What it does |
|---------|--------------|
| `pvfs forest init [--mount DIR] [--no-import]` | Create a forest (as your user); self-enrolls this box's client identity with read (§7.9). |
| `pvfs versions [--json]` | Release, wire proto, and projection schema — and, in a forest, the schema the on-disk cache is at (§9.5). |
| `pvfs forest register <mount> [--alias N]` | Register host-wide (`sudo`). |
| `pvfs forest unregister <alias\|mount>` | Remove from the registry (keeps `.pvfs/`). |
| `pvfs forest fix-permissions [--mount DIR]` | Repair `.pvfs/` ownership (`sudo` if root-owned). |
| `pvfs forest info [target]` | Show a forest's identity. |
| `pvfs ls [target]` | No target: list registered forests. With target: list children. |
| `pvfs walk <target>` · `pvfs node <target>` | Walk a tree · show one node. |
| `pvfs add <parent> --kind … --label …` | Add a node. |
| `pvfs loc add\|rm\|ls\|verify <file> …` | Manage where a file's bytes live. |
| `pvfs bind <folder> <dir> [--kind in-place\|migrate\|mirror --to <store>]` · `pvfs scan <folder>` | Enroll a real directory — as-is, self-draining staging, or mirrored backup (§6.1b) · index it. |
| `pvfs export <target> <dir> [--mode symlink\|hardlink\|copy] [--prune]` | Materialize a tree as a native directory for non-PVFS apps (§6.1). |
| `pvfs mount <target> <dir>` · `pvfs umount <dir>` | Live read-only FUSE view — bytes stream on demand (§6.2, Linux). |
| `pvfs region mark\|ls\|unmark <node>` | Make a subtree its own signed-log replication/audit unit (§6.3). |
| `pvfs region mark <node> --catalogue --owner key:<hex>` | Make a folder a catalogue region, owned by the box that holds its disk — the region model (§7.13). |
| `pvfs region entries <region>` · `pvfs region fetch [region]` | A catalogue region's rows · fetch now the catalogues this box is behind on (§7.13). |
| `pvfs region drain <region> on\|off` · `receive <region> on\|off` · `retention <region> <days>` | Staging (fleet-wide) · this box's receiving library region · how long its trash is kept (§7.13). |
| `pvfs view ls [dir]` · `pvfs view conflicts` | The merged view, one level at a time · every path where two regions disagree (§7.13). |
| `pvfs view receive [--dry-run]` · `pvfs view resolve [--dry-run]` | Run the mover's two halves now (§7.13). |
| `pvfs mount --view <dir> [--cache-mode keep\|stream] [--allow-other]` | The merged view as a filesystem; bytes from this box or read through by hash (§7.13). |
| `pvfs trash ls\|restore [path]` · `pvfs trash put <path> --region <id>` | What was moved aside on this box, and putting it back · one region's copy to its trash (§7.13). |
| `pvfs forest tip` · `pvfs forest fence [--clear]` | This box's copy of the log (seq, hash, owner or replica, fenced?) · an owner's fence (§7.13). |
| `pvfs forest backup [--to <dir>] [--keep <days>]` · `pvfs forest restore <copy> <dir>` | A dated copy of the log, verified by a full replay · a replica directory from one (§7.13). |
| `pvfs forest promote <dir> [--via-companion]` · `pvfs replica repoint <dir> --instance <name>` | Make this replica the forest's owner · follow the new owner (§7.13; doc 28). |
| `pvfs forest bind-certs` · `pvfs fleet forget <pin>` | Bind the forest's root certificates to it · forget a box that is gone for good (§7.13). |
| `pvfs fleet versions` · `pvfs fleet health [--now]` | What every box runs · every box up, or down since when (§9.5, §7.11). |
| `pvfs serve receive-plan` | Ask the running daemon what its mover has left to pull (§7.13). |
| `pvfs verify <id>` · `pvfs orphans` · `pvfs purge <ids…>` | Integrity · orphan management. |
| `pvfs link <parent> <child> [--type contains\|ref]` | Create an explicit link. Defaults to `ref`; `--type contains` is what re-attaches an island (§ `islands`). |
| `pvfs mv <node> <new-parent>` | Move a node to a new containing parent. The NAME is unchanged — use `relabel` to rename. Prompts for anything omitted. |
| `pvfs relabel <link> <name>` | Set a link's display label: the name **this parent** uses for this child. Renaming happens on the EDGE, not the node, so the same file can be called different things in different places (D72). |
| `pvfs reorder <link> <key>` | Change a link's sibling order key. |
| `pvfs roots <folder> [...]` | Declare which directories are roots of a folder's library, and which of them DRAIN (D81) — a staging root empties, a library root keeps. |
| `pvfs quality <node> [...]` | What a media file IS — record it, or read it back (D76). Capture it while the source still knows; an arr forgets. |
| `pvfs collide` | Resolve path collisions: two live nodes at one tree path (D84). |
| `pvfs explain <a> <b>` | Which of two copies would survive, and why — **without touching either**. The dry run for an upgrade decision. |
| `pvfs duplicates [--merge]` | Files the catalogue holds MORE THAN ONCE at the same place — same parent, same name. Reports by default and names the keeper before anything moves; `--merge` moves every location onto that node, retires it from the others, carries MediaQuality, then unlinks. Soft removes, so it is reversible. Production held 588 such groups (D113/D114). A group is **CONTESTED** when more than one member holds live bytes AND their sizes disagree — two boxes at two versions of one path, an upgrade in flight — and `--merge` skips it (D119); the box holding a copy settles it on its next scan. |
| `pvfs resolve <id> --rules [--size-margin N] [--dry-run]` | Weigh a pending change on the D76 ladder instead of deciding blind: quality, then a truncation guard, then size, then recency. Prints the reason. `REPLACE` applies it; `KEEP` leaves the flag, since the file on disk is still the wrong one. Off by default for the same reason `collide --rules` is (D120). |
| `pvfs islands [--drop <id>]` | Detached subtrees: live-linked nodes no tree root reaches. `orphans`/`missing`/`reclaim` ask about one node and call every one of them healthy; only a walk from the tree roots sees that nothing leads there (doc 24 §19). `--drop` unlinks a NAMED island and everything under it — named, not swept, because whether a detached subtree is finished with is a judgement (D116). |
| `pvfs audit` | Authorization health check: tag grants/memberships under a revoked authority, `key:` grants to revoked devices, and expired grants. |
| `pvfs secure create <parent> <label> [--path P]` | Create an encrypted-at-rest blob (managed storage; `--path` pins a location). |
| `pvfs secure put <node> <file\|-> [--raw]` | Encrypt (companion) & write the blob's bytes; `--raw` stores app ciphertext as-is. |
| `pvfs secure cat <node> [--raw]` | Verify vs the ledger, then decrypt (companion) to stdout; `--raw` emits ciphertext. |
| `pvfs secure grant <node> <pubkey>` | Add another key as a recipient (re-wraps the content key). |
| `pvfs secure verify <node>` · `pvfs secure status <node>` | Check bytes vs the signed head · show the ledger head. |
| `pvfs device authorize-member --pubkey <hex>` | Authorize a member's key (admin device; no phrase). |
| `pvfs device authorize-member --via-companion --companion-socket <p> --pubkey <hex>` | Root-sign the admit through a running companion — no phrase typed (doc 14). |
| `pvfs-companion init --vault <p>` · `pvfs-companion serve --vault <p> --socket <s> [--allow-root]` | Seal your seed into a vault · run the local signing agent. |
| `pvfs device revoke --pubkey <hex>` | Revoke a device/member key (admin device; no phrase). |
| `pvfs forest recovery-key [--forest F]` | Register an offline rotation recovery key (phrase on stdin; prints a paper phrase). |
| `pvfs forest rotate-root [--forest F]` | Rotate the root after seed compromise (phrase on stdin; prints a new phrase). |
| `pvfs identity replace` · `pvfs member replace <file>` | Replace a compromised identity key · adopt a member's replacement from a handoff. |
| `pvfs acl set <node> public\|any\|tag:<name>\|key:<hex> <rights> [--expires 7d\|@ms]` | Grant/clear rights (`-` clears); `--expires` makes the grant lapse after a duration (`45s`/`30m`/`12h`/`7d`/`2w`) or at `@<unix-ms>`. |
| `pvfs acl ls\|check <node> [principal]` | List grants · show effective rights. |
| `pvfs tag add\|rm <member-pubkey> <tag>` · `pvfs tag ls <member-pubkey>` | Assign/remove/list membership tags. |
| `pvfs whoami` | Print this machine's client identity pubkey. |
| `pvfs remote --socket <path> [--anon] info\|ls\|stat …` | Read a forest via its daemon. |
| `pvfs remote … add-node <parent> <label> <type> [--payload <text\|@file\|@->]` · `payload <node>` | Create / read a small typed record via the daemon (doc 13). |
| `pvfs remote --socket <path> mkdir <parent> <label>` | Create a folder via the daemon (member-signed). |
| `pvfs remote --socket <path> add-file <parent> <label> [--size N --mime M]` | Create a file node via the daemon. |
| `pvfs remote --socket <path> rm <node>` | Unlink a node from its home via the daemon. |
| `pvfs remote --socket <path> mv <node> <new-parent>` | Re-home a node under a new parent. |
| `pvfs remote --socket <path> add-location <file> <uri>` | Record where a file's bytes live. |
| `pvfs remote --socket <path> cat <node> [--offset N --len N]` | Stream a file node's bytes to stdout (ACL-checked); ranged reads, and on an in-flight ingest file the daemon waits for the covering chunks (§7.12). |
| `pvfs remote --connect <host:port> --pin <hex> …` · `--instance <name> …` | The same commands over TCP+TLS to a `pvfsd --listen` server (§7.4). |
| `pvfs instance add <name> <host:port> <pin>` · `ls` · `rm <name>` | Remember/list/forget pinned network instances. |
| `pvfs replica add <mount> --instance <name> [--region <node>]` · `pvfs replica sync <mount>` | Build / refresh a verified read-only replica of a served forest — whole, or scoped to one region (§7.7). |
| `pvfs replica follow <mount>` | Follow the source live (long-poll): new events land within seconds; run as a service. |
| `pvfs place <target> sync\|pointer\|central --to <dir>` · `pvfs sync [target]` | Placement policy · fetch missing bytes, verified (§7.8, §7.10). |
| `pvfs tier` · `pvfs evict` | Owner: migrate to the central store + retire edge locations · edge: reclaim space safely (§7.10). |
| `pvfs ingest begin <parent> --name N --infohash H --file rel:bytes…` | Open an external-ingest session — catalog the files before the bytes (§7.12). |
| `pvfs ingest write\|verified\|commit\|abort\|list` | Stream bytes in, mark verified ranges, commit through the gates, abort, or list sessions (§7.12; bare `pvfs ingest` = list). |
| `pvfsd --mount <dir> --socket <path>` | Serve a forest over a Unix socket. |
| `pvfsd --mount <dir> --listen <addr:port>` | Also serve TCP+TLS; prints the transport pin clients must pin. |
| `pvfs serve enable\|disable\|ls\|status [job]` | Configure/inspect the daemon's background jobs (§7.11, §7.13; `serve enable --help` lists every job and what it does); bare `pvfs serve` = status. |
| `pvfs fleet enroll <pubkey> [--rights r\|rw\|rwa]` | Admit a box: membership + rights in one logged step (§7.9). |

Add `--json` to most commands for machine-readable output. Use `--forest <alias>` or run inside a
mount to set the forest context for tree commands.

---

## 11. Roadmap

Available now: forests & import, the full ACL model **with per-key tags**, phrase-free member admin,
and daemon sharing — members **read** (`ls`/`stat`/`cat`) and **write**
(`mkdir`/`add-file`/`add-location`/`rm`/`mv`), each change signed by their own key, and the owner
does **live admin** (authorize/grant/tag) through the running daemon. Reach a forest's daemon with
`pvfs remote --forest <alias|mount>` (no socket path needed). Plain `pvfs acl set` / `tag add` /
`device authorize-member` **auto-route** to a running daemon (no `remote` prefix), and `acl`/`tag`
accept `pvfs://` URIs and paths. `cat` streams **raw bytes** with concurrent transfers, `pvfsd`
ships a `pvfsd@.service` systemd `--user` unit and shuts down cleanly on SIGTERM/SIGINT
(checkpointing the WAL), and `pvfs audit` reports any tag grants/memberships left under a revoked
authority.

The **companion** (a local custodian for your keys, doc 14) is built: it seals your seed in an
OS-keychain or passphrase vault, signs high-authority operations without you typing your phrase,
prompts before anything consequential, keeps a signature audit log, locks on idle, and runs a
loopback "Sign in with PVFS" agent for web apps. And **encryption at rest** (secure blobs, §8) is
built: encrypted opaque storage with a content-free signed ledger, companion-gated decryption, and
create/read/update over the running daemon.

**1.1 (library / daemon):** apps can create small log-resident typed nodes via `AddNode` and read
them with `Payload` over `pvfs-client` (used by PVOS for grant records); `stat` reports a node's home
parent. The operator CLI wrappers shipped too: `pvfs remote add-node` / `payload` (§10).

Coming next (see [08-roadmap-and-status.md](08-roadmap-and-status.md)):

- **Polish** — Touch ID unlock.
- **Compaction** — deliberately deferred by decision (2026-08-13, doc 11): revisit when a
  projection rebuild crosses ~a minute or a replica add takes minutes on LAN.
- **Federation / network sharing** — reach and sync forests across hosts. The first arc is
  **built** ([doc 17](17-federation-and-sync.md)): the native tree view (`pvfs export`, §6.1), the
  network transport (`pvfsd --listen` + pinned TLS, §7.4), verified read-only replicas
  (`pvfs replica`, §7.7), and pointer-vs-sync placement (`pvfs place` / `pvfs sync`, §7.8) — the
  cross-host media library works end to end; replicas accept writes by **write-through** (§7.9)
  and **follow their source live** (`pvfs replica follow` — new events in seconds); locations name
  their holding instance, reads **fetch on demand** from any pinned holder, and the
  **tiered-storage mover** migrates bytes to a central store with safe edge eviction (§7.10) — the
  full ingest-box → NAS pipeline. The F4 arc is **complete** (1.4.0, [doc 20](20-f4-regions-and-streaming.md)):
  the FUSE mount (§6.2), physical region logs (§6.3), region-scoped replication over the wire,
  cross-region moves, attachment kinds (doc 21) and the swarm (doc 22) all shipped. On main
  beyond 1.4: external-ingest sessions + in-flight streaming (doc 23, §7.12), and the **region
  model** (doc 26, §7.13) — in production since 2026-09-12 — with explicit promotion of a new
  owner, the fence, and dated copies of the log (doc 28), which is what standby failover
  became.
- **Availability** — beyond promotion: a warm standby with one-button takeover, then automatic
  failover as an opt-in per forest (doc 08's availability track). Neither is built.
