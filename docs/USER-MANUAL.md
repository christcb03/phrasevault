# PVFS User Manual

PhraseVault File System — a content-addressed, cryptographically-signed file system you own.
This manual covers everyday use of the `pvfs` command-line tool and sharing forests between users.

> Status: covers the features available today (forest management, import, access control, and
> read-only daemon sharing). Features still in progress are listed under [Roadmap](#10-roadmap).

---

## 1. What is PVFS?

PVFS organizes your files as a **forest** — a tree of *nodes* (folders and files) backed by an
append-only, signed event log. Unlike a normal directory:

- Every change is **signed** with your key and recorded in a tamper-evident log.
- Files are **content-addressed** (identified by a BLAKE3 hash), so identical content is recognized
  anywhere.
- A forest can be **registered** on a host so apps and other users can find it, **shared** with
  fine-grained per-folder permissions, and (soon) accessed over a network.

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
pvfs remote --forest media ls   <photos-node-id>
pvfs remote --forest media stat <node-id>
pvfs remote --forest media info

# or anonymously (only sees `public` grants):
pvfs remote --forest media --anon ls <node-id>
```
(`--socket <path>` still works for an explicit socket.)

The daemon checks the caller's rights on every request and returns only what they may read.

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

---

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

## 10. Command reference (summary)

| Command | What it does |
|---------|--------------|
| `pvfs forest init [--mount DIR] [--no-import]` | Create a forest (as your user). |
| `pvfs forest register <mount> [--alias N]` | Register host-wide (`sudo`). |
| `pvfs forest unregister <alias\|mount>` | Remove from the registry (keeps `.pvfs/`). |
| `pvfs forest fix-permissions [--mount DIR]` | Repair `.pvfs/` ownership (`sudo` if root-owned). |
| `pvfs forest info [target]` | Show a forest's identity. |
| `pvfs ls [target]` | No target: list registered forests. With target: list children. |
| `pvfs walk <target>` · `pvfs node <target>` | Walk a tree · show one node. |
| `pvfs add <parent> --kind … --label …` | Add a node. |
| `pvfs loc add\|rm\|ls\|verify <file> …` | Manage where a file's bytes live. |
| `pvfs bind <folder> <dir>` · `pvfs scan <folder>` | Bind a real directory · index it. |
| `pvfs verify <id>` · `pvfs orphans` · `pvfs purge <ids…>` | Integrity · orphan management. |
| `pvfs audit` | Authorization health check: list tag grants/memberships under a revoked authority. |
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
| `pvfs acl set <node> public\|any\|tag:<name>\|key:<hex> <rights>` | Grant/clear rights (`-` clears). |
| `pvfs acl ls\|check <node> [principal]` | List grants · show effective rights. |
| `pvfs tag add\|rm <member-pubkey> <tag>` · `pvfs tag ls <member-pubkey>` | Assign/remove/list membership tags. |
| `pvfs whoami` | Print this machine's client identity pubkey. |
| `pvfs remote --socket <path> [--anon] info\|ls\|stat …` | Read a forest via its daemon. |
| `pvfs remote --socket <path> mkdir <parent> <label>` | Create a folder via the daemon (member-signed). |
| `pvfs remote --socket <path> add-file <parent> <label> [--size N --mime M]` | Create a file node via the daemon. |
| `pvfs remote --socket <path> rm <node>` | Unlink a node from its home via the daemon. |
| `pvfs remote --socket <path> mv <node> <new-parent>` | Re-home a node under a new parent. |
| `pvfs remote --socket <path> add-location <file> <uri>` | Record where a file's bytes live. |
| `pvfs remote --socket <path> cat <node>` | Stream a file node's bytes to stdout (ACL-checked). |
| `pvfsd --mount <dir> --socket <path>` | Serve a forest over a Unix socket. |

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

Coming next (see [08-roadmap-and-status.md](08-roadmap-and-status.md)):

- **Compaction** — collapse a large forest's history into a fresh, compact snapshot to reclaim space
  and speed up rebuilds (signed by you; trades away old history).
- **Federation / network sharing** — reach and sync forests across hosts.
