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

## 8. Recovery & devices

- Your **recovery phrase** (shown once at `forest init`) regenerates your keys. Store it safely.
- Move a forest to a new machine: copy the whole mount (including `.pvfs/`), then
  `pvfs recover --mnemonic "<phrase>"` to re-derive this machine's device key.
- Revoke a lost/compromised key: `pvfs device revoke --pubkey <hex>` (signed by your admin device;
  add `--mnemonic "<phrase>"` to root-sign). Its already-signed history stays valid.

Your **recovery phrase** is needed only for recovery — admitting/revoking members is signed by your
everyday admin device, not the phrase (doc 09 §2.2).

---

## 9. Command reference (summary)

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
| `pvfs device authorize-member --pubkey <hex>` | Authorize a member's key (admin device; no phrase). |
| `pvfs device authorize-member --via-companion --companion-socket <p> --pubkey <hex>` | Root-sign the admit through a running companion — no phrase typed (doc 14). |
| `pvfs-companion init --vault <p>` · `pvfs-companion serve --vault <p> --socket <s> [--allow-root]` | Seal your seed into a vault · run the local signing agent. |
| `pvfs device revoke --pubkey <hex>` | Revoke a device/member key (admin device; no phrase). |
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

## 10. Roadmap

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

Coming next (see [08-roadmap-and-status.md](08-roadmap-and-status.md)):

- **A companion app** — a local custodian for your root key that also auto-logs you in to
  PVFS-backed web apps. It reproduces your identity key from your phrase on any machine, so your
  sharing works the same everywhere.
- **Compaction** — collapse a large forest's history into a fresh, compact snapshot to reclaim space
  and speed up rebuilds (signed by you; trades away old history).
- **Encryption at rest** and **federation / network sharing**.
