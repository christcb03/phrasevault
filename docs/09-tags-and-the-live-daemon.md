# PVFS — tags, and the daemon as the single live instance (09)

Status: **Decided (model)** — implementation phased (§5)
Date: 2026-06-18
Depends on: [06-access-control-and-daemon.md](06-access-control-and-daemon.md), [07-daemon-protocol.md](07-daemon-protocol.md)

Two related decisions: a **tag-based** sharing model layered on the ACLs, and the principle that a
running **`pvfsd` is the single instance** for a forest — all interfaces (CLI, API) submit to it
rather than opening their own engine. Together these give "change who-can-see-what, on the fly."

---

## 1. Tags (group-based sharing)

Two independent dials:

| Dial | What | Where it lives |
|------|------|----------------|
| **User tags** | the set of tags a member holds (`friends`, `media_users`, …) | forest events (`MemberTagged`), projected to `member_tags` |
| **Share tags** | the tags allowed to access a node | an ACL grant to a `tag:` **principal** (in the `acl` table) |

A member can read/write a node when **any tag they hold matches a tag the node grants** (with the
usual rights and inheritance). So sharing a library is: tag the content `tag:media_users r`, and
give each friend the `media_users` tag. Add a friend → grant them the tag → done; un-share content →
drop the node's tag grant. Both are single, on-the-fly events.

### 1.1 Principal extension
`Principal` gains a fourth kind: **`Tag(name)`** (`principal_kind = 3`, id = the tag name).
ACL grants therefore cover `public` ⊇ `any` ⊇ `tag:<name>` ⊇ `key:<hex>`. Tag names use the alias
charset (`[a-z0-9][a-z0-9_-]*`).

### 1.2 Member tags
`MemberTagged { member_pubkey, tag, granted, set_at, author, sig }` — `granted=true` adds, `false`
removes, checked live and on replay via `check_member_event`. Projected into
`member_tags(member_pubkey, tag, authority)`.

> **Superseded by per-key tags (doc 10, P2-G — shipped).** A tag is now `(authority, name)`, where
> the authority is the event author. Two changes from the original model below: (a) **any authorized
> member** may assign a tag **under its own authority** — the old "admin on the forest root"
> requirement is dropped, safe because a key-scoped membership only unlocks nodes that same key
> already controls; (b) a node's tag grant and a member's membership combine **only when authored by
> the same key**, so one forest hosts many apps' tag namespaces without collision.

### 1.3 Evaluation
`effective_rights(Key(pk), node)` for a non-owner member unions, at each node up the tree, the grants
for **every tag the member holds — matched on `(authority, name)`** (doc 10): the membership and the
node's `Tag` grant must share an authority, and that authority must still be an active member
(revoked authorities are masked). Owner devices still short-circuit to full rights.
`effective_rights(Tag(t), node)` reports that name's grants across all authorities (inspection /
`acl check`).

> **Scope (v1):** tags are **per-forest** (each forest's owner assigns them within that forest). A
> host-level overlay so one tag set spans all of an owner's forests is a later option; per-forest is
> the natural fit for the event-sourced model and still delivers the "community tag" workflow.

---

## 2. The daemon is the single instance

**Principle:** while a forest has a running `pvfsd`, it is the *only* process that opens that
forest's engine. Every mutation — member writes **and** admin ops (authorize a member, set an ACL,
assign a tag, move a node) — is submitted **to the daemon** and written by its one engine. The CLI
and any API are **clients**; they do not open a second engine on a served forest.

Why: it eliminates the two-writer hazard (two processes on one SQLite store), makes every change
take effect immediately (the daemon makes it and serves the next request under it), and is the only
model where "change tags/ACLs on the fly" actually works. It also matches doc 07's federation
direction (the key is the identity; the socket — and later the network — is the interface).

### 2.1 Routing
- `pvfs <admin-op>` on a forest with a registered/running socket → connects and submits the op.
- No running daemon → falls back to opening the engine directly (current behavior), for setup,
  scripting, and recovery.

### 2.2 Privilege of admin ops — a pluggable signer, no recovery phrase
All admin ops ride the existing two-phase rails (`prepare → sign → commit`); the only question is
**who signs**, which is abstracted as a *signer* (the CLI's device key today, the companion §6 later):

- **ACL grant / tag assign / mv / member writes** — signed by a device holding the needed right
  (`a` for ACL/tag, `w` for writes). The owner's device qualifies, so these are **device-signed,
  phrase-free**.
- **authorize-member / revoke** (admit/remove an identity) — **device certificates**. The rule is
  loosened from "root-only" to **"root **or** an admin device"** (a device holding `a` on the forest
  root, which the owner's device does). So an admin device admits members **phrase-free**; the root
  path remains for the strongest setups (signed by the companion, §6). Genesis stays root-signed
  (no admin device exists yet at that instant). Re-verified on replay with the same rule.

**The recovery phrase is for recovery only** — restoring keys on a new machine, or as the deep anchor
if every admin device is lost. No day-to-day op asks for it.

### 2.3 Live config
Because all changes flow through the daemon, there is no reload step: ACLs, tags, and memberships
are read live from the engine on every request. Removing the "set up before serving" limitation
(doc 08 §4.4) is a direct consequence.

---

## 3. Raw data plane (`cat`)

Control and data are separated. The control plane authorizes a read (ACL check, resolve the node →
location); the **bytes then stream raw** — no hex, no JSON envelope — over the connection (a length
header then the raw bytes), on a transfer path that doesn't tie up the request loop. This halves
the bytes vs. today's hex chunks, allows concurrent transfers, and is the seam for later
**torrent-like** multi-peer chunk serving (doc 07 §6).

---

## 4. New write op: `mv`

Re-home a node under a new parent: supersede its current `contains` link with a new one (or
remove+add). Member-signed; requires `w` on **both** the old and new parent. Fits the existing
`prepare_*` / `commit_member_write` rails.

---

## 6. The companion app (local signing agent)

An optional desktop **companion** is the strongest home for the **root key**: it is generated and
kept locally and **never leaves the desktop** — not over the wire, not to disk-in-the-clear, not
typed. It plays the role of a hardware wallet / `ssh-agent` / passkey authenticator for PVFS, with
two jobs:

1. **Root custodian / authorizer.** When the daemon prepares a `DeviceAuthorized` (admit a machine or
   member), it asks the companion to sign it. The companion signs with the root (with a user
   approval, like a passkey tap) and returns only the signature — the daemon appends it. This is just
   another **signer** behind the two-phase flow (§2.2), so it needs no new kernel path. Result:
   root-strength authorization with no phrase.
2. **Identity agent / auto-login.** The companion exposes a **localhost** endpoint. A PVFS-backed web
   app (e.g. a media-forest app) authenticates by having the companion sign the daemon's
   challenge-response (doc 07 §2) with the user's device key — so the app logs the user in with no
   password and no phrase ("Sign in with PVFS"). While the companion runs, any PVFS-backed site the
   user has authorized logs in automatically.

**Why the companion is also the tag-authority home (per-key tags, doc 10 §9).** Because the companion
reproduces the *same* identity key from the phrase on any machine, that key — **not a per-machine
device key** — is the stable **authority** behind a human's direct tag grants and memberships. This
is what makes per-key tags work for a human across devices (one authority, not one-per-machine).
Apps sign with their own key; device keys are never the tag authority. The cost of using one stable
key instead of per-device keys — you can't revoke a single machine without rotating the shared key —
is paid by the companion's posture below (encrypted at rest, unlocked only while running, signs
per-approval), which is strictly stronger than a device key cached on disk.

**Security to design in:** the localhost endpoint must gate **which web origins** may request a
signature (per-app "connect" approval, like a wallet), and the root should be encrypted at rest and
unlocked only while the companion runs. The companion is its **own application track** (key vault +
localhost web API + approval UI); the daemon/protocol are built to accept it as a drop-in signer, so
it does not block the live-daemon work.

---

## 7. Implementation phasing

| Phase | Deliverable |
|-------|-------------|
| **1** | ☑ Tags: `Tag` principal, `MemberTagged` event + `member_tags` table, `effective_rights` extension; local CLI. |
| **2** | ☑ `mv` (re-home a node, member-signed over the daemon). |
| **3a** | ☑ **Device certs = "root or admin device"** (replay rule + engine `authorize_member`/`revoke` by an admin device, phrase-free) — the kernel foundation. |
| **3b** | ☑ Conventional per-forest socket (`$PVFS_SOCKET_DIR/<forest_id>.sock`); `pvfsd` binds it by default; `pvfs remote --forest <alias\|mount>` resolves it (no manual socket path). |
| **3c** | ☑ Admin ops over the daemon — `SetAcl`/`TagMember`/`AuthorizeMember`/`Revoke` `WriteOp`s; engine `prepare_*` + a commit that routes device certs through `check_device_cert`; `pvfs-client` `set_acl`/`tag_member`/`authorize_member`/`revoke`. Owner does **live admin over the socket** (authorize a member + grant → member writes immediately, no restart). Pluggable-signer seam (device key now; companion later). |
| **3d** | ☑ CLI **auto-routes**: `acl`/`tag`/`device` mutations look for a daemon serving that forest → submit to it (device-signed); else write directly. Path/URI args too. Root-signed (`--mnemonic`) stays direct (the daemon can't proxy the phrase). |
| **4** | ☑ Raw binary data plane for `cat` (PROTO_VERSION 2; lock released before I/O → concurrent transfers). |
| **5** | Companion app (§6): root custodian + localhost identity agent / auto-login. Its own track (1.0 scope TBD — doc 08 §3). |

Kernel **event encodings** unchanged: the `MemberTagged` event was additive, and per-key tags
(doc 10, P2-G) added no wire fields (the authority is the existing author). The **projection** schema
did bump to `SCHEMA_VERSION` 2 for P2-G's `authority` columns — older projections self-heal by
replaying from the log.
