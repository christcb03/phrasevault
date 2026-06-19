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
removes. **Authorizing a tag assignment requires admin (`a`) on the forest root** (owner devices
qualify), checked live and on replay via `check_member_event`. Projected into
`member_tags(member_pubkey, tag)`.

### 1.3 Evaluation
`effective_rights(Key(pk), node)` for a non-owner member now also unions, at each node up the tree,
the grants for **every tag the member holds**. Owner devices still short-circuit to full rights.
`effective_rights(Tag(t), node)` reports a tag's own grants (for inspection / `acl check`).

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

### 2.2 Privilege of admin ops over the socket (two-phase, same as member writes)
- **ACL grant / tag assign / mv / member writes** — signed by a device that holds the needed right
  (`a` for ACL/tag, `w` for writes). The **owner's device** qualifies for all of them, so the owner
  connects with their device identity and signs.
- **authorize-member** — admits a new identity, so it must be signed by the **identity root**. The
  owner's client signs the prepared `DeviceAuthorized` with the root key (from the recovery phrase);
  the daemon appends it. Replay re-verifies (root-signed) as today.

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

## 5. Implementation phasing

| Phase | Deliverable |
|-------|-------------|
| **1** | Tags: `Tag` principal, `MemberTagged` event + `member_tags` table + fold + replay check, `effective_rights` extension; local CLI (`pvfs tag member …`, `pvfs acl set <node> tag:<name> …`). |
| **2** | `mv` (re-home) + `set_acl`/tag ops as daemon `WriteOp`s. |
| **3** | Single-instance routing: admin ops over the daemon (incl. root-signed `authorize-member`); CLI auto-detects the socket and submits; direct-engine fallback when no daemon. |
| **4** | Raw data plane for `cat`. |

Kernel encodings unchanged except the additive `MemberTagged` event + `member_tags` table (no
schema-version bump; additive table via `CREATE TABLE IF NOT EXISTS`).
