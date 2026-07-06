# PVFS — Access control, per-writer identity, and the mediating daemon (06)

Status: **Decided (model)** — implementation phased (A/B/C below); kernel additions noted
Date: 2026-06-15
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md), [02-p0-core-engine-spec.md](02-p0-core-engine-spec.md), [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md), [05-instance-registry-and-mounts.md](05-instance-registry-and-mounts.md)

This document locks **how multiple users share one forest with per-component read/write control**, how those writes stay **cryptographically attributable to the actual writer**, and the **runtime** that enforces it. It is the long-term model for PVFS as a multi-user file server. It does not change P0 log encodings; it **adds** event kinds and a projection table, and a new process (the daemon).

---

## 1. Requirements (what we are solving)

From the operator vision:

1. Behave like a filesystem: **restrict reads and writes to individual components (nodes / subtrees) individually.**
2. Regular users **create forests without `sudo`** as private storage for the apps they run.
3. A forest is **private to its creator unless shared**. Sharing is opt-in, per component.
4. The owner can **grant other users read and/or write** to parts of their forest **without giving up control and without granting `sudo`**.
5. Shared **writes are signed by the actual writer**, not by the owner on their behalf. Authorship is faithful and non-repudiable.
6. **Mounting a forest as a real OS filesystem** for any app on the host (FUSE) is an **admin/`sudo`** action.
7. **Registering** a forest into the host-wide listing is a one-time **`sudo`** action (acceptable).
8. Trust assumption: **any local login account is trusted enough** to *create its own* forest and to *access forests explicitly shared with it*. It is **not** trusted to reach unshared forests.

---

## 2. Core decision: sharing is daemon-mediated, not file-permission-based

A forest's logical tree lives in a single `log.db` / `index.db`. POSIX file bits on those files are **all-or-nothing** — they cannot express "user B may read `/media` but not `/private`." Requirement (1) therefore **cannot** be met at the filesystem-permission layer. Per-component control must be enforced **in software, by a process that holds the data and checks every request.**

That process is the **per-user daemon**. PVFS becomes a small file server:

- The **owner's daemon runs as the owner**, exclusively owns `<mount>/.pvfs/` (mode `0700`), and is the only thing that touches the raw log or any signing key.
- Other users' apps **connect over a Unix-domain socket**; the kernel vouches for the caller via **peer credentials** (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`getpeereid` on macOS). No passwords, no shared secrets.
- The daemon checks a **per-node ACL** on every operation and serves only what the caller is allowed.
- The owner grants/revokes through their **own** daemon — no OS permission changes, no `sudo`, no key sharing.

This is the proven pattern of `ssh-agent`, `gpg-agent`, the Docker socket, NFS, and Samba: a key/data-holding process, callers authenticated by peer credentials, ACLs enforced inside.

**Consequence for file permissions:** `.pvfs/` is **owner-private (`0700`)**, `device.key` stays `0600`. This *is* the enforcement of requirement (3): an unshared forest is unreachable except through its owner's daemon, which denies by default. (This supersedes the earlier exploration of group-readable `.pvfs/`; group file-bits cannot do per-component control and are no longer the sharing mechanism.)

---

## 3. Identity and per-writer signing (multi-user authorization)

### 3.1 What the kernel already gives us

- Every mutating event carries an `author` public key and a signature verified on replay (`Event::verify_sig`, [02 §6]).
- `DeviceAuthorized` / `DeviceRevoked` events define the **set of keys allowed to author** in a forest, and the kernel **already requires those events to be signed by the forest's identity root** (`replay_one`). Authorizing a key is therefore a root-only act, exactly as we want.
- `init` already emits a root-signed `DeviceAuthorized` for the genesis device (device 0), and `Engine::ensure_device_active` already **gates every local write** on the writing device being present-and-unrevoked in the `device_keys` projection. So single-host write authorization exists today; what is missing is (a) authorizing a key the owner does *not* derive from their own seed, and (b) re-checking authorization at **replay** time (below).

### 3.2 The extension: authorize *other users'* keys

Today device keys are all derived from the owner's one mnemonic (`m/43'/20566'/1'/n'`) — i.e. the owner's own machines. The multi-user model reuses the **same `DeviceAuthorized` machinery for a key that belongs to a different person:**

- Each user has their **own** PVFS identity (their own mnemonic → their own keys). A writer's **member key** is a public key they control.
- To admit writer *B*, the **owner's identity root signs a `DeviceAuthorized`** for *B*'s member pubkey. *B* is now an authorized author in this forest. (The existing `Engine::authorize_device` derives the key from *the owner's* mnemonic; Phase A adds an `authorize_member(pubkey)` that authorizes an externally-supplied key, still root-signed — so it requires the owner's recovery phrase / root key, as befits admitting a new writer.)
- *B*'s edits are **constructed and signed by B's own key**, in B's own process. The owner never signs for B. The owner's daemon **serializes and gatekeeps** (orders the append, checks the ACL), but the cryptographic author is B. This satisfies requirement (5).

`DeviceAuthorized.device_index` is meaningful only for the owner's own HD-derived devices; for an external member key it is recorded as a reserved sentinel (e.g. `u64::MAX`) and ignored by HD logic. (Encoding unchanged.)

### 3.3 Kernel addition required: enforce author-authorization at **replay**

Writes are already gated locally (`ensure_device_active`). But `replay_one` — which runs on rebuild and will run on every synced replica (P4) — currently verifies only that an event's signature is valid **for whatever author it names**; it does **not** check that the author was an *authorized, non-revoked* device. A tampered or hostile log could thus carry validly-self-signed events from a key the forest never authorized. **Implemented:** replay now rejects any non-genesis, non-device-certificate event whose author is not present-and-unrevoked in `device_keys`:

```
author ∈ device_keys  AND  revoked_at IS NULL    (evaluated as folded up to this event)
```

Because the fold runs in seq order, "present" already means "a `DeviceAuthorized` for this key was folded at an earlier seq" (i.e. authorized before this event), and "unrevoked at this point" means "no `DeviceRevoked` has been folded yet" — so the rule needs **no trust in author-supplied timestamps**. It is the exact rule `ensure_device_active` uses for local writes, now also enforced on replay.

**Ordering (confirmed favorable):** `init` emits `ForestCreated` (seq 1) → `DeviceAuthorized` device 0 (seq 2) → root `NodeCreated` (seq 3) → `LinkCreated` (seq 4). Device 0 is authorized *before* the first device-authored event, so in-order folding already has it in `device_keys` when the genesis node/link are checked. `ForestCreated` and `DeviceAuthorized` are root-authored and keep their existing special-casing. Enforcement is therefore low-risk — but because it is the one change that *could* break replay of existing forests, it still ships **behind a rebuild/replay test** (init a forest, full-rebuild, assert identical projection) rather than blind.

This check is the cryptographic backstop *behind* the daemon's ACL check: even a buggy or bypassed daemon cannot inject events from an unauthorized key, and every replica re-verifies independently.

### 3.4 Membership ≠ authorship rights

Being an authorized device means "may author events that the rules accept." **It does not by itself grant access to any node** — that is the ACL's job (§4). A member with zero ACL grants can write nothing. Revoking a member (`DeviceRevoked`, root-signed) disables all their future authorship at the kernel level; ACL removal (§4) is the routine, finer-grained control.

---

## 4. The ACL model (per-component, filesystem-like)

### 4.1 Shape

Access is controlled per **node** (a folder or file in the tree). An ACL entry binds a **principal** to a set of **rights** on a node:

| Field | Values |
|-------|--------|
| principal | **`public`** (anyone, even unauthenticated); **`any`** (any authorized member); or **`key:<pubkey>`** (one member). `public ⊇ any ⊇ key`. Named groups deferred. |
| rights | any of `r` (read), `w` (write/modify children & payload), `a` (admin: grant/revoke ACLs on this subtree) |
| scope | the node it is set on, **inherited by descendants** unless overridden |

The **owner** (identity root, and devices it marks admin) always has full rights everywhere — they cannot be locked out of their own forest.

### 4.2 Inheritance and evaluation

- A node with **no explicit ACL inherits** its nearest ancestor's effective ACL (POSIX default-ACL style). The forest root has a default ACL set at init: **owner = full, everyone else = none** (requirement 3).
- Effective rights for principal *P* on node *N* = union of grants on *N* and the nearest ancestor that names *P* (most-specific wins for deny; v1 is **grant-only**, no explicit deny — absence = no access, which keeps evaluation simple and matches the "private by default" rule).
- Read of a node requires `r` on that node; listing a folder returns only children the caller may `r`; writing requires `w` on the parent; re-sharing requires `a`.

### 4.3 Storage: ACLs are signed events

A new event kind **`AclSet`** (and its inverse, expressed as an `AclSet` to empty) records grants in the log, so access policy is **versioned, attributed, replayable, and replicated** like all other state — never a side file.

```
AclSet { node_id, principal, rights, set_at, author, sig }
```

- `author` must hold `a` (admin) on `node_id` (the owner's root always qualifies). Enforced both by the daemon (at request time) and by the projection (at apply time), using the same authorization spine as §3.3.
- Projected into an `acl(node_id, principal, rights, set_at)` table for O(1) lookups during traversal.
- Exact PCE field encoding and digest domain string (`pvfs:aclset:v1:`) are specified alongside implementation in [02] when Phase B lands.

### 4.4 Why not POSIX bits on nodes

We considered storing `mode`/owner/group on each node. Named-user/named-group grants (requirement 4) need extended ACLs anyway, and encoding policy as **events** gives history, attribution, and federation for free. A node may still expose a POSIX-style *summary* (owner + a derived `rwx` triple) for FUSE (§6) without that being the source of truth.

---

## 5. The daemon

> **Superseded by [07-daemon-protocol.md](07-daemon-protocol.md).** The §5 sketch below
> predates the Phase-C decisions. The authoritative model is doc 07: **challenge-response auth**
> (the key is the principal — *no* uid→key binding), JSON transport, two-phase member-signed
> writes, and a split control/data-plane concurrency model. Read doc 07 for §5.x details.

### 5.1 Responsibilities

- Own and open `<mount>/.pvfs/` (the **only** writer of the log on this host).
- Listen on a per-forest **Unix-domain socket** (path recorded in the registry, §7).
- For each connection: read **peer uid** from the socket; map uid → **principal** (member key) via the forest's membership binding (§5.2); evaluate ACLs per request; serve reads, and accept **member-signed** writes after checking ACL + author-authorization, then append.
- Refuse everything for a uid with no membership/grants (private-by-default).

### 5.2 uid → principal binding

The daemon must know which member key a connecting uid controls. Under the trust assumption (8), the owner binds them explicitly when granting access:

```
forest grant --uid 1003 --member <B-pubkey> --read /media
```

The daemon trusts the **peer-cred uid** (kernel-supplied) and attributes the connection to the bound member key. For *writes*, the client additionally supplies events **signed by that member key**, so attribution is cryptographic, not merely uid-based. A future challenge–response (client proves possession of the member key on connect) hardens this further; not required for v1 given (8).

### 5.3 Same-user fast path

When the caller's uid **is** the owner (the common case — the owner's media app talking to the owner's forest), the client may open the library directly (it can read `.pvfs/` and holds the owner key) and skip the socket entirely. The daemon is for **cross-user** access. Both paths enforce the same ACL/authorization rules.

---

## 6. Access surfaces (three, by privilege)

| Surface | Who | Privilege | Mechanism |
|---------|-----|-----------|-----------|
| **Library / same-user** | the owner's own apps | none | direct `Engine` open of `.pvfs/` (owner uid) |
| **Daemon socket** | other local users' apps | none | connect to owner's socket; peer-cred auth; ACL-enforced; member-signed writes |
| **FUSE mount** | any app on the host, path-based | **`sudo`/admin** | a privileged mounter exposes a forest as a real filesystem; under the hood a daemon client; node ACLs mapped to POSIX checks |

This matches the vision: regular users create and use forests (library/daemon, no `sudo`); making a forest look like a system-wide real filesystem is admin-only (FUSE).

---

## 7. Discovery registry (one-time `sudo`)

The host registry from doc 05 (`/etc/pvfs`, or `/var/lib/pvfs` for writable state) becomes the **discovery map** so any user's app can find forests shared with it:

```toml
# forests.d/<slug>.toml
mount  = "/home/alice/media"
alias  = "alice-media"
owner  = "alice"                 # owning uid/user
socket = "/run/pvfs/alice/media.sock"   # owner daemon's listening socket
enabled = true
# instance_id, forest_id — cached at register time (so listing never reads private .pvfs/)
```

- Written by **`sudo pvfs forest register`** (one-time per forest) — the registry stays root-owned and trustworthy; users do **not** write it directly (no alias-hijack surface).
- Caching identity in the entry means `pvfs ls` can list forests **without** reading the now-private `.pvfs/` of other users.
- Resolving a shared forest yields its **socket**, which the client connects to; the daemon then enforces access.

---

## 8. On-disk permission summary

| Path | Mode | Owner | Rationale |
|------|------|-------|-----------|
| `<mount>/` | operator's choice | creator | workspace; the owner may share the *files* with a group independently of PVFS |
| `<mount>/.pvfs/` | **`0700`** | creator | engine state is private; all cross-user access is daemon-mediated |
| `<mount>/.pvfs/device.key` | `0600` | creator | per-device signing secret; never shared (sharing a key = forging writes) |
| registry `/…/forests.d/*.toml` | `0644` root | root | trusted discovery map; `sudo` to write |
| daemon socket | `0660`/owner, or `0666` + ACL in daemon | owner | reachability is gated by peer-cred + ACL, not socket bits |

---

## 9. Security model

- **Private by default.** No ACL grant ⇒ no access. `.pvfs/` `0700` enforces this even if the daemon is down.
- **No key sharing.** Each writer signs with their own authorized key; revocation is root-signed and kernel-enforced (§3.3). A stolen member key is contained by `DeviceRevoked` **on both paths**: authorship dies at the kernel (§3.3), and the key's direct `key:` ACL grants are **masked at access time** — a revoked key reads nothing, even where its ACL rows linger (they go inert, like a dead tag authority, doc 10 §9.2; compaction reclaims them, doc 11). *Never-authorized* keys are different: their `key:` grants apply without membership — that is the ephemeral guest-key / public-link path (doc 13 §E). So the access rule is: owner ⇒ full; active member ⇒ `key:` + `tag:` + `any` + `public`; never-authorized ⇒ `key:` + `public`; revoked ⇒ `public` only.
- **Faithful authorship.** Every event names and is signed by its real author; the owner's daemon cannot silently forge another member's writes (it doesn't hold their key), and a replica re-verifies independently.
- **Daemon compromise.** A compromised owner daemon can mis-serve *that owner's* forest (it holds the owner key) but cannot author as other members, and cannot touch other owners' forests (separate uids, `0700`).
- **Peer-cred trust.** uid→principal rests on kernel-supplied peer credentials; acceptable under trust assumption (8). Optional connect-time key challenge removes even that assumption later.
- **Registry integrity.** Root-only writes; no user-writable registry ⇒ no alias hijack.

---

## 10. Implementation phasing

| Phase | Deliverable |
|-------|-------------|
| **A — foundation** | **`.pvfs/` `0700` (done)**; `authorize_member(pubkey)` + `forest authorize <member-pubkey>` / `forest revoke` CLI (root-signed, over the existing `DeviceAuthorized`/`DeviceRevoked` events); replay-time author-authorization enforcement (§3.3) shipped **behind a rebuild test**. *No protocol yet — proves the multi-writer kernel.* |
| **B — ACLs (done)** | `AclSet` event + `acl` projection table + inheritance/evaluation in core (`effective_rights`); apply-time admin check; `Engine::set_acl/effective_rights/acl_entries`; CLI `pvfs acl set|ls|check <node-id> …`. Read/write *enforcement* by caller arrives with the daemon (C). |
| **C — daemon** | per-user daemon, Unix socket, peer-cred auth, uid→principal binding, member-signed write protocol; registry gains `owner`/`socket`; client connects to shared forests. |
| **D — FUSE** | `sudo` system mount mapping nodes/ACLs to a real filesystem. |

P0 kernel encodings unchanged through A; B adds one event kind and one table; C/D are new processes around the kernel.

---

## 11. Open points

1. **Group principals** — whether ACL groups are PVFS-internal (members listed in-log) or resolved from OS groups by the daemon. Lean: PVFS-internal named groups (portable, federation-safe), with an optional daemon mapping from OS group → PVFS group.
2. **Explicit deny** — v1 is grant-only. Revisit if a "share all but one subtree" need appears.
3. **uid→principal proof** — peer-cred (v1) vs connect-time key challenge (later).
4. **Read-side attribution** — reads are not events; whether to audit-log reads in the daemon is a daemon policy, not a kernel concern.
5. **Encryption** — per-subtree confidentiality at rest (reserved key path `m/43'/20566'/2'`) is out of scope here; ACLs gate access to *plaintext via the daemon*, not at-rest secrecy. Tracked separately (P3 secure module).

---

## 12. Summary

| Topic | Decision |
|-------|----------|
| Sharing mechanism | Daemon-mediated (peer-cred auth + per-node ACL); **not** file-permission group sharing |
| Forest state perms | `.pvfs/` `0700`, `device.key` `0600` — private by default |
| Writer identity | Each writer authorized via root-signed `DeviceAuthorized`; **writes signed by the writer's own key** |
| Kernel addition | Enforce author-authorization on apply; add `AclSet` event + `acl` table |
| Access control | Per-node ACLs (`r`/`w`/`a`), inherited, grant-only v1, owner always full |
| Registration | One-time `sudo`; registry is a trusted discovery map (forest → owner → socket) |
| Surfaces | library (same-user) · daemon socket (cross-user) · FUSE (admin/`sudo`) |
