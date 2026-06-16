# PVFS — the per-user daemon & client protocol (07)

Status: **Draft for review** — design + open questions; not yet implemented
Date: 2026-06-15
Depends on: [06-access-control-and-daemon.md](06-access-control-and-daemon.md)

Phase C of doc 06. This pins *how* another user's process talks to a forest it doesn't own:
the transport, authentication, the read and (member-signed) write flows, and where host-local
config lives. **Several decisions below are genuinely yours — they're marked `❓Q-Cn` and listed
in §8.** I wrote this so the build can start the moment those are answered; I did **not**
implement the daemon, because the wrong protocol choice is expensive to undo.

---

## 1. Shape

```
member's app ──unix socket──▶  owner's pvfs daemon  ──▶ <mount>/.pvfs/ (single engine)
   (holds member key)            (runs as the owner,        log.db / index.db
                                  peer-cred auth, ACL)
```

- **One daemon per owning user**, one engine handle per forest it serves (SQLite is single-writer;
  the daemon serializes). The daemon is the only writer of the log on the host.
- Clients reach it over a **Unix-domain socket** whose path is published in the registry
  (`socket = …`, doc 06 §7). Same-uid callers may keep using the library directly (doc 06 §5.3).
- The daemon authenticates each connection by **peer credentials** and enforces per-node ACLs
  (Phase B `effective_rights`) on every request.

---

## 2. Authentication — peer credentials

On `accept()`, read the connecting peer's uid from the kernel:
- Linux: `getsockopt(SO_PEERCRED)`; macOS: `getpeereid()` / `LOCAL_PEERCRED`.
The uid is kernel-supplied and unforgeable, so no passwords. The daemon maps **uid → principal
(member key)** via host-local config (§4). An unmapped uid is treated as `Principal::Any` if it is
an authorized member, else denied — **TBD by ❓Q-C2**.

---

## 3. Transport & framing

A connection carries length-delimited request/response messages. Each message:
`u32 length (LE) || PCE-encoded body`, mirroring the on-disk encoding (`encoding.rs`).
One in-flight request per connection (pipelining deferred).

Request kinds (v1): `Info`, `Ls{node}`, `Stat{node}`, `Cat{node,range}`, and the write trio
`PrepareWrite{op}` / `Commit{prepared_id, signature}` (§5). Responses are typed results or a
typed error (reusing `PvfsError` codes).

> ❓**Q-C1 — wire format.** Length-prefixed **PCE** (consistent with the kernel, compact, but
> bespoke) vs **newline-delimited JSON** (trivially debuggable, language-agnostic for non-Rust
> clients). I lean PCE for parity; JSON is friendlier if you foresee third-party clients.

---

## 4. uid → principal binding (host-local, owner-managed)

A uid↔member-key mapping is **host-specific and not portable**, so it must NOT be a forest event
(those are federated) and NOT the root-owned registry. It is the owner's local daemon config:

```
~/.config/pvfs/<forest_id>/peers.toml      # owned 0600 by the owner
[[peer]]
uid    = 1003
member = "key:<B-pubkey-hex>"              # must already be authorized in the forest
read_default = true                         # optional convenience
```

The owner edits this (or via `pvfs forest peer add --uid … --member …`), having first run
`pvfs device authorize-member` (Phase A) and granted ACLs (Phase B). The daemon trusts the
peer-cred uid and attributes the connection to the bound member key.

> ❓**Q-C3 — binding location.** `~/.config/pvfs/<forest_id>/peers.toml` (XDG, per-forest) vs
> `<mount>/.pvfs/peers.toml` (travels with the mount, but then it's inside the 0700 state dir and
> only meaningful on this host). I lean XDG since the binding is host-local, not forest data.

---

## 5. Writes must be signed by the member (the hard part)

Doc 06 §3 requires the **writer's own key** to sign — the daemon must not forge. But a valid event
needs kernel-allocated bits the client can't compute alone (content-addressed node id, sibling
**order key**, server timestamp), and appends must be **serialized** to avoid order-key races. So a
write is **two phases**:

1. `PrepareWrite{op}` — client sends a high-level intent (e.g. *create folder `media` under `P`*).
   The daemon checks the caller's ACL (`w` on the parent), builds the **canonical event preimage**
   (assigns id/order-key/timestamp), and returns the exact bytes-to-sign + a `prepared_id`.
2. Client signs the preimage with the **member key** and returns `Commit{prepared_id, signature}`.
3. The daemon assembles the event with `author = member key` + that signature, re-checks ACL, and
   appends. Replay-time enforcement (Phase A/B) independently re-verifies author-authorization and
   admin, so a buggy daemon still can't smuggle in an unauthorized write.

This keeps authorship faithful at the cost of one round-trip and a short-lived prepared-state.

> ❓**Q-C2 — confirm the two-phase model** (and whether an unmapped-but-authorized uid may write,
> or only read). The alternative — daemon signs on the member's behalf — was explicitly rejected
> by you, so two-phase is the path unless you want to revisit.
>
> ❓**Q-C6 — member identity.** The member needs a keypair to be authorized and to sign. Is it the
> key from *their own* forest's `.pvfs/`, or a purpose-made "client identity" we generate and store
> at `~/.config/pvfs/identity.key`? The latter is cleaner (a member need not own a forest).

---

## 6. Concurrency & lifecycle

Simplest correct model: the daemon owns **one engine per forest** and runs a **single worker**
that serializes all ops (reads and writes) through it; connection handlers hand requests to the
worker over a channel and await replies. Reads could later use separate read-only SQLite
connections for parallelism, but v1 keeps one writer + one reader path for safety.

Lifecycle: started on demand or via systemd `--user`; socket at a well-known per-forest path;
clean shutdown checkpoints the engine (existing `clean_shutdown` flag).

> ❓**Q-C4 — concurrency.** Single-worker + channel (simplest, safe) vs async (tokio) with a
> mutex-guarded engine. I lean single-worker threads (no async runtime dependency in the kernel
> path); say the word if you'd rather standardize on tokio.

> ❓**Q-C5 — crate.** New workspace binary crate name: `pvfsd` (daemon) + client support folded
> into the existing `pvfs` CLI (`pvfs --forest <alias> ls` dials the socket when the forest is
> remote-to-this-uid). Confirm the name.

---

## 7. Registry additions (doc 06 §7)

`forests.d/<slug>.toml` gains `owner = "<user>"` and `socket = "<path>"`, written at
`sudo pvfs forest register` time. `pvfs ls`/resolve use them to find a shared forest's daemon.
Identity (`instance_id`/`forest_id`) is cached in the entry so listing never reads a peer's 0700
`.pvfs/`.

---

## 8. Open questions (consolidated — please answer inline)

- ❓**Q-C1** wire format: PCE (lean) vs JSON.
- ❓**Q-C2** confirm two-phase member-signed writes; may an authorized-but-unmapped uid write or only read?
- ❓**Q-C3** uid↔key binding location: `~/.config/pvfs/<forest_id>/peers.toml` (lean) vs in `.pvfs/`.
- ❓**Q-C4** concurrency: single-worker threads (lean) vs tokio.
- ❓**Q-C5** crate name `pvfsd` + client in the `pvfs` CLI.
- ❓**Q-C6** member identity: reuse their own forest key vs a generated client identity key.

---

## 9. What already exists for C to build on (Phases A–B, landed & tested)

- `authorize_member` / revoke (root-signed) + **replay-time author-authorization** — only authorized
  keys can ever appear in the log.
- `AclSet` events + `acl` table + `effective_rights(principal, node)` + admin-checked grants.
- `.pvfs/` is `0700` (owner-private); all cross-user access must go through the daemon.
- Enforcement primitives (`Engine::can`, `Engine::readable_children`) — the per-request checks the
  daemon calls. (See §10.)

## 10. Enforcement primitives (added ahead of C, pure-core, tested)

- `Engine::can(principal, node, right) -> bool` — `effective_rights & right == right`.
- `Engine::readable_children(principal, node) -> Vec<ChildEntry>` — children filtered to those the
  principal may read (doc 06 §4.2). The daemon composes these; the owner-context engine is unchanged.
