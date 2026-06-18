# PVFS — the per-user daemon & client protocol (07)

Status: **Decided** — implementation pending (`pvfsd` + `pvfs-client`); design locked 2026-06-16
Depends on: [06-access-control-and-daemon.md](06-access-control-and-daemon.md)

Phase C of doc 06: how another user's process talks to a forest it doesn't own. All six open
questions (Q-C1…Q-C6) are now resolved — see §8 for the decisions and rationale.

---

## 1. Shape

```
app ──unix socket──▶  pvfsd (owner's daemon, runs as owner)
 (holds identity key)   ├─ control plane: serialized writer + read-only conn pool (SQLite)
                        └─ data plane:   concurrent thread-per-transfer (bytes, no engine)
                                          └▶ <mount>/.pvfs/  +  file storage
```

- **One `pvfsd` per owning user**, serving that user's forests. The daemon is the only writer of
  the log on the host; same-uid callers may still use the library directly (doc 06 §5.3).
- Clients reach it over a **Unix-domain socket** (path published in the registry, §7), mode `0666`
  — reachability is gated by **ACL**, not socket bits.
- Three light pieces: **`pvfsd`** (daemon) · **`pvfs-client`** (Rust lib apps link) · **`pvfs`**
  (admin CLI, run on the server). The JSON protocol (§3) is itself the language-agnostic API, so a
  non-Rust app can speak it directly.

---

## 2. Authentication — challenge-response (key is the identity)

No uid→key table. The connecting **key** is the principal, proven cryptographically:

1. Client connects; daemon sends a fresh random **nonce**.
2. Client signs `PCE(nonce, forest_id, expiry)` with its **identity key** and returns `{pubkey, sig}`.
3. Daemon verifies → principal = that key. It then resolves the principal's tier (§4).

- The signed blob includes `forest_id` (a signature for forest A can't be replayed to forest B) and
  a short `expiry`; the nonce is single-use. Standard replay protection.
- A client that **skips** the handshake (or presents an unauthorized/unknown key) is **`Public`**
  (§4) — anonymous read of public-shared nodes only.
- Peer-cred uid (`SO_PEERCRED`/`getpeereid`) is **optional** defense-in-depth ("must be a local
  login"), no longer load-bearing for authorization.
- **Why this and not uid-mapping:** the same handshake works over the network, so it extends to
  federation (doc 03, P4) and torrent-like peering with **no rework**; uid-mapping dead-ends at the
  local socket. It also deletes a config file and keeps "the key is the identity" uniform with the
  rest of PVFS.

### Member identity
A member holds a generated standalone key at `~/.config/pvfs/identity.key` (0600, created on first
run; `pvfs whoami` prints the pubkey to hand to a forest owner). A member need **not** own a forest.
Lost key → owner re-authorizes a new one; stolen key → owner revokes (`DeviceRevoked`, Phase A).

---

## 3. Transport & framing — JSON envelope

Each message is `u32 length (LE) || JSON body`. JSON is debuggable and trivial for non-Rust
clients; PVFS identifiers are already hex strings, so the usual JSON binary/precision traps barely
apply. The one thing that must be **canonical** — the write preimage a client signs (§5) — is
carried as **hex-encoded PCE bytes** inside the JSON, so signing stays on the kernel's canonical
encoding. (u64 sizes/seqs are sent as JSON strings to dodge the 2⁵³ issue.)

Requests (v1): `Hello`/`Auth` (handshake, §2), `Info`, `Ls{node}`, `Stat{node}`, `Cat{node,range}`,
and the write pair `PrepareWrite{op}` / `Commit{prepared_id, signature}` (§5). Responses are typed
results or a typed error reusing `PvfsError` codes.

---

## 4. Principals & tiers (extends doc 06 §4)

| Principal | Who | Resolved from |
|-----------|-----|---------------|
| `Public` | **anyone**, even unauthenticated | the default when no key is proven |
| `Any` | any **authorized member** (holds an authorized, unrevoked key) | a proven authorized key |
| `Key(pk)` | one specific member | a proven specific key |

Evaluation (implemented in `projection::effective_rights`): an **owner device** (HD index, not the
member sentinel) is full-rights. Otherwise, walking the node and its `contains`-ancestors, a caller
gets the union of: **`Public` grants always**; **`Any` grants if they are an authorized member**;
and **`Key(pk)` grants for their own key**. Grant-only inheritance flows down the tree.

- **Forest existence is public** via the registry (world-readable entries) — listing registered
  forests needs no ACL. A forest's **contents** stay private unless the owner sets a `Public` (or
  `Any`/`Key`) grant on specific nodes.

---

## 5. Writes — two-phase, member-signed

The writer's own key signs (the daemon never forges), but the kernel allocates ids/order-keys/time
and must serialize appends — so a write is two phases:

1. `PrepareWrite{op}` — client sends a high-level intent (e.g. *create folder `media` under `P`*).
   The daemon checks the caller's ACL (`w` on the parent), builds the **canonical event preimage**
   (id digest, order key, timestamp), and returns the bytes-to-sign (hex-PCE) + a `prepared_id`
   (TTL'd).
2. `Commit{prepared_id, signature}` — client signs the preimage with its key; the daemon assembles
   the event (`author` = the member key + that signature), re-checks ACL, and appends.

Replay-time enforcement (Phases A/B) independently re-verifies author-authorization and admin, so a
buggy/bypassed daemon still cannot inject an unauthorized write. Thin clients only ever "sign these
bytes" — no kernel logic in the client (essential for non-Rust clients).

An **unauthorized/Public** caller cannot write at all (no key to sign with) — at most `Public` reads.

---

## 6. Concurrency — split control & data planes

The two planes have opposite needs, so they're built differently:

- **Control plane (metadata):** `ls`/`stat`/ACL checks/tree mutations hit SQLite (`rusqlite` is
  blocking and `!Sync`). One **serialized writer** connection + a **pool of read-only connections**
  (WAL allows many concurrent readers). So metadata reads run concurrently; only the cheap, rare
  mutations serialize. No async runtime.
- **Data plane (bytes):** once the control plane authorizes a read and resolves the node → storage
  location, streaming the bytes **never touches the engine**. So transfers run **concurrent,
  thread-per-transfer** — and this is exactly where **torrent-like chunk serving** lives later
  (many peers × many chunks, fully parallel, no SQLite involvement).

**tokio:** not used now. It earns its place only if a torrent *swarm* reaches a scale where
thread-per-transfer hurts — a later, **data-plane-only** optimization, isolated from the sync
control plane. Threads carry personal/small-team (and early swarm) loads fine.

Lifecycle: started on demand or systemd `--user`; clean shutdown checkpoints the engine.

---

## 7. Registry additions (doc 06 §7)

`forests.d/<slug>.toml` gains `owner = "<user>"` and `socket = "<path>"`, written at
`sudo pvfs forest register`. `pvfs ls`/resolve use them to find a shared forest's daemon; cached
identity means listing never reads a peer's `0700` `.pvfs/`.

---

## 8. Decisions (was: open questions)

- **C1 — wire format:** JSON envelope, length-prefixed; signable preimages as hex-PCE.
- **C2 — writes & anon:** two-phase member-signed writes; an unauthenticated caller gets **`Public`**
  reads only (and a new `Public` ACL tier was added, §4).
- **C3 — uid↔key binding:** *eliminated* by choosing key-based auth (C6).
- **C4 — concurrency:** split planes — serialized writer + read-pool (control) and concurrent
  thread-per-transfer (data); tokio deferred to a possible data-plane-only swarm optimization.
- **C5 — crates:** `pvfsd` + `pvfs-client` (apps) + `pvfs` admin CLI.
- **C6 — identity/auth:** generated standalone client identity + challenge-response; the key is the
  principal (federation-ready).

---

## 9. Foundation already in place (Phases A–B, landed & tested)

- `authorize_member`/revoke (root-signed) + **replay-time author-authorization**.
- `AclSet` events + `acl` table + `effective_rights` (Public/Any/Key tiers) + admin-checked grants.
- `.pvfs/` is `0700`; all cross-user access goes through the daemon.
- Enforcement primitives `Engine::can` / `Engine::readable_children` — the per-request checks the
  daemon calls.

## 10. Build order for Phase C

1. ☑ `Public` principal tier in the ACL model (additive — landed ahead of the daemon).
2. ☑ `pvfs-proto`: JSON frames + `auth_digest` + message types (unit-tested).
3. ☑ `pvfs-client`: connect + challenge-response handshake + `info`/`ls`/`stat`.
4. ☑ `pvfsd`: socket listener, handshake/auth, request dispatch via `effective_rights`/
   `readable_children`. **End-to-end ACL-enforced reads verified** (public + member clients over a
   real socket). *Engine shared behind a `Mutex` for now; read-pool optimization deferred.*
5. ◑ `pvfs` CLI client: `pvfs whoami` (generated client identity at
   `$XDG_CONFIG_HOME/pvfs/identity.phrase`) + `pvfs remote --socket <path> [--anon] info|ls|stat`.
   **Verified via the smoke suite** (owner grants `public r`, starts `pvfsd`, anon + signed clients
   read). Remaining: transparent remoting (`pvfs --forest <alias>` dials the socket) + registry
   `owner`/`socket` fields at register time.
6. ☑ Two-phase member-signed writes (`PrepareWrite`/`Commit`) — `Engine::prepare_add_node` /
   `commit_member_write`, the daemon's prepared-state, `pvfs-client::mkdir`, and
   `pvfs remote mkdir`. Authorization (author authorized + write-on-parent) is shared between live
   commit and replay (`projection::check_member_event`). **Verified end-to-end** (Rust + smoke).
7. ◑ More write ops on the same machinery: ☑ `add-file` (file node), ☑ `rm` (unlink from home).
   Remaining: file **locations** (record bytes), `mv` (re-home), and `set_acl` over the daemon.
8. ☐ Data-plane transfer threads for `Cat` (stream file bytes).
9. ☐ Federation/torrent hooks (later).
