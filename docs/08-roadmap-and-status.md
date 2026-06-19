# PVFS — roadmap, status, and open concerns (08)

Status: **Living document** — update as phases land. Last updated 2026-06-17.

The single place to see what's built, what's next, and the known loose ends. Phase specs
live in docs 02–07; this is the index + the honest "what's not done yet."

---

## 1. Phase status

| Phase | Scope | State |
|-------|-------|-------|
| **P0** | Core engine: append-only log, content-addressed signed nodes, links, projection, identity/devices | ✅ shipped (doc 02) |
| **P1** | Storage backends, bound folders, scan/reconcile, verified reads, serve daemon (local watcher) | ✅ shipped (doc 04) |
| **P1.5** | Mounts, `/etc/pvfs` registry, operator URIs, `forest init`/`register`, ownership repair | ✅ shipped (doc 05) |
| **P2-A** | Multi-writer kernel: `authorize_member`, replay-time author-authorization | ✅ shipped (doc 06 §3) |
| **P2-B** | Per-node ACLs: `AclSet` events, `public/any/key` tiers, `effective_rights`, `pvfs acl` | ✅ shipped (doc 06 §4) |
| **P2-C** | Daemon **read** path: `pvfs-proto`, `pvfsd`, `pvfs-client`, challenge-response auth, `pvfs remote`/`whoami` | ✅ shipped (doc 07 §1–4) |
| **P2-C (writes)** | Two-phase member writes through the daemon: `mkdir`, `add-file`, `rm`; shared live/replay authorization | ✅ shipped (doc 07 §5) |
| **P2-C (more writes)** | `add-file`, `rm`, `add-location` over the daemon (member-signed) | ✅ shipped |
| **P2-C (writes todo)** | `mv` (re-home) and `set_acl` over the daemon | ☐ next |
| **P2-C (read content)** | `Cat` — read file bytes via the daemon (`pvfs remote cat`), ACL-checked, ranged chunks | ✅ shipped (basic) |
| **P2-C (data plane)** | Dedicated concurrent transfer threads + raw byte stream + streaming verify | ☐ planned (doc 07 §6) |
| **P2-D (tags)** | Tag-based sharing: `tag:` ACL principal + member tags, evaluated with inheritance | ✅ shipped (doc 09 §1) |
| **P2-D (live daemon)** | Admin/ACL/tag ops routed *through* the running daemon (single instance, live changes) | ☐ next (doc 09 §2) |
| **P2-C (UX)** | Transparent remoting (`pvfs --forest <alias>` dials the socket); registry `owner`/`socket` | ☐ planned |
| **P3** | Encryption-at-rest (reserved key path `m/43'/20566'/2'`), secure module | ☐ future |
| **P4** | Federation: `@server` ≠ local, remote catalog, sync; **torrent-like swarm** sharing | ☐ future (doc 03) |

---

## 2. What works end-to-end today

- Create a forest (`forest init`, owner-owned `.pvfs/` at `0700`), import a directory tree
  (skipping files you can't read), register it host-wide (`sudo forest register`).
- Manage the tree: add/move/link/remove nodes, bind+scan real folders, verified reads.
- **Multi-user access control:** authorize another user's key (`device authorize-member`), grant
  per-node rights (`pvfs acl set <node> public|any|key:<hex> rwa`), evaluate with inheritance.
- **Cross-user reads via the daemon:** run `pvfsd` as the owner; other users `pvfs remote … ls/stat`
  over the socket, authenticated by signing a challenge (or anonymous = `public`), every request
  ACL-filtered.
- **Cross-user writes via the daemon:** an authorized member with `w` creates nodes with
  `pvfs remote mkdir` — the daemon builds the events, the member signs them with their own key, the
  daemon appends. Each `LinkCreated` placement is checked for write on the parent both live and on
  replay (`projection::check_member_event`). Verified by the smoke suite with real binaries.

## 3. Next deliverable: more write ops + data plane

Member node-create lands the hard part (the prepare/commit + shared authorization spine). Next:

- **More `WriteOp`s** reusing the same two-phase machinery: add a file + its locations, `rmdir`/
  `mv` (link remove/supersede), and `set_acl` over the daemon. Each is one or two member-signed
  events — `prepare_*`/`commit_member_write` already generalize.
- **Data plane (`Cat`):** stream file bytes over concurrent transfer threads (doc 07 §6); the seam
  for torrent-like serving later.

---

## 4. Open concerns / known loose ends

Tracked so they aren't forgotten. None block the read path; most are tied to the write/data work.

1. **Daemon concurrency is provisional.** `pvfsd` shares the engine behind a `Mutex` — all ops
   serialize. The doc 07 §6 design (serialized writer + read-only connection pool + concurrent
   data-plane threads) is **not built yet**. Do it alongside `Cat`. *Correctness-first today, not
   the concurrent target.*
2. **No data plane yet.** The daemon serves metadata/listings, not file **bytes** (`Cat`).
3. **No daemon lifecycle integration.** No systemd `--user` unit, no graceful shutdown; the binary
   only clears a stale socket on start. Needed before real deployment.
4. **The daemon serves a snapshot — no hot-reload of out-of-band changes.** `pvfsd` opens the engine
   once; changes the owner makes *directly* (via `pvfs acl set`, `device authorize-member`, etc.
   while the daemon runs) are **not** seen until restart. Writes *through* the daemon are visible
   (same connection). For now: set up authorizations/ACLs **before** serving, or restart `pvfsd`.
   Proper fix: have the daemon catch up its projection from the log (or route admin ops through it).
4. **No `Forbidden` error type.** `Engine::set_acl` by a non-admin returns `BadInput` (exit code 2).
   Add a dedicated `PvfsError::Forbidden` when non-owner writes land (it maps cleanly to a daemon
   `forbidden` code).
5. **`acl`/`remote` take node ids, not paths.** Path/URI resolution for these is a deferred nicety
   (the rest of the low-level CLI is node-id based too).
6. **Challenge replay window.** Auth binds `(nonce, forest_id, expiry)`; the nonce is per-connection
   and random, the expiry short. Sound for local sockets; revisit nonce single-use bookkeeping if
   the socket is ever proxied.
7. **Named ACL groups & explicit deny** are deferred (doc 06 §11). v1 is `public/any/key`,
   grant-only (grants inherit *down*, can't be carved out).
8. **Registry is `/etc/pvfs` (root-owned).** Registration needs `sudo` (acceptable per design).
   A per-user/`/var/lib/pvfs` variant is supported via `PVFS_REGISTRY_DIR` but not the default.

---

## 5. Crate map

| Crate | Role | Deps |
|-------|------|------|
| `pvfs-core` | the kernel (log, nodes, ACLs, identity, mounts, storage) | — |
| `pvfs-proto` | daemon/client wire protocol (JSON frames, auth digest) | pvfs-core |
| `pvfsd` | per-user daemon (socket, auth, ACL-enforced serving) | pvfs-core, pvfs-proto |
| `pvfs-client` | client library (connect, handshake, requests) | pvfs-core, pvfs-proto |
| `pvfs-cli` | the `pvfs` CLI (admin + `whoami`/`remote`) | pvfs-core, pvfs-client |

Build/test via the Ansible pipeline to a Linux host (`deploy/ansible/`); see
[INSTALL.md](INSTALL.md). User-facing docs: [USER-MANUAL.md](USER-MANUAL.md).
