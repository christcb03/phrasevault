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
| **P2-C** | Daemon **read** path: `pvfs-proto`, `pvfsd`, `pvfs-client`, challenge-response auth, `pvfs remote`/`whoami` | ✅ shipped (doc 07 §1–4, build steps 1–5) |
| **P2-C (writes)** | Two-phase member-signed writes through the daemon | ☐ next (doc 07 §5) |
| **P2-C (data)** | `Cat` over the data plane; concurrent transfer threads | ☐ planned (doc 07 §6) |
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
  ACL-filtered. Verified by the smoke suite with real binaries.

## 3. Next deliverable: member writes (P2-C writes)

The one remaining piece for a usable multi-writer file server. Design in doc 07 §5. Shape:

- Split `Engine::add_node` (and siblings) into **build → sign → append** so a member's *own* key
  signs the node + link digests (the daemon never forges). New API sketch:
  `Engine::prepare_*(...) -> Prepared` (unsigned events + digests) and
  `Engine::commit_prepared(prepared, sigs) -> …` (fills sigs, re-checks ACL/author, appends).
- Daemon `PrepareWrite{op}` → returns hex-PCE preimages + a TTL'd `prepared_id`; client signs;
  `Commit{prepared_id, sigs}` → daemon assembles + appends.
- **Care:** a node create is *two* signed events (NodeCreated + LinkCreated) → two preimages/sigs
  per op. This touches the well-tested kernel, so it ships behind a dedicated test pass (member
  creates a node via the daemon; replay/rebuild still verifies authorship).

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
