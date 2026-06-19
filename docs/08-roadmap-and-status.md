# PVFS — roadmap, status, and open concerns (08)

Status: **Living document** — update as phases land. Last updated 2026-06-19.

The single place to see what's built, what's next, and the known loose ends. Phase specs live in
docs 02–09; this is the index + the honest "what's not done yet."

---

## 1. Phase status

| Phase | Scope | State |
|-------|-------|-------|
| **P0** | Core engine: append-only signed log, content-addressed nodes, links, projection, identity/devices | ✅ shipped (doc 02) |
| **P1** | Storage backends, bound folders, scan/reconcile, verified reads, local watcher | ✅ shipped (doc 04) |
| **P1.5** | Mounts, `/etc/pvfs` registry, operator URIs, `forest init`/`register`, ownership repair | ✅ shipped (doc 05) |
| **P2-A** | Multi-writer kernel: authorize members, replay-time author-authorization | ✅ shipped (doc 06 §3) |
| **P2-B** | Per-node ACLs: `public`/`any`/`tag`/`key`, inheritance, admin-checked grants | ✅ shipped (doc 06 §4, 09 §1) |
| **P2-C reads** | Daemon read path: `pvfs-proto`/`pvfsd`/`pvfs-client`, challenge-response auth, `ls`/`stat`/`cat` | ✅ shipped (doc 07) |
| **P2-C writes** | Member writes over the daemon: `mkdir`/`add-file`/`add-location`/`rm`/`mv` (two-phase, member-signed) | ✅ shipped (doc 07 §5, 09 §4) |
| **P2-D tags** | Tag-based sharing: `tag:` principal + member tags, evaluated with inheritance | ✅ shipped (doc 09 §1) |
| **P2-E live daemon** | Phrase-free admin (root-or-admin-device), conventional socket discovery, **admin ops over the daemon** | ✅ shipped 3a–3c (doc 09 §2–3) |
| **P2-E (3d)** | CLI **auto-routes** plain commands (`acl`/`tag`/`authorize`) to a running daemon; direct-engine fallback | ☐ next (doc 09 §3d) |
| **P2-F data plane** | Raw byte stream for `cat` + concurrent transfer threads (today: ranged hex chunks) | ☐ next (doc 07 §6) |
| **Companion** | Local root custodian + localhost identity agent ("Sign in with PVFS" auto-login) | ☐ future (doc 09 §6) |
| **P3** | Encryption-at-rest (reserved key path `m/43'/20566'/2'`), secure module | ☐ future |
| **P4** | Federation: `@server` ≠ local, remote catalog, sync; **torrent-like swarm** | ☐ future (doc 03) |

---

## 2. What works end-to-end today (verified by 71 Rust tests + 86 smoke checks, clippy-clean)

- **Forests & ownership:** `forest init` (owner-owned `.pvfs/` at `0700`, raw-root refused), import a
  tree (skipping unreadable files), `sudo forest register` for host-wide listing, ownership repair.
- **Tree & content:** add/move/link/remove nodes, bind+scan real folders, verified reads, `cat`.
- **Access control:** authorize a member (admin device, **no recovery phrase**); grant per-node
  rights to `public`/`any`/`tag:<name>`/`key:<hex>` with inheritance; **tags** (tag content, tag
  people, access follows).
- **Cross-user over the daemon** (`pvfsd` runs as the owner; conventional socket at
  `$PVFS_SOCKET_DIR/<forest_id>.sock`; clients dial via `pvfs remote --forest <alias|mount>`):
  - **Reads:** `ls`/`stat`/`cat`, ACL-filtered per caller, authenticated by challenge-response (or
    anonymous = `public`).
  - **Member writes:** `mkdir`/`add-file`/`add-location`/`rm`/`mv` — the daemon builds the events,
    the member signs with their own key, the daemon appends. Authorization is enforced identically
    live and on replay.
  - **Live admin:** the owner connects to their own daemon and authorizes members / grants ACLs /
    assigns tags **over the socket** — changes take effect immediately, no restart.

The recovery phrase is **recovery-only**; everyday admin is signed by the owner's device.

---

## 3. Next deliverables

1. **3d — seamless CLI auto-routing.** Make plain `pvfs acl set` / `tag add` / `device
   authorize-member` automatically dial a running daemon for that forest (signing with the local
   device key), falling back to direct-engine when none runs. The engine/daemon/client machinery is
   all in place; 3d is CLI wiring (an `admin_route` helper + routing the mutation handlers).
2. **Data plane** for `cat` — raw byte stream + concurrent transfer threads (the torrent seam).
3. **Companion app** (its own track, doc 09 §6) — local root custodian + auto-login agent.

---

## 4. Open concerns / known loose ends

Real, tracked items. None block what's shipped.

1. **CLI mutations still go direct, not through the daemon (until 3d).** Plain `pvfs acl set` /
   `tag add` open a separate engine. While a daemon runs, those reads *are* seen live (shared
   SQLite), but two writers (CLI + daemon) on one store risk lock contention — 3d removes this by
   routing mutations through the daemon. Admin **over the daemon** already works (P2-E §3c).
2. **Daemon concurrency is provisional.** `pvfsd` shares the engine behind a `Mutex` — ops serialize
   (the `cat` chunk loop releases the lock between chunks). The read-pool + data-plane design
   (doc 07 §6) is not built.
3. **`cat` is ranged hex chunks, not a raw stream.** ~2× bytes on the wire, no concurrent transfer
   path. The data-plane work (P2-F) fixes this and is the torrent seam.
4. **No daemon lifecycle integration.** No systemd `--user` unit, no graceful shutdown; the binary
   only clears a stale socket on start.
5. **One-home invariant not enforced at replay/commit.** The "one active `contains` home per node"
   rule is enforced by the *local* `link()` API; the daemon's `prepare_*` ops maintain it by
   construction, but a forged `LinkCreated` could add a second home. Hardening item — add the check
   to `check_member_event`.
6. **`acl`/`remote` take node ids, not paths.** Path/URI resolution is a deferred nicety (the
   low-level CLI is node-id based throughout).
7. **Challenge replay window.** Auth binds `(nonce, forest_id, expiry)`; nonce is per-connection and
   random, expiry short. Fine for local sockets; revisit nonce single-use if the socket is proxied.
8. **Arbitrary named groups & explicit deny** are deferred. v1 has `tag` groups, grant-only
   (grants inherit *down*, can't be carved out).
9. **Registry is `/etc/pvfs` (root-owned), register needs `sudo`** (by design). `$PVFS_REGISTRY_DIR`
   gives a per-user variant. Daemon **sockets** live in `$PVFS_SOCKET_DIR` (default `/tmp/pvfs`,
   world-traversable + sticky) — set to `/run/pvfs` for production.
10. **Additive schema, no version bump.** `acl`/`member_tags` were added via `CREATE TABLE IF NOT
    EXISTS` (SCHEMA_VERSION stays 1) — fine because they're additive and rebuildable; bump the
    version only on a non-additive change.

**Resolved since earlier drafts:** `PvfsError::Forbidden` now exists; the daemon socket is
discoverable (conventional path, P2-E §3b); admit/revoke no longer need the recovery phrase (§3a);
admin can be done live through the daemon (§3c).

---

## 5. Crate map

| Crate | Role | Depends on |
|-------|------|------------|
| `pvfs-core` (~7.9k LOC) | the kernel — log, nodes, links, ACLs/tags, identity/devices, mounts, storage, projection | — |
| `pvfs-proto` | daemon/client wire protocol (JSON frames, challenge digest, message types) | pvfs-core |
| `pvfsd` | per-user daemon — socket, challenge-response auth, ACL-enforced read/write/admin serving | pvfs-core, pvfs-proto |
| `pvfs-client` | client library — connect, handshake, read/write/admin requests | pvfs-core, pvfs-proto |
| `pvfs-cli` | the `pvfs` CLI (forest/tree/acl/tag/device admin + `whoami`/`remote`) | pvfs-core, pvfs-client |

Build/test via the Ansible pipeline to a Linux host (`deploy/ansible/`); CI mirrors it on GitHub.
See [INSTALL.md](INSTALL.md); user docs: [USER-MANUAL.md](USER-MANUAL.md); design: docs 06, 07, 09.
