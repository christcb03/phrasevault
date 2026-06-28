# PVFS — roadmap, status, and open concerns (08)

Status: **Living document** — update as phases land. Last updated 2026-06-25.

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
| **P2-E (3d)** | CLI **auto-routes** plain `acl`/`tag`/`device` mutations to a running daemon (path/URI args too); direct-engine fallback | ✅ shipped (doc 09 §3d) |
| **P2-F data plane** | **Raw binary byte stream** for `cat` (PROTO_VERSION 2), lock released before I/O → concurrent transfers; daemon lifecycle (SocketGuard + `pvfsd@.service`) | ✅ shipped (doc 07 §6) |
| **P2-G per-key tags** | Multi-tenant tags: tag identity = `(authority, name)`, relaxed `MemberTagged` auth, scoped matching, authority-liveness masking — lets one forest host many apps' tag namespaces | ✅ shipped (doc 10) |
| **Companion** | Local root custodian + localhost identity agent ("Sign in with PVFS" auto-login) | ☐ future (doc 09 §6) |
| **Maintenance** | Forest-wide **rights audit** (`pvfs audit`) + **orphaned-tag sweep**: find grants/memberships under revoked authorities and remove them with signed events (`effective_rights` masks them live; the sweep cleans up) | ☐ future (doc 08 §4 items 13–14) |
| **P3** | **Secure node type / encryption-at-rest** (reserved key path `m/43'/20566'/2'`): opaque **mutable encrypted blob** + **content-free signed hash-state log** + **companion-gated decryption**; per-blob replication opt-out. PVOS-driven (Messenger app) | ☐ future (doc 12) |
| **P4** | Federation: `@server` ≠ local, remote catalog, sync; **torrent-like swarm**; **sub-forest (tree/region) replication & sharing** (PVOS-driven: per-app backup, peer-hosting, isolated-app cross-host links) | ☐ future (doc 03) |
| **Compaction** | Signed **snapshot / log re-genesis** to shrink `log.db` + rebuild time — rebuild a region's DAG from current state; **sealed archive** of the old log for audit + replica verification | ☐ future (doc 11) |

---

## 2. What works end-to-end today (76 Rust tests + smoke suite, clippy-clean, CI-green on `main`)

- **Forests & ownership:** `forest init` (owner-owned `.pvfs/` at `0700`, raw-root refused), import a
  tree (skipping unreadable files), `sudo forest register` for host-wide listing, ownership repair.
- **Tree & content:** add/move/link/remove nodes, bind+scan real folders, verified reads, `cat`.
- **Access control:** authorize a member (admin device, **no recovery phrase**); grant per-node
  rights to `public`/`any`/`tag:<name>`/`key:<hex>` with inheritance; **tags** (tag content, tag
  people, access follows). **Per-key tag authority (P2-G):** a tag is `(authority, name)`, so one
  forest hosts many apps' namespaces without collision; any member may tag under its own authority;
  revoking an authority masks its tags immediately.
- **Cross-user over the daemon** (`pvfsd` runs as the owner; conventional socket at
  `$PVFS_SOCKET_DIR/<forest_id>.sock`; clients dial via `pvfs remote --forest <alias|mount>`):
  - **Reads:** `ls`/`stat`/`cat`, ACL-filtered per caller, authenticated by challenge-response (or
    anonymous = `public`).
  - **Member writes:** `mkdir`/`add-file`/`add-location`/`rm`/`mv` — the daemon builds the events,
    the member signs with their own key, the daemon appends. Authorization is enforced identically
    live and on replay.
  - **Live admin:** the owner connects to their own daemon and authorizes members / grants ACLs /
    assigns tags **over the socket** — changes take effect immediately, no restart.
- **Seamless CLI (3d):** plain `pvfs acl set` / `tag add` / `device authorize-member` **auto-route**
  to a running daemon for that forest (signing with the local device key), falling back to the direct
  engine when none runs — no two-writer hazard, no `remote` prefix. `acl`/`tag` commands now accept
  `pvfs://` URIs and mount-relative paths, not just node ids.
- **Raw data plane (P2-F):** `cat` streams **raw binary frames** (no hex, no JSON envelope;
  PROTO_VERSION 2). The daemon holds the engine lock only for the ACL check + path resolution, then
  releases it and streams from the filesystem — so transfers run **concurrently** across connections.
- **Daemon lifecycle:** `SocketGuard` removes the socket on any clean exit; stale sockets are cleared
  at next bind; `pvfsd@.service` is a systemd `--user` unit template for per-forest installs.
- **Replay hardening:** the one-active-`contains`-home-per-node invariant is now enforced at replay
  (not just the live API), so a crafted/corrupt log can't give a node two homes.

The recovery phrase is **recovery-only**; everyday admin is signed by the owner's device.

---

## 3. Road to 1.0

The core multi-user signed file server is **capability-complete**: signed tree + content, per-node
ACLs, per-key tags, the live daemon with seamless CLI, member-signed writes, a raw concurrent data
plane, and replay-enforced authorization. What remains for a shippable **1.0** is completeness,
hardening, packaging, and two scope calls. Tracked as a checklist; details in §4.

**Must-have for 1.0 (committed scope):**

0. **⚠ Fix the auto-route admin signing identity** (§4 item 16) — the seamless `pvfs acl set` (3d)
   signs with the CLI client identity, not the owner's authorized forest device key, so owner admin
   through a running daemon can be rejected by default. Decide the model (sign local admin with the
   `.pvfs/` device key, or auto-authorize the client identity at `forest init`) and **test it with a
   daemon running**. *Most important — it's a gap in a shipped feature.*
1. **Orphaned-tag sweep** (§4 item 13) — masking ships; add the daemon-side **signed sweep** that
   removes grants/memberships under revoked authorities. *Small; finishes P2-G.*
2. **`pvfs audit`** (§4 item 14) — forest-wide stale/revoked-permission scan + cleanup, warnings
   optional. The authorization counterpart to `pvfs verify`. *Small–medium.*
3. **Graceful daemon shutdown** (§4 item 4) — on SIGTERM/SIGINT, checkpoint the WAL and exit cleanly
   (SocketGuard already removes the socket). *Small.*
4. **Multi-user / two-host end-to-end test** — a scenario test (owner + member, separate identities,
   over the socket) beyond the single-host smoke suite. *Medium.*
5. **Release packaging** — `INSTALL.md` for the systemd path, `$PVFS_SOCKET_DIR=/run/pvfs` default in
   the unit, `LICENSE`, `CHANGELOG`, version tag, and a top-level `README`. *Medium.*
6. **Docs/manual sweep** — bring `USER-MANUAL` and docs 06–11 fully current with 3d + P2-F + P2-G
   (this pass started it). *Small, ongoing.*

**Nice-to-have for 1.0 (do if time; otherwise 1.1):**

7. **Read-pool concurrency** (§4 item 2) — the data plane is already off-lock; metadata still
   serializes behind `Mutex<Engine>`. A WAL read-only pool removes that. Fine to defer for
   personal/small-team scale.
8. **Path/URI everywhere** — `remote` subcommands still take node ids (the `acl`/`tag` resolver
   landed in 3d); extend it. *Small.*

**Scope decisions needed (these set the size of 1.0):**

- **Companion app** (doc 09 §6) — ship 1.0 with device-key signing and make the companion 1.1, or
  hold 1.0 for it? It's the strongest root-key story but its own application track.
- **Encryption at rest** (P3) — in 1.0, or 1.1? The key path is reserved; the feature is unbuilt.

**Explicitly post-1.0:** federation + sub-forest replication (P4, doc 03), compaction (doc 11),
single-use challenge nonce (only matters once the socket is network-proxied), arbitrary named groups
/ explicit deny.

---

## 4. Open concerns / known loose ends — with fix plans

Real, tracked items. None block what's shipped. Each carries its planned fix and target phase.

1. **CLI mutations route through the daemon. ✅ RESOLVED (3d).** `pvfs acl set` / `tag add/rm` /
   `device authorize-member`/`revoke` now auto-route to a running daemon (signing with the local
   device key via the `daemon_client()` helper), falling back to the direct engine when none runs or
   a recovery phrase is given (root-signed, can't proxy). The two-writer hazard is gone.

2. **Control-plane concurrency is still one `Mutex<Engine>` (data plane is now off-lock).** P2-F moved
   byte transfers off the lock (concurrent `cat`), but metadata ops (`ls`/`stat`/mutations) still
   serialize behind the mutex.
   → **Fix (1.0 nice-to-have / 1.1):** the doc 07 §6 split — a WAL read-only connection pool for
   metadata so reads run concurrently; only mutations serialize. No async runtime. Fine to defer at
   personal/small-team scale.

3. **`cat` raw data plane. ✅ RESOLVED (P2-F).** Raw binary frames (no hex/JSON), PROTO_VERSION 2; the
   daemon resolves the path under the lock then streams from the filesystem lock-free, so transfers
   run concurrently. This is also the torrent seam.

4. **Daemon lifecycle. ◑ MOSTLY DONE (P2-F).** `SocketGuard` removes the socket on any clean exit;
   `pvfsd@.service` is a systemd `--user` unit template.
   → **Remaining (1.0):** a **graceful shutdown** that traps SIGTERM/SIGINT and checkpoints the WAL
   before exit. Small.

5. **One-home invariant at replay. ✅ RESOLVED.** `projection::fold` now rejects a `LinkCreated`
   `contains` link whose child already has an active home (idempotent-replay-safe), so a crafted or
   corrupt log can't give a node two homes. Covered by `replay_rejects_double_home_link`.

6. **`acl`/`tag` take paths/URIs. ✅ RESOLVED (3d).** `acl set/ls/check` and `tag add/rm/ls` accept
   `pvfs://` URIs and mount-relative paths, not just node ids.
   → **Remaining (small):** extend the same resolver to the `remote` subcommands, which still take
   node ids.

7. **Challenge replay window.** Auth binds `(nonce, forest_id, expiry)`; nonce is per-connection and
   random, expiry short — fine for local sockets.
   → **Fix (P4, before the handshake is proxied/networked):** make the nonce single-use server-side
   (a short-lived seen-nonce set) when federation exposes auth over a network.

8. **Arbitrary named groups & explicit deny are deferred.** v1 has `tag` groups, grant-only (grants
   inherit *down*, can't be carved out).
   → **Plan:** revisit only on real need; grant-only inheritance is the deliberate v1 model. Per-key
   tags (P2-G) remove the multi-app pressure that would otherwise push on this.

9. **Registry is `/etc/pvfs` (root-owned), register needs `sudo`; sockets default to `/tmp/pvfs`.**
   → **Fix (deploy, with the P2-F lifecycle unit):** set `$PVFS_SOCKET_DIR=/run/pvfs` in the systemd
   unit for production; `$PVFS_REGISTRY_DIR` already gives a rootless registry variant. By design,
   not a code bug.

10. **Schema versioning. ✅ RESOLVED at `SCHEMA_VERSION` 2 (P2-G).** P2-G added the `authority` column
    to `acl`/`member_tags` (non-additive), so the version bumped to 2. Older projections **self-heal**:
    `startup_check` now drops and replays the projection from the log when it finds an older schema
    (it's a pure cache), while a *newer*-than-supported schema is still a hard stop. Note: doc 10 §5
    assumed `acl` already stored the author — it did not, so the work added the column to **both**
    tables (still no event wire change; the author was always in the event).

11. **P2-G — tag authority granularity. ✅ SHIPPED (doc 10 §9.1).** Tag matching is scoped to
    `(authority, name)` where the authority is the event author; apps sign with their own key, so one
    forest hosts many app namespaces without collision. The companion (doc 09 §6) makes a human's
    authority a stable phrase-derived identity key across devices; until then the author is the
    signing device key (documented multi-device caveat). Implemented: `authority` column on
    `acl`/`member_tags`, scoped `grant_for`, relaxed `MemberTagged` gate, `SCHEMA_VERSION` 2.

12. **P2-G — authority liveness. ✅ SHIPPED (doc 10 §9.2).** `effective_rights` counts a
    `(authority, name)` match only while the authority is a currently authorized, unrevoked member —
    `member_tags_of` masks memberships under a revoked authority on the read path (no write), so
    revoking an app drops its tags immediately. Verified by `revoking_tag_authority_denies_access`
    (live + across rebuild). Key rotation orphans an app's grants until re-issued (v1).

13. **Orphaned-tag cleanup *sweep*** (P2-G follow-on — masking shipped, removal pending). The read
    path already **masks** tags under a revoked authority (item 12); the dead `acl`/`member_tags` rows
    are still physically present.
    → **Plan:** a daemon-side **signed sweep** — the daemon (acting as the owner) appends the removal
    events (`AclSet` clear / `MemberTagged{granted:false}`) for orphaned grants/memberships it
    encounters. Removal is a *write* and needs a signer, so it must **not** run on the read path
    (a read can't sign, and the revoked authority can't sign its own cleanup) — it is triggered
    opportunistically by the daemon and by item 14.

14. **Forest-wide rights audit / verify** (`pvfs audit`, future). A command that scans an entire
    forest for **stale/revoked permissions** — grants/memberships whose authority key is no longer an
    active member, ACLs referencing revoked keys, orphaned tags — and **cleans them up** via signed
    removals, with per-item **warnings to the user optional** (`--quiet` to just fix, default to
    report). Reuses the item-13 sweep over the whole tree. Pairs with `pvfs verify` (integrity) as the
    *authorization* health check.

15. **Log / DAG compaction (signed snapshot + sealed archive). → spec'd in [doc 11](11-compaction-and-verifiable-snapshots.md).**
    The log is strictly append-only and **never shrinks** — even `purge` appends a `NodePurged` event
    — so `log.db` and full-rebuild time grow without bound (steady-state *reads* are unaffected; they
    hit the current-state projection). Compaction re-genesises a region from its *current* state into
    a fresh, smaller DAG. The key design points (doc 11): an **owner-signed `Checkpoint`** binds the
    pre-snapshot chain tip + a Merkle `state_root` + the archive ref; pre-snapshot events are **sealed
    into a content-addressed archive** (long-term audit), not discarded; that archive doubles as the
    **federation verification artifact** — a replica re-runs the archived log (deterministically) to
    prove the compaction is faithful *and* properly authored, or trusts the signature for the cheap
    path. Resolves doc 03 §6 Q8.

16. **⚠ Auto-route admin signs with the *client identity*, not the forest device key (1.0 must-fix).**
    `daemon_client()` signs auto-routed `acl`/`tag`/`device` ops with the CLI client identity
    (`<config>/identity.phrase`, `device_key(0)`), which is a **different key** from the forest owner's
    device key in `<mount>/.pvfs/device.key`. By default that client identity is **not** an authorized
    admin, so when a daemon is running the "seamless" owner admin (`pvfs acl set …`) would be rejected
    unless the owner first authorizes their own client identity and grants it admin. The smoke suite
    doesn't catch this — its admin ops run with explicit `--data-dir` **before** `pvfsd` starts, so
    they go direct (forest device key).
    → **Decide + fix (1.0):** either (a) for **local owner** admin, have the CLI sign with the forest
    device key it can read from `.pvfs/` (prefer the authorized admin device over the generic client
    identity), or (b) make "the owner's client identity is an admin member" an explicit, `forest
    init`-time step (auto-authorize the local client identity). Then add a test that exercises
    auto-routed admin **with a daemon running** (ties into Road-to-1.0 item 4).

**Resolved since earlier drafts:** `PvfsError::Forbidden` now exists; the daemon socket is
discoverable (conventional path, P2-E §3b); admit/revoke no longer need the recovery phrase (§3a);
admin can be done live through the daemon (§3c); P2-G's tag-authority granularity and liveness are
now **decided** and **shipped** (items 11–12, doc 10 §9); CLI auto-routing (3d), the raw data plane
(P2-F), and one-home-at-replay all landed (items 1, 3, 5; §2).

---

## 5. Crate map

| Crate | Role | Depends on |
|-------|------|------------|
| `pvfs-core` (~8.1k LOC) | the kernel — log, nodes, links, ACLs/tags, identity/devices, mounts, storage, projection | — |
| `pvfs-proto` | daemon/client wire protocol (JSON frames, challenge digest, message types) | pvfs-core |
| `pvfsd` | per-user daemon — socket, challenge-response auth, ACL-enforced read/write/admin serving | pvfs-core, pvfs-proto |
| `pvfs-client` | client library — connect, handshake, read/write/admin requests | pvfs-core, pvfs-proto |
| `pvfs-cli` | the `pvfs` CLI (forest/tree/acl/tag/device admin + `whoami`/`remote`) | pvfs-core, pvfs-client |

Build/test via the Ansible pipeline to a Linux host (`deploy/ansible/`); CI mirrors it on GitHub.
See [INSTALL.md](INSTALL.md); user docs: [USER-MANUAL.md](USER-MANUAL.md); design: docs 06, 07, 09.
