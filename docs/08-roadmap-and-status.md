# PVFS — roadmap, status, and open concerns (08)

Status: **Living document** — update as phases land. Last updated 2026-06-21.

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
| **P2-G per-key tags** | Multi-tenant tags: tag identity = `(authority, name)`, relaxed `MemberTagged` auth, scoped matching, authority-liveness masking — lets one forest host many apps' tag namespaces | ✅ shipped (doc 10) |
| **Companion** | Local root custodian + localhost identity agent ("Sign in with PVFS" auto-login) | ☐ future (doc 09 §6) |
| **Maintenance** | Forest-wide **rights audit** (`pvfs audit`) + **orphaned-tag sweep**: find grants/memberships under revoked authorities and remove them with signed events (`effective_rights` masks them live; the sweep cleans up) | ☐ future (doc 08 §4 items 13–14) |
| **P3** | Encryption-at-rest (reserved key path `m/43'/20566'/2'`), secure module | ☐ future |
| **P4** | Federation: `@server` ≠ local, remote catalog, sync; **torrent-like swarm**; **sub-forest (tree/region) replication & sharing** (PVOS-driven: per-app backup, peer-hosting, isolated-app cross-host links) | ☐ future (doc 03) |
| **Compaction** | Signed **snapshot / log re-genesis** to shrink `log.db` + rebuild time — rebuild a region's DAG from current state; **sealed archive** of the old log for audit + replica verification | ☐ future (doc 11) |

---

## 2. What works end-to-end today (verified by 74 Rust tests + 86 smoke checks, clippy-clean)

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

The recovery phrase is **recovery-only**; everyday admin is signed by the owner's device.

---

## 3. Next deliverables

1. **3d — seamless CLI auto-routing.** Make plain `pvfs acl set` / `tag add` / `device
   authorize-member` automatically dial a running daemon for that forest (signing with the local
   device key), falling back to direct-engine when none runs. The engine/daemon/client machinery is
   all in place; 3d is CLI wiring (an `admin_route` helper + routing the mutation handlers).
2. **Data plane** for `cat` — raw byte stream + concurrent transfer threads (the torrent seam).
   Bundle the **daemon lifecycle** (systemd `--user` unit + clean shutdown) and the **read-pool**
   here so the daemon is actually deployable (§4 items 2, 4).
3. **P2-G — per-key tags** (app-driven, doc 10): multi-tenant tag authority `(authority, name)`.
   Spec'd and low-cost — **no event wire change**, one `SCHEMA_VERSION` bump + a rebuild/replay
   parity test. Slot after 3d, or pull forward when PVOS needs it. Resolve the two design questions
   first (§4 items 11–12).
4. **Companion app** (its own track, doc 09 §6) — local root custodian + auto-login agent.

---

## 4. Open concerns / known loose ends — with fix plans

Real, tracked items. None block what's shipped. Each carries its planned fix and target phase.

1. **CLI mutations still go direct, not through the daemon.** Plain `pvfs acl set` / `tag add` open a
   separate engine. While a daemon runs those reads *are* seen live (shared SQLite), but two writers
   (CLI + daemon) on one store risk lock contention. Admin **over the daemon** already works (§3c).
   → **Fix (P2-E 3d, next):** an `admin_route` helper — each mutation handler resolves the forest's
   socket (`daemon_socket_path`); if a daemon answers, sign with the local device key
   (`DeviceKeyCache::load`) and submit via `Client::connect_signed`, else fall back to the direct
   engine. CLI wiring only; engine/daemon/client machinery already exists.

2. **Daemon concurrency is provisional (one `Mutex<Engine>`).** Ops serialize; the `cat` loop drops
   the lock between chunks.
   → **Fix (P2-F):** build the doc 07 §6 split — one serialized writer connection + a WAL read-only
   connection pool for metadata, so reads run concurrently and only mutations serialize. No async
   runtime; threads carry personal/small-team load.

3. **`cat` is ranged hex chunks, not a raw stream** (~2× bytes, no concurrent transfer path).
   → **Fix (P2-F):** the raw data plane (doc 09 §3) — control plane authorizes + resolves node →
   location, then bytes stream raw (length header + bytes) on a dedicated transfer path off the
   request loop. Also the torrent seam.

4. **No daemon lifecycle integration** (no systemd `--user` unit, no graceful shutdown).
   → **Fix (P2-F, with the data plane):** ship a `pvfsd@.service` `--user` unit + a clean-shutdown
   path that checkpoints the engine (WAL) and removes the socket. Small; pair it with P2-F so the
   daemon is deployable.

5. **One-home invariant not enforced at replay/commit.** The "one active `contains` home per node"
   rule is enforced by the *local* `link()` API; daemon `prepare_*` maintains it by construction, but
   a forged `LinkCreated` could add a second home.
   → **Fix (hardening, fold into P2-E 3d):** add the check to `projection::check_member_event`
   (`LinkCreated` arm) — reject a `contains` link whose child already has an active home — so the rule
   holds live *and* on replay. Cover with a forge test in `p2_access.rs`. Cheap; no schema change.

6. **`acl`/`remote` take node ids, not paths.**
   → **Fix (post-3d nicety):** reuse the existing path/URI resolver (already used by tree commands) in
   `acl`/`remote` arg parsing so a mount-relative path or `pvfs://` URI resolves to a node id.

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

**Resolved since earlier drafts:** `PvfsError::Forbidden` now exists; the daemon socket is
discoverable (conventional path, P2-E §3b); admit/revoke no longer need the recovery phrase (§3a);
admin can be done live through the daemon (§3c); P2-G's tag-authority granularity and liveness are
now **decided** (items 11–12, doc 10 §9).

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
