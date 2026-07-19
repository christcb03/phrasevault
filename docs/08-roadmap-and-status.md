# PVFS — roadmap, status, and open concerns (08)

Status: **Living document** — update as phases land. Last updated 2026-07-11.

The single place to see what's built, what's next, and the known loose ends. Phase specs live in
docs 02–16; this is the index + the honest "what's not done yet."

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
| **Companion** | Root/identity key vault + local signer + localhost identity agent ("Sign in with PVFS") | ✅ **shipped** ([doc 14](14-companion-app.md) phases 1–7 + [doc 16](16-joint-agent-api.md)): vault, signer + policy, Unix-socket agent, CLI wiring, multi-tenant custody, OS keychain sealing, approval UI (prompts, rate limit, audit, lock/idle re-unlock), loopback identity agent, joint API (`ApprovalContext`, `user_action`, `api_version`, live `pvfsd` sign-in test). Touch ID / biometric unlock remains deferred (polish) |
| **Key replacement** | Identity swap, member handoff, root rotation + offline recovery key | ✅ **shipped** (doc 15 cases A/B/C) |
| **Maintenance** | Inert-grant flagging in `acl ls` / `tag ls` (revoked-authority rows shown `[inert]`) ✅; forest-wide **rights audit** (`pvfs audit`) ✅; revoked-device direct `key:` grants masked at access time ✅ (1.1). No signed sweep — masking handles correctness live, compaction reclaims the rows (items 13–14) | ✅ shipped (follow-on: audit also flagging `key:`→revoked devices) |
| **P3** | **Secure node type / encryption-at-rest** (reserved key path `m/43'/20566'/2'`): opaque **mutable encrypted blob** + **content-free signed hash-state log** + **companion-gated decryption**; per-blob replication opt-out. PVOS-driven (Messenger app) | ✅ **shipped** (doc 12): kernel ledger, mutable storage (atomic overwrite, integrity-on-read), envelope + companion gating (ECDH wraps, `2'/0'` key, `secure_unwrap` — server-alone = inert ciphertext), daemon path (`SecurePut`/`SecureCat`/`SecureCreate` — create + update secure stores on the fly while serving, managed storage, member-signed, ciphertext-only, multi-user tested), USER-MANUAL §8 + durability/recovery matrix |
| **1.1 (PVOS M1)** | Daemon `AddNode`/`Payload` (log-resident typed records), `stat` exposes home `parent`, typed `already_exists`, revoked-key `key:` ACL masking | ✅ **shipped** (tagged `v1.1`, 2026-07-09) — see [CHANGELOG](../CHANGELOG.md) |
| **P4** | Federation: `@server` ≠ local, remote catalog, sync; **torrent-like swarm**; **sub-forest (tree/region) replication & sharing** (PVOS-driven: per-app backup, peer-hosting, isolated-app cross-host links) | ☐ future (doc 03) |
| **Compaction** | Signed **snapshot / log re-genesis** to shrink `log.db` + rebuild time — rebuild a region's DAG from current state; **sealed archive** of the old log for audit + replica verification | ☐ future (doc 11) |

---

## 2. What works end-to-end today (~151 Rust tests + smoke suite, clippy-clean, CI-green on `main`)

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
- **Secure blobs (P3):** create/put/cat encrypted stores over the CLI and daemon; companion-gated
  unwrap — server alone holds inert ciphertext.
- **Companion:** local vault + signer + "Sign in with PVFS" loopback agent; end-to-end against live
  `pvfsd` (doc 16).
- **1.1 PVOS surface:** `AddNode`/`Payload` (log-resident typed records via `pvfs-client`), `stat`
  home parent, typed `already_exists`, revoked-key `key:` grant masking.

The recovery phrase is **recovery-only**; everyday admin is signed by the owner's device.

---

## 3. Road to 1.0 — the release checklist (nailed down 2026-07-03)

The engine is **feature-complete for the committed 1.0 scope**: signed tree + content, per-node
ACLs, per-key tags, the live daemon with seamless CLI, member-signed writes, a raw concurrent data
plane, replay-enforced authorization, encryption-at-rest (P3), key replacement/rotation (doc 15
cases A/B/C), and the companion through phase 6 + the doc 16 API spec. Every earlier must-have
(items 0–4 of previous drafts) is resolved — history lives in §4. What separates today from a
tagged `1.0` is **four gates**; everything else is explicitly 1.1+.

**Gate 1 — companion phase 7, PVFS side** (doc 16 §7 items 1, 2, 4) — ✅ **DONE (2026-07-03)**:

- ☑ **`ApprovalContext` on the sign surface** — optional `context` on `AgentRequest::Sign` and the
  tenant sign ops; the `Prompter` renders it (`approve_with_context`), the audit log records it
  whole; new `user_action` request type (identity key, prompt-by-default); a `digest_hex` that
  disagrees with the digest being signed is refused before any prompt (doc 16 §2–3).
- ☑ **`pvfsd` challenge consumer** — `pvfs-companion/tests/signin_pvfsd.rs` closes the "Sign in
  with PVFS" loop end-to-end against a live daemon (doc 16 §6); the signing closure is the
  app-side reference.
- ☑ **`api_version` handshake** — `API_VERSION` (= 1) + an `api_version` op on both the local
  agent and tenant sockets, answered even while locked (doc 16 §7 item 4).

(The `pvos.sso` service itself is PVOS-repo work consuming this API — **not** a PVFS 1.0 gate.)

**Gate 2 — docs current: ✅ DONE (2026-07-03).** `USER-MANUAL` covers secure blobs (§8), case C
rotation (§9), and the companion (§11); docs 14/16 flipped to built; README status table and
`VERSIONING.md` match reality; stale "not built" markers cleared (item 17, doc 13 Q-E3).

**Gate 3 — validation: ✅ DONE.** CI (build, tests, clippy *enforced*, smoke) green at the release
commit; validated on the Linux host via the Ansible pipeline.

**Gate 4 — release packaging: ✅ DONE.** `CHANGELOG.md` (the 0.1 → 1.0 narrative), workspace
version `1.0.0`, README + `VERSIONING.md` flipped, **tagged `v1.0` (2026-07-03)**.

**→ 1.0 SHIPPED.** This checklist is closed.

### 3.1 — 1.1 SHIPPED (2026-07-09)

Tagged `v1.1` after PVOS M1 feedback. Backward-compatible engine additions + fixes:

| Item | State |
|------|--------|
| **`AddNode` / `Payload` daemon ops** (doc 13 grants / log-resident typed records) | ✅ `pvfs-proto` + `pvfsd` + `pvfs-client` (`add_node` / `payload`); reserved types keep dedicated ops |
| **`stat` exposes home `parent`** (additive `NodeInfo.parent`) | ✅ |
| **Typed `already_exists`** (not `internal`) | ✅ daemon + `pvfs remote` exit mapping |
| **Revoked keys: mask direct `key:` ACL grants** on the read path | ✅ regression in `p2_access.rs` |

**Still polish / post-1.1 (not in the 1.1 tag):**

- **Touch ID / biometric unlock gate** (doc 14) — keychain seal covers at-rest; biometrics are UX.
- **Read-pool metadata concurrency** (§4 item 2) — data plane is off-lock; fine at personal/small-team scale.
- **Path/URI resolver in `remote` subcommands** (§4 item 6 remainder).
- **CLI `remote add-node` / `payload` wrappers** — library API exists; thin CLI surface optional for operators.
- **`key:`-grants-to-revoked-devices in `pvfs audit`** (§4 item 14 follow-on; masking already correct).
- **Richer tenant provisioning/rotation UX** (doc 14 §13 remainder) — driven by PVOS D18.

**Post-1.1 (unchanged tracks):** federation + sub-forest replication (P4, doc 03), compaction (doc 11) —
both carry the doc 15 lineage edges (checkpoint embeds the root lineage; federation pins genesis +
lineage) — single-use challenge nonce (when the socket is network-proxied), arbitrary named groups /
explicit deny, and cross-OS-user / two-host end-to-end (needs a second account/host; federation track).

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

4. **Daemon lifecycle. ✅ RESOLVED.** `SocketGuard` removes the socket on any clean exit;
   `pvfsd@.service` is a systemd `--user` unit template. **Graceful shutdown** now lands too: a
   SIGTERM/SIGINT handler sets an atomic flag, the accept loop (`serve_until`, non-blocking poll every
   200 ms) returns, and the daemon calls `Engine::shutdown_checkpoint` — `wal_checkpoint(TRUNCATE)` on
   the projection + attached `log` db, then `clean_shutdown = 1` — before `SocketGuard` drops. In-flight
   connection threads are best-effort (not joined) in v1. Covered by `serve_until_stops_on_shutdown_flag`
   and a smoke check (SIGTERM → exit 0, socket removed).

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

13. **Orphaned-tag cleanup. ✅ RESOLVED (no signed sweep — decided 2026-06-29).** The read path already
    **masks** tags under a revoked authority (item 12). A *signed-removal* sweep was considered and
    **rejected**: it can't even be expressed cleanly (an owner-signed `AclSet`/`MemberTagged` folds to
    `authority = owner`, so it can't target a *different* revoked authority's row without a wire-format
    change), and it would buy nothing — the append-only log never shrinks, and a rebuilt projection
    would just re-derive then re-mask the rows. So:
    - **Masking** already guarantees correctness (item 12).
    - **Inspection reports *effective* permissions, never a grant that isn't in force.** A grant whose
      tag authority is revoked is inert, so `acl ls` shows its effective rights as `-` and moves the
      stored value into an annotation: `- tag:crew (by a1b2)  [inert: authority revoked; granted r]`
      (JSON: `"rights"` = effective, `"granted"` = stored, `"active": false`). `tag ls` flags inert
      memberships the same way, and `acl check tag:<name>` excludes revoked-authority grants from its
      union (they're unsatisfiable, so this never changes access — it just makes the check effective,
      like `acl check key:`). This keeps a troubleshooter from reading a dead grant as live access.
      Built on the read-only `Engine::authority_active` / `projection::authority_active`; covered by
      `revoking_tag_authority_denies_access`.
    - **Physical removal** is deferred to **compaction's re-genesis** (doc 11 §… / item 15): rebuilding
      a region from current state simply doesn't carry inert rows forward — free cleanup, no new events.

14. **Forest-wide rights audit. ✅ SHIPPED (`pvfs audit`).** A **read-only** command that scans the
    whole forest for **stale/revoked authorizations** — tag grants and memberships whose authority key
    is no longer an active member (the per-node `[inert]` flag from item 13, lifted to a whole-forest
    report). Text lists each finding (`<node> tag:<name> (by <auth>) (granted <rights>)` and
    `<member> tag:<name> (by <auth>)`); `--json` emits `{inert_grants, inert_memberships}`. **No cleanup
    writes** — masking already makes them inert and physical removal is compaction's job (item 15).
    Implemented as `projection::inert_tag_grants` / `inert_memberships` (a direct `acl`/`member_tags`
    scan with the same liveness predicate as `member_tags_of`), surfaced via `Engine`. Pairs with
    `pvfs verify` (integrity) as the *authorization* health check. Covered by
    `audit_reports_inert_grants_and_memberships` + a smoke clean-case check.
    *Possible follow-on (post-1.0): also flag `key:` grants to revoked device keys.*

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

16. **Auto-route admin signs with the forest device key. ✅ RESOLVED (model (a)).**
    `daemon_client()` previously signed auto-routed `acl`/`tag`/`device` ops with the CLI client
    identity (`<config>/identity.phrase`, `device_key(0)`) — a **different key** from the forest
    owner's authorized device key in `<mount>/.pvfs/device.key` — so with a daemon running the
    "seamless" owner admin (`pvfs acl set …`) was rejected as non-admin. **Fix:** `daemon_client()`
    now loads the forest device key from `state_dir` (`<mount>/.pvfs/device.key`, mode `0600`, owner
    only) and signs with that authorized admin device; it falls back to the generic client identity
    only when that key isn't readable (a non-owner auto-routing against a forest it doesn't own).
    **Test:** the smoke suite gained a "P2-E 3d: auto-routed owner admin with the daemon RUNNING"
    section — it runs `pvfs acl set` / `tag add` with **no `--data-dir` and no `remote`** while
    `pvfsd` is up; rc 0 is decisive because the old client-identity signer (a member, not an admin)
    returned `forbidden`. This also covers the daemon-running half of Road-to-1.0 item 4.

17. **Owner / identity key replacement — ✅ BUILT (doc 15 cases A/B/C, 2026-07-03).** The companion (doc 14)
    makes a human's identity **one stable key across devices** (doc 10 §9.1), whose accepted cost is
    that you can't revoke a single lost machine's copy of the *identity* without rotating that key. That
    is only acceptable if a clean **key-replacement** path exists. Three cases: replace a lost/compromised
    **identity key** (re-issue its tag grants/memberships under the new key — they go inert until then,
    via existing masking); replace an **owner device key** (mostly `device revoke` + authorize-new, to
    confirm); rotate the **root key** (hardest — re-anchor `ForestCreated` to a new root while preserving
    content-addressed ids; interacts with compaction re-genesis item 15 and federation trust doc 03).
    → **Plan:** its own mini-spec (new doc) before companion §9 phase 7; see [doc 14 §11](14-companion-app.md).
    → **Drafted (2026-07-01):** [doc 15 — key replacement & rotation](15-key-replacement.md): identity-index
    bump + root-signed swap + `reissue_authority` re-homing (case A), revoke/re-authorize composition (case B),
    and a `RootRotated` **root lineage** with an optional offline **recovery key** so the forest survives full
    seed compromise with `forest_id`/history intact (case C).
    → **Built (2026-07-03):** all three cases shipped (`pvfs forest rotate-root` / `recovery-key` /
    `member replace`, doc 15 §6 decisions settled); the compaction-lineage and federation-pinning
    edges are folded into those tracks (docs 11, 03).

**Resolved since earlier drafts:** `PvfsError::Forbidden` now exists; the daemon socket is
discoverable (conventional path, P2-E §3b); admit/revoke no longer need the recovery phrase (§3a);
admin can be done live through the daemon (§3c); P2-G's tag-authority granularity and liveness are
now **decided** and **shipped** (items 11–12, doc 10 §9); CLI auto-routing (3d), the raw data plane
(P2-F), and one-home-at-replay all landed (items 1, 3, 5; §2); the auto-route admin signing identity
is fixed and tested with a daemon running (item 16). **Scope decided (2026-06-29):** companion app
and encryption-at-rest (P3) are both committed to 1.0.

---

## 5. Crate map

| Crate | Role | Depends on |
|-------|------|------------|
| `pvfs-core` (~8.1k LOC) | the kernel — log, nodes, links, ACLs/tags, identity/devices, mounts, storage, projection | — |
| `pvfs-proto` | daemon/client wire protocol (JSON frames, challenge digest, message types) | pvfs-core |
| `pvfsd` | per-user daemon — socket, challenge-response auth, ACL-enforced read/write/admin serving | pvfs-core, pvfs-proto |
| `pvfs-client` | client library — connect, handshake, read/write/admin requests | pvfs-core, pvfs-proto |
| `pvfs-cli` | the `pvfs` CLI (forest/tree/acl/tag/device admin + `whoami`/`remote`) | pvfs-core, pvfs-client, pvfs-companion |
| `pvfs-companion` | key vault + tiered signer + loopback identity agent (`pvfs-companion` binary) | pvfs-core |

Build/test via the Ansible pipeline to a Linux host (`deploy/ansible/`); CI mirrors it on GitHub.
See [INSTALL.md](INSTALL.md); user docs: [USER-MANUAL.md](USER-MANUAL.md); status: this doc; design: docs 02–16.
