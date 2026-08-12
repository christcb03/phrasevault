# PVFS — roadmap, status, and open concerns (08)

Status: **Living document** — update as phases land. Last updated 2026-08-10.

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
| **P4** | Federation: `@server` ≠ local, remote catalog, sync; **torrent-like swarm**; **sub-forest (tree/region) replication & sharing** (PVOS-driven: per-app backup, peer-hosting, isolated-app cross-host links) | ◑ **in progress** — phased in [doc 17](17-federation-and-sync.md); **F0 `pvfs export`** (native tree view), **F1 network transport** (`pvfsd --listen`, pinned TLS, single-use nonces), **F2 replicas** (verified log shipping, read-only serving), **F3 placement & sync** (`pvfs place`/`sync` — hash-verified bytes pulled local) built. **The cross-host media scenario works end-to-end.** Remaining: region logs, FUSE, swarm, failover (F4) |
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
- **Native view (P4 F0):** `pvfs export` materializes any tree as a plain directory
  (symlink / hardlink / hash-verified copy) for non-PVFS apps — a media server points its library
  at the export; idempotent re-runs, `--prune`, per-entry skip reporting (doc 17 §3).

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
  *Deferred by Chris (2026-07-22) — later.*
- ~~Read-pool metadata concurrency~~ ✅ **built for 1.2** (§3.2).
- ~~Path/URI resolver in `remote` subcommands~~ ✅ **built for 1.2** (§3.2).
- ~~CLI `remote add-node` / `payload` wrappers~~ ✅ **built for 1.2** (§3.2).
- ~~`key:`-grants-to-revoked-devices in `pvfs audit`~~ ✅ **built for 1.2** (§3.2, with expired-grant reporting).
- **Richer tenant provisioning/rotation UX** (doc 14 §13 remainder) — blocked on PVOS D18 (non-owner users).

### 3.2 — Unreleased (the 1.2 line, as of 2026-07-22)

| Item | State |
|------|--------|
| **Expiring ACL grants** (doc 13 Q-E1): `AclSet.expires_at`, read-path masking, `--expires`, daemon `SetAcl.expires_at`, projection schema v3 | ✅ built — *recovered from a stranded worktree*: authored post-1.0 but never merged, so the `v1.1` tag shipped without it; now rebased onto the 1.1 line (expiry masking composes with revoked-key `key:` masking) |
| **Companion: key-based pairing trust + auto sign-in** (PVOS D27/D29) | ✅ built (doc 14 §6.1, doc 16 §2) |
| **Companion: singleton per user + restart affordance** | ✅ built (doc 14 §2) |
| **Companion: web agent serves https** (PVOS M3.6 §4a) — localhost cert next to the vault, dual-mode port 7421 (TLS + plain http through the transition) | ✅ built (2026-07-22, after the validation run below; covered by the dual-mode e2e test) |
| **Metadata read pool** (doc 07 §6 split, §4 item 2): `pvfsd` reads (`ls`/`stat`/`payload`/`info` + `cat`/secure-cat control phase) run concurrently over read-only WAL views (`Engine::open_read_view`); only mutations serialize behind the writer | ✅ built (2026-07-22) |
| **`remote` takes paths/URIs** (§4 item 6 remainder): resolved over the daemon by ACL-filtered `ls`, never the owner's engine | ✅ built (2026-07-22) |
| **`pvfs remote add-node` / `payload`** — the CLI face of the 1.1 daemon ops | ✅ built (2026-07-22) |
| **`pvfs audit` completeness**: revoked-key direct `key:` grants + expired grants reported (guest keys stay unreported — their grants are live) | ✅ built (2026-07-22) |

The whole 1.2 line **validated on presubuntu** (2026-07-22): pipeline `deploy →
build → test → smoke` green — **172 unit/integration tests + 193 smoke checks,
0 failures**, clippy `-D warnings` clean (includes the expiring-grant
engine/wire/CLI tests, the D27/D29 trust + auto sign-in tests, the real-process
takeover/restart e2e, the read-pool cross-connection visibility test, and the
new remote path / add-node / audit smoke sections). Workspace at `1.2.0`;
`v1.2` tag pending (Chris tags manually).

### 3.4 — Unreleased (the post-1.3 line)

| Item | State |
|------|--------|
| **P5 serve integration** ([doc 18](18-serve-integration.md)) — the fleet runs itself: pvfsd job supervisor (`serve.jobs`, SIGHUP reload, `pvfs serve` verbs + live status), follow/sync/export/tier/evict as fold-nudged daemon jobs, `pvfs export --keep-fresh`, and **`pvfs fleet enroll`** (doc 17 §9 Q5 → resolution (c)) | ✅ built + fleet-validated 47/47 (2026-08-11) |
| **Chaos validation** ([deploy/chaos-test.sh](../deploy/chaos-test.sh)) — kill -9 either side mid-transfer, edge reboot mid-2GiB-fetch, follower through source death: no partial ever published, clean recovery throughout | ✅ run green (2026-08-11) |
| **P6 write-through completeness + `sync --to`** ([doc 19](19-write-through-completeness.md)) — loc rm/link/unlink/reorder over the wire, member-signed; the sync store moves to the big disk with both roots readable; plus the concurrent-fold race fix | ✅ built + validated (2026-08-11) |
| **P7.0 region boundaries + P7.3 FUSE streaming mount** ([doc 20](20-f4-regions-and-streaming.md)) | ✅ built + validated (2026-08-11) |
| **Punch batch** (surprise-behavior review): job auto-reload, enroll-guidance errors, rebuild notice, catalog mtimes on the mount, watcher→`watch` job + bare `pvfs serve` = status, member-gated `serve status`, tier commit-nudges | ✅ built + validated (2026-08-11) |
| **P7.2a physical region logs** ([doc 20](20-f4-regions-and-streaming.md) §2.3) — per-region signed logs with baseline commitments, head attestations, sealed generations, tree replay (schema v5); every rebuild re-verifies each baseline | ✅ built + validated both hosts (2026-08-11) |
| **P7.2b region logs over the wire** ([doc 20](20-f4-regions-and-streaming.md) §2.4) — generation-addressed log shipping (region-root gated), whole-forest replicas ship every generation (the P7.2a hazard is gone), `replica add --region`, follower region sweeps, daemon head attestation tick | ✅ built + validated both hosts (2026-08-11) |
| **P7.2d fleet region phase** ([deploy/fleet-test.sh](../deploy/fleet-test.sh) phase H) — ship one app's region to the edge across two real machines: hands-free follow sweep, verified cross-machine region streams, scoped replica isolation, seal verification | ✅ 57/57 (2026-08-11) |
| **P7.2c cross-region moves** ([doc 20](20-f4-regions-and-streaming.md) §2.5) — the paired protocol (`NodeMovedOut`/`NodeMovedIn`, shared timestamp, mutual head refs), order-free replay, subtree stickiness, purge tombstones; lifts the P7.0 mv refusal + the adoption refusal (schema v6); plus the latent link-id reactivation fix | ✅ built + validated both hosts (2026-08-11) |

**THE REGION ARC (P7.2) IS COMPLETE.** The queue's remainder: ② **P8**
attachment policies (doc 21, approved); ③ **P9** swarm data plane (doc 20 §6 —
parallel multi-holder chunk reads, resume, serve-while-fetching). The
**release cut** was waiting on this arc — it is now Chris's call (doc 19 §4's
packaging note: 1.4.0 = P5 + P6 + the P7 region/mount arc + fixes).

**The standing next-work list** (was HANDOFF.md §4; that file retired 2026-08-11 with the
`v1.2`/`v1.3` tags — its validation record lives in §3.3 above and doc 18 §7):

1. **Write-through completeness:** `loc rm`, `link`/`unlink`/`reorder` wire ops (deliberately
   unrouted in F5.0).
2. **`pvfs sync --to <dir>`** custom sync-store destinations (today: managed store under `.pvfs/`).
3. **Mode B crosslink** (doc 03 §6 Q4): a grant that lets a replica's held copy be recorded in the
   owner's log as catalog-visible redundancy (today only the owner's own `tier` does that).
4. **F4 tier** (doc 17 §8): region-granular logs (doc 13 §B — the decided design), FUSE
   read-through mount (open-and-stream without prefetch), swarm transfer (resumable/chunked —
   also the answer to interrupted-transfer restarts, per the chaos run), standby failover.
5. Doc 18 §6 leftovers: the P1 watcher as a `watch` job, tier's local-commit nudge, backoff tuning.
6. Long-deferred polish: Touch ID unlock (doc 14), stable macOS .app signing identity.

### 3.3 — the 1.3.0 line (released 2026-08-10)

> **Validation state: complete.** The real Ansible pipeline ran green on two hosts (presubuntu
> + pvos-test): release build, 194 tests, 268 smoke checks, systemd daemon stage, clippy clean.
> The **two-machine fleet test** (`deploy/fleet-test.sh`) passed **40/40** — USER-MANUAL
> §7.7–§7.10 across real machines, plus a 3 GiB ingest → tier → evict → stream cycle at
> ~37 MB/s over the LAN. Findings: doc 17 §9 Q5 and USER-MANUAL §7.9 (the authorize-member
> rule); the retired HANDOFF.md's full record is in git history at `v1.3`.
> Workspace at `1.3.0`; `v1.2` (pre-arc) and `v1.3` tags pending (Chris tags manually).

| Item | State |
|------|--------|
| **Companion: browser invite redemption** (PVOS D18 §2.7) — `POST /redeem-invite` on the web agent: one prompt pairs the server *and* signs the acceptance; redeem prompts show the signed email; pairing names pin the install | ✅ built (2026-07-27) |
| **Tenant custody: provision and remove hosted users over the socket** (PVOS D32) | ✅ built (2026-07-28) |
| **`pvfsd`: sd_notify READY when serving** (PVOS D57) — `Type=notify` units gate dependents on the socket actually accepting | ✅ built (2026-08-05) |
| **P4 F0: `pvfs export`** — the native tree view ([doc 17](17-federation-and-sync.md) §3): symlink/hardlink/verified-copy materialization, `.pvfs-export` manifest, idempotent re-runs + `--prune`, per-entry skips | ✅ built (2026-08-08) |
| **P4 F1: network transport** ([doc 17](17-federation-and-sync.md) §4) — `pvfsd --listen` serves the same protocol over TCP+TLS (pinned self-signed cert, **transport pin** = BLAKE3 of the cert DER, printed + `nettls/pin`); `pvfs instance add/ls/rm` + `remote --connect/--pin/--instance`; **single-use challenge nonces** (item 7 below — done ahead of the proxied-socket trigger) | ✅ built (2026-08-08) |
| **P4 F2: forest replicas** ([doc 17](17-federation-and-sync.md) §5, doc 03 Mode A) — `LogInfo`/`LogRead` ship raw signed rows (gated: **admin on the forest root**); `pvfs replica add/sync` ingests with row-by-row chain verification, then the standard replay verifies the whole log (chain + signatures + authorization) at open; replicas are ordinary read-only forest dirs (`replica` marker) — `pvfsd` serves them with identical ACLs, `pvfs export` works on them | ✅ built (2026-08-08) |
| **P4 F3: placement & sync** ([doc 17](17-federation-and-sync.md) §6) — `pvfs place <target> sync\|pointer` (deployment file, never log events); `pvfs sync` / `export --fetch` stream missing bytes from the replica's source over the raw data plane, **hash-verified while arriving**, into a managed node-id-addressed store; the read path synthesizes `pvfs-sync:///<id>` locations from store existence (no projection state — survives rebuilds, works on read-only replicas) | ✅ built (2026-08-08) |
| **P4 F5.0: write-through replicas** ([doc 17](17-federation-and-sync.md) §7 — the download-box arc, spec'd F5.0–F5.4) — mutations on a replica mount route to its recorded source, **member-signed with the client identity** (`pvfs add`, `loc add`, and every `daemon_client` auto-routed op — a replica's "daemon" is its source); best-effort read-your-writes tail pull; temp/link/loc-rm deliberately unrouted; no offline queue (doc 13 §A). The write model stays single-writer — a "writable replica" forwards, never merges | ✅ built (2026-08-08) |
| **P4 F5.1: instance-qualified locations** ([doc 17](17-federation-and-sync.md) §7.2) — `pvfs-host://<transport-pin>/<abs-path>`: which instance holds the bytes, as catalog truth; resolves locally only under the data dir's own pin, degrades cleanly elsewhere (and `pvfs sync` already fetches such files via the source); `pvfs loc add --here <path>` | ✅ built (2026-08-08) |
| **P4 F5.2: remote read-through** ([doc 17](17-federation-and-sync.md) §7.3) — per-file candidate fetch (registry-pinned holders first, then the replica source; pooled connections); **`pvfs cat` self-heals** (fetch-on-demand, verified, into the sync store); owner-side `pvfs sync` pulls edge bytes home (the mover's primitive); write-through folds its tail immediately so serving daemons see it live | ✅ built (2026-08-08) |
| **P4 F5.3: the mover** ([doc 17](17-federation-and-sync.md) §7.4) — `pvfs place <subtree> central --to <dir>` + **`pvfs tier`** (verified migration into a node-id-addressed store, logged as a location; foreign-pin locations retired only after the central copy is live) + **`pvfs evict`** (edge reclaims space from retired-own-pin rows, only ever with another live location recorded). **The download-box → NAS tiering pipeline is complete**: ingest → visible everywhere → migrate → evict, availability unbroken throughout | ✅ built (2026-08-08) |
| **P4 F5.4: tail-subscribe** ([doc 17](17-federation-and-sync.md) §7.5) — `LogWait` long-poll (gated like `LogRead`, server-capped hold, no push state) + **`pvfs replica follow`** (long-poll → verify → ingest → fold, reconnect backoff); owner events land on following replicas in seconds. **The doc 17 §7 arc is complete** | ✅ built (2026-08-08) |

**Post-1.1 (unchanged tracks):** federation + sub-forest replication (P4, doc 03 — **now phased and started**, [doc 17](17-federation-and-sync.md)), compaction (doc 11) —
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

2. **Control-plane concurrency. ✅ RESOLVED (1.2).** The doc 07 §6 split landed: `pvfsd` keeps one
   serialized writer `Mutex<Engine>` for mutations, and metadata reads run concurrently over a pool
   of **read-only WAL views** (`Engine::open_read_view` — same databases, `SQLITE_OPEN_READ_ONLY`,
   none of `open`'s startup writes), checked out round-robin. No async runtime. Best-effort: if a
   view can't open, reads fall back to the writer lock (the pre-pool behavior). Covered by
   `read_pool_sees_committed_writes_immediately` (cross-connection read-your-writes).

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

7. **Challenge replay window. ✅ RESOLVED (F1, 2026-08-08).** Auth binds `(nonce, forest_id,
   expiry)`; with the network listener (doc 17 §4) the deferred hardening landed: nonces are
   **registered at issue and consumed on first use** (server-side seen-set with expiry purge), on
   both transports — a captured auth signature can never be replayed. Covered by
   `nonce_is_single_use` and the TLS e2e test.

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

**Shipped (2026-07-22): web-agent HTTPS (PVOS M3.6 §4a).** The loopback agent serves 7421
dual-mode (TLS-or-plain via first-byte peek) with a generated localhost cert offered to the login
keychain — the https desktop no longer relies on the browser loopback mixed-content exemption.
Operational lesson: replacing a binary inside the .app breaks the ad-hoc bundle seal, and keychain
approvals stop sticking (prompt storms) — re-sign after any swap (`codesign --force --deep -s -`);
a STABLE signing identity for the .app would make approvals survive rebuilds (wanted, small).

**Built (2026-07-22, unreleased — companion trust + session UX, PVOS D27/D29):** (a) pairing now
binds to the server's **key**, not a pinned origin list: the relay envelope verifies against the
paired key first, and a relay from a new url for a known key prompts once ("trust this new address
for <server>?") and is remembered as a per-`(key, url)` trust grant (`pairings trust/untrust`
manage them; pairing itself needs no origins, `API_VERSION` 3 additive); (b) **auto sign-in** for
trusted (key, url) pairs — `sign_in` joined the auto tier (doc 16 §2), no approval tap per login;
prompts remain for first contact and admin/sensitive request types. Doc 14 §6.1. Details in PVOS
`docs/DECISIONS.md` D27/D29.

**Built (2026-07-22, unreleased — requested 2026-07-21 from PVOS M3.5 live testing):** the
companion is now a **singleton per user** — on launch `serve` detects an existing instance
(conventional socket + `<socket>.pid` pidfile) and **takes over: kills the stale copy (SIGTERM →
SIGKILL), rebinds the socket, re-acquires the stable web relay port** (retry while the predecessor
releases it). The observed dual-instance failure (menu-bar app + CLI `serve` both holding FDs on
the socket, later bind orphaning the first) can no longer happen; a pre-pidfile instance is
orphaned with a loud warning. Explicit **restart** affordances: `pvfs-companion restart` and a
menu-bar "Restart agent" item. Doc 14 §2.

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
