# Changelog

PVFS uses the layered version scheme in [VERSIONING.md](VERSIONING.md): this
file tracks Layer 0, the file-system engine.

## Unreleased

- **In-flight streaming (P10.1, doc 23 §11):** everything an ingest session
  has verified serves **while the download runs**, through one seam —
  ranged `Cat` on the ingesting daemon. Marked chunks stream immediately;
  a request for unverified bytes *waits* server-side (60 s cap, lock-free)
  and registers as a **hot range** in `IngestList` — the demand signal the
  BT app maps to sequential piece priority, so hitting play reprioritizes
  the torrent. FUSE mounts (local or replica) proxy reads of in-flight
  files through the same op, gated by the early-serve license: the session
  opener must hold admin on the target, the attestation bar. Fleet phase K
  proved the arc across two machines: out-of-order ingest, mid-ingest
  chunk pulls, a blocked edge reader surfacing as demand and unblocking on
  verify, an in-flight consumer mount, and a bit-perfect post-commit read
  — **89/89**.
- **Replica-ingest race fixed (latent since P7.2b):** the follow job's
  sweep and a manual `replica sync` shipping the same tail concurrently
  could die on a PRIMARY KEY collision. Both ingest paths now take the
  write transaction first and verify-then-skip rows another writer already
  landed; a diverging row for an existing seq still refuses at its seq.
- **External-ingest sessions (P10.0, doc 23):** the seam a downloader app
  (first consumer: the PVOS BitTorrent app) uses to land bytes **as they
  arrive**. Six wire ops: `IngestBegin` catalogs the whole torrent up front
  (unhashed pointer nodes + a log-resident `pvos.download` origin record
  carrying the infohash) in one member-signed commit, with a free-space
  preflight (`allow_shortfall` overrides at the caller's risk);
  `IngestWrite` streams bytes sparse and out of order into a crash-safe
  partial (disk-full pauses, never poisons); `IngestVerified` turns the
  app's piece verification into marked 8 MiB chunks in an authoritative
  progress sidecar; `IngestCommit` runs the existing gates — hash-fill
  successor, `ChunkManifestRecorded` attestation, atomic publish — and the
  session's last commit (or `IngestAbort`) writes a `pvos.download.closed`
  record, so origin records never dangle. Sessions are deployment state
  (`ingest.sessions`) and survive kill -9; `pvfs ingest` drives it all from
  the CLI (bare form lists sessions). Live member commits may now batch
  nodes with intra-batch parentage (authority resolves at the nearest
  pre-existing ancestor — replay semantics unchanged), and `LinkSuperseded`
  joined the member-signable kinds (a latent gap the e2e test caught).
  Validated: 233 cargo tests + 366 smoke checks green on both hosts,
  clippy clean; USER-MANUAL §7.12.

## 1.4.0 — 2026-08-13

Validated end to end: the Ansible pipeline on two hosts (227 tests + 344
smoke checks, clippy clean), the chaos suite (20/20 — crash semantics
re-validated under the live-writer flock), and the two-machine fleet test
(`deploy/fleet-test.sh`, **75/75**: regions shipped to the edge hands-free,
attachment kinds draining and mirroring, a 1 GiB swarm split across two real
holders with kill -9 resume, and the streaming mount serving its first MiB
while the fetch ran).

- **Serve-while-fetching (P9.1, doc 22 §2):** the streaming mount delivers on
  punch J — opening an unfetched file whose chunk layout the owner attested
  starts a background chunked fetch, and each read waits only for the chunks
  covering its range (first MiB of a 1 GiB file in ~2 s on the fleet, fetch
  still in flight). The attestation (`ChunkManifestRecorded`, projection
  schema v7) is admin-gated on replay and binds the content hash; it is
  authored wherever a content hash is computed from bytes, in the same read.
  Unattested files keep the safe block-until-verified mount behavior and
  attest on their next re-hash.
- **The swarm data plane (P9.0, doc 22):** a fetch with two or more reachable
  holders pulls a hashed file as **parallel verified chunks from every holder
  at once** — 8 MiB BLAKE3 chunks, one worker per holder, bad chunks requeued
  to other seeds, dead holders dropped. Chunk manifests are computed at the
  sync sink (sidecar-cached) and served over two additive wire ops (ranged
  `Cat`, `ChunkManifest`); they are deliberately advisory — the catalog hash
  and the whole-file verify-then-rename gate remain the only trust anchor.
  Transfers are **resumable**: a kill at any point leaves a `.swarmpart` the
  next attempt re-verifies locally and completes (the long-standing chaos
  caveat, retired). Single-holder, small, and unhashed fetches keep the
  existing single-stream path byte-for-byte.
- **Attachment policies (P8, doc 21):** `pvfs bind <folder> <dir> --kind
  in-place|migrate|mirror [--to <store>]` — enrollment chooses the space's
  fate in one command. `migrate` = staging: the mover lands a verified copy
  in the store, retires the staged location (a new capability — the binding's
  own `file://` locations retire once a non-staged copy is live), and evict
  reclaims the bytes. `mirror` = the new `central-keep` placement mode: the
  mover maintains a verified second copy and never retires the source — a
  live backup that also seeds the future swarm (doc 20 §6). Placement file
  grows `central-keep` lines; `pvfs place <node> central-keep --to <dir>`
  exposes the mode directly.
- **Cross-region moves (P7.2c, doc 20 §2.5):** `mv` across a region boundary
  works — the paired protocol authors `NodeMovedOut` in the source region's
  log and `NodeMovedIn` in the destination's, one commit, one shared
  timestamp, each half carrying the other region's last committed head. Replay
  converges in either inter-log order; the moved subtree's sticky regions
  follow; orphan adoption across a boundary is the same protocol. New purge
  tombstones keep a purge that replays before its node's creation from
  resurrecting it (schema v6). Also fixes a latent pre-region bug: moving a
  node back under a former parent regenerates the same content-addressed link
  id, and recreation now reactivates the soft-removed row instead of being
  silently ignored.
- **The live-writer flock:** every open writer engine holds a shared `flock`
  on `writer.lock`; an engine opening a forest whose `clean_shutdown` flag is
  down now distinguishes "another writer is live" (catch up — no rebuild, no
  minutes-long lock holds under a running daemon) from "the last writer
  crashed" (full rebuild, exactly as before — chaos-suite re-validated). Ends
  the full-projection-rebuild-per-CLI-command era on daemon-served forests,
  and the SQLITE_BUSY races that came with it. Serve config verbs
  (`enable`/`disable`/`ls`/`status`) no longer open an engine at all.
- **Region logs over the wire (P7.2b, doc 20 §2.4):** `LogInfo`/`LogRead`/
  `LogWait` gain an additive **generation address** scope, gated on admin of
  the region's root; replicas discover generations by scanning shipped
  `RegionBaseline` rows and chain-verify each region log against its committed
  genesis before ingest. Whole-forest `replica add`/`sync`/`follow` ship every
  generation; `pvfs replica add --region <node>` scopes a replica to one
  region (absent siblings replay as attested-but-unfetched — replicas only;
  owners keep the strict check). Followers wake on any log's activity and
  sweep their generations, and the daemon attests dirty region heads on a
  60-second tick.
- **Physical region logs (P7.2a, doc 20 §2.3):** a marked region now owns its
  own signed, dense hash-chained log (`regions/<id>/g-*.db`). The mark commit
  carries a deterministic **baseline commitment** of the subtree's state (the
  doc 11 verifiable-snapshot subset), the region log's genesis binds it, and
  the enclosing log attests region heads (`SubRegionHead`, final one sealing
  the generation at unmark — files stay in place; a re-mark starts a fresh
  generation). Replay walks the tree of logs root-down, re-verifying every
  baseline and seal on every rebuild; membership checks became as-of-time to
  make parallel logs replay soundly. Legacy P7.0 marks split lazily at first
  writer open. New refusals guard causal isolation until P7.2c's paired-event
  protocol: cross-region orphan adoption, and purging a subtree that still
  contains a boundary. Projection schema v5 (one-time rebuild on first open).
- **Serve integration — the fleet runs itself (P5, doc 18):** `pvfsd` grows a job
  supervisor — `serve.jobs` deployment config (`pvfs serve enable|disable|ls|status|
  exports`, SIGHUP reload, corrupt-config-refuses-start), the F5.4 follower absorbed
  as the `follow` job, and `sync` / `export` / `tier` / `evict` as fold-nudged passes
  with 5-minute safety intervals and a catch-up pass at start. `pvfs export
  --keep-fresh` records a view the export job re-runs on change. **`pvfs fleet
  enroll`** admits a box's client identity (member + root rights) in one visible,
  logged, revocable step — the doc 17 §9 Q5 resolution (c): client identities dial,
  forest device keys never do. The fetch/tier/follow engines moved to `pvfs-client`
  (evict to core) so the CLI and daemon run one implementation.

## 1.3.0 — 2026-08-10

Validated end to end: the Ansible pipeline on two hosts (194 tests + 268
smoke checks, clippy clean) and the two-machine fleet test
(`deploy/fleet-test.sh`, 40/40, including a 3 GiB tier/evict/stream cycle
over the LAN) — see [HANDOFF.md](docs/HANDOFF.md) §2.

- **Tail-subscribe (P4 F5.4, doc 17 §7.5):** the `LogWait` long-poll — the
  daemon holds a gated log read (up to a server-capped 60 s) until new
  events arrive — and **`pvfs replica follow <mount>`**, the follower loop
  that long-polls, chain-verifies, ingests, and folds, with reconnect
  backoff and tolerance for concurrent local commands. Events authored on
  the owner appear on following replicas (and through daemons serving
  them) within seconds. This completes the doc 17 §7 arc: the ingest-box →
  central-store pipeline is built end to end.
- **The mover — tiered storage (P4 F5.3, doc 17 §7.4):** `pvfs place
  <subtree> central --to <dir>` (owner-side) declares "every file here must
  hold a verified copy in this store"; **`pvfs tier`** enforces it — bytes
  already on the owner's disks satisfy it in place, everything else is
  reached (locally or by read-through), streamed through the verified read
  path into a node-id-addressed store, and logged as a new location; only
  THEN are foreign-instance locations retired. **`pvfs evict`** on the edge
  acts on the catalog's retired rows for its own pin and deletes local
  bytes only when another live location is recorded — a stale replica
  evicts less, never wrongly. End-to-end: an ingest box catalogs a file,
  consumers stream it, the owner migrates it home, the edge reclaims its
  space, and the file never stops being available.
- **Remote read-through (P4 F5.2, doc 17 §7.3):** fetching now resolves
  **per file**: candidates are every `pvfs-host://` location whose pin the
  instance registry knows (the holder), then the replica's recorded source
  — pooled connections, dead targets skipped. `pvfs sync` / `export
  --fetch` therefore work when bytes live on a third instance the source
  can't read, and **`pvfs cat` self-heals**: a read with no local bytes
  fetches on demand (blocking, hash-verified, into the sync store) and
  serves — a catalog entry alone is enough to reach the bytes. Owned
  forests fetch too: `pvfs sync` on the owner pulls edge bytes home (the
  F5.3 mover's core primitive). Write-through's read-your-writes now folds
  the pulled tail into the projection immediately, so a daemon serving the
  same replica sees the change live.
- **Instance-qualified locations (P4 F5.1, doc 17 §7.2):**
  `pvfs-host://<transport-pin>/<abs-path>` records **which instance** holds
  a file's bytes — the pin is the host's F1 transport pin, so the claim is
  verifiable and survives address changes. Resolution is local exactly when
  the pin is the data dir's own; a foreign pin degrades cleanly (`stat`
  unavailable, `cat` skips, `missing_bytes` counts it) and `pvfs sync`
  already fetches such files through the replica's source, which resolves
  its own pin. New `pvfs loc add <file> --here <path>` records a path on
  this instance under its pin (requires having served with `pvfsd --listen`
  once); composes with write-through, so an ingest box records its own pin
  into the owner's log.
- **Write-through replicas (P4 F5.0, doc 17 §7):** mutations on a replica
  mount now **route to its recorded source** instead of being refused —
  `pvfs add` and `pvfs loc add` explicitly, and every op that auto-routes
  through the daemon-client path (`acl`/`tag`/`device`, secure ops), because
  a replica's "daemon" is its source now. Writes are member-signed with the
  client identity over the same two-phase protocol as `pvfs remote`; after a
  write-through the CLI best-effort pulls the source's log tail so the
  change is locally visible at once (read-your-writes; silently skipped
  without replication rights). Temp nodes, `link`/`unlink`/`reorder`, and
  `loc rm` stay unrouted (the engine still refuses locally); writes need
  the source reachable — no offline queue, offline divergence stays
  app-level (doc 13 §A). The write model is unchanged: single writer per
  forest — a "writable replica" forwards, never merges. Doc 17 §7 specs the
  rest of the arc (instance-qualified `pvfs-host://` locations, remote
  read-through, the tiering mover with edge eviction, tail-subscribe) —
  the download-box → NAS media pipeline.
- **Placement & sync (P4 F3, doc 17 §6) — the pointer-vs-sync knob:**
  `pvfs place <target> sync` marks a subtree "keep its bytes local" (a plain
  per-instance deployment file — never log events; different replicas
  legitimately pin different subtrees). `pvfs sync` (and `pvfs export
  --fetch`) then streams every file that has **no readable local location**
  from the replica's recorded source over the raw data plane, hashing while
  the bytes arrive: a hashed node must match its content hash exactly, a
  lazy node its recorded size — wrong bytes never land, failures report per
  file. Fetched bytes live in a managed node-id-addressed store
  (`<data-dir>/synced/…`) and the read path synthesizes a
  `pvfs-sync:///<id>` location **from the store's existence** — no new
  projection state, so synced bytes survive rebuilds by construction and
  the whole mechanism works on read-only replicas. Verify-on-read and
  quarantine apply to the store like any location; a fresh verified sync
  lifts a stale quarantine. With F0–F2 this completes the cross-host media
  scenario: replicate the catalog, place the library `sync`, export, point
  the media server at it.
- **Forest replicas (P4 F2, doc 17 §5 — doc 03 Mode A):** `pvfs replica add
  <mount> --instance <name> | --connect <addr> --pin <hex> | --socket <path>`
  pulls a served forest's **full signed log** and builds a local, read-only
  replica; `pvfs replica sync` ships the tail from the recorded source. Log
  shipping (`LogInfo`/`LogRead`) is gated on **admin rights on the forest
  root** — replication is an owner/admin capability, not a member read.
  Ingest verifies chain linkage row-by-row (fail fast on a tampered tail);
  the open then runs the standard startup replay, verifying the entire log —
  chain from genesis, every event signature, replay-time authorization — so
  *a replica that opens is a proven copy*. Replicas are ordinary forest dirs
  with a `replica` marker: `Engine::open` routes them to a read-only open
  (every local write refused; the owner instance stays the only writer),
  `pvfsd` serves them with identical ACL answers (the grants are in the
  shipped log), and `pvfs export` materializes them like any forest — the
  cross-host media library composes today from F0 + F2.
- **Network transport (P4 F1, doc 17 §4):** `pvfsd --listen <addr>` serves the
  full daemon protocol (reads, member-signed writes, the raw data plane) over
  **TCP+TLS** alongside the Unix socket — same `serve_connection`, one generic
  body. No CA: the daemon generates a self-signed cert on first use
  (`<data-dir>/nettls/`, key 0600) and clients verify only its **transport
  pin** (BLAKE3 hex of the cert DER, printed at startup and written to
  `nettls/pin`). New `pvfs instance add|ls|rm` remembers `(address, pin)`
  pairs — adding the entry is the pinning step — and `pvfs remote` gains
  `--connect <host:port> --pin <hex>` / `--instance <name>`. Challenge
  **nonces are now single-use** (registered at issue, consumed on first
  auth; doc 08 §4 item 7 closed): a captured signature can never be
  replayed, on either transport. Principals still authenticate per
  connection by challenge-response — TLS is transport privacy + server
  identity, never authorization.
- **`pvfs export` — the native tree view (P4 F0, doc 17):** materialize any
  tree as a plain directory that non-PVFS apps (media servers, backup tools)
  read natively — files from every bound location appear as one hierarchy.
  Symlinks by default; `--mode hardlink` for apps that refuse symlinks;
  `--mode copy` streams through the verified read path (a corrupted location
  quarantines instead of landing bytes). A `.pvfs-export` manifest marks the
  directory export-owned (never adopts a foreign directory) and makes re-runs
  idempotent: unchanged entries counted, departed entries pruned (`--prune`)
  or reported stale. Files without local bytes, secure blobs, and folder refs
  are skipped with per-entry reasons. First slice of the federation & sync
  track (doc 17 phases F0–F4).
- **Companion: `POST /redeem-invite`** — join a PVOS server from the browser
  (PVOS D18 §2.7): one human prompt pairs the server and signs the invite
  acceptance with the identity key; redeem prompts show the signed email, and
  pairing names pin the install.
- **Tenant custody: provision and remove hosted users over the socket**
  (PVOS D32).
- **`pvfsd`: sd_notify READY when serving** (PVOS D57) — `Type=notify`
  systemd units gate dependents on the socket actually accepting.

## 1.2.0 — 07/22/2026

- **Daemon: concurrent metadata reads** (doc 07 §6 split): `ls`/`stat`/
  `payload`/`info` and the `cat`/secure-cat control phase now run over a pool
  of read-only WAL views (`Engine::open_read_view`); only mutations serialize
  behind the writer. No async runtime; if a view can't open, reads fall back
  to the writer lock.
- **CLI: `pvfs remote` takes paths and `pvfs://` URIs** everywhere a node id
  was required — resolved over the daemon by ACL-filtered `ls` (the owner's
  engine is never opened), so callers can only resolve what they could list.
- **CLI: `pvfs remote add-node` / `payload`** — operator surface for the 1.1
  log-resident typed records (payload from a literal, `@<file>`, or `@-`).
- **CLI: `pvfs audit` completeness**: now also reports direct `key:` grants
  to revoked device keys (never-authorized guest keys stay unreported — their
  grants are live by design) and grants past their `expires_at`, as two new
  appended sections (JSON keys `inert_key_grants`, `expired_grants`).
- **Companion: pairing trust binds to the server key, not pinned urls**
  (PVOS D27, doc 14 §6.1): the relay envelope verifies against the paired key
  first; a relay from a new url for a known key gets a one-time "trust this
  new address?" prompt, remembered as a per-`(key, url)` trust grant
  (`pvfs-companion pairings trust|untrust`). Pairing no longer requires
  origins (`Pair.origins` optional; `API_VERSION` 3, additive) — no re-pair
  when a server moves or adds an https origin.
- **Companion: auto sign-in over trusted pairs** (PVOS D29, doc 16 §2):
  `sign_in` relayed over a trusted `(key, url)` auto-approves — no tap per
  login; prompts remain for first contact and admin/sensitive request types
  (`user_action` unchanged). Rate limit, lock, and audit unchanged.
- **Companion: web agent serves https** (PVOS M3.6 §4a): the loopback agent
  generates a `localhost`/`127.0.0.1` cert next to the vault (key `0600`),
  offers it to the macOS login keychain once, and serves port 7421
  **dual-mode** — a one-byte peek distinguishes a TLS ClientHello from plain
  HTTP, so https pages and older http callers share the port through the
  transition. Closes the reliance on Chromium's loopback mixed-content
  exemption.
- **Companion: singleton per user + restart** (2026-07-21 request, PVOS M3.5):
  `serve` takes over an existing instance on launch — kill via `<socket>.pid`
  (SIGTERM → SIGKILL), rebind the socket, re-acquire the stable web port —
  and `pvfs-companion restart` / the menu-bar "Restart agent" item make it
  explicit. The dual-instance socket-orphaning failure can no longer happen.
- **Expiring ACL grants** (doc 13 Q-E1): `AclSet` gains an optional
  `expires_at` (ms epoch, 0 = never). An expired grant is inert on the read
  path — masked by `effective_rights` like a revoked-authority tag grant —
  while the row stays listed (`acl ls` flags `[expired]`) until compaction.
  Backward compatible: the expiry is a trailing wire field written only when
  set, so 1.0 events decode unchanged and no-expiry events stay byte-identical
  (expiring grants sign under a new `pvfs:aclset:v2:` digest domain). Replay
  judges expiry at the row's chain-protected `written_at`, so writes
  authorized by a then-valid grant rebuild deterministically. Surfaces:
  `pvfs acl set … --expires <45s|30m|12h|7d|2w|@unix-ms>`, engine/client
  `set_acl_expiring`, daemon `SetAcl.expires_at` (serde-defaulted; old
  clients unaffected). Projection schema v3 (self-heals by rebuild).

## 1.1.0 — 07/09/2026

Backward-compatible additions + fixes surfaced by the first PVOS milestone
(the M1 walking skeleton builds and tests against this engine).

### Added

- **`AddNode` / `Payload` daemon ops** (doc 13, PVOS-driven): create a
  custom-typed node with a small inline payload (≤64 KiB, lives in the signed
  event log — auditable + replayable) and read it back, both ACL-gated.
  Reserved types (`file`/`folder`/`secure`) keep their dedicated ops. Client:
  `add_node()` / `payload()`. Carries PVOS grant records (`/grants`).

### Fixed

- **Daemon error fidelity:** `pvfsd` now sends `already_exists` as a typed
  error code instead of the `internal` catch-all, and `pvfs remote …` maps it
  back to `AlreadyExists` (exit 4), matching the local-path semantics scripts
  already rely on. (Surfaced by PVOS's idempotent hand-install path.)

### Security

- **Revoked keys are contained on the read path** (doc 06 §5, doc 06 §9 rule
  table). `effective_rights` now distinguishes a key's standing: *revoked* keys
  have their direct `key:` ACL grants masked at access time (previously only
  `any`/tag grants and authorship died with `DeviceRevoked`; a lingering `key:`
  row still granted reads). *Never-authorized* guest keys are unchanged —
  their `key:` grants apply without membership (the doc 13 §E public-link
  path). Found by the PVOS M1 §0 default-deny smoke gate; regression test in
  `p2_access.rs` (`revoked_key_acl_grants_are_masked_but_guest_keys_keep_theirs`).

## 1.0.0 — 07/03/2026

The first complete release: a standalone, multi-user, signed file-system
engine, ready to host an application layer (sync/file server) above it.
Everything below was built across the `0.1` development line (P0 → P3 +
companion phases 1–7); `1.0.0` is the point where the committed scope closed.

### The engine (P0–P1.5)

- Append-only signed event log with hash chaining; content-addressed, signed
  nodes and links; a disposable SQLite projection rebuilt from the log.
- BIP39/BIP32 identity: one recovery phrase; per-machine device keys signed by
  the root; recovery is recovery-only (everyday admin never touches the phrase).
- Storage: bind real folders, scan/reconcile, verified reads, quarantine,
  a `serve` watcher, temp spool.
- Mounts & registry: portable `<mount>/.pvfs/` forests, `/etc/pvfs` host
  registry (`PVFS_REGISTRY_DIR` override), `pvfs://alias@local/tree/path` URIs
  and path shorthand.

### Multi-user (P2 A–G)

- Per-node ACLs (`public`/`any`/`tag:`/`key:`) with grant-only inheritance,
  admin-checked grants, and replay-time authorization (a crafted log cannot
  smuggle rights).
- Per-key tag authority: a tag is `(authority, name)`, so one forest hosts many
  apps' namespaces; revoking an authority masks its tags immediately;
  `pvfs audit` reports inert grants forest-wide.
- The `pvfsd` per-user daemon: challenge-response auth, ACL-filtered reads,
  member-signed two-phase writes, live admin over the socket, a raw binary
  data plane with concurrent transfers, graceful SIGTERM/SIGINT shutdown with
  WAL checkpointing, and a `pvfsd@.service` systemd `--user` unit.
- Seamless CLI: plain `acl`/`tag`/`device` commands auto-route to a running
  daemon (signing with the forest's admin device key) and fall back to the
  direct engine.

### Encryption at rest (P3)

- The secure node type (`m/43'/20566'/2'`): an opaque **mutable encrypted
  blob** plus a **content-free signed hash-state ledger**; envelope encryption
  with ECDH-wrapped per-blob content keys; companion-gated decryption — the
  server alone holds only inert ciphertext.
- Secure stores work over the daemon (`SecureCreate`/`SecurePut`/`SecureCat`):
  apps create and update encrypted stores on the fly, member-signed,
  ciphertext-only on the wire.

### Key replacement & rotation (doc 15, cases A/B/C)

- Replace a lost identity key (index bump + root-signed swap + authority
  re-issue), replace a member key (dual-signed handoff), and rotate the root
  itself (`RootRotated` lineage) with an optional offline **recovery key** —
  the forest survives full seed compromise with its id and history intact.

### The companion (doc 14, phases 1–7)

- A local key custodian: the seed sealed in an OS-keychain or passphrase vault
  (Argon2 + AEAD), never written unsealed.
- A tiered signer over an owner-only Unix socket: root events always prompt,
  the owner's local identity ops are friction-free, everything is rate-limited,
  audit-logged (append-only JSONL), and idle-locked with on-demand re-unlock.
- Approval UI: desktop dialog or terminal prompt, headless denies.
- Multi-tenant custody for servers: per-user sealed vaults, session tokens for
  trusted devices, root ops always require a fresh unlock.
- "Sign in with PVFS": a loopback identity agent with a per-launch token and
  wallet-style origin connects — proven end-to-end against a live `pvfsd`.
- The joint PVFS⇄PVOS agent API (doc 16): broker-built `ApprovalContext`
  rendered in prompts and recorded in the audit log, the `user_action` request
  type (prompt-by-default), and an explicit `api_version` handshake.

### Explicitly after 1.0

Federation & sub-forest replication (doc 03), log compaction & verifiable
snapshots (doc 11), single-use challenge nonces (needed only when the socket
is network-proxied), named groups / explicit deny, Touch ID unlock, and a
read-only metadata connection pool.
