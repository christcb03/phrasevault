# Changelog

PVFS uses the layered version scheme in [VERSIONING.md](VERSIONING.md): this
file tracks Layer 0, the file-system engine.

## Unreleased

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
