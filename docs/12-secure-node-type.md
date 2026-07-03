# PVFS — Secure Node Type / Encryption-at-Rest (12)

Status: **Buildable design** (§8–§9 added 2026-07-02; §1–§7 are the original design input) — PVOS-driven (the Messenger app); the P3 driver.
Date: 2026-06-21
Depends on: [01 (core engine)](01-core-engine-design.md), [02 (P0 spec)](02-p0-core-engine-spec.md), [04 (storage/FS ops)](04-p1-storage-and-fs-ops-spec.md), [11 (compaction)](11-compaction-and-verifiable-snapshots.md)
Motivation: a **privacy-first messenger** (and any app storing data the server must not read or retain forever) needs storage that is **encrypted so the server can't read it** and **truly deletable** — which the append-only log resists. This is the same crypto core as the original PhraseVault (envelope encryption, client-side decryption, server-as-blob-store).

---

## 1. Problem

PVFS is an append-only, content-addressed, signed log with soft-delete + compaction. Two app needs fight that:

1. **The server must not see content** (E2EE; keys never in server hands).
2. **Real deletion** — disappearing messages, delete-for-me — which an immutable log doesn't give (even compaction seals an *archive* of the old data).

Per-node encryption ("encrypt every node, keep them in the log") does **not** solve #2: the encrypted nodes still pile up immutably.

---

## 2. The model — an opaque mutable blob + a content-free hash-ledger

The app's private data is **one opaque encrypted blob** (its own encrypted DB file), not a set of log nodes:

- **Blob bytes** live at a storage **location** the app owns; the app **overwrites/truncates/deletes** them in place (decrypt → edit/delete inside → re-encrypt → write back). **Old bytes are discarded** — real deletion.
- The **log records only signed state-transitions**: `SecureBlobUpdated { blob_id, new_content_hash, author, time, sig }`. Content-free. The log proves *that* the blob changed and *who* changed it, **never what**.
- The node has a **stable identity** (the blob), with a **moving content hash** advanced by these signed events — unlike a normal content-addressed file (whose identity == content hash and whose old versions are retained).

**Trade (intended):** you give up *content* history/verifiability (the whole point — deletability) for a tamper-evident **state-transition** ledger (sequence + attribution). Integrity-on-write still holds: the daemon can verify current bytes match the current signed hash without seeing plaintext.

---

## 3. Encryption & companion-gated decryption

- **Envelope encryption** (the original PhraseVault model): content encrypted with a random **content key**; the content key **wrapped per credential** (owner identity key, a recipient's pubkey, a community-phrase-derived key). Any one credential unwraps. Server stores ciphertext + wrapped keys only.
- **Companion-gated:** the content key is wrapped under the **owner's identity (the companion)**. PVFS/the daemon will **not** yield plaintext, and the decryptor will not unlock, without the companion attached — **server-alone = inert ciphertext**, wherever it runs.
- The daemon **never holds the content key or plaintext**; decryption is client/companion-side. (For PVFS this means: the secure blob's bytes are opaque to `pvfsd`; it stores, verifies-against-hash, serves, and replicates *ciphertext* only.)

---

## 4. Replication

- A secure blob can **opt out of replication** entirely (the Messenger's local store does — each instance keeps its own; delivery is app-level, §5).
- If a secure blob *is* replicated, the daemon replicates **ciphertext** as-is (it can't do anything else — it has no key). Note this is the one case where content-addressing is of ciphertext the owner can rewrite; replicas hold whatever ciphertext was shipped.

## 5. What stays out of scope for PVFS

App-level concerns PVFS does **not** implement (the app/secure-module-above does): the key hierarchy (per-message/conversation keys), per-recipient wrapping policy, message **delivery/transport** between users, group epochs/rekey, forward-secrecy ratchets. PVFS provides the **opaque-mutable-blob storage + content-free signed hash-ledger + ciphertext-only handling**; the app builds messaging on top.

---

## 6. Impact / cost

- New node behavior: a **mutable blob** node (stable id, moving content-hash, old bytes discarded). New event kind `SecureBlobUpdated` (content-free). Likely a new node-type flag (`secure`) + a location that permits overwrite/truncate.
- Projection: track current `(blob_id → content_hash, author, time)`; no content indexed.
- Compaction (doc 11) interplay: secure-blob history is *already* content-free in the log, so compaction mostly reclaims superseded **bytes** at the location (the discarded old versions), not log entries.
- Keys: reuses the reserved encryption key path `m/43'/20566'/2'`; envelope/wrapping primitives.

---

## 7. Open questions

1. **Mutable-location semantics** — exact overwrite/truncate/secure-erase guarantees at the storage layer (and on different backends).
2. **Hash domain** — does the log hash the ciphertext, or a canonical plaintext digest the client provides (so replicas/recipients can agree on "what" without the server seeing plaintext)? Leaning: **ciphertext hash** (server-verifiable), since the local store isn't shared byte-for-byte anyway.
3. **Secure-erase on replicas / backups** — deleting locally can't force deletion on copies; document the limit (matches the crypto-shred reality).
4. **TEE / confidential computing** (decrypt on an untrusted host without it seeing memory) — a **later enhancement**, not P3-launch (PVOS DECISIONS D24).

Full app-side architecture: PVOS `docs/examples/messenger-app.md`.

---

## 8. Buildable design (settles §7; decisions marked, 2026-07-02)

### 8.1 The node

A third node type, `TYPE_SECURE = "secure"`. `NodeCreated` is unchanged on the wire — the type
string selects the behavior. A secure node's **identity** is its node id (stable, minted at
creation like any node); its **content** is described only by the moving hash in the projection
(§8.2), never by the node row. Labels stay plaintext (they're metadata the owner chose to expose;
apps that want opaque labels use opaque strings).

### 8.2 The ledger event

One new event kind, member-event class:

```
SecureBlobUpdated {
    blob_id:      NodeId,     // the secure node
    content_hash: [u8; 32],   // hash of the NEW ciphertext bytes (§8.4)
    size:         u64,        // ciphertext length (integrity + quota, not content)
    updated_at:   u64,
    author:       Vec<u8>,    // must hold WRITE (w) on the node; replay-enforced
    sig:          Vec<u8>,
}
```

Projection: `secure_blobs (blob_id PK, content_hash, size, updated_at, author)` — **last write
wins**, previous rows overwritten (the whole point: the log keeps the content-free transition
chain; the projection keeps only "current"). Replay/commit rule: author holds `w` on `blob_id`
(same `require_right` as writes), node exists and is `secure`.

### 8.3 Mutable location (§7.1 — DECIDED)

A secure node takes **exactly one location** (v1). It is normally **managed** —
`<data_dir>/secure/<node_id>`, allocated automatically on the blob's first write (§8.6), so an app
never chooses a filesystem path and a member can't point storage at an arbitrary owner path — with
an explicit `--path` escape hatch for local/advanced use. Either way it is added with the existing
`FileLocationAdded`. The storage layer treats a location on a `secure` node as
**overwrite-permitted**: `secure put`
writes the new ciphertext to a temp file in the same directory, fsyncs, and **renames over** the
old bytes (atomic on POSIX; discarded bytes are unlinked). No overwrite of location bytes is ever
permitted for `file` nodes — the existing quarantine-on-mismatch behavior stays their contract.
**Secure-erase guarantee (§7.3 — DECIDED: documented limit):** PVFS guarantees *logical* deletion
(the bytes are no longer referenced and the projection hash moves); physical remanence
(filesystem journals, SSD wear-leveling, replicas, backups) is explicitly out of scope —
crypto-shredding (discarding the content key) is the real erasure, and that is the app's/envelope's
job. `verify` on a secure node = hash the location bytes against the projected hash.

### 8.4 Hash domain (§7.2 — DECIDED: ciphertext hash)

The log hashes **ciphertext**. It's what the daemon can verify without keys, what replicas hold,
and what `verify` checks. Apps that need a plaintext-agreement digest put it *inside* the
authenticated envelope.

### 8.5 Envelope + companion gating (the `2'` branch)

PVFS ships a **reference envelope** (one canonical format, apps may bring their own):

- **Content key**: random 32 bytes; ciphertext = XChaCha20-Poly1305(content key) — same AEAD as
  the vault, one crypto suite in the codebase.
- **Wraps**: the content key encrypted to one or more **recipient public keys** via ECIES-style
  ECDH on secp256k1 (ephemeral key + HKDF → AEAD) — one wrap per credential, any one unwraps
  (§3). The envelope file/bytes: version, wraps `[{recipient_pubkey, ephemeral_pub, wrapped_key}]`,
  nonce, ciphertext.
- **The owner's encryption key** is `m/43'/20566'/2'/0'` — derived and custodied **only by the
  companion**, like the identity key. New companion request type `secure_unwrap` (tier: same row
  as identity ops — **auto while unlocked, local only**; never web, never a tenant token op).
  The companion returns the unwrapped **content key**, not the private key. Daemon and `pvfsd`
  never see keys or plaintext (§3): encrypt/decrypt happen in the client (CLI/app) with the
  companion supplying the unwrap.

### 8.6 Surface

- **Engine**: `prepare_secure_update(author, blob_id, hash, size)`; `secure_current(blob_id)`;
  secure nodes excluded from content dedupe/scan paths.
- **CLI** (prompt-first): `pvfs secure create <parent> <label>`; `pvfs secure put <node> [file]`
  (encrypts via the companion envelope by default, `--raw` for app-supplied ciphertext; writes
  bytes, commits the ledger event — auto-routes through the daemon like other writes);
  `pvfs secure cat <node>` (verifies hash, decrypts via companion; `--raw` for ciphertext out);
  `pvfs secure grant <node> <pubkey>` (re-wrap the content key for a recipient — client-side,
  since only a key-holder can).
- **Daemon**: ciphertext up/down over the existing raw data plane + the signed update in the
  member-write path; ACL-checked identically live and at replay.

### 8.6a Concurrency note (single-writer-per-store)

The two-phase member-signed write splits *write bytes* (data plane, off-lock) from *commit ledger*
(control plane), so two clients writing the **same** blob concurrently can interleave such that the
on-disk bytes are the last *writer*'s while the ledger head is the last *committer*'s — a **detectable**
(`secure verify`) and **self-healing** (next `put` fixes it) mismatch, the same shape as the
documented write-then-commit crash window (§8.3). This is fine under the design assumption of
**one writer per secure store** (a messenger's store, a per-app blob). Multiple concurrent writers to
one blob is out of scope for v1; a per-blob write lock would close it if a future app needs it.

### 8.7 Non-goals (v1, unchanged from §5)

Ratchets, group epochs, delivery, per-message keys, TEE (§7.4 stays post-1.0), multi-location
secure blobs, replica secure-erase.

## 9. Build plan (phased, pipeline-verifiable)

1. ☑ **Kernel** — `TYPE_SECURE`, `SecureBlobUpdated` (encode/decode/digest/sig, domain
   `pvfs:secureblob:v1:`), `secure_blobs` last-write-wins projection, the author-`w` rule wired into
   `check_member_event` (one seam = live commit AND replay), `prepare_secure_update` +
   `secure_current`. Tests: update chain + head replacement, full-rebuild parity, no-grant refused at
   prepare, TOCTOU (prepared-while-granted, committed-after-revoke) refused at commit, wrong node
   type / unknown node refused.
2. ☑ **Mutable storage** — `storage::atomic_overwrite` (tmp+fsync+rename, the one sanctioned
   overwrite); `add_location` admits secure nodes with the one-location rule; engine
   `secure_put_local` (validate → write bytes → advance the signed ledger, device-authored),
   `secure_read` (integrity-on-read against the head), `secure_verify`; CLI
   `pvfs secure create/put/cat/verify/status` (`--raw` required until phase 3 supplies the
   envelope default). Tests: put/read/overwrite (old bytes gone from disk), tamper → verify false
   + read Integrity, repair put, one-location rule, no-location refused. Smoke: the full
   put→cat→overwrite→tamper→repair cycle + rc contracts.
3. ☑ **Envelope + companion** — `pvfs_core::envelope` (XChaCha20-Poly1305 content key; ECDH-on-
   secp256k1 wraps with a per-wrap ephemeral key + `blake3::derive_key` KDF; PCE-serialized,
   multi-recipient; `seal`/`parse`/`unwrap_content_key`/`open_with_key`/`add_recipient`). The
   `2'/0'` **encryption key** joins the companion (`identity::encryption_key`, new `KeyRole::Encryption`);
   `SecureUnwrap` request type + `AgentRequest::SecureUnwrap`/`ContentKey` reply — local,
   auto-while-unlocked tier, the private key never leaves the agent (only the content key is
   returned). CLI: `secure put`/`cat` now encrypt/decrypt through the companion by default (`--raw`
   keeps the app-managed path), and `secure grant <pubkey>` re-wraps for a recipient without
   re-encrypting. Tests: envelope unit suite (multi-recipient round-trip, stranger/tamper refused,
   grant, raw-isn't-an-envelope); companion socket unwrap integration; smoke proves default-encrypt
   → on-disk bytes are NOT the plaintext → companion-decrypt round-trips → `--raw` shows the opaque
   envelope → grant + verify.
4. ☑ **Daemon path** — `SecureCat` (server verifies vs the ledger, then streams the opaque
   ciphertext on the existing data plane) and `SecurePut` (client uploads ciphertext frames →
   daemon writes them in place and prepares the member-signed `SecureBlobUpdated` → client signs +
   `Commit`s). Client `secure_cat`/`secure_put`; the CLI `secure put/cat/grant` **auto-route**
   through a running daemon (encrypt/decrypt stay client-side — the daemon only ever handles
   ciphertext). Integration test (`daemon_secure_put_and_cat_multi_user`): a member with `w`
   updates over the socket, the daemon writes exactly the uploaded bytes (no decryption), a
   read-only member downloads the verified ciphertext, and a member without `w` is refused; 256 MB
   upload cap.
4.5. ☑ **Create over the daemon (on the fly)** — apps provision a secure store *while the daemon
   serves*, no restart, no path chosen: `WriteOp::SecureCreate` mints the node, and its ciphertext
   location is a **managed** path (`<data_dir>/secure/<node_id>`) allocated on the first write by
   `prepare_secure_write` (which emits the `FileLocationAdded` + `SecureBlobUpdated` in one
   member-signed commit). So `secure create` needs no location, a member can't point storage at an
   arbitrary owner path, and the messenger "new chat = new encrypted store" case just works.
   `--path` still pins an explicit location for local/advanced use. Integration test
   (`daemon_creates_secure_store_on_the_fly`) + engine test (managed-location auto-allocation) +
   smoke (create→put→cat over the live daemon).
5. ☑ **Docs + audit** — USER-MANUAL §8 (secure blobs: create/put/cat/grant/verify/status, the
   companion-envelope default vs `--raw`, and the **durability & recovery matrix** — what survives
   rebuild/reboot/machine-loss and what doesn't); command-reference rows; roadmap updated (companion
   + encryption-at-rest now "built"). **Audit/verify coverage:** per-blob integrity is
   `pvfs secure verify` (bytes vs the signed head, rc 5 on mismatch); `pvfs audit` remains the
   *authorization* health check (inert grants) and is unaffected — a secure blob's ledger is already
   content-free, so there's nothing authorization-inert to sweep. A forest-wide secure-integrity
   sweep (verify every blob at once) is a natural future `pvfs verify --secure`, noted for post-1.0.
