# PVFS — Secure Node Type / Encryption-at-Rest (12)

Status: **Proposed (design input)** — PVOS-driven (the Messenger app); the P3 driver.
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
