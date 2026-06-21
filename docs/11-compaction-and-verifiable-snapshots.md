# PVFS — Compaction & verifiable snapshots (11)

Status: **Proposed — design note (future)**
Date: 2026-06-21
Depends on: [02 (P0 core / log & chain)](02-p0-core-engine-spec.md), [03 (federation & trust)](03-federation-trust-and-uris.md), [06 (access control)](06-access-control-and-daemon.md)
Roadmap: [08 §4 item 15](08-roadmap-and-status.md) (Compaction row)

---

## 1. Problem — the log never shrinks

PVFS's log is **strictly append-only**. Every mutation is appended and hash-chained; even *deletion*
(`purge`) appends a `NodePurged` event rather than removing anything. So over a forest's life
`log.db` and the **full-rebuild time** (replay the whole log to rebuild the projection) grow without
bound — superseded links, moves, removed nodes, ACL/tag churn all accumulate forever. A long-lived
PVOS forest with many apps makes this acute.

What compaction does **not** fix: steady-state *read* latency. Reads hit the current-state projection
(`index.db`), which is already history-free, so queries are fast regardless of log size. Compaction
targets **disk** and **rebuild/replay time**, not query speed. Be precise about this when motivating
it.

---

## 2. What compaction is

Re-genesis a region from its **current** state into a fresh, smaller DAG:

- **Identities survive.** Node ids are content-addressed; link ids exclude `created_at`/`author`
  (doc 03 §3.2). A compacted DAG keeps the same node/link ids — what's discarded from the hot log is
  the **provenance history** (who/when/how the state was reached), not the current objects.
- **Current authorization survives.** The snapshot carries the live ACLs, tags, memberships, and
  device-cert state, so access control is unchanged across the cut.
- **Scope is a region** (a subtree), not necessarily the whole forest — which dovetails with
  sub-forest replication (doc 03 §1.5): the region is the natural unit for both.

---

## 3. The checkpoint event (new signed genesis)

Compaction emits one **owner/admin-signed `Checkpoint`** event that becomes the new chain genesis for
the region. It does **not** merely assert "here is the state" — it cryptographically **binds**:

| Field | Purpose |
|-------|---------|
| `prev_tip = (seq N, chain_hash[N])` | The **pre-snapshot chain tip** — pins the checkpoint to *this exact* prior history; it cannot claim a different past. |
| `state_root` | A **Merkle root** over the materialized current state (nodes, links, ACLs, tags, memberships). A succinct commitment to *what* was snapshotted. |
| `archive_ref` | Content hash (+ optional storage URI) of the sealed archive (§4). Locates the audit log; the *binding* is the hash, not the location. |
| `author` + `sig` | The owner or an admin device (the same root-or-admin-device rule as device certs, doc 09 §2.2). |

Because node ids are already content hashes, the `state_root` is cheap and meaningful: two parties who
compact the *same* state compute the *same* root.

---

## 4. The sealed archive (long-term storage & audit trail)

Pre-snapshot events are **not discarded** — they are sealed into a content-addressed **archive
artifact**: the original signed, chain-hashed log up to `seq N`.

- **Self-verifying.** Every event already carries `author` + `sig` and is chain-hashed, so the archive
  is tamper-evident *on its own*. Its tip **must equal** the checkpoint's `chain_hash[N]`, so it
  cannot be swapped for a different history without breaking either the chain or the checkpoint
  binding.
- **Where it lives.** It's just content-addressed bytes — keep it in cold storage, store it as a file
  node inside PVFS (dogfooding: a `FileLocationAdded` blob), and/or pin it to replicas for durability.
  Integrity is self-certifying wherever it sits.
- **Durability matters for the guarantee.** If the archive is lost, verification (§5) falls back to
  signature-only trust. So pin it where the audit guarantee is required.

---

## 5. Federated verification — the archive *is* the proof artifact

A replica (or auditor) accepts the checkpoint as a new chain root at the **assurance level it
chooses** — and the archive is what makes the strong level possible:

1. **Cheap (trust the anchor).** Verify the checkpoint's signature and that the author is an
   authorized admin. Accept `state_root` as the new genesis. No archive needed. (This is the baseline
   "trust the owner's snapshot.")
2. **Full (verify the anchor).** Fetch the archive and:
   1. Run the **existing replay verification** — chain intact, every event signed and **authorized**
      (the per-event author/admin/ACL checks PVFS already does on replay).
   2. Confirm the archive's tip `chain_hash` **==** the checkpoint's `prev_tip`.
   3. **Re-run compaction deterministically** over the archived log and confirm the resulting
      Merkle root **==** the checkpoint's `state_root`.
   - Passing all three proves the compaction is both **faithful** (a correct derivation of real,
     authorized history) and **properly authored** — exactly the question this design answers.

**On-demand, not every sync.** The archive travels only when someone wants the *full* proof or the
audit trail; ordinary replicas take the small checkpoint and keep the space/time win. Verifiers pay
the one-time replay cost only when they want certainty — there's no way to both discard history *and*
independently re-derive it without re-reading it once, but only those who care pay, and only once.

This resolves doc 03 §6 Q8 (how a replica accepts a checkpoint as a new root).

---

## 6. Constraints & caveats

- **Deterministic compaction is required.** The full verification (§5.2.iii) re-derives the snapshot,
  so compaction must be reproducible bit-for-bit: a **canonical ordering** of nodes/links in the
  snapshot and the Merkle tree, no wall-clock or map-iteration nondeterminism.
- **Cannot compact away referenced nodes.** Nodes still reachable by live links — including `ref`
  links from other regions/forests — must be retained in the snapshot.
- **Trust-model shift is real.** Pre-snapshot, anyone can replay from genesis. Post-snapshot, the
  region's trust anchor is the signed checkpoint; full provenance lives in the archive, not the hot
  log. Acceptable for an owner compacting their own forest; the archive keeps it auditable.
- **No succinct (replay-free) proof in v1.** Proving `state_root` equals the replay result *without*
  re-running the log would need a SNARK/STARK over the replay function — out of scope; noted as a
  far-future possibility.

---

## 7. Open questions

- **Checkpoint as a kernel event vs. a meta-operation** — is `Checkpoint` a new log event kind (so it
  replays like any other), or an out-of-band re-genesis that rewrites `log.db`? (Leaning: a real
  signed event so it stays uniform with the rest of the model.)
- **`SCHEMA_VERSION` / chain-genesis interaction** — the new genesis seed must bind `instance_id` +
  `forest_id` like the original `ForestCreated` (doc 03 §1.2); define how `prev_tip` threads into the
  new chain seed.
- **Incremental vs. full archive** — chain successive compactions (archive of archives) vs. one
  growing cold log.
- **Granularity** — per-region compaction needs the sub-forest accumulator work (doc 03 §6 Q7); start
  with whole-forest compaction.
