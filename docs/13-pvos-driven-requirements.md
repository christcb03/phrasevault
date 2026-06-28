# PVFS — Requirements Driven by PVOS (13)

Status: **Open questions / requirements brief** — the consolidated set of things PVFS must answer or change to be a complete foundation for PVOS. Written from the PVOS side so the PVFS work has one clear target. Goal: **finish the PVFS layer before PVOS goes deeper.**
Date: 2026-06-21
Related: doc 03 (federation), doc 10 (per-key tags — done, P2-G), doc 11 (compaction), doc 12 (secure node — P3 proposal).

Most of what PVOS needs already exists (P0–P2-G). The PVFS-impacting work concentrates in **two big workstreams (P3 secure node, P4 federation)** plus **three smaller additions**. This doc enumerates every open question; §A is flagged as the **most impactful** (settle it first).

---

## A. Federation write model — **MOST IMPACTFUL** (P4)

PVFS today is **single-writer**: the daemon is the only writer and the log is one linear signed chain. Federation across sites forces the deepest fork in the whole system.

- **Q-A1 (the pivotal one):** Does federation support **true active-active multi-writer** (two+ sites concurrently writing the *same* forest/region, needing merge), or **single-writer-per-region** (one active writer at a time; other sites are read replicas / warm standby with failover)?
  - *Why it matters:* single-writer preserves the linear signed chain and **all** of PVFS's integrity properties — replication is just verified log shipping, no conflict resolution. Multi-writer breaks the single linear chain → needs a causal event DAG / vector clocks / CRDT-style merge → a far larger change.
  - *What "active-active HA" might mean for us:* (a) **reads anywhere, writes to one** (single-writer; both sites live for availability) vs (b) **concurrent multi-master** (both writable at once). These are very different builds.
- **Q-A2:** If multi-writer: **conflict semantics** (PVOS D9) — last-writer-wins per entity (signed-time + node-id tiebreak), app-defined merge, CRDT, or single-writer-per-entity leases?
- **Q-A3:** Is collaborative *concurrent editing of a shared region by multiple people* a real near-term need, or can it wait? (This is the main thing that truly requires multi-writer.)

## B. Sub-forest (tree/region) replication mechanics (P4)

PVOS needs replicate/share/host at **tree/region** granularity, not just whole forests (per-app backup, peer-hosting, isolated-app cross-host links).

- **Q-B1:** How is a "region" defined for replication — the `contains`-closure under a chosen root node (doc 03 §1.5)? Confirm.
- **Q-B2 (hard problem):** A region's events are **not a simple chain prefix** of the forest log, so a replica can't verify a region tail by chain-prefix alone. **Per-region accumulator vs filtered-proof scheme?** (doc 03 §1.5 / §6 Q7) — this is the core integrity puzzle of sub-forest replication.
- **Q-B3:** Selective log subscription — a replica follows only events touching the region's nodes. Mechanism?
- **Q-B4:** How do per-key tags / authorities (P2-G) and ACLs travel with a replicated region (a region usually maps to one app authority)?

## C. Replication policy / opt-out

- **Q-C1:** A per-node / per-blob **"do not replicate" (local-only)** policy — the Messenger's local secure blob is app-local and never PVFS-replicated. Extend the existing `temp`-node (local-only, never-replicated) semantics, or a new explicit flag on normal/secure nodes?
- **Q-C2:** Secure blobs (P3) that *are* replicated travel as **ciphertext only** (the daemon has no key). Confirm the daemon replicates opaque bytes + the content-free hash-ledger.

## D. Cross-forest access — isolated apps & sharing (P4)

- **Q-D1:** **Local** cross-forest grant (authorize another forest's key into this forest with scoped ACLs/tags) — confirm this works today with the existing member-auth + ACL model (no change needed for same-host).
- **Q-D2:** **Cross-host** cross-forest access — needs the federation transport + the scoped grant. Design (the "linked-in isolated app on another host," PVOS doc 00 §3.5).
- **Q-D3:** **Peer-hosting / PVFS File Server** — one host serves another user's region. Trust model: for secure regions the host sees only ciphertext; for non-secure regions access is ACL-gated and the host *can* read — is that acceptable, or must hosted data always be encrypted-at-rest-to-the-owner?

## E. Identity & ACL additions

- **Q-E1:** **Expiring / time-limited ACL grants** — PVOS "public link" sharing (D16) wants a `public`/`key` read grant that **auto-expires**. PVFS grants are currently grant-only with no TTL. Add expiry to grants, or have PVOS revoke on a timer?
- **Q-E2:** **Guest / anonymous / ephemeral identities** — sharing to a non-PVOS recipient (D16) needs a lightweight identity they can hold. Does PVFS want a guest-key notion, or is `public` + a capability link enough?
- **Q-E3:** **Shared companion API (PVOS D7)** — the companion is partly a PVFS component (doc 09 §6). One agent must serve **PVFS root-signing + PVOS owner-signing + PVOS SSSO** (identity assertion + human-signature brokering). Agree the agent's API surface across both projects.

## F. Multi-user / per-user daemon

- **Q-F1:** Confirm **one `pvfsd` (and `pvosd`) per OS user** as the multi-user-host model; how multiple users' forests relate on one host.
- **Q-F2:** **Non-owner users (PVOS D18):** their identity = a PVFS member key; where their companion runs; how they reach **shared regions** they're granted (overlaps §D). Largely existing member model + §A/§D.

## G. Secure node type (P3) — open questions (from doc 12)

- **Q-G1:** Mutable-location semantics — exact overwrite/truncate/secure-erase guarantees at the storage layer (and per backend).
- **Q-G2:** Hash domain — the log hashes the **ciphertext** (server-verifiable) vs a canonical plaintext digest the client supplies. (Leaning ciphertext, since the local store isn't shared byte-for-byte — §C.)
- **Q-G3:** Secure-erase on replicas / backups — local delete can't force deletion on copies; document the limit.
- **Q-G4:** TEE / confidential computing (decrypt on an untrusted host) — **later enhancement, not P3-launch** (PVOS D24).

---

## Priority / sequencing

1. **Settle §A (write model)** — it determines whether the linear log survives and shapes all of P4. *Tackle first.*
2. **§B (sub-forest replication mechanics)** — the region-tail integrity scheme, once the write model is set.
3. **§G/doc 12 (secure node, P3)** — independent of federation; can proceed in parallel (the Messenger's local store needs only §C opt-out + P3, not P4).
4. **§C, §D, §E, §F** — the smaller additions, mostly downstream of §A/§B.

**Net:** the secure node (P3) can be built fairly independently; the federation cluster (§A–§D, §F) all hinges on **§A**. Decide §A and the rest of the foundation falls into a clear order.
