# PVFS — Key replacement & rotation (15)

Status: **§6 decisions resolved 2026-07-02**; §5 phases 1–3 (cases A + B) built; case C (root lineage) building next
Depends on: [01 (identity & derivation)](01-core-engine-design.md), [03 (federation trust)](03-federation-trust-and-uris.md), [10 (per-key tag authority)](10-per-key-tag-authority.md), [11 (compaction & snapshots)](11-compaction-and-verifiable-snapshots.md), [13 §B (multi-region logs)](13-pvos-driven-requirements.md), [14 (companion)](14-companion-app.md)
Motivation: the companion makes a human's identity **one stable key everywhere** (doc 10 §9.1). The accepted cost is that a compromise of that key — or, worse, of the seed — cannot be contained by revoking one machine. This spec is the mitigation that makes the tradeoff acceptable: a clean, verifiable path to replace **any** key in the system, up to and including the root.

---

## 0. The principle, and the three cases

**Identity is the log, not the key.** `forest_id` is a genesis UUID carried by `ForestCreated` and anchored by the hash-linked log — it is *not* derived from the root public key. So every key in the system is replaceable in principle; what this spec defines is (a) **who may authorize** each replacement, and (b) how the **live state that hangs off the old key** is re-homed. History is never rewritten: replay validates each event against the authority *as of that log position*, so replacement only redirects future authority.

| Case | Trigger | Blast radius | Mechanism |
|------|---------|--------------|-----------|
| **A. Identity key** (`3'/<id>'`) | key compromise (a machine that held the unlocked signer; exported material). *Loss* is not a trigger — the seed re-derives any index. | that human's tag grants/memberships everywhere; their member admissions in other forests | bump the identity index; root-signed swap in the own forest; **re-issue** authored state; signed **handoff** to other forests |
| **B. Owner device key** (`1'/n'`) | machine lost/stolen | that device's future writes; any grants it authored (rare post-companion) | existing `device revoke` + authorize a new index; the same re-issue op for stragglers |
| **C. Root key** (`0'`, i.e. **seed compromise**) | phrase leaked; vault + store both breached | everything: root, all device keys, all identities, `2'` encryption | **root lineage**: a `RootRotated` event re-anchors authority to a new seed's root, first-in-log-wins, optionally co-signed by an offline **recovery key**; then case A/B mass re-issue under the new seed |

What a key's authority touches (the re-homing inventory):

- **Device certs** — `DeviceAuthorized`/`DeviceRevoked` it authored (historical; stays valid).
- **Tag memberships** — `(authority = author, name)` pairs (doc 10): revoking the author masks them (inert) immediately.
- **ACL `tag:` grants** — scoped to their authoring key (doc 10 scoped matching); inert with the author.
- **ACL `key:` grants** — grants *to* the old key on nodes, in its own and other forests.
- **Everyday events** it signed — immutable, validated against authority-at-that-time; never touched.

---

## 1. Case A — replace a compromised identity key

**A1 — derivation.** The new key is the next hardened identity index: `m/43'/20566'/3'/<id+1>'`, same seed. The companion records the **current identity index** as a plaintext field in the vault envelope (`identity_index`, absent ⇒ 0). Plaintext is fine: the field is public information, and tampering with it yields a key that matches nothing — a visible DoS, not an escalation.

**A2 — the swap (own forest).** One commit, both events root-signed through the companion (no phrase): `DeviceRevoked(old_identity_pub)` + `DeviceAuthorized(new_identity_pub, IDENTITY_DEVICE_INDEX)`. From that instant the old key's grants and memberships are **inert** via the existing authority-liveness masking (doc 10 §9.2) — the compromise window closes before any re-homing happens.

**A3 — re-issue (own forest).** A new engine op `reissue_authority(old_pub, new_pub)` scans the projection for live state keyed to `old_pub` and emits fresh events under `new_pub`, signed by the companion (`identity_tag` tier):

- each live `member_tags` row with `authority = old` → a new `MemberTagged` authored by the new key;
- each ACL `tag:` grant authored by `old` → re-issued `AclSet` by the new key;
- each ACL `key:old` grant → an `AclSet` granting `key:new` (author: any admin; the companion's identity key is an owner).

Old rows are left to masking now and compaction later (doc 11) — no deletions, no rewrites. `pvfs audit` already reports inert leftovers, so the operator can verify the re-issue converged (audit clean = done).

**A4 — other forests (memberships).** The old key is also this person's **member key** elsewhere. The companion produces a signed **handoff assertion** — `{old_pub, new_pub, replaced_at}` signed by *both* keys (both derive from the seed, so both are always available; the attacker holding the old key can forge *half* of nothing — they don't have the new key). The receiving forest's owner verifies both signatures and runs `pvfs member replace <old> <new>`: revoke old member key, authorize new, re-grant the tags *they* had granted. The assertion is a **convenience, not an authority**: the receiving owner's root/admin signature is what actually changes their forest, and for a compromise they SHOULD confirm out of band (the attacker can present the old key too — but only the real owner presents a valid handoff naming a key the attacker doesn't hold).

**UX (per the CLI rule: prompts, not flags).** `pvfs identity replace` — interactive: states what will happen, performs A2 + A3 in the current forest, bumps the vault's `identity_index`, prints the handoff blob with instructions for each forest the CLI knows the old key is a member of.

---

## 2. Case B — replace an owner device key

Already mostly built; this spec confirms the composition and closes one gap.

- `pvfs device revoke --via-companion --pubkey <old>` (or from any admin device) ends the lost machine's write authority. Its historical events remain valid at replay.
- The new machine runs `pvfs recover` with the phrase at the next device index — or is admitted from an existing machine, phrase-free, via the companion.
- **The gap:** grants authored *by the old device key* (admin ops done from that machine before the companion made identity-key authoring the norm) go inert on revoke. `reissue_authority(old_device_pub, new_authority_pub)` is deliberately key-agnostic — the same op re-homes them, and the sensible `new_authority` is the **identity key**, so the grant never binds to hardware again.

**Decision:** no new event kinds for case B. Add a smoke that proves revoke → re-authorize → reissue leaves effective rights identical (`pvfs audit` clean, `acl check` unchanged for a probe set).

---

## 3. Case C — rotate the root (seed compromise)

The disaster case: everything under `m/43'/20566'/…` is burned. The goals are (1) the forest survives with its identity — `forest_id`, node ids, history — intact, (2) the attacker cannot rotate it away from the owner, or at least cannot do so quietly.

**C1 — new seed.** A fresh 24-word phrase; every key class re-derives under it.

**C2 — `RootRotated`.** A new event kind, device-cert class:

```
RootRotated { new_root_pubkey, rotated_at, author, sig }
```

Valid iff `author` is the **current root of the lineage** (or the recovery key, C5), and it appends to the **root region** of the canonical log (doc 13 §B — rotation is never valid from a sub-region log). Projection maintains a **root lineage**: `root(t)` = the `new_root_pubkey` of the latest `RootRotated` at-or-before position `t`, else the genesis root. `check_device_cert` and replay validate every device cert against `root(position)` — so history validates forever, and the old root's authority ends at the rotation, atomically.

**C3 — forest identity is unchanged.** `forest_id` stays; URIs (doc 05) stay; node/link ids are content-addressed and never referenced the root key. What *changes* is what federation peers must pin: **not the root pubkey but the genesis + lineage** — each `RootRotated` signed by the then-current root (or recovery key) forms a custody chain any peer can verify (doc 03 gets a short amendment). A peer seeing a lineage extension should surface it like an SSH host-key change: loud, but verifiable.

**C4 — the race.** The attacker holds the old root too. **First valid `RootRotated` in the canonical log wins**; a second is invalid at append and at replay (its author is no longer `root(t)`). This is honest about the residual risk: if the attacker appends first, the owner has lost the forest — which is why C5 exists and why peers alarm on lineage changes rather than silently following them.

**C5 — the recovery key (decided: build it).** At `forest init`, generate a **second, independent phrase** — the *rotation recovery phrase* — deriving a single key registered in the log:

```
RecoveryKeyRegistered { recovery_pubkey, registered_at, author = root, sig }
```

**Registration is phrase-authenticated (§6 decision 4):** the event must be signed by the root key **derived from the typed recovery-seed phrase**, never by the companion-held root. This closes the retrofit window by prevention — a compromised companion root cannot register an attacker's recovery key, and a phrase-holder has already won. So registration happens at `forest init` (the default) or via an explicit later command that types the phrase; there is no companion-signable mid-life path.

`RootRotated` may be authored by the current root **or** the registered recovery key. The recovery phrase lives on paper, is never typed into any machine except at registration and rotation, and is never held by the companion — so a thief of the *operating* seed cannot rotate, and the owner can rotate even after total compromise of every machine. Init prompts for it (default: yes, print and confirm); declining falls back to C4 race semantics. **Scope (§6 decision 1):** a local companion → one recovery key per forest; a remote companion → the owner may choose per-forest or one shared recovery key per seed.

**C6 — after the rotation.** The new root mass-revokes the old device and identity keys and admits their replacements (cases A and B under the new root — same ops, same re-issue). One guided command: `pvfs forest rotate-root` — interactive, states consequences, takes the old phrase *or* the recovery phrase, prints the new phrase, performs the rotation + mass re-admission + re-issue, ends with `pvfs audit`.

**C7 — compaction.** A compacted snapshot's re-genesis (doc 11) must embed the **full lineage** (`RootRotated` chain, plus `RecoveryKeyRegistered`) so a verifier of the snapshot can validate device certs without the pruned history.

---

## 4. Kernel impact

- **No changes** to existing event encodings or ids.
- **Two new event kinds**: `RootRotated`, `RecoveryKeyRegistered` — both follow the root-lineage validation rule; neither is writable from a member, the web path (doc 14 §4), or a sub-region log.
- **Projection**: a `root_lineage` table (position → root pubkey); `check_device_cert` + replay consult `root(position)` instead of the fixed genesis root.
- **Engine ops**: `prepare_replace_identity` (the A2 pair, atomic), `reissue_authority(old, new)`, `prepare_member_replace`, `prepare_rotate_root`, `prepare_register_recovery`.
- **Companion**: `identity_index` in the vault envelope; the handoff assertion (signed at the `identity_assertion` tier — it *is* an identity assertion); rotation always prompts (never `--allow-root`-auto) and is audited.
- **CLI** (prompt-first, doc 14 §9 4.5): `pvfs identity replace`, `pvfs identity reissue`, `pvfs member replace <old> <new>`, `pvfs forest rotate-root`.

## 5. Build plan (phased, pipeline-verifiable)

1. ☑ **Re-issue core** — `prepare_replace_identity` (the atomic two-event swap) + `prepare_reissue_authority` (memberships, tag grants, `key:old → key:new`); integration test: member loses access at the swap, regains it identically after re-issue, re-running the swap refused.
2. ☑ **Identity replace UX** — companion `identity_index` in the vault envelope; `RotateIdentity` agent op (root-tier gate: `--allow-root` or the rotation prompt; persist-then-swap; dual-signs the handoff with both keys before swapping); `pvfs identity replace` does rotate → swap → re-issue → prints the handoff. Smoke: grant re-homed to the new authority end to end.
3. ☑ **Member handoff** — `identity::handoff_digest`/`verify_handoff` (domain-tagged, dual-signature) + `pvfs member replace <file|->` (verify, revoke old, admit new, re-grant tags — composing existing device-signed ops, no new events). Smoke: replace across a second forest; tampered handoff refused (rc 5).
4. ☑ **Root lineage** — `RootRotated` + `RecoveryKeyRegistered` (full event plumbing); the projection's
   `identity_root_pubkey` is the **current** lineage root (genesis seeds it, `RootRotated` updates it),
   so `check_device_cert`/replay and every engine root-authority check consult `current_root()` — a
   rotated-away seed is rejected, a new root accepted, all with replay/rebuild parity. `recovery_keys`
   table; author rules (rotate = current root OR recovery key, first-valid wins; register = current
   root only, phrase-authenticated). CLI `pvfs forest recovery-key` (register, phrase on stdin, prints
   a paper recovery phrase) and `pvfs forest rotate-root` (rotate via current-or-recovery phrase,
   prints the new phrase). Tests: `case_c_lineage.rs` (rotation moves authority + rebuild parity,
   recovery-key rotation after total seed loss, stranger refused); smoke: register → rotate via
   recovery phrase → old seed rejected, new accepted, `forest_id` survives.
5. ☐ **Edges** — compaction lineage embedding (doc 11 update); federation lineage pinning (doc 03
   amendment); optional `forest rotate-root` mass re-admission of old-seed devices; doc 08 item 17 closed.

## 6. Resolved decisions (2026-07-02)

1. **Recovery-key scope — gated by companion location.** A **local** companion (on the same host as
   the served forest) always uses **one recovery key per forest**: a compromise there could reach
   both the operating seed and the recovery setup, so isolate the blast radius. A **remote**
   companion (a separate device) is a stronger posture, so the owner may **choose** per-forest or
   one shared recovery key **per seed** (across all their forests) — the convenience is earned by the
   stronger custody. Default per-forest either way.
2. **Handoff transport — printable blob** (works everywhere, zero infra), consistent with cases A/B.
   A daemon-to-daemon channel is a post-1.0 convenience.
3. **Re-issue linkability — accepted, and transient.** Re-homing `key:old → key:new` writes both keys
   into the log, so a reader can see "X became Y" — inherent to *continuity* of access (the handoff
   already asserts it publicly). But it is **transient**: after the swap the old key is revoked and
   its grants are inert, so the **next compaction** (doc 11 re-genesis rebuilds from current effective
   state) drops the old key and the linkage entirely — effectively crypto-shredding it over time.
   *Boundary:* this applies to **grant re-homing** (cases A/B). It does **not** apply to the **root
   lineage** (case C), which compaction must *preserve* (§C7) so device certs across rotations stay
   verifiable. Caveat: doc 11's sealed archive of the pre-compaction log, and any replica synced
   before compaction, still hold the linkage; the live/compacted forest is what sheds it.
4. **Retrofit window — closed by prevention, not detection.** `RecoveryKeyRegistered` is
   **phrase-authenticated only** — it must be signed by the root **key derived from the typed
   recovery phrase**, never by the companion-held root. So a compromised *companion* root cannot
   silently register an attacker's recovery key; and anyone who holds the *phrase* has already won
   (they can rotate root directly), so allowing it there adds no new attack surface. The phrase is
   naturally present at `forest init` (the default moment) and at `recover`; adding a recovery key to
   an existing forest later is an explicit phrase-typed command. No mid-life companion-signable
   registration exists, so there is no quiet-retrofit surface to alarm on.
