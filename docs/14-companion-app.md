# PVFS — Companion app: key custodian & identity agent (14)

Status: **Design** (committed to 1.0 scope, doc 08 §3) — drafted 2026-06-29
Depends on: [01 (identity)](01-core-engine-design.md), [06 (ACLs & daemon)](06-access-control-and-daemon.md), [07 (daemon protocol)](07-daemon-protocol.md), [09 §6 (the companion sketch)](09-tags-and-the-live-daemon.md), [10 §9.1 (identity = tag authority)](10-per-key-tag-authority.md), [12 (encryption at rest)](12-secure-node-type.md), [13 (PVOS superset API)](13-pvos-driven-requirements.md)
Motivation: give the **root/identity key** a strong home (a hardware-wallet / `ssh-agent` posture) so root-strength authorization needs no typed phrase, a human's tag authority is stable across machines, and PVFS-backed apps can "Sign in with PVFS." Decisions in §0 are settled; the rest is the buildable design.

---

## 0. Decisions (settled 2026-06-29)

- **1.0 scope: the full companion** — both the local **signer/custodian** *and* the localhost **identity agent / auto-login** web endpoint.
- **Key vault: OS keychain with a passphrase fallback** — prefer the platform secret store; fall back to a passphrase-derived key where none exists or the user opts out.
- **Approval: tiered by request type** (not one global policy) — see §4. The companion only ever signs in response to something the owner did; the prompt exists so *high-authority* and *remotely-originated* requests can't be driven silently by local malware.
- **Implementation: a Rust single binary** (`pvfs-companion`), a Unix-domain socket for the local signer protocol (same posture as `pvfsd`), and a loopback HTTP listener for the web agent.
- **Server / multi-tenant custody** (decided 2026-06-29, §13) — the dominant multi-user case is *app-driven*: the companion also runs **server-side as a per-user custody service** the app calls on each user's behalf. Per-user encrypted vaults, app-driven on-demand unlock with a per-device "trusted/public" TTL, root ops always re-authenticate, self-custody as the opt-out.

---

## 1. What the companion holds — and what it doesn't

The companion is the home for the **high-value, cross-device-stable keys**, derived from the recovery seed it custodies:

| Key | Path (doc 01) | Who signs with it | Where it lives |
|-----|---------------|-------------------|----------------|
| **Root key** | `m/43'/20566'/0'` | genesis, `DeviceAuthorized`, `DeviceRevoked` (admit/revoke a device or member) | **companion vault only** |
| **Identity key** | `m/43'/20566'/3'/<id>'` (new branch) | the human's own tag grants/memberships (the stable **authority**, doc 10 §9.1); their **member key** in other forests; identity assertions for auto-login | **companion vault only** |
| **Device keys** | `m/43'/20566'/1'/n'` | everyday writes (`mkdir`/`add-file`/`rm`/`mv`), ACL/tag ops by an admin device, in the owner's *own* forest | **stay local** in `<mount>/.pvfs/device.key`, as today |

`2'` is reserved for encryption (P3, doc 12); `3'` is the new **identity-authority** branch, with `<id>` an identity index (default `0`) so one seed can hold several identities (§10).

**The identity key is the human's one key everywhere.** It is authorized as an **owner** key in the user's own forest (a root-signed `DeviceAuthorized` with a *non-`MEMBER_DEVICE_INDEX`* index → implicit full rights *and* an active membership, so its tags count for liveness, doc 10 §9.2), and it is the **member key** a *different* forest's owner authorizes for this person. Because it is reproduced from the seed on any machine, a forest owner authorizes **one** key per human, not one-per-machine — the doc 10 §9.1 payoff. It replaces today's per-machine "client identity" for cross-forest membership.

**Key point:** per-machine device keys keep signing everyday, low-stakes writes **in the owner's own forest** with **no companion round-trip**. The companion is consulted for **root-authority events**, **identity-key** signatures (the human's tags + their writes in *other* people's forests), and auto-login — the consequential, cross-boundary operations. This matches the security model (a device key cached on disk is the weakest link; the companion is strictly stronger for the keys that matter) and keeps the local hot path fast.

**Kernel impact:** none to event encodings. `DeviceAuthorized` already carries `(device_pubkey, device_index)`; the identity key is authorized with a reserved sentinel index (`IDENTITY_DEVICE_INDEX`, distinct from both real device indices and `MEMBER_DEVICE_INDEX`) that marks "identity key at `3'/<id>'`" so `recover`/the companion derive it from the right path rather than the `1'/n'` device range. Projection treats it as an owner exactly as today (any non-`MEMBER_DEVICE_INDEX` index ⇒ owner).

The seed never leaves the vault: not over the socket, not to disk in the clear, not typed for routine use. The companion returns **signatures**, never key material — exactly the existing signer seam (`Fn(&[u8;32]) -> Vec<u8>`), now backed by an IPC call instead of a local key.

---

## 2. Architecture

```
                         ┌─────────────────────────────────────────┐
   pvfs CLI / pvfsd ───► │  pvfs-companion (per-user, single binary)│
   (signer requests)     │                                          │
   AF_UNIX  $RUNTIME/pvfs-companion.sock                            │
                         │   ├─ vault: sealed seed (keychain/pass)  │
   web app ────────────► │   ├─ signer: request types + policy (§4) │
   loopback HTTP         │   ├─ approval UI (prompt / notification) │
   127.0.0.1:<port>      │   └─ identity agent: origin gating (§6)  │
                         └─────────────────────────────────────────┘
```

- **`crates/pvfs-companion`** — new crate; depends on `pvfs-core` (identity/crypto) and `pvfs-proto` (digests, message shapes). Reuses BIP39/BIP32 derivation and `crypto::sign_digest`; adds the vault, the two listeners, and the approval UI.
- **Local signer socket** (`AF_UNIX`, `0600`, in `$XDG_RUNTIME_DIR/pvfs-companion.sock`): owner-only. The CLI/daemon dial it to request a signature.
- **Loopback HTTP** (`127.0.0.1`, ephemeral port published to a well-known file): the "Sign in with PVFS" surface for browsers/apps. Never bound to a non-loopback address.
- **Approval UI**: a desktop prompt (native dialog where available; a terminal prompt for headless/CLI-only). The agent is usable headless with a pre-approved policy for automation (§4).

---

## 3. The signer seam (how it plugs into today's code)

No kernel change. The two-phase write flow (doc 07 §5, doc 09 §3c) already separates *prepare* (build unsigned events) from *sign* + *commit*. Today the CLI signs with a local key; the companion replaces that closure with an IPC call:

- **`pvfs device authorize-member` / `revoke`** — instead of `--mnemonic` (typed phrase) or the admin device key, the CLI asks the companion to **root-sign** the prepared `DeviceAuthorized`/`DeviceRevoked`. This is the phrase-free bootstrap of a *first* admin device on a new machine — the one case that still needs the phrase today.
- **Tag grants/memberships under the human's authority** — signed by the **identity key** in the companion, so the same authority holds across all the user's machines (doc 10 §9.1).
- **Daemon challenge (doc 07 §2)** — for "Sign in with PVFS," the companion signs the challenge with the identity key on behalf of a web app (§6).

Everyday device-signed writes are unchanged. A `--signer companion` (or auto-detect the running socket) selects the companion; absent it, the CLI behaves exactly as today.

---

## 4. Approval policy — tiered by request type

Every signature traces to an owner action; the prompt's job is to stop a **local attacker** (malware talking to the socket) or a **web origin** from driving a high-authority signature without the human in the loop. Policy is keyed on the request type, not a global mode.

| Request type | Key | Default approval | Rationale |
|--------------|-----|------------------|-----------|
| `DeviceAuthorized` / `DeviceRevoked` (admit/revoke a device or member) | root | **Always prompt** (explicit, per-action) | Rare; changes *who can act* in the forest. The one place to be paranoid. |
| genesis (`ForestCreated`) | root | **Always prompt** | One-time, creates a new identity root. |
| Tag grant / membership the owner initiated **locally** (CLI/daemon on this host) | identity | **Auto-sign while unlocked** (optional "confirm" toggle) | The owner just ran the command — the action *is* the intent; prompting again is noise. |
| Identity assertion / daemon-challenge from a **web origin** (auto-login) | identity | **Per-origin connect** (approve the origin once → auto within a TTL; §6) | The request comes from an app, not the keyboard; bind it to an explicit, revocable origin grant. |
| Any request type from a **connected origin** that is high-authority (a web app asking to admit/revoke) | root | **Always prompt** (connect never covers root events) | A connected app must not be able to silently escalate trust. |
| Anything while the vault is **locked** | — | **Unlock first** (keychain / passphrase), then apply the row above | A locked companion signs nothing. |

Cross-cutting controls: a **rate limit** + an audit log of every signature (type, requester, origin, timestamp); a "remember for N minutes" affordance on per-action prompts; and an explicit **lock** command/idle-timeout that re-seals the vault.

---

## 5. Key vault — at rest and unlock

Goal: the seed is encrypted at rest and only decrypted into memory while the companion is unlocked and running.

- **Sealing.** The seed is sealed under a data key. The data key is held by the OS secret store where available, with a passphrase fallback:
  - **macOS** — Keychain (data key in the keychain; optional Touch ID gate via LocalAuthentication).
  - **Linux** — Secret Service / `libsecret` (GNOME Keyring, KWallet).
  - **Windows** — DPAPI (per-user) / Credential Manager.
  - **Fallback / portable** — a passphrase → **Argon2id** → key-encryption key; one code path everywhere, no OS dependency, used when no keychain exists or the user opts out.
- **At rest** the vault file holds: salt/KDF params, the sealed seed (AEAD, e.g. XChaCha20-Poly1305), and a version tag. No plaintext key ever touches disk.
- **In memory** the derived keys live only while unlocked; **lock** (explicit or idle-timeout) zeroizes them. Use a zeroizing allocator for key material.
- **Recovery** is unchanged: the 24-word phrase still reconstructs everything; the vault is a convenience+security layer over the same seed, not a new root of trust.

---

## 6. Identity agent — "Sign in with PVFS"

A loopback HTTP endpoint lets a PVFS-backed web app authenticate the user with no password and no phrase.

- **Flow.** App ↔ its PVFS daemon does the doc 07 §2 challenge; the app hands the challenge to the companion's loopback endpoint; the companion signs it with the **identity key** and returns the signature; the app proves the identity to the daemon. While the companion runs and the origin is connected, this is automatic.
- **Origin gating (the security boundary).** Every request carries its web **origin**. First contact from an origin requires an explicit **connect** approval (wallet-style: "Allow `app.example` to sign in as you?"). Connected origins are stored with a scope + TTL and are individually **revocable** in the UI. The connect grant authorizes **identity assertions only** — never root events (§4).
- **No ambient authority.** Loopback only; a per-launch token in the well-known port file so only local processes that can read the user's runtime dir can talk to it; CORS/Origin checks; no wildcard origins.

---

## 7. Joint PVFS + PVOS agent API (doc 13 Q-E3)

PVOS wants the *same* agent. The companion exposes a **superset** API both consume, to be pinned in a short joint spec (PVFS doc 09 §6 + PVOS doc 10 §4.1):

| Method | Used by | Notes |
|--------|---------|-------|
| `get-identity` / `get-pubkey` | both | the connected identity's public key(s) |
| `sign(digest, type, context)` | both | the core signer; `type` selects the §4 policy row |
| `sign-in(challenge, origin)` | PVFS auto-login | §6 |
| `sign-as-user(context)` | PVOS SSSO | human-signature brokering; same approval tiers |

The PVFS build targets the PVFS subset first; the methods are named/shaped so PVOS's additions are additive.

---

## 8. Threat model & posture

- **Defends against:** a device-key compromise (root/identity never on disk in the clear); local malware silently driving high-authority signatures (per-action prompts for root events; vault lock); a malicious/unknown web origin (connect gating, loopback-only, no root via web).
- **Accepts (v1):** an attacker who fully controls an **unlocked** session can request auto-signed *low-tier* signatures (everyday/identity-local) until lock — the same exposure as `ssh-agent`. High-tier events still prompt. Using one stable identity key (vs per-device) means revoking a single lost machine rotates the shared key (doc 10 §9.1 tradeoff) — mitigated by the vault posture.
- **Out of scope (v1):** hardware-token (FIDO/PKCS#11) backing for the seed itself (future); remote/networked agent access (loopback + local socket only).

---

## 9. Build plan (phased, each pipeline-verifiable)

1. ☑ **Vault core** — `pvfs-companion` crate: `Vault` seals/unseals the seed (Argon2id passphrase → XChaCha20-Poly1305), zeroizing secret, versioned `0600` JSON file. 7 unit tests (round-trip, wrong passphrase, ciphertext/nonce tamper, version reject, salt/nonce uniqueness, file mode).
2a. ☑ **Signing core + policy** — `UnlockedSigner` (request type → root/identity key → signature; `identity_key` at `3'/<id>'`), the §4 `ApprovalPolicy` (tiered, headless-safe defaults), and the kernel fix so the **root may author a device cert via prepare** (`require_admin_on_root` accepts the root, matching `check_device_cert`). Integration test: the companion root-signs a prepared `DeviceAuthorized` and the engine commits it (phrase-free admit, end to end).
2b. ☑ **Local signer socket** — `Agent` (signer + policy) served over an `AF_UNIX` listener; length-prefixed JSON protocol (`get_pubkey`, `sign`) reusing `pvfs_proto::{read_msg, write_msg}`; headless (a `Prompt` → deny, no UI yet). Round-trip test: get-pubkey, an approved sign whose signature verifies, and a policy denial.
3. ☑ **CLI wiring** — ☑ a runnable `pvfs-companion` binary (`init` seals a phrase from stdin; `serve` unlocks via `$PVFS_COMPANION_PASSPHRASE` and serves, `--allow-root` to opt a headless agent into root signing) + a `request` client; ☑ `pvfs device authorize-member --via-companion` root-signs through the companion (no phrase) and commits; smoke admits a member with no phrase typed and proves the cert landed. ☑ `device revoke --via-companion` (same root-signed prepare→sign→commit shape, shared as `companion_commit`). ☑ The human's identity key: `device authorize-identity` fetches the identity pubkey from the companion and root-signs its owner cert (`IDENTITY_DEVICE_INDEX`, engine `prepare_authorize_identity`); `tag add`/`tag rm --via-companion` sign under the **identity key** (`identity_tag`), so the grant's authority is stable across machines (doc 10 §9.1). ☑ Socket auto-detection: `--companion-socket` wins, else `$PVFS_COMPANION_SOCKET`, else `$XDG_RUNTIME_DIR/pvfs-companion.sock` if present (clean `BadInput` otherwise). Smoke: identity admit + tag grant/rm whose `tag ls` authority is the identity key, companion revoke via env-detected socket, unknown-key revoke → NotFound, missing socket → clean failure.
3.5. ☑ **Server / multi-tenant custody core** (§13) — a per-user `VaultStore` (one sealed vault per app-user) and an on-demand **session manager** (`Sessions`): unlock a user's key from their app-login secret, cache it for a per-device TTL (trusted) or sign once and drop (public), with **root request types always requiring a fresh unlock**. ☑ Served over a socket by `TenantAgent` (`get_pubkey`/`open_session`/`sign_once`/`sign_with_session`/`close_session`), with a socket round-trip test. This is the PVOS "sign-as-user" core. ☑ Runnable via the binary: `pvfs-companion tenant-init` (provision a user's vault from a phrase + password) / `serve-tenant` (serve the store) / `tenant-pubkey` (ops helper); smoke provisions two users, serves, and checks per-user key isolation + wrong-password rejection over the socket. ☐ Remaining: richer per-user provisioning/rotation UX and the app-side integration (PVOS).
4. ☑ **OS keychain backends** — the §5 abstraction is a `SecretStore` trait (where the vault's random 32-byte **data key** lives); `OsKeychain` implements it over the `keyring` crate (macOS Keychain / Linux Secret Service / Windows Credential Manager, cargo feature `os-keychain`, on by default; Linux build needs `libdbus-1-dev`). Vault format v2: `sealing:"keychain"` + `key_id`, no KDF material on disk; v1 passphrase vaults unchanged and both sealings share one AEAD code path. CLI: `init --keychain` (no passphrase at all), `serve` auto-detects the sealing from the vault file. Tested with an in-memory store (CI/servers are headless): round-trip, orphaned-vault (lost store entry ≠ tamper), tamper, wrong-unlock-path errors, v1 compat; a `#[ignore]`d test exercises the real platform keychain by hand. ☐ Deferred to phase 5 (UI): the optional Touch ID / biometric gate on unlock.
4.5. ☑ **Flagless CLI UX** — normal use needs no flags (per the project CLI rule): `init` / `serve` / `status` run bare with defaults (vault `~/.config/pvfs/companion.vault`, socket `$XDG_RUNTIME_DIR/pvfs-companion.sock`; `$PVFS_COMPANION_VAULT`/`$PVFS_COMPANION_SOCKET` for scripts, flags for troubleshooting). Interactive `init` **validates the phrase** (typos fail at init, not at serve), refuses to overwrite an existing vault, prefers the OS keychain, and falls back to a prompted + confirmed passphrase (`rpassword`, hidden input); interactive `serve` prompts for the passphrase. Piped/scripted behavior is unchanged (env passphrase, never touches a keychain). `status` reports vault sealing, agent liveness over the socket, and an orphaned keychain vault. The `pvfs` CLI auto-detects the same default socket, so `--via-companion` ops need no socket flag either.
5. ☑ **Approval UI + §4 controls** — a `Prompter` seam behind the policy's `Decision::Prompt`: **desktop dialog** where a GUI session exists (`osascript` on macOS, `zenity` on Linux), **terminal prompt** on `/dev/tty` otherwise (serialized, default-deny on EOF/error), and headless stays deny — `--allow-root` remains the explicit server opt-in. **Rate limit**: sliding-window signatures/minute (default 60, `--rate-limit`, 0 = off). **Audit log**: append-only `0600` JSONL next to the vault (`companion.audit.jsonl`) of every signing decision (approved/denied/rate_limited/locked/error, with type + origin + digest) plus serve_start/lock/unlock events; best-effort by design. **Lock**: `pvfs-companion lock` (new `Lock` protocol op) and an idle timeout (default 15 min, `--idle-lock-secs`) drop the seed from memory; a locked agent **re-unlocks on demand** through an `Unlocker` that retains no secrets (keychain refetch / env re-read / fresh terminal prompt), so aggressive locking costs nothing. 5 agent unit tests (prompter-approved root sign vs headless deny, rate limit + audit trail, lock without unlocker, lock + re-unlock same key, idle lock + restore). ☐ Deferred: the optional Touch ID / biometric unlock gate (macOS LocalAuthentication).
6. **Identity agent** — loopback HTTP, origin connect/scope/revoke, "Sign in with PVFS" against a `pvfsd` challenge.
7. **Joint API + spec** — finalize the §7 superset surface with PVOS.

Phases 1–3 deliver the root-custodian/signer value (and unblock phrase-free bootstrap); 4–5 harden it; 6–7 complete the identity-agent half. Each phase ships behind the build/test/smoke pipeline like the rest of P2.

---

## 10. Resolved design decisions (2026-06-29)

- **Identity-key derivation path — `m/43'/20566'/3'/<id>'`.** A new hardened branch (`3'`), distinct
  from root (`0'`), device keys (`1'/n'`), and encryption (`2'`, reserved). `<id>` is the identity
  index; `0` is the default identity. Authorized as an **owner** key via a root-signed
  `DeviceAuthorized` with a reserved `IDENTITY_DEVICE_INDEX` sentinel (non-`MEMBER_DEVICE_INDEX`, so
  owner; flagged so `recover`/the companion derive from `3'`, not `1'/n'`). No event-encoding change.
- **Per-origin web scope — sign-in (identity assertion) only for 1.0.** A connect grant authorizes
  identity assertions and nothing else; it never reaches root events or arbitrary signing. Finer
  per-app capabilities are deferred until a concrete PVOS need (doc 13).
- **Multi-identity — one vault, multiple selectable identities.** Each identity is `3'/<id>'` under the
  same seed; the vault lists them and a sign/connect request names the identity (default `0`). One
  vault per identity is *not* the model — a person's identities share the seed they recover from.
- **Headless / server companion — a policy file with conservative defaults.** No-UI deployments load
  an explicit policy: **identity-local auto-sign enabled**, **root events disabled** (a headless agent
  must not silently admit/revoke devices — re-enable only with an explicit, audited opt-in), **web
  origin connect disabled** (no new origins without a human). So a server can do everyday identity
  signing but never trust-set changes unattended.

## 11. Required follow-on: owner / identity key replacement

**Decision (2026-06-29): we must build a way to replace an owner/identity key.** It is the mitigation
that makes the "one identity everywhere" tradeoff (§1, doc 10 §9.1) acceptable — without it, a lost or
compromised identity key has no clean recovery short of abandoning the forest. Not required for the
companion's first phases, but committed before the companion is considered done.

What it needs to cover:

- **Replace a compromised/lost identity key** with a freshly derived one (`3'/<id+1>'`), and
  **re-home its authority**: existing tag grants and memberships authored by the old key must be
  re-issued (or transferred) under the new key, since `(authority, name)` matching and liveness
  (doc 10 §9.2) are keyed on the authoring key. Until re-issued they go inert (the existing masking).
- **Replace an owner device key** (the per-machine case) — already partly covered by `device revoke` +
  authorize-a-new-device; confirm it composes with the identity model.
- **Rotate the root key** (worst case, seed compromise) — the hardest: the root is the identity anchor
  in `ForestCreated` and the signer of every device cert. Likely needs a signed "root rotation" event
  that re-anchors the forest to a new root while preserving node/link identity (content-addressed, so
  ids survive) — interacts with compaction's re-genesis (doc 11) and federation trust (doc 03).

Design this as its own mini-spec (a new doc) before the companion's §9 phase 7. Tracked in doc 08 §4.

## 12. Remaining open questions

- **Identity ⇄ device-key relationship for the owner's *own* writes.** In the owner's own forest both
  the local device key and the identity key are owners with full rights; confirm the CLI's default
  (prefer the local device key for speed; use the identity key only where authority/stability matters —
  tags, other forests, auto-login). Mostly a CLI policy, no kernel impact.

---

## 13. Server / multi-tenant custody (app-driven) — decided 2026-06-29

The dominant multi-user case is **app-driven**: users act through a PVOS app and never log into the
server. For them the companion also runs **server-side as a per-user custody service** the app calls on
each user's behalf — the PVOS "sign-as-user" broker (doc 13 Q-E3). This is *additive* to the local
companion (§1–§6), not a replacement.

### 13.1 Model
- **Per-user vault store.** Each app-user has their own encrypted vault on the server (the §5 `Vault`,
  one per user). The app authenticates the user; that login supplies the **unlock secret**; the
  companion unseals *that user's* key, signs, and re-locks.
- **Self-custody opt-out.** A user who wants maximum safety keeps their key off the server on their own
  device, and the app talks to that local companion (§6) instead. Server custody is the convenience;
  self-custody is the stronger posture — a per-user choice.

### 13.2 Threat model (operator's stance)
A server-account compromise is **total** — own the account and the whole install is already lost, so
there is no weaker layer worth defending. Encrypting each key to a secret **not stored on the server**
is therefore sufficient. The single invariant: **the unlock secret is never persisted at rest** — it is
supplied live by the operator's passphrase or the user's app login. (So unattended auto-unlock across
reboots is out of scope: re-supply the secret after a restart.)

### 13.3 Unlock lifetime — a per-device trust setting
Like a website's "private vs public computer / remember me" at login. Since the key lives server-side,
the flag governs **how long the server may hold a user's unlocked key for that device's session**:
- **Trusted device** — a longer session TTL; the unlocked key is cached for the session, so everyday
  signing is friction-free.
- **Public device** — near-zero; the key is not cached beyond the immediate operation, each sensitive
  action re-supplies the secret, and the session expires fast.

**Composition with §4:** device trust governs the *identity* tier's friction only. **Root operations
(admit/revoke a device) always re-authenticate** regardless of remember-me — changing *who is in the
forest* always wants a fresh unlock. (On a local companion this re-auth *is* the approval prompt;
server-side it is a fresh unlock secret.)

### 13.4 Unlock secret (v1)
Unlock with either the **recovery passphrase** PVFS already generates **or** a **password** the user
picks at account creation — both feed the existing Argon2id → vault-key path (§5), so no new crypto.
Passkeys (via the WebAuthn **PRF** extension, keeping the secret off the server) and other methods come
later.

### 13.5 What's new vs phases 1–3
The `Vault` primitive is reused unchanged. New: a **per-user `VaultStore`**; an **on-demand unlock +
session manager** (trusted vs public TTL, root-always-reauth); and a multi-tenant request shape (a
request names the user and carries the unlock secret or a session token). Build target: §9 phase 3.5.
