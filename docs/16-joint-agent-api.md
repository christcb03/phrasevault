# PVFS ⇄ PVOS — Joint Companion Agent API (16)

Status: **PVFS side implemented** (phase 7 items 1, 2, 4 done in 1.0); **`pvos.sso` remains PVOS-repo work**. Coordination doc for PVFS companion §7 (doc 14) and PVOS D7/D19. Drafted 2026-07-02.
Depends on: [14 (companion)](14-companion-app.md), [12 (secure blobs)](12-secure-node-type.md); PVOS [10 (companion requirements)](../../PVOS/docs/10-companion-requirements.md), [02 (delegation)](../../PVOS/docs/02-delegation-and-revocation.md), [04 (control socket)](../../PVOS/docs/04-control-socket-protocol.md), [07 §3.5 (`pvos.sso`)](../../PVOS/docs/07-built-in-services.md).
Resolves: PVOS **D7** (one shared companion — coordinate the API) and **D19** (the SSSO context protocol).

> **One companion serves PVFS, PVOS, and every app** (PVOS D7 ✅). This doc pins the surface that companion exposes so both projects — and third-party apps — build to one contract. It is the buildable form of PVFS doc 14 §7's "superset API."

---

## 0. The two layers (and who talks to whom)

```
   ┌─ apps ──────────────┐         ┌─ pvosd (the broker) ───────────┐      ┌─ companion ─────────┐
   │  Channel-2 client    │        │  pvos.sso service (doc 07 §3.5)  │      │  the ONE signer      │
   │  pvos.sso.sign_as_user│──req──▶│  builds the digest + context    │──▶──▶│  renders context,    │
   │  (operation, not a    │        │  from the operation, authorizes │  L1  │  human approves,     │
   │   raw digest)         │◀─sig──│  via the capability set (doc 02)│◀────│  signs the digest    │
   └──────────────────────┘         └────────────────────────────────┘      └─────────────────────┘
        ▲                                                                          ▲
        │  browser / web desktop: "Sign in with PVFS" (challenge)                  │  PVFS CLI/pvfsd
        └──────────────────────── loopback HTTP (doc 14 §6) ──────────────────────┘  root admin (doc 14 §3)
```

- **Layer 1 — the companion agent (this doc, PVFS-owned).** The low-level signer over its `AF_UNIX` socket (doc 14 §3) and its loopback HTTP endpoint (doc 14 §6). It holds the identity/root/encryption keys, renders approval prompts, and returns **signatures, never key material**. It has no notion of PVOS apps or capabilities.
- **Layer 2 — `pvos.sso` (PVOS-owned, in `pvosd`).** A built-in PVOS service (doc 07 §3.5) that brokers human-attributed signatures for apps. It is the **only** thing apps talk to for signing; apps never open the companion socket. It authorizes the request against the effective capability set (doc 02 §4), **constructs the context and the digest together** (§3), and forwards to Layer 1.

**The division of labor is the whole design:** the companion knows *how* to sign and *how* to show a prompt; `pvosd` knows *what* an app is allowed to do and *what* the operation means. Neither could safely do the other's job.

---

## 1. The canonical agent surface (Layer 1)

The methods PVOS doc 10 §7 and PVFS doc 14 §7 both name, pinned to the built PVFS companion protocol (`crates/pvfs-companion/src/proto.rs`):

| Canonical method | PVFS companion wire form | Key used | Built? |
|------------------|--------------------------|----------|--------|
| `get-identity` / `get-pubkey` | `AgentRequest::GetPubkey { role }` → `Pubkey` | root / identity / encryption | ✅ (phases 2–4) |
| `sign(digest, type, context)` | `AgentRequest::Sign { request_type, digest, context?, origin }` → `Signature` | by request type (§4 policy tier) | ✅ (phase 7: `ApprovalContext` rendered + audited, `user_action` type) |
| `sign-in(challenge, origin)` | loopback `POST /sign-in { challenge }` → `{ sig, pubkey }` | identity | ✅ (phase 6); ✅ real `pvfsd` challenge consumer (§6, `tests/signin_pvfsd.rs`) |
| `sign-as-user(context)` | tenant `sign_once` / `sign_with_session` **+ context** (§5) | per-user identity | ✅ (phase 7: context accepted + digest-checked on the tenant ops) |
| lifecycle | `Lock`, `RotateIdentity`, `SecureUnwrap` (doc 12 §8.5) | — | ✅ |

So the surface is **already ~90% built**. Phase 7 is: (a) the **approval-context** field on `Sign` and the tenant sign ops (§3), and (b) the **`pvfsd` challenge consumer** (§6). Everything else exists.

---

## 2. Request types and policy tiers (unchanged, doc 14 §4)

Every signature carries a `request_type` selecting the approval tier. The existing set stands; `pvos.sso` maps onto it:

| `request_type` | Tier (doc 14 §4) | PVOS use |
|----------------|-------------------|----------|
| `root_device_cert` | always prompt | owner admin (PVFS root) |
| `identity_tag` | auto while unlocked, local | the human's own tag grants / delegations they initiate |
| `identity_assertion` | per-origin connect (web) | "Sign in with PVFS"; SSSO identity assertion |
| `secure_unwrap` | auto while unlocked, local | companion-gated decryption (doc 12) |
| **`user_action`** (new) | **context-driven (§3)** | **`sign_as_user` — the D19 path** |

`user_action` is the one addition: a human-attributed app action whose approval decision is driven by the **context**, not a fixed tier — auto-approved when it matches a policy allow-list, prompted otherwise (§3.3).

---

## 3. The approval-context protocol (resolves D19)

**The problem (D19).** Signature brokering is only as trustworthy as the prompt. If an app hands the companion a raw 32-byte digest plus a free-text summary, a malicious app can show *"share one photo"* while the digest authorizes *"delete everything"* — the human approves a lie, the companion signs the real (malicious) digest.

**The resolution — a trusted broker binds context to digest.** The app does **not** hand anyone a digest. It hands `pvosd` an **operation description**; `pvosd` — which already knows the operation's real shape (it's the broker for every capability and service call, doc 04) — **computes the canonical digest and builds the human context from the same operation**, so the two are consistent *by construction*. The app cannot make the prompt lie because it never chose the digest.

### 3.1 The `ApprovalContext` object

```jsonc
ApprovalContext {
  "app_id":    "app:mediaforest",          // the authenticated app key's id (pvosd fills this — the app can't forge it)
  "action":    "share",                    // a verb from a controlled vocabulary (share|delete|grant|revoke|publish|admin|…)
  "summary":   "Share 3 photos with your Friends",  // one human line pvosd composed from the operation
  "resource":  "pvfs://…/media/albums/trip",// the affected node/scope (optional, shown in the prompt)
  "digest_hex":"…64 hex…"                   // what will be signed — computed by pvosd, NOT supplied by the app
}
```

- **`app_id` is authenticated, not asserted.** `pvosd` sets it from the Channel-2 connection's proven app key (doc 04 §6) — an app can't claim to be another.
- **`digest_hex` is computed by `pvosd`.** For an SSSO action, `pvosd` builds the exact bytes the operation signs (e.g. a PVFS `MemberTagged`/`AclSet` digest for a share, doc 02 §8) and puts *that* in the context. The app supplied the operation, not the digest.
- **`summary` + `action` + `resource` are `pvosd`'s rendering** of that same operation for the human. Because one component produced all four fields from one operation, the prompt provably describes the digest.

### 3.2 What the companion does with it

The companion (Layer 1) treats `ApprovalContext` as **display + audit**, and signs `digest_hex`:

1. Render `app_id`, `action`, `summary`, `resource` in the approval prompt (desktop dialog / terminal, doc 14 §5). The human sees *"MediaForest wants to share 3 photos with your Friends"* — never an opaque hash.
2. On approval, sign `digest_hex` with the key the `request_type` selects (`user_action` → the identity/user key).
3. Record the full context (minus nothing — it's all public metadata) in the signature audit log (doc 14 §5).

The companion does **not** re-derive or verify the digest against the summary — it *can't*, it doesn't understand app operations. **The security rests on `pvosd` being the honest broker** that built both. This is sound because `pvosd` is already the trusted authorizer for every capability (doc 02) — an app that could subvert `pvosd`'s digest construction could already subvert its capability checks. The companion adds the *human* gate on top; the two together are defense in depth (broker authorizes, human confirms).

### 3.3 Approval policy (PVOS side)

`pvosd` applies policy *before* forwarding to the companion (D19 rec):

- **Auto-approve allow-lists** for low-risk, high-frequency actions (an app's routine writes in its own region) — `pvosd` may hold a session-scoped approval so the human isn't prompted per write.
- **Mandatory prompt** for sensitive actions (`action ∈ {grant, revoke, admin, delete, publish}` or any cross-app / cross-forest scope) — always reaches the companion prompt, never auto.
- **Rate limits** — `pvosd` caps `sign_as_user` frequency per app (composes with the companion's own rate limit, doc 14 §4).

The companion's tiers (§2) are the *floor*; PVOS policy can only make an action **more** gated, never less — the companion still applies its own `request_type` tier independently (monotone-restrictive, mirroring doc 02 §8.5's two-liveness-layers invariant).

---

## 4. Trust boundary summary

| Guarantee | Enforced by | How |
|-----------|-------------|-----|
| An app can't sign as another app | `pvosd` | connection principal = proven app key (doc 04 §6) |
| An app can't make the prompt lie | `pvosd` | it builds `digest` + `summary` from one operation (§3) |
| An app can't exceed its authority | `pvosd` | capability check against the effective set (doc 02 §4) before signing |
| The server-alone can't sign | companion | key is in the vault, unlocked only while running (doc 14 §5) |
| A web origin can't drive a root event | companion | request-type tiers; web path = identity assertions only (doc 14 §4/§6) |
| The human is the final gate on sensitive acts | companion | renders context, prompts, signs on approval (§3.2) |
| Every signature is attributable | companion | audit log of `{context, request_type, digest, time}` (doc 14 §5) |

---

## 5. `sign-as-user` and multi-tenant custody

`sign_as_user` is **`sign` with a `user_action` request type and an `ApprovalContext`**, routed to the key of the signed-in *user* (not the app). Two deployments, both already built on the custody side:

- **Owner, local companion.** The user *is* the owner; `sign_as_user` uses the owner's identity key via the local agent (doc 14 §3). The context drives the prompt.
- **Multi-user / server (PVOS D18, deferred).** Each user has a per-user sealed vault; `pvosd` opens a session and signs on their behalf via the **tenant custody core** (`TenantAgent::sign_once` / `sign_with_session`, doc 14 §13, phase 3.5 — built). Phase 7 adds the `ApprovalContext` to those tenant ops so the per-user prompt is meaningful too. Full non-owner UX is D18 (deferred).

The identity separation doc 10 §4.1 requires holds automatically: the **app's own key** signs the app's routine writes (it never touches the companion — those are ordinary member-signed PVFS writes, doc 07 §5); the **human's key** (via the companion, brokered by `pvos.sso`) signs human-attributed actions. Two keys, two paths, one companion.

---

## 6. "Sign in with PVFS" — the real `pvfsd` challenge consumer

Today the loopback agent (doc 14 §6) signs a challenge, but nothing closes the loop against a live daemon. The end-to-end flow to wire (phase 7):

1. A web app authenticates its user to **its PVFS daemon**: `pvfsd` issues a doc 07 §2 challenge (`auth_digest(nonce, forest_id, expiry)`).
2. The app hands the challenge to the companion's loopback `POST /sign-in { challenge }` (origin-gated, doc 14 §6).
3. The companion signs it with the **identity key** and returns `{ sig, pubkey }`.
4. The app presents `{ pubkey, sig }` to `pvfsd`, which verifies exactly as it does a CLI client's `Auth` (doc 07 §2) — the identity key must be an authorized member.

The only new code is a **consumer/example** proving steps 1→4 against a running `pvfsd` (an integration test + a short "Sign in with PVFS" reference in the identity-agent surface). The signing and verification primitives already exist on both ends.

---

## 7. Built vs. remaining (phase 7 scope)

**Already built (PVFS companion phases 1–6 + 3.5):** the vault, the tiered signer + approval prompts + audit + lock, `GetPubkey`/`Sign`, the loopback identity agent with origin connect, and the multi-tenant custody core. That is the bulk of doc 14 §7's surface.

**Remaining for phase 7:**
1. ☑ **`ApprovalContext` on the sign surface** — the optional `context` field on `AgentRequest::Sign` and the tenant sign ops; the `Prompter` renders it (`approve_with_context`, doc 16 §3.2 wording in the terminal/desktop backends); the audit log records the full context; new `user_action` request type signed by the identity key, **prompt-by-default** (§3.3's allow-list is broker-side only). A context whose `digest_hex` disagrees with the digest being signed is refused as `bad_input` before any prompt, on both the local agent and the tenant ops. *Built.*
2. ☑ **`pvfsd` challenge consumer** — `crates/pvfs-companion/tests/signin_pvfsd.rs` proves the §6 loop 1→4 against a live `pvfsd`: challenge → loopback `POST /sign-in` → identity-key signature → daemon `Auth` verifies the member, and ACLs bind to the signed-in principal. The signing closure in that test is the app-side reference. *Built.*
3. ☐ **`pvos.sso` service** — `whoami` / `session` / `sign_as_user`, the policy engine (§3.3), and the digest+context construction (§3.1). *PVOS-side, in `pvosd` — built in the PVOS repo, consuming this API.*
4. ☑ **`api_version` handshake** — `API_VERSION` (= 1) in `pvfs_companion::proto`, answered by the new `api_version` op on **both** the local agent and the tenant socket; answered even while locked, so negotiation never requires an unlock. *Built.*

PVFS's phase-7 work (items 1, 2, 4) is **done**; item 3 is PVOS's, and this doc is the contract it builds to.

## 8. Open items (carried, not blocking)

- **Non-owner users (PVOS D18).** Where their companions run on a shared server, multi-user unlock, how `pvos.sso` asserts non-owner identity. Deferred; the tenant custody core (§5) is the substrate.
- **Approval-context vocabulary.** The `action` verb set and `summary` composition rules want a short registry so prompts are consistent across apps — grow it with real apps.
- **Session-scoped approvals vs. per-signature.** The auto-approve allow-list (§3.3) needs a concrete policy grammar; start conservative (prompt-by-default), relax with usage.
