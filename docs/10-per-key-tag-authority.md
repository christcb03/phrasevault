# PVFS — Per-key tag authority (multi-tenant tags) (10)

Status: **Implemented** (`SCHEMA_VERSION` 2; doc 08 P2-G) — proposed 2026-06-20, landed 2026-06-21
Date: 2026-06-20
Depends on: [02 (P0 spec)](02-p0-core-engine-spec.md), [06 (ACLs & daemon)](06-access-control-and-daemon.md), [09 (tags & live daemon)](09-tags-and-the-live-daemon.md)
Motivation: PVOS hosts **many apps in one forest**. The current tag model assumes a single administrative domain per forest and breaks under multi-tenancy.

---

## 1. Problem — the current model is single-app-centric

Today (as implemented in `pvfs-core`):

- **Tags are matched by name only.** `projection::effective_rights` collects the member's tag *names* (`member_tags(member_pubkey, tag)`) and, per node, ORs in `grant_for(node, kind=3, tag_name)`. There is **no record of who granted** a membership and **no binding** between the key that set a node's tag grant and the key that granted a member that tag.
- **`member_tags` carries no authority.** Just `(member_pubkey, tag, set_at)`.
- **Assigning any tag requires admin on the forest root.** `check_member_event` gates `MemberTagged` with `require_right(author, forest_root, ACL_A)`.

Consequences when one forest hosts multiple apps:

1. **One global tag namespace** — App A's `friend` and App B's `friend` are the same tag. A membership granted in one app's context unlocks the other app's nodes that happen to use the same name.
2. **Only forest-root admins can assign tags** — an app cannot manage its own sharing without forest-wide admin power.
3. **No attributable tag authority** — "who decided this member is a `friend`" is not recorded or enforced.

---

## 2. Goal — a tag belongs to the key that defines it

A tag is identified not by a bare name but by **(authority, name)**, where the *authority* is the key that signed the grant. A node's tag grant and a member's tag membership **combine only when authored by the same key.** Each key is its own independent **tag authority**; one forest hosts arbitrarily many side by side.

This is the model PVOS needs (an app's grant key scopes its tags) and restates the MediaForest "share with friends" flow: the same app key signs both the node's `tag:friend → r` grant and each friend's `friend` membership, and only memberships under that key satisfy that grant.

---

## 3. The model

- **Tag identity = `(authority_pubkey, name)`.** `authority` is the `author` of the event that created the grant/membership.
- **Node tag grant:** `AclSet(node, Tag(name), rights)` — authority = the `AclSet` author (already recorded in the `acl` table's `author` column).
- **Membership:** `MemberTagged(member, name)` — authority = the `MemberTagged` author.
- **Evaluation:** a member holds a set of `(authority, name)` pairs. A node's tag grant `Tag(name)` authored by `A` is satisfied **iff** the member holds `(A, name)`. `public`, `any`, `key:` and the owner-override are unchanged.

So matching changes from *"member holds tag name N"* to *"member holds tag name N **under the same authority** that granted it on this node."*

---

## 4. Authorization change

- **`AclSet` — unchanged.** Still requires `ACL_A` on the target node. The resulting tag grant is implicitly scoped to the author's authority. An app with admin over its own region can set tag grants there, as today.
- **`MemberTagged` — relaxed.** Today it requires `ACL_A` on the **forest root**. New rule: **any authorized member may author a `MemberTagged` that assigns a tag under its own authority** (`authority == author`). The forest owner/root retains full power (can assign anything).
  - **Why this is safe:** a key-scoped membership `(A, name)` only unlocks nodes whose `Tag(name)` grant was *authored by A* — i.e. nodes A already controls (A needed `ACL_A` to set that grant). So A can only widen access to A's own region. A cannot forge a membership under another key's authority, because the authority **is** the signed author. The forest-root-admin requirement was over-broad precisely because tags were unscoped; scoping removes the need for it.

---

## 5. Why this is cheap (impact analysis)

- **Event wire encodings: UNCHANGED.** Every event already carries `author` + `sig`; the authority *is* the author. No new event fields, no PCE preimage or digest-domain changes, no signing changes.
- **Projection:** add an `authority` column to **`member_tags` and `acl`**, both populated from the event author. *(Correction, as built: the `acl` table did **not** previously store the author — this draft assumed it did — so the column was added to both tables. The author was always present in the event, so still no wire change.)* For a tag grant `authority` = the `AclSet` author; for `public`/`any`/`key` grants `authority` is empty, so those rows behave exactly as before. The primary keys gain `authority`.
- **`effective_rights`:** when gathering a member's tags, gather `(authority, name)` **filtered to authorities still active** (liveness, §9.2); when ORing a node's tag grant, require the grant row's `authority` to equal the membership authority. (Implemented in `member_tags_of` and a new `authority` parameter on `grant_for`, plus `grant_for_tag_any_authority` for `acl check` inspection.)
- **Authorization:** change the `MemberTagged` gate in `check_member_event` from "root `ACL_A`" to "author asserts its own authority" (+ owner override).
- **Schema:** this is **non-additive** (member_tags key/columns + matching semantics), so **bump `SCHEMA_VERSION`**. The projection self-heals from the log on rebuild, so no data migration script is needed beyond the rebuild.

---

## 6. Migration & compatibility

- **Existing forests rebuild cleanly.** On rebuild, legacy `MemberTagged` events are re-folded; their `author` (a forest-root admin in existing single-app forests) becomes the tag's authority. Legacy `AclSet` tag grants keep their stored `author`. Because in a today's single-app forest both were the same root/owner authority, **effective rights are preserved** — the new model's `(authority, name)` match collapses to the old name-only match when there is exactly one authority.
- **Replay safety.** The `MemberTagged` authorization rule changes, so — exactly as doc 06 §3.3 did for its replay-time author check — ship behind a **rebuild/replay parity test**: init a forest with tags under the old rule, rebuild under the new code, assert identical `effective_rights` for every (principal, node).

---

## 7. CLI & display

`tag:<name>` is now `(authority, name)`. Suggested ergonomics:

- When acting as a key, `tag:<name>` defaults `authority = the acting key` (the common case: you manage your own tags).
- Display a foreign authority explicitly, e.g. `tag:<authority-short>:<name>`, so cross-authority grants are legible.
- `acl`/`tag` inspection commands show the authority alongside the name.

---

## 8. Tests (extend `crates/pvfs-core/tests/p2_access.rs`)

1. **Cross-app isolation:** App A grants `tag:friend → r` on A-node and assigns member M `(A, friend)`; App B grants `tag:friend → r` on B-node. M can read A-node, **cannot** read B-node.
2. **Self-service tagging:** a non-root authorized member assigns its own-authority tag and shares its own node — **without** forest-root admin — and it works.
3. **No forgery:** a member cannot author a `MemberTagged` claiming another key's authority (rejected live and on replay).
4. **Revocation paths:** revoking the authority's device key, the node grant, or the membership each denies access.
5. **Migration parity:** old-rule forest with tags rebuilds to identical effective rights.

---

## 9. Authority model — decided

### 9.1 Authority is the identity key, never a per-machine device key
A tag's authority is the event *author*. The author is **one stable key per principal**, not a
per-machine key:

- **A human's direct grant/tag** is signed by their **identity key** — derived from their recovery
  phrase and reproduced by the **companion** (doc 09 §6) on *any* machine. Same phrase → same key
  everywhere, so a human has exactly **one** tag authority regardless of which device they're on.
- **An app's grant/tag** is signed by **the app's own key** (a key the owner authorized for that app).
- **Per-machine device keys (`m/43'/20566'/1'/n'`) are never the tag authority.**

This dissolves the multi-device problem at the root: a `tag:friend` grant set on the laptop and the
matching membership assigned on the phone are both authored by the **same** identity key, so they
combine. "A tag namespace = one authority key" then holds **automatically** — one key per human, one
per app — without relying on operator discipline.

> **Rejected alternative:** normalizing authority *up* to the certifying identity root. Because PVOS
> app keys are authorized members **under the forest owner's root**, that would collapse every app's
> authority back into the owner and destroy the multi-tenant isolation this change exists to provide.
>
> **Tradeoff, accepted:** using one stable identity key (vs. per-device keys) gives up *per-device*
> revocation for a human's own authority — revoking a single lost machine means rotating the shared
> key. This is covered by the companion's posture (root/identity key **encrypted at rest, unlocked
> only while the companion runs, signs per-approval** — wallet / `ssh-agent` model). See doc 09 §6.

### 9.2 Authority liveness, and orphaned-tag cleanup
A `(authority, name)` match counts **only while the authority key is a currently authorized,
unrevoked member** — §8 test 4 requires that revoking the authority denies access. Two mechanisms:

1. **Live masking (read path, no write).** `effective_rights` must confirm the grant's *and* the
   membership's authority is still active before counting the match — not merely that the rows exist.
   A revoked authority's grants/memberships go **inert immediately**, with no log write on a read.
2. **Signed sweep (maintenance, write).** Actually *removing* the now-dead rows is **not** done from
   the read path (a read can't sign, and the revoked authority can't sign its own cleanup). Instead a
   **signed maintenance sweep** appends the removal events, authored by the forest owner/admin (the
   daemon runs as the owner, so it can perform this). It runs opportunistically when masking finds an
   orphaned tag, and on demand via the forest-wide **rights audit** (doc 08 §4 items 13–14).

**Key rotation:** rotating an app's authority key orphans its existing grants/memberships until
re-issued under the new key (acceptable v1; revisit if apps need seamless rotation).

---

## 10. Open questions

- **Tag-admin delegation** — should an authority be able to authorize *another* key to assign memberships under its tag namespace? (Maps to PVOS capability delegation; defer until needed.)
- **Display/addressing** of cross-authority tags (ergonomics only).
- **Federation** — tags travel with their authority key across replicas; confirm the projection rebuild on a replica reproduces `(authority, name)` correctly (it should, since it folds the same signed events). Interacts with sub-forest replication (doc 03 §1.5): a region typically maps to one app authority, so "replicate app A's region" = "replicate the nodes A controls."
