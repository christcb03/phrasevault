# Phase B — per-node ACLs: implementation plan, decisions, open questions, progress

Working journal for the Phase B build (doc 06 §4). Written **before** implementation
so the plan survives if the session ends mid-way. Update the Progress Log as steps land.

Status legend: ☐ todo · ◑ in progress · ☑ done & verified on presubuntu

---

## 0. Scope (from doc 06 §4 / §10 Phase B)

Per-node access-control lists, stored as signed events, evaluated with inheritance.
Phase B delivers the **data + evaluation + management**, not cross-user enforcement —
that arrives with the daemon (Phase C). The owner's own engine stays full-rights; the
ACL machinery is what the daemon will consult per connected principal.

Out of scope for B (deferred, tracked below): the daemon/socket, read-path filtering by
caller, named groups, explicit deny.

---

## 1. Open questions for Chris (answered by sensible defaults; flag if you disagree)

I proceeded with the defaults so the build could continue overnight. Each is cheap to change.

1. **Principals in v1 = `key:<pubkey>` and `any` (every authorized member).**
   Named groups deferred to a later sub-phase (they need a group-membership mechanism /
   another event kind). `any` is the filesystem-"other-but-authenticated" bucket. → default taken.
2. **Grant-only (no explicit deny).** Rights are inherited *down* the tree and can only be
   *added* by descendants, never carved out. "Share /media but hide /media/private" needs
   explicit deny, which is a future item (doc 06 §11.2). → default taken.
3. **Owner vs member discriminator = `device_index`.** HD-derived owner devices
   (`index < 2^31`, incl. genesis device 0) have implicit **full (rwa)** rights everywhere;
   external members (`authorize_member`, `index == u64::MAX`) get rights **only** via ACL.
   This reuses data already in `device_keys` — no new event/field. → default taken.
4. **CLI is `pvfs acl set|ls|check` (setfacl/getfacl-style)** rather than doc 06 §10's
   illustrative `forest grant/revoke`. More filesystem-like and self-contained. doc 06 §10
   updated to match. → default taken.
5. **Phase B does not filter reads or block the owner.** The owner is always full-rights, so
   ACL enforcement is a no-op for owner-context engine ops. `effective_rights()` is provided
   for the daemon (Phase C) to enforce per connected principal. → default taken.

If any of these is wrong, the fix is localized (noted per step below).

---

## 2. Data model

### 2.1 Rights — `u8` bitmask
`R = 0b001` (read), `W = 0b010` (write children/payload), `A = 0b100` (admin: set ACLs on
this node + subtree). `0` = no grant (and an `AclSet` with rights 0 removes the entry).

### 2.2 Principal
```
enum Principal { Any, Key(Vec<u8>) }      // Key = 33-byte compressed secp256k1
```
Wire form: `principal_kind: u64` (0 = Any, 1 = Key) + `principal_id: bytes` (pubkey, or empty).

### 2.3 `AclSet` event (new kind `K_ACL_SET = "AclSet"`)
```
AclSet { node_id, principal_kind, principal_id, rights, set_at, author, sig }
```
- digest domain `pvfs:aclset:v1:` over (node_id, principal_kind, principal_id, rights, set_at, author).
- `author` is a device key that **holds `a` (admin)** on `node_id` at apply time
  (owner devices always qualify). Verified in `replay_one` (apply) and later in the daemon.
- Encoding order (PCE): string(node_id) · u64(principal_kind) · bytes(principal_id) ·
  u64(rights) · u64(set_at) · bytes(author) · bytes(sig). Matches existing event style.

### 2.4 `acl` projection table
```sql
CREATE TABLE acl (
  node_id        TEXT    NOT NULL,
  principal_kind INTEGER NOT NULL,   -- 0=any, 1=key
  principal_id   BLOB    NOT NULL,   -- pubkey for key; X'' for any
  rights         INTEGER NOT NULL,   -- bitmask, always > 0 when row present
  set_at         INTEGER NOT NULL,
  PRIMARY KEY (node_id, principal_kind, principal_id)
);
```
Fold `AclSet`: rights>0 → INSERT OR REPLACE; rights==0 → DELETE the row. Added to
`MAIN_OBJECTS` so full rebuild drops/recreates it.

---

## 3. Evaluation — `effective_rights(conn, principal, node_id) -> u8`

```
if principal is Key(pk) and pk is an authorized, unrevoked OWNER device (index != u64::MAX):
    return R|W|A
rights = 0
cur = node_id
loop:
    rights |= grant(conn, cur, principal)      # exact match
    rights |= grant(conn, cur, Any)            # wildcard
    cur = contains_parent(conn, cur)           # links: child=cur, type=contains, active
    if cur is None: break
return rights
```
- `contains_parent`: `SELECT parent_id FROM links WHERE child_id=?1 AND link_type=<contains>
  AND removed_at IS NULL` — `parent_id IS NULL` (root link) ends the walk.
- Inheritance = union of grants on the node and every contains-ancestor (grant-only).
- Shared by the engine API and the `AclSet` apply check (same function, takes `&Connection`;
  a `Transaction` derefs to `&Connection`).

---

## 4. Engine API (engine.rs)

- `pub fn set_acl(&mut self, node_id, principal: &Principal, rights: u8) -> Result<()>`
  - `ensure_device_active()`; require local device holds `A` on `node_id`
    (`effective_rights(conn, Key(self.device_pub), node_id) & A != 0`) — owner passes.
  - sign + `append_durable(AclSet{...})` authored by the local device.
- `pub fn effective_rights(&self, principal: &Principal, node_id) -> Result<u8>`
- `pub fn acl_entries(&self, node_id) -> Result<Vec<(Principal, u8)>>` (direct grants on node, for `acl ls`).
- `Principal`, `rights` consts (`ACL_R/W/A`), and `rights_to_str`/`parse_rights` helpers exported from the crate.

## 5. CLI (main.rs) — `pvfs acl …` (operates in the current forest context `ctx`)
- `pvfs acl set <path> <principal> <rights>` — `<principal>` = `any` | `key:<hex>`;
  `<rights>` = e.g. `rw`, `r`, `rwa`, or `-`/`none` to clear. Resolves `<path>` → node via
  `mount::node_at_path` (URI/abs path) or treats a 64-hex arg as a node id.
- `pvfs acl ls <path>` — list direct grants on the node.
- `pvfs acl check <path> <principal>` — print effective rights (incl. inherited + owner rule).

## 6. Apply-time check (projection.rs replay_one)
For `AclSet`: after the generic author-must-be-authorized check, additionally require
`effective_rights(tx, Key(author), node_id) & A != 0`, else reject (Integrity/UnknownAuthor).
Owner devices pass implicitly; bootstrapping the first ACL works (owner has implicit admin).

---

## 7. Test plan
Core unit (projection / engine internal):
- AclSet encode→decode roundtrip; `Event::author()` returns the signer.
- owner device → full rights on any node, even with no ACL rows.
- member key: no grant → 0; grant R on a folder → R on it and its descendants (inheritance);
  no rights on ancestors above the grant.
- `any` grant visible to an authorized member; revoke (rights 0) removes it.
- apply rejects an `AclSet` whose author lacks admin (member without `a` trying to grant).
- survives full rebuild (delete index.db → reopen): acl table repopulated.
Integration (public API): set/ls/check happy path + bad principal/rights guards.

---

## 8. Progress log
- 2026-06-15: Plan written (this doc). Starting implementation.
- 2026-06-15: **Phase B implemented and verified on presubuntu — 55 tests pass, smoke green.**
  - ☑ `acl.rs`: `Principal`, rights consts/parse/format, `MEMBER_DEVICE_INDEX`.
  - ☑ `AclSet` event (kind/author/encode/decode/verify, `msg_acl_set`).
  - ☑ `acl` table + `MAIN_OBJECTS` + fold (insert/replace; rights 0 → delete).
  - ☑ `projection::effective_rights` + `grant_for` + `contains_parent`; owner short-circuit.
  - ☑ `replay_one` apply check: `AclSet` author must be authorized **and** hold `a` on the node.
  - ☑ Engine `set_acl` / `effective_rights` / `acl_entries`.
  - ☑ CLI `pvfs acl set|ls|check`.
  - ☑ Tests: rights/principal parse, forged non-admin `AclSet` rejected, inheritance + `any`
    wildcard + owner-full + clear + rebuild.
  - **Decision deviation (noted):** CLI takes a **node id** (64-hex), not a path — consistent
    with the rest of the low-level CLI (`add`, `loc`, `ref` all take node ids). Path/URI
    resolution for `acl` is a later nicety. Updated doc 06 §10.
  - **No SCHEMA_VERSION bump:** the `acl` table is additive via `CREATE TABLE IF NOT EXISTS`,
    so existing forests gain it on next open without a migration/version error.

### Remaining for later phases (not Phase B)
- ☐ Read-path filtering by caller (Phase C / daemon) — `children()`/`cat` stay owner-context.
- ☐ Named groups; explicit deny (doc 06 §11).
- ☐ A dedicated `Forbidden` error (set_acl currently returns `BadInput` when a device lacks
  admin — only reachable for non-owners, which arrive with the daemon).
