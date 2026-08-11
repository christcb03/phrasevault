# 19 — Write-through completeness + sync --to (P6)

**Status: BUILT + VALIDATED (2026-08-11, commit `7c868c0`) — 209 tests, 297 smoke,
clippy clean.** As-built notes: the `set_sig` accessor was missing `LinkReordered`
(caught by the new authorization test — a member's signature was silently dropped);
the smoke's daemon-jobs section exposed a latent concurrent-fold race in projection
catch-up, fixed separately (`58adaa2`). Packaging DECIDED (Chris,
2026-08-11): no 1.4 cut yet — nothing is deployed beyond testing, so Unreleased
accumulates until the region arc (doc 20) completes, then one release tells the
whole story.
Prerequisite reading: doc 17 §7 (the write-through model), doc 18 (the job supervisor
these ops ultimately serve).

## 1. Goal

F5.0 deliberately left three things unrouted on replica mounts — `loc rm`, the link
ops (`link`/`unlink`/`reorder`), and any say over where synced bytes land. That was
right then (no consumer needed them); the P5 fleet changes that:

- An **ingest box** that catalogs with `loc add --here` has no way to *retract* a
  location it recorded wrongly (`loc rm` refuses on a replica) — only the owner's
  mover retires locations today.
- A consumer curating shared trees (ref links, ordering — doc 04's link model) must
  shell into the owner to do it.
- A consumer's synced bytes always land inside `.pvfs/` on whatever disk holds the
  replica — the media box wants the big disk (doc 17 §7.4 mentioned this gap).

P6 closes all three. The write model does NOT change: the owner stays the only
writer; these are the same member-signed, source-routed mutations as `add`/`loc add`
(doc 17 §7.1), just completing the op set. Temp nodes stay forest-local by design.

## 2. P6.0 — the four missing wire ops

New `WriteOp` variants, mirrored end to end (proto → pvfsd prepare/commit → client
methods → CLI routing):

| Op | Engine call (exists) | Authority (same as local) |
|---|---|---|
| `RemoveLocation { file, uri }` | `remove_location` | `w` on the file |
| `Link { parent, child, link_type, key? }` | `link` | `w` on the parent |
| `Unlink { link_id }` | `remove_link` | `w` on the link's parent |
| `Reorder { link_id, key }` | `reorder_link` | `w` on the link's parent |

- The daemon's two-phase prepare/commit shape is unchanged — each op builds its
  signable event(s), the member signs, the daemon authorizes + commits. No new
  authority semantics: whatever the local engine refuses, the daemon refuses.
- CLI: on a replica mount these currently die with "replica engine refuses local log
  writes"; they now route via `daemon_client` exactly like `add`/`loc add`
  (read-your-writes tail pull included). Owned mounts keep their local path.
- `pvfs evict` note: an edge that `loc rm`'s its own `--here` location must not
  strand bytes — removal is catalog truth, eviction stays gated on *retired* rows;
  no interaction (verified by test).

## 3. P6.1 — `pvfs sync --to <dir>`

Deployment state, never log events (the placement rule): `pvfs sync --to <dir>`
records the store root in `<data_dir>/sync.store`; `sync_store_path()` resolves
against it. As-built decisions:

- **Both roots stay readable.** Files fetched before the move still serve: the read
  path synthesizes `pvfs-sync://` locations from existence in the *configured* root
  first, then the default root. No migration pass — `pvfs evict`/re-fetch churn
  converges naturally (a `sync migrate-store` helper is cut until someone needs it).
- New fetches (sync job included) land under the configured root; the sink's
  tmp+rename atomicity is unchanged (chaos-validated invariant).
- Bare `pvfs sync --to` with no dir prints the current root; `--to default` clears.

## 4. Phases + turnkey checklist

| Phase | Deliverable | Done means |
|---|---|---|
| **P6.0** | 4 wire ops + daemon handlers + client methods + CLI replica routing | replica-side `loc rm`/`link`/`unlink`/`reorder` land in the owner's log, member-signed; refused without `w`; pvfsd tests + smoke checks |
| **P6.1** | `sync.store` config + `--to` plumbing through sync/cat/export read paths | fetch lands on the configured disk; pre-move files still serve; jobs honor it |
| **Validate** | pipeline both hosts + smoke + a fleet-test ingest-retraction check + clippy | all green; doc 08 §3.4 updated |

Packaging intent (Chris to confirm at close): **1.4.0 = P5 + P6 + the tmp-sweep fix.**

## 5. Open questions

1. `Link` across trees (a ref into another tree's node) — allowed locally today?
   Route whatever local allows; no new policy on the wire.
2. Should `loc rm` of the *last* location warn (the file goes UNAVAILABLE)? Local
   behavior is silent today; wire mirrors local. Revisit with UX polish.
