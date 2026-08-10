# Handoff — the P4 federation & sync arc (session of 2026-08-08 → 08-10)

**Status: built and container-validated; awaiting Chris's local pipeline run + real-fleet test.**
This file is disposable — delete it once the validation lands and release packaging is done.
The design record is [doc 17](17-federation-and-sync.md); status tables are
[doc 08](08-roadmap-and-status.md) §1 + §3.3; operator docs are
[USER-MANUAL](USER-MANUAL.md) §6.1 and §7.4–§7.10.

---

## 1. What was built (9 commits on `claude/phrasevault-continuation-fjdohv`)

| Commit | Phase | One line |
|---|---|---|
| `0d826de` | **F0** | `pvfs export` — materialize a tree as a native directory (symlink/hardlink/verified-copy) for Plex & any non-PVFS app |
| `1bcf0ae` | **F1** | `pvfsd --listen` — TCP+TLS with a **transport pin** (no CA), `pvfs instance` registry, `remote --connect/--instance`, single-use challenge nonces (doc 08 §4 item 7 closed) |
| `b7dca98` | **F2** | `pvfs replica add/sync` — admin-gated log shipping, chain-verified ingest, the standard replay proves the whole copy; replicas are read-only forest dirs `pvfsd` serves with identical ACLs |
| `b5dfb79` | **F3** | `pvfs place <t> sync` + `pvfs sync` / `export --fetch` — hash-verified fetch into a managed store; `pvfs-sync://` locations synthesized from store existence (no projection state) |
| `84f4f1f` | **F5.0** | Write-through replicas: `add`/`loc add`/admin ops on a replica route to its source, member-signed; read-your-writes tail pull |
| `d49ceb7` | **F5.1** | `pvfs-host://<pin>/<path>` locations — *which instance* holds the bytes, as catalog truth; `loc add --here` |
| `c5fdd71` | **F5.2** | Read-through: per-file candidate fetch (registry-pinned holders → source), self-healing `cat`, owner-side pulls |
| `1d24318` | **F5.3** | The mover: `place <t> central --to <dir>` + `pvfs tier` (migrate, log, retire) + `pvfs evict` (safe edge reclaim) |
| `8758c21` | **F5.4** | Tail-subscribe: `LogWait` long-poll + `pvfs replica follow` — owner events on replicas in seconds |

The end-state fleet (doc 17 §7.6): ingest box catalogs downloads in seconds and evicts on a
schedule; the NAS owns the forest and runs the mover; consumer boxes follow live, sync or
read-through bytes, and export to Plex. Multi-master was deliberately avoided throughout — the
owner's single signed chain is still the only log (doc 13 §A).

## 2. Validation state

**Done, in the dev container (every commit):**
- `cargo test --workspace` green as a non-root user (including ~20 new tests across
  `p4_export.rs`, `p4_sync.rs`, `pvfsd/tests/{tls,replica}.rs`, nonce unit test)
- `cargo clippy --workspace --all-targets -- -D warnings` clean
- The smoke suite, grown **193 → 262 checks, 0 failures** — includes multi-daemon, multi-replica,
  three-instance choreography of the entire pipeline (ingest → read-through → tier → evict →
  still-streams), all over real sockets and real TLS on one machine

**Done locally (2026-08-10) — the checklist completed:**
1. **The real Ansible pipeline**, on presubuntu *and* a fresh second host (pvos-test,
   192.168.0.138): release build, 194 cargo tests, smoke **268 passed / 0 failed** (after the
   silent-miss repair, `1536edc`), install + the full systemd daemon stage green on both,
   `clippy -D warnings` clean. Artifacts in `deploy/ansible/artifacts/<host>/`.
2. **The genuine two-machine test** — `deploy/fleet-test.sh` (presubuntu owner/NAS,
   pvos-test edge/ingest): **40/40**. Replicate over the LAN, the honest cross-machine
   UNAVAILABLE stat, read-through in both directions, write-through ingest with
   `loc add --here`, tier to central, evict reclaiming the edge, still-streams throughout.
3. **Scale spot-check**: one 3 GiB file — cataloged in 10 s, `tier` pulled it over the LAN in
   83 s (~37 MB/s, verified), `evict` freed all 3 GiB, streamed back bit-perfect at ~38 MB/s.

**Findings from the two-machine run (for docs / the next arc):**
- Write-through authorship needs `device authorize-member` on the owner — an ACL grant alone
  is refused at ingest (`UnknownAuthor`; default-deny working as designed). USER-MANUAL §7.9
  should say so explicitly.
- **Outbound fetches authenticate as the box's client identity, never the forest device
  key** — including the owner's own mover: on a private forest (no `public r`), `pvfs tier`
  cannot pull from an edge box until the owner's *client* identity is authorized + granted
  read. Single-host smoke never sees this (it grants `public r` early). Decide: document the
  grants as the model, or teach owner engines to dial with the device key.
- Operational: pvosd holds port 7420 on presubuntu; the fleet test uses 7430/7431.
- Container-only caveat (expected, not a bug): `p15_mounts` and `init_via_companion` fail
  *as root* (raw-root init refusal working as designed); both pass as a normal user.

## 3. Release housekeeping (after validation)

- **Decided (2026-08-10): the two-release shape.** Packaged as `1.3.0` — workspace bumped,
  CHANGELOG dated, `INSTALL.md` and doc 08 §3.3 updated. Pending (Chris, manual): tag `v1.2`
  at `49b0e0d` (where the 1.2 line was validated) and `v1.3` at the packaging commit, then
  push. The outbound-fetch identity finding is parked as doc 17 §9 Q5 (deferred, Chris's
  call in a future arc). After the tags land, this file can be deleted.
- `pvfsd@.service` stays `Type=simple` (sd_notify is a no-op there); PVOS's `Type=notify` units
  are the D57 consumers.

## 4. Next work, in rough order (the standing list)

1. **Serve integration (F0.1/F3.1):** the `serve` loop keeps exports fresh and runs
   sync/tier/evict/follow as background jobs — turns the cron-style loops into daemons.
2. **Write-through completeness:** `loc rm`, `link`/`unlink`/`reorder` wire ops (deliberately
   unrouted in F5.0).
3. **`pvfs sync --to <dir>`** custom sync-store destinations (today: managed store under `.pvfs/`).
4. **Mode B crosslink** (doc 03 §6 Q4): a grant that lets a replica's held copy be recorded in the
   owner's log as catalog-visible redundancy (today only the owner's own `tier` does that).
5. **F4 tier** (doc 17 §8): region-granular logs (doc 13 §B — the decided design), FUSE
   read-through mount (open-and-stream without prefetch), swarm transfer, standby failover.
6. Long-deferred polish: Touch ID unlock (doc 14), stable macOS .app signing identity.

Pick-up note for a future session: doc 17 is the map — every phase section carries its as-built
decisions, and §9 holds the open questions.
