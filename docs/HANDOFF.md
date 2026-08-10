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

**NOT yet done — the local checklist:**
1. **The real Ansible pipeline** (release build, release-binary smoke, install, and the **systemd
   daemon stage** — the container had no systemd):
   ```sh
   git fetch origin claude/phrasevault-continuation-fjdohv
   git checkout claude/phrasevault-continuation-fjdohv
   cd deploy/ansible && ansible-playbook -i inventory.ini pipeline.yml
   # artifacts land in deploy/ansible/artifacts/<host>/
   ```
2. **A genuine two-machine test.** Everything above simulated the fleet on one host (all
   `file://` paths incidentally resolve everywhere there). USER-MANUAL §7.7–§7.10 top to bottom
   across two real machines is the honest test — especially: `replica add --instance` over the
   LAN, `loc add --here` on a box that is *not* the owner, read-through across machines, and
   `tier`/`evict` actually freeing space on the edge.
3. **Scale spot-check.** Sync/tier/cat stream in 1 MiB chunks and were tested on toy files; run
   one real multi-GB media file through sync → tier → evict → stream.
4. **Container-only test caveat** (expected, not a bug): `p15_mounts` and `init_via_companion`
   fail *when run as root* (the raw-root init refusal working as designed); both verified passing
   as a normal user. Presubuntu runs as a user — unaffected.

## 3. Release housekeeping (after validation)

- Workspace is still `1.2.0` and `v1.2` is still untagged (pre-session state). The CHANGELOG's
  Unreleased section now holds this arc **plus** the earlier D18/D32/D57 companion/tenant/pvfsd
  work. Suggest: tag `v1.2` where it was validated, then package this arc as `1.3.0` (bump
  workspace version, date the CHANGELOG, flip `INSTALL.md`'s version string, update doc 08 §3.3
  header) — or fold everything into one release; Chris's call.
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
