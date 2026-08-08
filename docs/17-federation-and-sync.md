# PVFS — P4 federation & sync: the plan, phased (17)

Status: **Phasing proposal (F1–F4) + F0 built** — drafted 2026-08-08. F0 (`pvfs export`) is
implemented; F1+ are design-locked by docs 03/13 but not yet built.
Depends on: [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md) (data model —
decided), [13-pvos-driven-requirements.md](13-pvos-driven-requirements.md) §A–§D (write model +
region design — decided), [04](04-p1-storage-and-fs-ops-spec.md)/[05](05-instance-registry-and-mounts.md)
(storage & mounts), [07](07-daemon-protocol.md) (daemon protocol), [11](11-compaction-and-verifiable-snapshots.md)
+ [15](15-key-replacement.md) (compaction/lineage edges).

This doc turns the decided P4 model into an implementation order, driven by one concrete scenario.
It adds **no new trust decisions** — where doc 03/13 decided, this doc only sequences.

---

## 1. The driving scenario

**A media server.** Plex (or any non-PVFS app) points a library at a PVFS tree. The actual files
live in many places — several disks on this host, and other hosts entirely. The tree presents them
as **one hierarchy**, and per tree (or subtree) the deployment either:

- **pointer** — the tree references bytes where they already live; nothing is copied; or
- **sync** — bytes are replicated to chosen locations (e.g. pulled local so the media server
  streams from its own disk).

Generalized: **the PVFS tree is the catalog; placement policy decides where bytes live; a
presentation layer makes the tree readable by software that has never heard of PVFS.**

### What exists today vs. what's missing

| Need | Today |
|------|-------|
| Many storage locations behind one tree | ✅ multiple bound folders + `FileLocationAdded` (multi-location per node), doc 04 |
| Verified reads, quarantine, reconcile | ✅ doc 04 |
| Cross-user serving on one host | ✅ `pvfsd`, doc 07 |
| **Native-FS presentation for non-PVFS apps** | ❌ — **F0 (this doc, built)** |
| **Cross-instance transport & identity** | ❌ — F1 |
| **Forest replica (verified log shipping)** | ❌ — F2 (doc 03 Mode A) |
| **Placement policy + sync engine (pointer vs sync)** | ❌ — F3 |
| Region-granular logs, FUSE streaming, swarm, failover | ❌ — F4 (doc 13 §B / doc 03 §6) |

### Why this order

F0 delivers the media-server integration **immediately** for bytes that are already local, with no
kernel or wire change — and every later phase feeds the same surface (F3 fills the exported tree
from remote locations; F4 streams what isn't synced). F2 does **whole-forest** replication first
because doc 03 Mode A needs no kernel change (one linear chain, prefix verification), while doc 13
§B's per-region logs restructure the log itself — a media forest is naturally a whole-forest unit,
so region granularity isn't on this scenario's critical path.

---

## 2. Phase table

| Phase | Scope | State |
|-------|-------|-------|
| **F0** | `pvfs export` — materialize a tree as a native directory (symlink / hardlink / verified copy), manifest-tracked idempotent re-runs, prune | ✅ built (§3) |
| **F0.1** | `pvfs serve` keeps exports fresh (re-export on change), `export --fetch` once F3 lands | ☐ small follow-on |
| **F1** | Network transport: `pvfsd --listen` over TCP+TLS with a pinned transport cert, single-use challenge nonces (doc 08 §4 item 7), `pvfs instance` registry + `remote --connect/--instance` | ✅ built (§4) |
| **F2** | Forest replica — doc 03 Mode A: full-log fetch + tail follow, chain/signature verification on ingest, replica projection served read-only by `pvfsd`; multi-forest data dir (doc 03 §1.1) | ☐ |
| **F3** | Content plane: per-subtree **placement policy** (`pointer` \| `sync`), the sync engine (fetch-by-hash, verify, record), replica-local cache locations | ☐ |
| **F4** | Region logs (doc 13 §B — the decided target architecture), FUSE read-through mount (pointer-mode streaming), swarm/torrent data plane (doc 03 §2.2 future schemes), standby failover (doc 03 §6 Q3) | ☐ later |

---

## 3. F0 — `pvfs export`: the native view (built)

**One command materializes a tree as a plain directory** any app can read:

```
pvfs export <target> <dest-dir> [--mode symlink|hardlink|copy] [--prune]
```

`<target>` is anything the CLI already resolves (node id, mount-relative path, `pvfs://` URI).
Point Plex at `<dest-dir>`; done.

### Decisions

1. **Materialized view, not a mount.** A symlink tree needs no kernel module, no FUSE dependency,
   works on every OS target, and is trivially inspectable. FUSE remains the F4 answer for
   *pointer-mode streaming* (bytes that aren't local); it is explicitly **not** required for the
   sync-mode media case — media you stream repeatedly should be synced local anyway (F3).
2. **Three modes.**
   - `symlink` (default): zero bytes copied; entries point at the node's first readable location
     (same resolution the daemon data plane uses — quarantined/pending locations skipped).
   - `hardlink`: same-filesystem exports where the consuming app refuses symlinks; skips (with a
     per-entry report) across devices.
   - `copy`: streams through `Engine::cat`, so every copy is **hash-verified** while it's written
     (a mismatched location quarantines exactly like a normal read; the entry is reported skipped).
     Copies land via temp-file + rename.
3. **The export dir is owned, marked, and idempotent.** A `.pvfs-export` manifest at the dest root
   records the exported root id and every entry. Re-running refreshes what changed, counts what
   didn't, and either prunes entries that left the tree (`--prune`) or lists them as stale.
   Exporting into a non-empty directory **without** a manifest is refused — `export` never adopts a
   directory it didn't create. A manifest for a different root is likewise refused.
4. **Skips are reported, never fatal.** Per-entry skip reasons in the report (and `--json`):
   - a file with **no readable local location** — the "pointer without bytes" case that F3's sync
     engine (or F4's FUSE) resolves;
   - **secure nodes** — ciphertext is meaningless to a media app (companion-gated reads are the
     point, doc 12);
   - **folder `ref` children** — descending a ref would duplicate a subtree that has its one home
     elsewhere (spec §12); file refs export normally (same bytes, second name — cheap under
     symlink/hardlink).
5. **Names are labels, made filesystem-safe.** `/`, control chars sanitized; empty/`.`/`..` become
   `node-<id8>`; a within-folder collision (or an over-long name) is disambiguated as
   `<label>~<id8>`. Deterministic across runs (child order is `order_key`-stable).
6. **Owner-side, full-tree.** v1 exports over the local engine (the owner reads everything), so no
   ACL filtering applies. A member-scoped export materializes what that member can `ls` — that
   composes with F2 (export *from a replica*) and is deferred to it.

### The media flow, today

```
pvfs forest init --mount ~/media
pvfs bind ~/media/library /mnt/disk1/movies     # as many binds as there are places
pvfs bind ~/media/library /mnt/disk2/tv
pvfs scan
pvfs export ~/media/library /srv/plex-library   # → point Plex at /srv/plex-library
```

Files on other hosts join the same tree when F2/F3 land — same export, more entries filled in.

---

## 4. F1 — instance identity & transport ✅ BUILT (2026-08-08)

The smallest network layer that makes doc 03's model real. As built:

- **Transport identity = the pin, not the genesis id.** `instance_id` is bound into every existing
  forest's `ForestCreated` genesis (doc 03 §1.2), so it cannot retroactively become a key. Instead
  each serving instance gets a **transport pin**: `pvfsd --listen` generates a self-signed TLS cert
  on first use (`<data_dir>/nettls/`, key `0600`) and the pin is the **BLAKE3 hex of the
  certificate DER** — printed at startup and written to `nettls/pin`. Clients verify **only** the
  pin (no CA, no roots, no names): a MITM needs the private key. Rotating the material mints a new
  pin; peers re-pin explicitly, like re-pairing (doc 14's lesson). The registry binds
  `instance_id`-bearing forests to `(address, pin)` — which is exactly doc 03 §2.2's "reachability
  is resolved via config, not URIs".
- **Transport:** the existing `pvfs-proto` framing over **TCP + TLS** (rustls, blocking
  `StreamOwned`, no async runtime — doc 07 §8's decision carries over), listening alongside the
  Unix socket; `serve_connection` is one generic body for both. TLS is transport privacy + server
  identity; **principals still authenticate per connection** with the same challenge-response, so
  ACL enforcement is identical on both transports.
- **Single-use nonces (doc 08 §4 item 7): done.** Challenge nonces are registered at issue and
  consumed on first use, on every transport — a captured auth signature can never be replayed.
- **Reachability registry:** `pvfs instance add <name> <host:port> <pin>` (stored in
  `<config>/instances`), `instance ls|rm`; `pvfs remote --instance <name>` dials it, or
  `--connect <host:port> --pin <hex>` directly. Manual, explicit trust — adding the entry **is**
  the pinning step. Discovery is not v1.
- **Remote append stays closed** in F1 — reads and member-signed writes ride the existing daemon
  ops; replication protocols come with F2, the crosslink grant (doc 03 §6 Q4) with F3.

## 5. F2 — forest replica (doc 03 Mode A)

- `pvfs replica add pvfs:<instance_id>/<forest_id>` — fetch the full log from the owner, verifying
  chain hashes + event signatures **during ingest** (the doc 03 §3 trust fixes are already in every
  event); then `replica sync` / a `serve`-integrated tail follow.
- A replica is a **second forest in the data dir** — this is where doc 03 §1.1's multi-forest host
  lands. The projection rebuilds locally; `pvfsd` serves it **read-only**, ACL-filtered as usual
  (the log carries every grant, so a replica enforces exactly what the owner would).
- **Lineage edges honored:** a `RootRotated` chain (doc 15 case C) verifies across the swap; a
  compacted forest replicates from its checkpoint with the sealed archive as the deep-verification
  path (doc 11, doc 03 §6 Q8).
- `pvfs export` from a replica = the cross-host media library, pointer-mode (metadata local, bytes
  still remote until F3).

## 6. F3 — placement policy & the sync engine

The pointer-vs-sync knob, per subtree:

- **Placement policy is deployment state, not catalog truth** — stored per-instance (projection /
  config, like bindings), **never** log events: two replicas legitimately pin different subtrees,
  and policy must not need the owner's signature. Precedent: temp data and bindings already live
  outside the log (doc 01, doc 04).
  - `pvfs place <target> pointer` (default — today's behavior)
  - `pvfs place <target> sync [--to <bound-folder>]` — "keep this subtree's bytes local, here."
- **The sync engine** (a `serve` job + `pvfs sync` one-shot): walk `sync`-placed subtrees; for each
  file node with no local bytes, fetch from a remote location by **content hash** over the F1 data
  plane (the raw `cat` plane already streams; P2-F was built as "the torrent seam"), verify against
  the node's hash while writing, then record the new copy.
- **Where the new copy is recorded:** a replica cannot append to the owner's log, so locally
  fetched bytes are recorded as **replica-local locations** (projection-only, like
  `temp_file_locations`) — instantly readable, never claiming to be owner-catalog truth. The
  optional doc 03 **Mode B crosslink** (owner appends `FileLocationAdded` naming the replica's
  copy, via an authenticated remote-append grant) upgrades a copy to catalog-visible redundancy —
  that's where doc 03 §6 Q4's grant mechanism lands.
- **`local_only` honored:** a `local_only` region (doc 13 §C) never syncs out, ever. Secure regions
  sync as **ciphertext + hash-ledger only** (doc 13 Q-C2).
- `pvfs export` gains `--fetch`: materialize missing bytes through the sync engine during export.

## 7. F4 — later, in this order when needed

1. **Region logs** (doc 13 §B — already the decided architecture): per-region logs + parent
   head-commitments; unlocks per-app replication, per-region compaction, and region-scoped
   active-active (doc 13 §A's later HA mode).
2. **FUSE read-through mount**: the pointer-mode streaming answer (open → resolve → stream via the
   data plane, cache-promote per policy). The materialized export stays the zero-dependency path.
3. **Swarm data plane**: multi-source fetch-by-hash (doc 03 §2.1's future schemes; P2-F's seam).
4. **Standby failover** (doc 03 §6 Q3) — explicit promotion protocol, never automatic dual-writers.

---

## 8. Open questions (new ones only — doc 03 §6 still governs the old ones)

1. **TLS details (F1):** self-signed cert pinned by instance key vs. raw-key TLS (RFC 7250-style);
   how the companion's localhost-cert experience (doc 14) informs the trust prompt when adding an
   instance.
2. **Tail-follow transport (F2):** long-poll over the existing request/response framing vs. a
   subscribe frame; resume tokens are just `(seq, chain_hash)` prefixes either way.
3. **Sync scheduling (F3):** how aggressive the `serve` sync job is (bandwidth caps, schedules,
   "sync on first read" promotion).
4. **Export of folder refs (F0/F4):** revisit once region links exist — a folder ref to a replicated
   region could export as a real subtree scoped to that region's log.
