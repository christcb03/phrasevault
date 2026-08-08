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
| **F2** | Forest replica — doc 03 Mode A: admin-gated log shipping (`LogInfo`/`LogRead`), `pvfs replica add/sync`, chain-verified ingest + fully verified replay at open, read-only replica forests served by `pvfsd` | ✅ built (§5) |
| **F3** | Content plane: per-subtree **placement policy** (`pvfs place` — `pointer` \| `sync`), the sync engine (`pvfs sync`, `export --fetch` — hash-verified streaming into the managed store, synthesized `pvfs-sync://` locations) | ✅ built (§6) |
| **F5.0** | **Write-through replicas**: mutations on a replica route to its source, member-signed; read-your-writes tail pull | ✅ built (§7.1) |
| **F5.1** | **Instance-qualified locations**: `pvfs-host://<pin>/<path>` — cross-host location truth | ☐ next (§7.2) |
| **F5.2** | **Remote read-through**: fetch-on-demand from the instance a location names, into the F3 store | ☐ (§7.3) |
| **F5.3** | **The mover**: `place <subtree> central` + owner-side migration + edge eviction — the tiering flow | ☐ (§7.4) |
| **F5.4** | **Tail-subscribe**: long-poll log shipping for seconds-fresh replicas | ☐ (§7.5) |
| **F4** | Region logs (doc 13 §B — the decided target architecture), FUSE read-through mount (pointer-mode streaming), swarm/torrent data plane (doc 03 §2.2 future schemes), standby failover (doc 03 §6 Q3) | ☐ later (§8) |

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

## 5. F2 — forest replica (doc 03 Mode A) ✅ BUILT (2026-08-08)

As built:

- **Log shipping is a gated daemon read.** New wire ops `LogInfo` / `LogRead` ship raw signed log
  rows in batches (row + byte capped). The gate: **admin rights (`a`) on the forest root** — true
  for the owner's devices automatically (rights short-circuit) and for anyone the owner grants `a`
  at the root. A full log reveals the whole forest's history, so replication is an owner/admin
  capability, not a member read (consistent with doc 13 §D3's "a host can read what it hosts").
- **`pvfs replica add <mount> --instance <name> | --connect+--pin | --socket <path>`** pulls the
  full log into a fresh forest dir. Ingest verifies **chain linkage row-by-row** (fail fast on a
  tampered tail); then the open runs the standard startup replay, which verifies **everything** —
  chain from the genesis seed, every event signature, and replay-time authorization (doc 03 §3's
  trust fixes were built for exactly this). *A replica that opens is a proven copy*, not a trusted
  download. A `replica` marker records the source; `pvfs replica sync` re-dials it, ships the
  tail, and re-verifies.
- **A replica is an ordinary forest dir, read-only.** Not a second forest *inside* a data dir —
  each forest (owned or replica) keeps its own `.pvfs/`, which the mount/registry model already
  handles; doc 03 §1.1's multi-forest host is satisfied at the host level, no kernel restructure.
  `Engine::open` routes marked dirs to a replica open that refuses every log write (the owner
  instance stays the forest's only writer) — so `pvfsd` serves a replica read-only with **identical
  ACL answers** (the grants are in the shipped log), and `pvfs export` works on it unchanged.
- **F0 + F2 compose today:** export from a replica = the cross-host media library. Bytes resolve
  where the owner's `file://` locations happen to exist locally; elsewhere they're the exported
  view's reported skips until F3 syncs them.
- **Lineage edges honored by construction:** replay already validates `RootRotated` chains (doc 15
  case C), so a rotated forest replicates correctly; the compaction-checkpoint cut remains with
  doc 11 (doc 03 §6 Q8).

## 6. F3 — placement policy & the sync engine ✅ BUILT (2026-08-08)

The pointer-vs-sync knob, per subtree. As built:

- **Placement policy is deployment state, not catalog truth** — a plain per-instance file
  (`<data_dir>/placement`, like the replica marker and bindings), **never** log events: two
  replicas legitimately pin different subtrees, and policy must not need the owner's signature.
  - `pvfs place <target> pointer` (default — pointer entries are simply absent)
  - `pvfs place <target> sync` — "keep this subtree's bytes local."
- **The sync engine:** `pvfs sync` (one target, or every `sync`-placed subtree) walks the
  contains-closure, finds file nodes with **no readable local location**, and streams each from the
  replica's recorded source over the existing raw data plane (P2-F, "the torrent seam"), **hashing
  while the bytes arrive**: a hashed node must match its content hash exactly; a lazy node is
  checked against its recorded size. Wrong bytes never land — the tmp file is discarded and the
  failure reported per file, at the exact node. `pvfs export --fetch` runs the same pass before
  materializing.
- **Where the copy is recorded: nowhere — deliberately.** Fetched bytes land in a **managed,
  node-id-addressed store** (`<data_dir>/synced/<id[..2]>/<id>`), and the read path synthesizes a
  `pvfs-sync:///<id>` location **from the store's existence**. No projection table means nothing to
  keep consistent: synced bytes survive projection rebuilds by construction, and the whole
  mechanism works on read-only replicas (which is where it matters — an owned forest already holds
  its bytes). Verify-on-read still applies; a corrupted store copy quarantines like any location,
  and a fresh verified sync lifts the quarantine. The optional doc 03 **Mode B crosslink** (owner
  appends `FileLocationAdded` naming the replica's copy, via a remote-append grant — doc 03 §6 Q4)
  remains future work: it upgrades a local copy to catalog-visible redundancy.
- **Deferred from this slice:** `--to <dir>` custom destinations (put the replica's mount on the
  big disk instead), the `serve`-integrated background sync job (F3.1 with F0.1's export
  freshness), and `local_only` regions (doc 13 §C — arrives with region marks, F4). Secure blobs
  already ship ciphertext-only through F2's log shipping (their bytes live in the mutable store,
  doc 12; region-scoped replication of those is F4).

## 7. F5 — write-through & tiered storage (the download-box arc)

**Driving scenario (recorded 2026-08-08).** Radarr/Sonarr run on a download server with ~3 TB free;
the canonical store is a NAS; Plex and a new media app consume the library from other machines. New
downloads must enter the catalog **immediately** and be visible everywhere, while a background
process migrates the bytes to the NAS and frees the download server — with zero interruption to
consumers.

**The key architectural call:** this needs **no multi-master**. Doc 13 §A's resolved write model
already contains the answer — *reads anywhere, writes to one*. A "writable" replica is a replica
that **forwards writes to the owner** over the F1 transport (member-signed, the same two-phase
protocol every daemon write uses) and sees them return through log sync. The owner's single linear
signed chain remains the only log; every integrity property survives untouched. True active-active
stays the deferred doc 13 §A HA mode — nothing in this arc moves toward it.

Deployment shape: **the NAS owns the media forest** (`pvfsd --listen`); the download server and
every consumer box hold replicas.

### 7.1 F5.0 — write-through replicas ✅ BUILT (2026-08-08)

Mutations on a replica mount now **route to the recorded source** instead of being refused,
signed by the **client identity** (a replica has no forest device key — and the member model is
exactly what remote writes are):

- `pvfs add` (folder/file) and `pvfs loc add` route explicitly; every op that already auto-routes
  through `daemon_client` — `acl`/`tag`/`device`, secure create/put/cat — routes too, because a
  replica mount's "daemon" **is its source** now.
- **Read-your-writes:** after a write-through the CLI best-effort pulls the source's log tail into
  the replica, so `pvfs ls` shows the change immediately. Log shipping needs replication rights on
  the connection; without them the pull is silently skipped and visibility arrives with the next
  `replica sync`.
- **Deliberately not routed** (the engine still refuses locally): temp nodes (forest-local by
  definition), `link`/`unlink`/`reorder` (no wire ops yet — add them when a consumer needs them),
  and `loc rm` (location lifecycle belongs to F5.3's mover). **No offline queue**: a write-through
  needs the source reachable; offline divergence stays app-level (doc 13 §A), by design.

With F5.0, the download server can already catalog new files into the NAS's forest:
`pvfs add … --kind file` + `pvfs loc add <id> file:///downloads/...` — but that location is only
meaningful on the download server itself, which is exactly what F5.1 fixes.

### 7.2 F5.1 — instance-qualified locations (next)

A `file://` location is host-implicit — it resolves wherever the path happens to exist, which is
wrong the moment locations cross machines. Fill doc 03 §2.1's reserved "future schemes" row:

- **`pvfs-host://<transport-pin>/<abs-path>`** — bytes live at `<path>` **on the instance whose
  transport pin this is** (the F1 pin is already the stable, verifiable instance identity).
- Resolution: local when the pin matches one of *this* host's identities (its own listener pin, if
  serving) — else a **remote candidate** for F5.2. `pvfs loc add` keeps accepting `file://` (a
  same-host claim) and gains the qualified form; the download server's agent records
  `pvfs-host://<its-pin>/downloads/…`, making "these bytes are on the download box" catalog truth
  every replica understands.

### 7.3 F5.2 — remote read-through (sync-on-demand)

Doc 03 §2.3's resolution order, step 3, implemented: when no location resolves locally and a
`pvfs-host://` location names a reachable instance (known pin → address via the instance registry
or the replica marker), **fetch on demand** — stream through that instance's daemon into the F3
sync store (verified, promoted to a local location by existence), then serve. v1 blocks the read
while fetching; true open-and-stream is F4's FUSE mount. With F5.2, "immediately available
everywhere" holds even before anyone has synced: the catalog entry is enough to reach the bytes.

### 7.4 F5.3 — the mover (tiering policy)

Placement (doc 17 §6) grows a **canonical** dimension, owner-side:

- `pvfs place <subtree> central --to <bound-folder>` (on the owner): every file under the subtree
  must hold a verified copy in that owner-bound storage.
- **The mover** (a `serve` job + `pvfs tier` one-shot): for each file whose only live locations are
  edge instances, fetch the bytes (F5.2 machinery, verified), land them in the bound folder,
  append `FileLocationAdded` (owner log — catalog-visible redundancy, doc 03 Mode B's crosslink
  without needing remote append: the owner appends to its own log), then **retire the edge
  location** (`FileLocationRemoved`).
- **Eviction:** the edge host's agent (its `serve` loop) watches its own `pvfs-host://` locations;
  when one is removed from the catalog, it deletes the local bytes — space freed, and never before
  the canonical copy is live. Consumers never notice: resolution finds the NAS copy (or their own
  synced copy) throughout.

### 7.5 F5.4 — tail-subscribe

A long-poll variant of `LogRead` so replicas learn of new events in seconds instead of on a sync
schedule — the difference between "available on the next cron tick" and "available now" for the
whole fleet. (Resume tokens are just `(seq, chain_hash)`; doc 17 §9's open question 2 decides the
frame shape.)

### 7.6 The end state for the media fleet

```text
download box:  replica + Radarr agent → pvfs add / loc add (pvfs-host://download-pin/…)
NAS (owner):   pvfsd --listen · place <library> central --to /volume1/media · the mover
plex box(es):  replica + place <library> sync · pvfs sync loop (or F5.2 read-through) · export
```

New episode lands → cataloged in seconds (F5.0) → visible fleet-wide (F5.4, or next sync) →
readable everywhere immediately (F5.2) → migrated to the NAS in the background (F5.3) → edge bytes
evicted, 3 TB stays free — Plex streaming the whole time.

---

## 8. F4 — later, in this order when needed

1. **Region logs** (doc 13 §B — already the decided architecture): per-region logs + parent
   head-commitments; unlocks per-app replication, per-region compaction, and region-scoped
   active-active (doc 13 §A's later HA mode).
2. **FUSE read-through mount**: the pointer-mode streaming answer (open → resolve → stream via the
   data plane, cache-promote per policy). The materialized export stays the zero-dependency path.
3. **Swarm data plane**: multi-source fetch-by-hash (doc 03 §2.1's future schemes; P2-F's seam).
4. **Standby failover** (doc 03 §6 Q3) — explicit promotion protocol, never automatic dual-writers.

---

## 9. Open questions (new ones only — doc 03 §6 still governs the old ones)

1. **TLS details (F1):** self-signed cert pinned by instance key vs. raw-key TLS (RFC 7250-style);
   how the companion's localhost-cert experience (doc 14) informs the trust prompt when adding an
   instance.
2. **Tail-follow transport (F2):** long-poll over the existing request/response framing vs. a
   subscribe frame; resume tokens are just `(seq, chain_hash)` prefixes either way.
3. **Sync scheduling (F3):** how aggressive the `serve` sync job is (bandwidth caps, schedules,
   "sync on first read" promotion).
4. **Export of folder refs (F0/F4):** revisit once region links exist — a folder ref to a replicated
   region could export as a real subtree scoped to that region's log.
