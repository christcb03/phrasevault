# PVFS — P4 federation & sync: the plan, phased (17)

Status: **F0–F3 and F5.0–F5.4 built; F4 built except standby failover** (region logs P7.2, FUSE
P7.3, swarm P9 — docs 20/22); ingest sessions (P10, [doc 23](23-ingest-sessions-and-the-bt-bridge.md))
extend the arc. Drafted 2026-08-08 as the phasing proposal.
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
| Region-granular logs, FUSE streaming, swarm, failover | ✅ region logs (P7.2), FUSE (P7.3), swarm (P9); ❌ failover only |

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
| **F5.1** | **Instance-qualified locations**: `pvfs-host://<pin>/<path>` — cross-host location truth, `loc add --here` | ✅ built (§7.2) |
| **F5.2** | **Remote read-through**: per-file candidate fetch (registry-pinned holders, then the source), self-healing `cat`, owner-side pulls | ✅ built (§7.3) |
| **F5.3** | **The mover**: `place <subtree> central --to <dir>`, `pvfs tier` (verified migrate + retire), `pvfs evict` (safe edge reclaim) | ✅ built (§7.4) |
| **F5.4** | **Tail-subscribe**: `LogWait` long-poll + `pvfs replica follow` — seconds-fresh replicas | ✅ built (§7.5) |
| **F4** | Region logs (doc 13 §B — the decided target architecture), FUSE read-through mount (pointer-mode streaming), swarm/torrent data plane (doc 03 §2.2 future schemes), standby failover (doc 03 §6 Q3) | ◑ — only failover left (§8) |

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
   *pointer-mode streaming* (bytes that aren't local) *(since shipped: the unprivileged
   `pvfs mount`, P7.3 — doc 20 §3)*; it is explicitly **not** required for the
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
  freshness), and `local_only` regions (doc 13 §C — was to arrive with region marks; the marks
  landed in P7.2, so `local_only` is no longer blocked but remains unbuilt as of 1.4). Secure blobs
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

### 7.2 F5.1 — instance-qualified locations ✅ BUILT (2026-08-08)

A `file://` location is host-implicit — it resolves wherever the path happens to exist, which is
wrong the moment locations cross machines. Doc 03 §2.1's reserved "future schemes" row fills in:

- **`pvfs-host://<transport-pin>/<abs-path>`** — bytes live at `<path>` **on the instance whose
  transport pin this is** (the F1 pin is already the stable, verifiable instance identity; a host
  that has never run `pvfsd --listen` has no pin — and correctly, no location to offer, since
  nobody could dial it).
- **Resolution:** local exactly when the pin is this data dir's own (`nettls/pin`); a foreign pin
  is unresolvable-here — `stat` shows the location unavailable, `cat` skips it, `missing_bytes`
  counts the file, and **`pvfs sync` already closes the loop**: the source *can* resolve its own
  pin, so a replica fetches host-qualified bytes through it today (full read-through from
  arbitrary instances is F5.2).
- **Surface:** `pvfs loc add <file> --here <path>` canonicalizes the path and records it under
  this instance's pin (write-through composes — an ingest box records its own pin *into the
  owner's log*). Explicit URIs still pass through, `file://` included (a same-host claim, still
  right for bound folders).

### 7.3 F5.2 — remote read-through (sync-on-demand) ✅ BUILT (2026-08-08)

Doc 03 §2.3's resolution order, step 3, implemented. As built:

- **Per-file candidate resolution.** A fetch pass resolves each missing file to candidates, best
  first: every `pvfs-host://` location whose **pin the instance registry knows** (that host
  *definitely* holds the bytes), then the replica's recorded source (which resolves its own
  locations). Connections pool per target; dead targets aren't re-dialed. `pvfs sync` and
  `export --fetch` use this — so a sync now succeeds even when the bytes live on a *third*
  instance the source can't read.
- **`pvfs cat` self-heals.** A read of a file with no local bytes fetches on demand (blocking,
  verified, into the F3 store) and then serves — the catalog entry alone is enough to reach the
  bytes, before anyone has run a sync pass. Wrong bytes never land; on total failure the original
  not-found surfaces. True open-and-stream (no full prefetch) remains F4's FUSE mount *(since
  shipped — P7.3, doc 20 §3; extended to in-flight ingest partials in P10.1, doc 23 §11)*.
- **Owned forests fetch too**: `pvfs sync` on the *owner* pulls edge bytes home through the
  registry — the mover's core primitive, ready for F5.3 to build the policy around.
- **Freshness note:** write-through's read-your-writes now folds the pulled tail into the
  projection immediately, so a daemon serving the same replica picks the change up live (its
  readers see committed projection rows). Between write-throughs, a serving replica still learns
  of *other* writers' changes only at `replica sync` — the standing gap F5.4's tail-subscribe
  closes.

### 7.4 F5.3 — the mover (tiering policy) ✅ BUILT (2026-08-08)

Placement (doc 17 §6) grows a **central** dimension, owner-side. As built:

- **`pvfs place <subtree> central --to <dir>`** (owner): every file under the subtree must hold a
  verified copy in that directory. One mode per subtree; `pointer` clears it. The store is
  **mover-managed, node-id-addressed** (`<dir>/<id[..2]>/<id>`) — deliberately *not* a scan-bound
  folder (a scan would re-index the copies as new nodes); humans browse via `pvfs export`, which
  gives the tree its names.
- **`pvfs tier`** (owner one-shot; `serve` integration later): per file, a subtree is
  central-satisfied by any **logged** location that resolves locally (a live `file://` path — bytes
  already on the owner's disks never move — or an own-pin `pvfs-host://`; synthesized sync-store
  entries never count, they aren't catalog truth). Otherwise the mover reaches the bytes (locally
  or by F5.2 read-through), lands a **verified copy** (streamed through `cat`, hash-checked,
  tmp+rename) in the store, and appends `FileLocationAdded` — doc 03 Mode B's catalog-visible
  redundancy without remote append, since the owner appends to its own log. Only **after** a
  central copy is live does it retire foreign-pin locations (`FileLocationRemoved`); a failed
  migration never retires anything.
- **`pvfs evict`** (edge one-shot): acts on the catalog's *retired* rows bearing this instance's
  own pin (`Engine::retired_own_host_locations` — removed, not re-added). Belt-and-braces: a file
  is deleted only when the catalog still records **another live location**, the path is a regular
  file, and the retirement has actually been synced (a stale replica evicts less, never wrongly —
  the log's ordering guarantees the central add folded before the removal). Reports bytes freed.
- **Consumers never notice:** the smoke suite proves the invariant end-to-end — edge catalogs a
  file, consumer read-throughs it, owner migrates + retires, edge evicts, and the file still
  streams from every machine afterwards.

### 7.5 F5.4 — tail-subscribe ✅ BUILT (2026-08-08)

As built (settling §9's open question 2 in favor of **long-poll over the existing framing** — no
subscribe frame, no server push state):

- **`LogWait { from_seq, max, timeout_ms }`**: like `LogRead`, but the daemon holds the request —
  on the connection's own thread, engine locks taken only for instantaneous tip checks — until the
  log reaches `from_seq` or the (server-capped, 60 s) timeout lapses; an empty reply means "poll
  again". Same admin gate; resume position is just the replica's own tip + 1.
- **`pvfs replica follow <mount>`**: the follower loop — long-poll, chain-verified ingest, fold —
  with reconnect-on-failure backoff and tolerance for transient lock contention from concurrent
  local commands. Events authored on the owner appear on a following replica (and through any
  daemon serving it) **within seconds**, proven live in the smoke suite with two consecutive
  events. Run it as a service on each consumer box; `replica sync` remains the one-shot.

### 7.6 The end state for the media fleet — ✅ the whole arc is BUILT

```text
download box:  replica + Radarr agent → pvfs add / loc add --here · pvfs evict on a schedule
NAS (owner):   pvfsd --listen · place <library> central --to /volume1/media · pvfs tier
plex box(es):  replica + pvfs replica follow · place <library> sync + pvfs sync · export --prune
```

New episode lands → cataloged in seconds (F5.0/F5.1) → visible fleet-wide in seconds (F5.4) →
readable everywhere immediately (F5.2) → migrated to the NAS in the background (F5.3) → edge bytes
evicted, 3 TB stays free — Plex streaming the whole time. Every step is covered end-to-end by the
smoke suite.

*Since P10 (doc 23): the blessed downloader path is an **external-ingest session** —
catalog-at-add, verified partials, gated commit — replacing the hand-rolled `pvfs add` +
`loc add --here` on the download box.*

### 7.7 F5.5 — advertised holders (spec 2026-08-15, the D69 fleet's finding)

The gap, found live on real hardware (PVOS D69 F0.5, a QNAP serving a
lab fleet): a replica's sync-store copies are **per-machine deployment
state** — deliberately unlogged (F3) — so a box that syncs a subtree
holds verified bytes the rest of the fleet cannot discover. The NAS
held the whole library and nobody could dial it until the copy was
advertised by hand (`loc add --here <.pvfs/synced path>` — which works
today and is the semantic F5.5 automates). Two additions, no new wire
ops (write-through carries everything, so **no PROTO_VERSION bump**):

1. **`pvfs place <target> sync --advertise`** — placement line
   `sync-advertise <id>`. `pvfs sync` (CLI and the daemon's `sync` job
   alike — shared pass) then follows every verified fetch under such a
   subtree with a routed, member-signed `loc add` of
   `pvfs-host://<own-pin>/<abs sync-store path>` — idempotent (skipped
   when an own-pin location for the store path is already logged), and
   catch-up on re-runs (already-fetched files missing their
   advertisement get one). Needs `rw` at the root (it IS a write) and a
   transport pin (a box that never ran `--listen` has nothing to
   advertise — refused with that sentence). **`cat` self-heal never
   advertises**: casual reads must not grow the log; advertising is the
   deliberate act of becoming a holder.
2. **`pvfs place <target> central --to <dir> --served-by
   <instance>:<remote-prefix>`** — placement line
   `served-by <id> <instance> <remote-prefix>`. The mover writes
   through its local `--to` path as today, but logs the central
   location **as the serving instance's**:
   `pvfs-host://<that instance's pin>/<remote-prefix>/<store-relative
   path>` alongside the owner-local `file://` row. The named instance
   must exist in the registry at place time (its pin is the
   attribution); the path equivalence — that `<remote-prefix>` on that
   box IS `--to` here (the NAS export mounted on the owner) — is the
   operator's assertion and is stated in the place output. Consumers
   then fetch store bytes straight from the NAS instead of hairpinning
   through the owner.
3. **Evict retracts before it deletes.** An advertised copy adds a
   step to `pvfs evict`'s contract: first retract the own-pin location
   (routed `loc rm`, write-through), then delete bytes — and only when
   the catalog still records another live location. Source unreachable
   → the file is skipped with a reason, never deleted: a dangling
   advertisement is a lie the fleet would trust.

Deliberately not in F5.5: advertising cat's self-healed copies (above);
a gossip/refresh protocol (advertisements are log rows like any other —
revocation is `loc rm`, visibility is replica sync); and
advertisement-driven placement (what to sync stays the operator's call).

**F5.6 (named, not built): attested external ingest.** The D69 fleet's
mount profiling found the boundary precisely: a file cataloged by hand
(`pvfs add` + `loc add --here` — the §7.9 ingest-box flow, and the arr
hook that automates it) carries **no content hash**, so it is an
unhashed pointer everywhere: the mount PROXIES every read (ranged Cat —
correct, nothing can verify it; ~1.4 s per 3 MB open on the lab), it
can never stream-while-fetching, and nothing heals. The fix is not in
the mount — it is making external ingest ATTEST: the "hash-fill
successor + attestation" machinery the P10 ingest commit already runs
(fs.rs) exposed for an already-landed local file, e.g.
`pvfs loc add --here <path> --attest` (hash + chunk manifest computed
from the bytes right there, routed like every write-through). Scanned
files have the same knob already (the bind's hash policy); external
adds deserve parity.

### 7.8 F5.7 — the self-teaching swarm (spec 2026-08-16, Chris's ask)

Doc 03's open question #1, answered: *how do peers discover
`instance_id` → network address?* Today every box must `pvfs instance
add` every holder by hand — the D69 QNAP proof tripped on exactly this
(the NAS could SEE `pvfs-host://<pin>/…` rows for the ingest box and
could not dial them). The catalog already teaches every replica WHERE
copies are; F5.7 makes it teach HOW TO REACH the holders too.

**The endpoint directory** — regular nodes, no new event kinds, no new
wire ops (and so no PROTO_VERSION change):

```text
<root>/.fleet/endpoints/<transport-pin>   payload = host:port
```

- **Publish**: `pvfs fleet announce <host:port>` upserts this box's
  record (label = own pin, the `--listen` pin) — a plain member-signed
  write, write-through from replicas like every mutation (F5.0). The
  dial address cannot be guessed (NAT, names, multi-home): the operator
  states it. Re-run to change; `pvfs fleet announce --retract` removes.
- **Learn**: the fetcher's candidate resolution, for a location pin the
  LOCAL registry doesn't know, consults `.fleet/endpoints/<pin>` from
  the catalog it already holds. **The local registry always wins** —
  the operator's word beats the log. One replica-source bootstrap entry
  is now enough: everything else self-teaches from the synced log.
- **Trust is unchanged and this is the crux**: the pin in the location
  row is still the only verification anchor — every connect proves the
  pin (doc 17 §4), so a wrong or hostile published address can only
  fail the handshake and cost a fallback to the next candidate, never
  authority. An endpoint record is a HINT with an audited author (the
  log row's member signature), not a trust statement.
- **Staleness**: a dead address behaves exactly like today's stale
  registry entry — pin-verified connect fails, candidate skipped.
  Records refresh on `announce` re-runs (the F3 playbooks make it a
  unit-start step).

Not in v1 (recorded): engine-enforced pin↔author binding on endpoint
rows (today: last-writer-wins among members with `w`, every write
member-signed and auditable in the log — the household threat model);
`pvfsd --announce` as a daemon flag (the CLI + a unit ExecStartPre
covers it until the flag earns its place); and any gossip beyond the
log (the log IS the gossip).

---

## 8. F4 — later, in this order when needed

1. ✅ **Region logs** (doc 13 §B — already the decided architecture): per-region logs + parent
   head-commitments; unlocks per-app replication, per-region compaction, and region-scoped
   active-active (doc 13 §A's later HA mode). **Built as P7.2a–c (doc 20 §2.3–2.5).**
2. ✅ **FUSE read-through mount**: the pointer-mode streaming answer (open → resolve → stream via the
   data plane, cache-promote per policy). The materialized export stays the zero-dependency path.
   **Built as P7.3's unprivileged `pvfs mount` (doc 20 §3).**
3. ✅ **Swarm data plane**: multi-source fetch-by-hash (doc 03 §2.1's future schemes; P2-F's seam).
   **Built as P9 (doc 22).**
4. ☐ **Standby failover** (doc 03 §6 Q3) — explicit promotion protocol, never automatic
   dual-writers. **The only remaining F4 item.**

---

## 9. Open questions (new ones only — doc 03 §6 still governs the old ones)

1. **TLS details (F1):** self-signed cert pinned by instance key vs. raw-key TLS (RFC 7250-style);
   how the companion's localhost-cert experience (doc 14) informs the trust prompt when adding an
   instance. **DECIDED (F1, §4):** self-signed cert pinned by the BLAKE3 of the cert DER.
2. **Tail-follow transport (F2):** long-poll over the existing request/response framing vs. a
   subscribe frame; resume tokens are just `(seq, chain_hash)` prefixes either way.
   **DECIDED (F5.4, §7.5):** long-poll `LogWait` over the existing framing.
3. **Sync scheduling (F3):** how aggressive the `serve` sync job is (bandwidth caps, schedules,
   "sync on first read" promotion). **Answered by P5 (doc 18)** — sync/export run as fold-nudged
   serve jobs; backoff tuning is the only leftover.
4. **Export of folder refs (F0/F4):** revisit once region links exist — a folder ref to a replicated
   region could export as a real subtree scoped to that region's log. *(Region links exist now —
   P7.2 — so this is due: revisit, or record as deliberately deferred.)*
5. **Outbound fetch identity (found by the 2026-08-10 two-machine test) — ✅ DECIDED
   (2026-08-10, option c; extended 2026-08-13, c+ — doc 18 §4 + addendum):** every outbound
   dial — mover/tier, read-through fetch, replica follow/sync, and the swarm workers —
   authenticates as the box's *client identity*, never the forest device key, and **that stays
   the model**. The friction (on a private forest even the owner's boxes must be
   authorize-member'd + granted read) is answered with tooling, not a trust-path change:
   `pvfs forest init` self-enrolls the creating box's own client identity with read on the
   root, and `pvfs fleet enroll` admits other boxes as a one-step, logged, revocable
   operation (doc 18 P5.4). `device.key` never dials.
