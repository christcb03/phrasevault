# Versioning

PVFS carries five version numbers, each answering a different question:

| number | today | answers | where |
|---|---|---|---|
| the release | `1.4.0` | which release this is | `Cargo.toml` (`[workspace.package]`), the `v1.x` tags |
| the build id | e.g. `v1.4-549-gea84559` | which commit, exactly | `--version` of every binary, `pvfs versions` |
| the wire protocol | **16**, talks back to **3** | can two boxes talk, and which ops can one ask of the other | `pvfs_proto::PROTO_VERSION`, `PROTO_COMPATIBLE_WITH` |
| the projection schema | **20** | can this binary open this box's catalogue, and how | `pvfs_core::projection::SCHEMA_VERSION` |
| the mount compatibility | **1** | can a running view mount stay up across an upgrade | `pvfs_core::MOUNT_COMPAT` |

`pvfs versions` prints all of them for the binary and, run inside a forest,
what opening that forest would do; `pvfs fleet versions` prints the release,
protocol and schema of every box (user manual §9.5).

## A release version is not a build identity (2026-08-30)

**`1.4.0` meant two materially different binaries at once**, and nothing said
so. `main` sat 80 commits behind the branch the fleet actually ran; both
reported `pvfs 1.4.0`. A fix was written, tested and clippy-cleaned against the
stale tree before anyone noticed, and the only reliable tell was **content** —
`grep -c MediaQuality crates/pvfs-core/src/event.rs`, an event kind the live log
held 24,585 of and the stale tree had never heard of.

**RULE: the version a binary reports must identify the build, not just the
release.** Each binary's `build.rs` stamps `git describe --tags --always
--dirty` into `--version`, so a tree that is 27 commits past `v1.4` cannot
present itself as the same thing as one that is 107 past.

**Built:** `pvfs` in D100 (`pvfs 1.4.0 (v1.4-133-g82bd163)`), `pvfsd` in D110,
`pvfs-companion` in D124 (which also re-stamps when only a tag changes). Two
things about how, because the obvious implementation does not work here:

* `build.rs` cannot run `git describe` on the build host: the pipeline rsyncs
  the repo with `.git` excluded, so the first attempt stamped `unknown` on
  precisely the builds that get deployed. Whoever builds resolves the id on
  the CONTROL machine and passes `PVFS_BUILD` in; `build.rs` prefers that,
  falls back to git, then to the literal `unknown`. Four paths do this: this
  repo's pipeline (which since D110 also fails a daemon that says `unknown`),
  PVOS's `build-nas.sh` for the QNAP (D109), PVOS's `build-x86-musl.sh` for
  mediabox (D147), and PVOS's release builds (D184). The two PVOS scripts
  check that both binaries carry the stamp before they leave the build host.
* Until D109, the NAS binaries said `unknown` and a QNAP deploy was verified
  by content alone.

Checking content — grep the installed binary for a string only the intended
build has — is still how a roll proves what landed (doc 24 §7 A2–A4).

### Reading a build id

`v1.4-549-gea84559` is `<nearest tag>-<N>-g<commit>[-dirty]`. **The commit is
the identity.** N counts every commit since the tag, merged branches'
included, so it orders builds only along one line of history. `-dirty` means
the checkout that named the build had uncommitted changes, which the rsync
shipped into it.

The id is printed by `pvfs --version`, `pvfsd --version`, `pvfs-companion
--version` and `pvfs versions` (with the mount compatibility); a view mount
records the build it runs, which `serve status` and the fleet's health record
carry; a dated log copy's `manifest.json` names the build that made it. It is
**not** in the connect handshake (which carries the protocol) or in a box's
fleet version record (`.fleet/versions/<pin>`: release, protocol, schema), so
`pvfs fleet versions` cannot tell two builds of one release apart.

## Wire protocol version (`pvfs_proto::PROTO_VERSION`)

A single monotonic integer, sent in every connect `Challenge`.

- **`PROTO_COMPATIBLE_WITH` (3, since D73)** is the oldest protocol a binary
  still talks to. Since D73 a peer that receives an op it does not know
  answers `unknown_op` and keeps the connection open, so every change
  between 3 and today has been additive: any two boxes in `[3, 16]` work
  together, and a fleet upgrade rolls box by box. PVOS's roll refuses only a
  build whose floor is above what a box runs. Moving this number would be the
  fleet-wide event.
- A consumer that needs an op checks the number first: `Client::daemon_proto()`,
  and a PVOS app's manifest floor (`requires.pvfs_proto`, PVOS D63), which
  pvosd checks before it starts the app.

**RULE: bump `PROTO_VERSION` in the SAME commit as any new wire op**, so a
consumer can require "protocol ≥ N". A new field with a default is not a bump:
no message refuses unknown fields, and an older peer ignores it. The P10
ingest ops shipped without a bump (the protocol stayed at 2 while gaining
`IngestBegin` and the rest), so nothing downstream could tell an
ingest-capable daemon from one without, and a PVOS app built on them panicked
against an older daemon (PVOS D63). The rule was broken twice after it was
written — `ClaimWriteLease` shipped at 3 and `SetContentHash` at 4 — and has
been kept for every op since protocol 5.

| protocol | what it added | milestone | first main build |
|---|---|---|---|
| 1 | the daemon wire (doc 07): challenge-response auth, reads, then member writes and admin ops | P2 phase C | 2026-06-16 |
| 2 | **incompatible**: `cat` as raw binary data frames instead of hex. Then, with no further bump, everything through v1.4: secure blobs, typed records, expiring grants, replicas and log shipping, tail-follow, serve jobs, write-through, region logs, the swarm, ingest sessions | P2-F | 2026-06-24 |
| 3 | no new op: the floor for the ingest ops, ranged `Cat` and partial paths already shipped at 2; `Client::daemon_proto()` | PVOS D63 | `v1.4-10` |
| 4 | `Relabel`; `unknown_op` instead of a dropped connection; `PROTO_COMPATIBLE_WITH = 3` | PVOS D73 | `v1.4-54` |
| 5 | `CommitRegionHead` — a region's box publishes its catalogue head through the owner | PVOS D125 | `v1.4-209` |
| 6 | `Purge`, `SetQuality` routed from a replica | PVOS D124 | `v1.4-220` |
| 7 | `RegionManifest` — a catalogue fetched by its head | PVOS D129 | `v1.4-242` |
| 8 | `CatHash` — bytes by content hash, for the view mount | PVOS D130 | `v1.4-252` |
| 9 | `TrashPath` — a delete through the view, done by the box that holds the file | PVOS D169 | `v1.4-371` |
| 10 | `RenamePath`, `RemoveDir` — renames and `rmdir` through the view | PVOS D170 | `v1.4-383` |
| 11 | `ReceivePlan` — the mover's plan from the running daemon | PVOS D174 | `v1.4-391` |
| 12 | `RegionClaims` — signed heads handed to peers while the owner is away | PVOS D183 | `v1.4-435` |
| 13 | `ViewLs`, `ViewEntry`, `CatalogueStatus` — the merged view over the socket | PVOS D187 | `v1.4-443` |
| 14 | `BindCertificates`, and forest-bound certificates understood (a forest binds only when every box is at 14) | PVOS D192 | `v1.4-468` |
| 15 | `CommitSigned` — events their authors signed elsewhere (a session certificate signed in a browser) | PVOS D193 | `v1.4-488` |
| 16 | `SetRegionQuality` — what another box's header probe saw of this box's copy (mediabox probing the NAS's video) | PVOS D211 | `v1.4-541` |

Every release tag, v1.0 to v1.4, shipped at protocol 2.

## Projection schema version (`pvfs_core::projection::SCHEMA_VERSION`)

The projection (`index.db`) is each box's own cache of what the log says, so a
schema change is a **per-box** matter: the fleet never has to stop for one. On
the first open by a newer binary the cache either **migrates in place** (every
step from v7 to v20 has one; sub-second on a large forest) or, where it
cannot, is **replayed from the log** beside the live one and swapped in at one
commit. A replay keeps what is not in the log — the catalogue regions' rows
(D173). A binary refuses a schema newer than its own. `pvfs versions` says
beforehand which of the three the first open would do.

| schema | what changed | milestone | upgrade |
|---|---|---|---|
| 1 | the initial projection | P0 | — |
| 2 | tag authority on ACL rows and member tags | P2-G | replay |
| 3 | expiring grants | 1.2 | replay |
| 4 | regions | P7.0 | replay |
| 5 | physical region logs | P7.2a | replay |
| 6 | cross-region moves | P7.2c | replay |
| 7 | attested chunk layouts (**v1.4's schema**) | P9.1 | replay |
| 8 | which device bound a folder | D71 | in place |
| 9 | an index on file labels | D71 | in place |
| 10 | link labels (names on edges) | D72 | in place |
| 11 | an index on link labels | D72 | in place |
| 12 | media quality | D76 | in place |
| 13 | one folder, many roots | D81 | in place |
| 14 | the mover remembers unfetchable files | D99 | in place |
| 15 | the unlink grace | D112 | in place |
| 16 | catalogue regions: `region_entries`, `region_snapshots` | D125 | in place |
| 17 | drain flags | D127 | in place |
| 18 | which catalogue copies this box holds | D129 | in place |
| 19 | the view's lookup indexes | D171 | in place |
| 20 | provisional heads, taken while the owner is away | D183 | in place |

## Mount compatibility (`pvfs_core::MOUNT_COMPAT`)

**1** since PVOS D181. A view mount (`pvfs mount --view`) may keep running on
an older build across an upgrade — restarting it would end every stream open
through it — while this number, the protocol it speaks and the catalogue
format it reads still match. `pvfs versions` says, for each running mount,
whether it keeps working under this build.

## The companion's protocol

`pvfs_companion::proto::API_VERSION` is **4** (PVOS D189: one companion,
several phrases), answered by the `api_version` op even while locked. 1 was
companion phase 7 (doc 16), 2 PVOS M3.1's pairing and relay, 3 PVOS D27/D29's
key trust.

## Layer 0 — PVFS (the file-system engine, this repo)

```
MAJOR.MINOR
```

- `0.1`, `0.2`, … — pre-release development toward a feature-complete engine.
- `1.0` — the first complete release, ready to host an application layer above it.
- After `1.0`: bump **MINOR** for backward-compatible additions, **MAJOR** for breaking changes to the engine's contract.

## Layers above PVFS — the scheme, not yet used

Products built on PVFS were to append the major version of each layer beneath
them. Nothing uses this yet: sync and sharing were built into the engine
itself (1.3), and PVOS — the layer that sits on PVFS today — versions itself
on its own (PVOS `VERSIONING.md`).

```
Layer 1 — a sync / sharing file server:  MAJOR.MINOR.<pvfsMajor>          e.g. 1.0.1
Layer 2 — a media server app on it:      MAJOR.MINOR.<syncMajor>.<pvfsMajor>   e.g. 1.0.1.1
```

The **rightmost** component is always the PVFS major version required; reading
right to left, each component is the next layer up.

## Current status

- **The latest release is `1.4.0`** (tag `v1.4`, 2026-08-13; `v1.3` 2026-08-10,
  `v1.2` 2026-07-22, `v1.1` 2026-07-09, `v1.0` 2026-07-03). 1.3 = the
  federation & sync line (replicas, write-through, TLS + pinning, placement,
  the tiered mover — doc 17). 1.4 = serve jobs (doc 18), the region arc and
  the streaming FUSE mount (doc 20), attachment kinds (doc 21), and the swarm
  data plane (doc 22).
- **Main has run ahead with no release since** — about 550 commits, protocol
  2 → 16, schema 7 → 20: ingest sessions (doc 23), the doc 24 fleet repairs,
  the region model and its view mount (doc 26; the fleet's model since the
  2026-09-12 cutover, doc 29), moving the owner and dated log copies (doc 28),
  monitoring (doc 30), forest-bound certificates and personal forests, one
  writer per daemon (PVOS D199), video quality in the catalogue and probing
  for another box (D208, D211), placement by folder with a free-space floor
  (D216), and creates and edits through the view mount (D217). The
  **media fleet runs `v1.4-549-gea84559`** (rolled 2026-10-04, about 1:00 PM
  Eastern; `v1.4-495-gc17ae29` before that, from 2026-09-27). See
  [CHANGELOG.md](CHANGELOG.md), whose "Unreleased" section is the record.
  Whether to cut a release past v1.4 is Chris's decision (PVOS BACKLOG,
  "Decisions needed").
- Engine work is tracked in [docs/08-roadmap-and-status.md](docs/08-roadmap-and-status.md)
  and in PVOS's `docs/BACKLOG.md`; compaction is deferred by decision (doc 11).
  Build: [docs/INSTALL.md](docs/INSTALL.md).
- The previous Python + TypeScript prototype is archived under `v0.0-concept/` and tagged `v0.0-concept`.
