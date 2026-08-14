# Versioning

PVFS and the application layers built on top of it use a **layered version scheme**. Each layer's version is its own `MAJOR.MINOR`, followed by the **major** version of each layer beneath it (top to bottom), ending with PVFS.

## Wire protocol version (`pvfs_proto::PROTO_VERSION`)

Separate from the release version above: a single monotonic integer sent
in every connect `Challenge`, so a consumer (e.g. a PVOS app via
`Client::daemon_proto()`) can require "protocol ≥ N" and a mismatched
daemon is caught at the launch boundary — not by the connection closing
mid-op.

**RULE: bump `PROTO_VERSION` in the SAME commit as any additive wire op.**
The P10 ingest ops shipped without a bump (stayed at 2 while gaining
`IngestBegin` etc.), so nothing downstream could tell an ingest-capable
daemon from one without — and a PVOS app built on the ingest seam
panicked against an older daemon that still reported 2. That is the
failure this rule prevents (PVOS D63).

| PROTO_VERSION | Added |
|---|---|
| 2 | P2-F baseline (2026-06-24) |
| 3 | P10 external-ingest ops, ranged `Cat`, P10.2 partial paths |

## Layer 0 — PVFS (the file-system engine, this repo)

```
MAJOR.MINOR
```

- `0.1`, `0.2`, … — pre-release development toward a feature-complete engine.
- `1.0` — the first complete release, ready to host an application layer above it.
- After `1.0`: bump **MINOR** for backward-compatible additions, **MAJOR** for breaking changes to the engine's contract.

## Layer 1 — Sync / sharing file server (built on PVFS)

```
MAJOR.MINOR.<pvfsMajor>
```

The trailing component is the PVFS **major** version this layer requires.

- e.g. `1.0.1` — sync server `1.0` running on PVFS major `1`.

## Layer 2 — Media server app (built on the sync layer)

```
MAJOR.MINOR.<syncMajor>.<pvfsMajor>
```

Each additional layer appends one more major-version component for the layer it sits on.

- e.g. `1.0.1.1` — media app `1.0`, on sync major `1`, on PVFS major `1`.

## How to read a version

The **rightmost** component is always the PVFS major version required. Reading right to left, each component is the next layer up. The leading `MAJOR.MINOR` is the layer's own version.

| Layer | Format | Example |
|---|---|---|
| PVFS | `MAJOR.MINOR` | `0.1`, `1.0`, `1.2`, `1.4` |
| Sync / sharing server | `MAJOR.MINOR.<pvfs>` | `1.0.1` |
| Media server app | `MAJOR.MINOR.<sync>.<pvfs>` | `1.0.1.1` |

## Current status

- **PVFS: `1.4.0` (tag `v1.4`, 2026-08-13; `v1.3` 2026-08-10, `v1.2`/`v1.1`/`v1.0` before).** 1.3 = the federation & sync line (replicas, write-through, TLS + pinning, placement, the tiered mover — doc 17). 1.4 = serve jobs (doc 18), the region arc + streaming FUSE mount (doc 20), attachment kinds (doc 21), and the swarm data plane (doc 22). Unreleased on main: the ingest-session/BT-bridge arc (doc 23). See [CHANGELOG.md](CHANGELOG.md). Build: [docs/INSTALL.md](docs/INSTALL.md).
- **Next:** apps (notably PVOS) target PVFS major `1`; ongoing engine work is tracked in [docs/08-roadmap-and-status.md](docs/08-roadmap-and-status.md); compaction is deferred by decision (doc 11). The sync/file-server layer (Layer 1) remains the next product layer above the engine.
- The previous Python + TypeScript prototype is archived under `v0.0-concept/` and tagged `v0.0-concept`.
