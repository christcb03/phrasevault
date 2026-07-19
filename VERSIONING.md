# Versioning

PVFS and the application layers built on top of it use a **layered version scheme**. Each layer's version is its own `MAJOR.MINOR`, followed by the **major** version of each layer beneath it (top to bottom), ending with PVFS.

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
| PVFS | `MAJOR.MINOR` | `0.1`, `1.0`, `1.1` |
| Sync / sharing server | `MAJOR.MINOR.<pvfs>` | `1.0.1` |
| Media server app | `MAJOR.MINOR.<sync>.<pvfs>` | `1.0.1.1` |

## Current status

- **PVFS: `1.1.0` — released (tagged `v1.1`, 2026-07-09).** Builds on `1.0.0` (tagged `v1.0`, 2026-07-03): P0–P2 (core, storage, mounts, multi-user daemon), P3 encryption-at-rest, key replacement/rotation (doc 15), and the companion through phase 7 (joint agent API, doc 16). **1.1** adds PVOS-driven daemon ops (`AddNode`/`Payload`, `stat` parent) plus revoked-key `key:` grant masking and typed `already_exists` — see [CHANGELOG.md](CHANGELOG.md). Build: [docs/INSTALL.md](docs/INSTALL.md).
- **Next:** apps (notably PVOS) target PVFS major `1`; engine-side post-1.1 work (federation, compaction, polish) is tracked in [docs/08-roadmap-and-status.md](docs/08-roadmap-and-status.md). The sync/file-server layer (Layer 1) remains the next product layer above the engine.
- The previous Python + TypeScript prototype is archived under `v0.0-concept/` and tagged `v0.0-concept`.
