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
| PVFS | `MAJOR.MINOR` | `0.1`, `1.0` |
| Sync / sharing server | `MAJOR.MINOR.<pvfs>` | `1.0.1` |
| Media server app | `MAJOR.MINOR.<sync>.<pvfs>` | `1.0.1.1` |

## Current status

- **PVFS: `0.1` (implemented, under validation).** P0 core engine and P1 storage/FS ops are implemented in Rust (`crates/pvfs-core`, `crates/pvfs-cli`). See [docs/INSTALL.md](docs/INSTALL.md) to build and test.
- **Target for `0.1` complete:** P0+P1 tests and smoke suite pass on a representative Linux host; install docs validated.
- **`1.0`** remains the first release ready to host the sync/file-server layer above PVFS.
- The previous Python + TypeScript prototype is archived under `v0.0-concept/` and tagged `v0.0-concept`.
