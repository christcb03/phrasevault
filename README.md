# PVFS — PhraseVault File System

PVFS is a standalone, cross-platform command-line service that provides a **real filesystem abstraction layer** over any accessible storage. Data is organized as a **forest** of **trees** of content-addressed, signed **nodes**. A small core engine handles identity, integrity, and traversal; all domain behavior (encryption, media, configuration, search, …) is added through sandboxed **WASM extension modules**.

This is a ground-up implementation. It is designed to run as a single binary on Windows, Linux, and macOS — no container or language runtime required.

## Status

**Version `0.1` — implemented, under validation.**

| Phase | What | State |
|-------|------|--------|
| **P0** | Core engine — event log, projection, nodes/links, locations, BIP39/BIP32 identity + device certs | Implemented, spec tests in `crates/pvfs-core/tests/p0_spec.rs` |
| **P1** | Storage — bind folders, scan/reconcile, verified reads, quarantine, `serve` watcher, temp spool | Implemented, tests in `p1_storage.rs` |
| **P1.5** | Mounts & registry ([doc 05](docs/05-instance-registry-and-mounts.md)) — `<mount>/.pvfs/` layout, `pvfs forest init/register/unregister/info`, `/etc/pvfs` registry (`PVFS_REGISTRY_DIR` override), `pvfs://alias@local/tree/path` + path shorthand, portable forests | Implemented, tests in `p15_mounts.rs` |
| **P2+** | WASM modules, HTTP, mount, federation sync | Specified; not built yet |

Build locally with `cargo test --workspace`, or on a remote Linux host — see **[Install guide](docs/INSTALL.md)**.

## Quick install

**On your machine:** clone repo → install [Rust](https://rustup.rs) → `cargo build --release` → `target/release/pvfs`.

**On a remote server:** SSH in, clone repo, `cargo build --release` — **[docs/INSTALL.md](docs/INSTALL.md) Option B**.

## Code layout

- [`crates/pvfs-core`](crates/pvfs-core) — kernel library (P0 + P1 storage layer)
- [`crates/pvfs-cli`](crates/pvfs-cli) — `pvfs` CLI
- [`deploy/ansible/`](deploy/ansible/) — optional remote build, test, smoke, install pipeline
- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — Rust CI on push

See [`VERSIONING.md`](VERSIONING.md) for the layered version scheme.

## Documentation

| Doc | Contents |
|-----|----------|
| [**INSTALL.md**](docs/INSTALL.md) | **Build, install, and test PVFS** (start here to run PVFS) |
| [00-architecture-decisions.md](docs/00-architecture-decisions.md) | ADR — vision, WASM-first modules, roadmap |
| [01-core-engine-design.md](docs/01-core-engine-design.md) | Data model, event log, identity, lifecycle |
| [02-p0-core-engine-spec.md](docs/02-p0-core-engine-spec.md) | P0 normative spec (implemented) |
| [03-federation-trust-and-uris.md](docs/03-federation-trust-and-uris.md) | Forest ownership, sync model, URIs, trust |
| [04-p1-storage-and-fs-ops-spec.md](docs/04-p1-storage-and-fs-ops-spec.md) | P1 storage & FS ops spec (implemented) |
| [05-instance-registry-and-mounts.md](docs/05-instance-registry-and-mounts.md) | Mount layout (`.pvfs/`), `/etc/pvfs/` registry, mount URIs, CLI |

## Core ideas

- **Forest → trees → nodes/links.** A root node is the base of a tree; trees are walked link by link.
- **Content-addressed + signed.** Every node's id is a BLAKE3 hash of its contents; nodes and links are signed (secp256k1). Tampering is structurally detectable.
- **Append-only event log is the source of truth**, with SQLite as a rebuildable, queryable projection. The log is tamper-evident via a hash chain, and the index self-heals from the log on startup.
- **Recovery phrase identity.** A one-time 24-word BIP39 mnemonic creates your keys; device certificates in the log control which device may write.
- **Base node types** (`file`, `folder`, plus a `temp` flag) are built into the core. Everything else is a WASM module (future).

## Archive

The previous concept implementation (Python + TypeScript MediaForest/PVFS prototype) lives under [`v0.0-concept/`](v0.0-concept/) and is tagged `v0.0-concept`.

## License

See [`LICENSE`](LICENSE).
