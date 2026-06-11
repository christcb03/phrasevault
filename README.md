# PVFS — PhraseVault File System

PVFS is a standalone, cross-platform command-line service that provides a **real filesystem abstraction layer** over any accessible storage. Data is organized as a **forest** of **trees** of content-addressed, signed **nodes**. A small core engine handles identity, integrity, and traversal; all domain behavior (encryption, media, configuration, search, …) is added through sandboxed **WASM extension modules**.

This is a ground-up implementation. It is designed to run as a single binary on Windows, Linux, and macOS — no container or language runtime required.

## Status

**Version `0.1` — in development.** The P0 core engine is implemented as a Rust workspace:

- [`crates/pvfs-core`](crates/pvfs-core) — the kernel library (PCE encoding, nodes/links, event log + hash chain, projection + startup recovery, BIP39/BIP32 identity with device certificates, engine API) plus the P1 storage layer (bound folders, scan/reconcile, verified reads with quarantine, flag-and-resolve for changed files, managed temp spool).
- [`crates/pvfs-cli`](crates/pvfs-cli) — the `pvfs` CLI (`init`, `recover`, `tree`, `add`, `link`, `ls`, `walk`, `loc`, `verify`, `orphans`, `purge`, `device`, plus P1: `bind`, `scan`, `stat`, `cat`, `hash`, `changes`, `resolve`, `serve`; `--json`, scriptable exit codes).

Build and test locally with `cargo test --workspace`, or run the full build/test/deploy pipeline against the presubuntu test server: [`deploy/ansible/`](deploy/ansible/).

See [`VERSIONING.md`](VERSIONING.md) for the layered version scheme.

## Documentation

The design is captured as a reviewed, decision-by-decision record in [`docs/`](docs/):

- [`docs/00-architecture-decisions.md`](docs/00-architecture-decisions.md) — foundational concepts, the WASM-first module model, and the architecture decisions (language, core vs. modules, base node types).
- [`docs/01-core-engine-design.md`](docs/01-core-engine-design.md) — the core-engine design: data model, event-log source of truth, identity, lifecycle.
- [`docs/02-p0-core-engine-spec.md`](docs/02-p0-core-engine-spec.md) — the buildable P0 spec: exact encodings, schemas, projection rules, integrity checks, error model, and test plan.
- [`docs/03-federation-trust-and-uris.md`](docs/03-federation-trust-and-uris.md) — forest ownership, federation sync modes, PVFS URI grammar, and P0 trust fixes.

## Core ideas

- **Forest → trees → nodes/links.** A root node is the base of a tree; trees are walked link by link.
- **Content-addressed + signed.** Every node's id is a BLAKE3 hash of its contents; nodes and links are signed (secp256k1). Tampering is structurally detectable.
- **Append-only event log is the source of truth**, with SQLite as a rebuildable, queryable projection. The log is tamper-evident via a hash chain, and the index self-heals from the log on startup.
- **Base node types** (`file`, `folder`, plus a `temp` flag) are the only types built into the core. Everything else is a WASM module.

## Archive

The previous concept implementation (Python + TypeScript MediaForest/PVFS prototype) lives under [`v0.0-concept/`](v0.0-concept/) and is tagged `v0.0-concept`.

## Test server

Reset **presubuntu** (Proxmox VM 101) to a clean Ubuntu host for PVFS testing via the Homelab repo: [`infra/README.md`](infra/README.md) → `./scripts/presubuntu-reset.sh`.

## License

See [`LICENSE`](LICENSE).
