# PVFS — Instance registry, mounts, and operator URIs (05)

Status: **Decided (operator UX)** — implementation follows P0 kernel; replaces `PVFS_DATA_DIR` as the primary CLI model
Date: 2026-06-11
Depends on: [00-architecture-decisions.md](00-architecture-decisions.md), [03-federation-trust-and-uris.md](03-federation-trust-and-uris.md)

This document locks **how operators address forests on a host** (registry, mount layout, CLI). It does **not** change P0 log encodings. Federation **node catalog URIs** remain as defined in doc 03 §3; this doc adds a separate **mount URI** class for day-to-day CLI use.

---

## 1. On-disk layout

Every forest lives at a **mount directory** chosen by the operator (e.g. `/home/alice/pvfs`, `/media/usb/project`).

| Path | Purpose |
|------|---------|
| `<mount>/` | Workspace tree — normal files and folders indexed/bound into PVFS |
| `<mount>/.pvfs/` | Engine state only (hidden metadata) |

**`.pvfs/` contents** (minimum):

| File | Role |
|------|------|
| `log.db` | Append-only event log |
| `index.db` | Rebuildable projection |
| `device.key` | This machine’s device signing key (mode 0600) |

Optional later: `manifest.json` — cached `instance_id`, `forest_id`, `root_node_id`, bind roots (rebuildable from log).

**Rule:** All engine files live under `.pvfs/` unless a future spec documents a clear exception.

---

## 2. Two classes of forest

| Kind | Registry | Typical use |
|------|----------|-------------|
| **Registered** | Entry in `/etc/pvfs/` | Server forests — always visible, daemon-managed |
| **Portable** | None | USB stick, tar extract, offline copy — `.pvfs/` travels with the tree |

Portable forests are **first-class**: the CLI opens them by **mount path** in a URI or path argument. They do not appear in `pvfs ls` (forest inventory) unless explicitly registered.

---

## 3. System registry (`/etc/pvfs/`)

Owned by the **PVFS daemon** (future). CLI writes via root/polkit helper.

```text
/etc/pvfs/
  config.toml          # this host instance_id, daemon socket, defaults
  forests.d/
    *.toml             # one file per registered forest
```

Example `forests.d/pvfshome.toml`:

```toml
mount = "/home/alice/pvfs"
alias = "pvfshome"              # optional; unique on this host
enabled = true
# instance_id, forest_id — read from <mount>/.pvfs/ at register time (cache)
```

- **`mount`** — directory containing `.pvfs/` (canonical key for path-based lookup).
- **`alias`** — optional friendly name (`[a-z0-9][a-z0-9_-]*`, case-sensitive or normalized — pick one at implement time).
- Cryptographic identity (`instance_id`, `forest_id`) always comes from the log; registry only **points** at mounts.

---

## 4. Mount URIs (operator addressing)

### 4.1 Grammar

Primary form for scripts and explicit addressing:

```text
pvfs://[<forest>[@<server>]/]<tree-path>
```

| Part | Meaning |
|------|---------|
| `pvfs://` | Scheme — marks a PVFS mount address (not `file://` storage) |
| `<forest>` | Registered **alias**, or **absolute mount path** (portable / unaliased) |
| `@<server>` | Optional. Owner/resolver: `local`, hostname, or `instance_id`. Omitted ⇒ `local`. |
| `<tree-path>` | Path **inside the forest tree** from root (labels / logical segments). May be empty. |

**Examples**

```text
pvfs://pvfshome@local/docs/notes
pvfs://pvfshome@local/                    # forest root
pvfs:///home/alice/pvfs/photos/2024       # registered mount by path (alias optional)
pvfs:///media/usb/project/readme.txt      # portable — no registry entry
pvfs://archive@backup-server/             # remote read (P4+)
```

### 4.2 Resolution order

1. Parse URI; default `server` = `local`.
2. **`server` ≠ local** → resolve via instance discovery (P4); not required for first implementation.
3. **`server` = local**:
   - If `<forest>` matches a registry **alias** → `mount` from `/etc/pvfs/`.
   - Else if `<forest>` is an absolute path (or URI path-only form `pvfs:///…`) → use as **mount** if `<path>/.pvfs/log.db` exists (registered or portable).
4. Open `<mount>/.pvfs/`; map `<tree-path>` to node(s) via bound layout / labels (P1 bind model).

### 4.3 Relation to doc 03 catalog URIs

| Class | Example | Use |
|-------|---------|-----|
| **Mount URI** (this doc) | `pvfs://pvfshome@local/docs/x` | CLI, local daemon, “which forest + where in tree” |
| **Storage URI** (doc 03 §2.1) | `file:///var/data/x` | Bytes on disk — `FileLocationAdded` |
| **Node catalog URI** (doc 03 §3) | `pvfs:<instance_id>/<forest_id>/node/<node_id>` | Federation, dedupe, cross-instance identity |

Mount URIs are **operator-facing**. Node catalog URIs are **identity-facing**. A mount URI resolves to a subtree; a catalog URI resolves to one content-addressed node.

### 4.4 CLI path shorthand

For local use, these are equivalent when unambiguous:

```text
pvfs://pvfshome@local/docs/notes
pvfs ls /home/alice/pvfs/docs/notes      # absolute path: longest matching mount + tree suffix
```

**Rules for `/path/` shorthand**

- Must be absolute (starts with `/`) on Unix.
- Longest registered (or portable) **mount prefix** wins.
- Remainder is `<tree-path>`.
- If the path is exactly the mount (or mount + trailing slash) → list **forest root** children.

**Node id (power user):** a single argument matching the node id grammar (hex, fixed length) lists that node’s children in the forest implied by `--forest` / context, or requires a mount URI prefix in a later flag. Prefer tree paths for humans.

---

## 5. Init and registration (two-step)

### 5.1 `pvfs forest init`

Run from the directory that will become the **mount** (or specify `--mount`).

1. Create `<mount>/.pvfs/` and run genesis (`ForestCreated`, device 0, root node) — same kernel as today.
2. Print recovery phrase once.
3. Prompt: **Import this directory’s tree into the forest?** (bind + scan of `<mount>/`, excluding `.pvfs/`).
4. Prompt: **Friendly alias?** (optional; stored only on register, or in local `.pvfs/manifest.json` as hint).

Does **not** write `/etc/pvfs/` or require root. Produces a **portable** forest until registered.

**Ownership:** always run **`pvfs forest init` as your normal user** (never `sudo init`). Engine state in `<mount>/.pvfs/` is owned by you. System-wide listing is a separate step:

```bash
pvfs forest init                    # as your user, in or under the mount directory
sudo pvfs forest register /path/to/mount --alias myforest
```

`register` may run under `sudo` (writes `/etc/pvfs/` only). It also **repairs ownership** if `.pvfs/` was created root-owned by mistake.

Recovery: `sudo pvfs forest fix-permissions /path/to/mount` (reassigns `.pvfs/` to your user via `SUDO_UID`).

### 5.2 `pvfs forest register`

1. Verify `<mount>/.pvfs/log.db` exists.
2. Write `/etc/pvfs/forests.d/<slug>.toml` with `mount`, optional `alias`.
3. Notify daemon to load forest (future).

Idempotent update if mount already registered. **`unregister`** removes registry entry only — does **not** delete `.pvfs/`.

### 5.3 Portable use (USB, etc.)

- Copy entire `<mount>/` including `.pvfs/`.
- On any machine: `pvfs ls /media/usb/project/docs/` or `pvfs://…` with full mount path — **no register required**.
- Optional: `pvfs forest register /media/usb/project` when the stick should appear in `pvfs ls` inventory on that host.

---

## 6. CLI commands (hybrid)

### 6.1 Forest inventory

```text
pvfs ls
```

Lists **registered** forests only: alias (if any), mount path, `instance_id`, `forest_id`, enabled state.

Flags (future): `--portable` scan paths; `--json`.

### 6.2 Forest lifecycle

```text
pvfs forest init [--mount PATH] [--no-import] [--alias NAME]   # alias is a hint only; does not register
pvfs forest register <mount-path> [--alias NAME]               # sudo for /etc/pvfs/
pvfs forest fix-permissions [--mount PATH]                     # sudo if .pvfs/ is root-owned
pvfs forest unregister <alias|mount-path>
pvfs forest info [<mount-uri>]
```

`pvfs forest` without a subcommand prints subcommand help (or `info` for a default forest if exactly one registered — **deferred**; prefer explicit subcommands).

### 6.3 Tree listing

```text
pvfs ls <mount-uri>
pvfs ls </absolute/path/under/mount/>
pvfs ls <node-id>                    # optional; power user / scripts
```

**Behavior:** List **immediate children** of the resolved tree location (folder nodes under that parent). Same semantics as today’s `pvfs ls <node-id>`, but addressed by mount URI or filesystem path under a mount.

For “all descendants”, a separate command later (`pvfs walk`, already exists) — not overloaded into `ls`.

### 6.4 Deprecation of `PVFS_DATA_DIR`

- **Tests and scripts** may keep `--data-dir` / `PVFS_DATA_DIR` as an override.
- **Interactive / daemon operation** uses registry + mount URIs / path shorthand.
- Document in INSTALL.md once implemented.

---

## 7. Implementation phasing

| Phase | Deliverable |
|-------|-------------|
| **P1.5** | `.pvfs/` layout convention; `forest init` / `register`; `/etc/pvfs/` schema; resolver; `pvfs ls` / `pvfs forest *` |
| **P2** | Daemon reads registry; `serve` per registered mount |
| **P4** | `@server` ≠ `local`; mount URI → remote catalog |

P0 kernel (`Engine::init`, log, bind, scan) unchanged — wrap with mount path + registry layer.

---

## 8. Open points (minor)

1. **Alias charset and case** — recommend lowercase `[a-z0-9][a-z0-9_-]{0,63}`.
2. **`local` vs empty `@`** — treat omitted server and `@local` identically.
3. **Windows paths** — defer `pvfs://` with drive letters or use `file:`-style mount paths in a later platform doc.
4. **Single registered forest** — whether bare `pvfs ls docs/` resolves without mount prefix when CWD is inside mount (convenience); default **no** until specified.

---

## 9. Summary

| Topic | Decision |
|-------|----------|
| Engine files | `<mount>/.pvfs/` |
| Registry | `/etc/pvfs/` (registered forests only) |
| Portable forests | `.pvfs/` on USB etc.; address by mount path URI or `/path/` shorthand |
| Addressing | `pvfs://<forest>@<server>/<tree-path>` + absolute path shorthand |
| Init | Two-step: `forest init` then `forest register` |
| `pvfs ls` | No args → list forests; with target → list tree children |
| `pvfs forest` | Lifecycle subcommands (`init`, `register`, `info`, …) |
