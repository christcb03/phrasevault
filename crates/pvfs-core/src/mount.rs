//! P1.5 — mounts, the system registry, and operator addressing (doc 05).
//!
//! - Engine state lives at `<mount>/.pvfs/` (log.db, index.db, device.key).
//! - Registered forests have a file in the registry dir (default `/etc/pvfs`,
//!   override with `PVFS_REGISTRY_DIR` for tests/non-root use).
//! - Operator targets: `pvfs://<forest>[@<server>]/<tree-path>` or an
//!   absolute path under a mount (longest mount prefix wins).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension};

use crate::engine::Engine;
use crate::error::{map_db, PvfsError, Result};
use crate::event::Event;
use crate::fs::{BindSpec, HashPolicy, ScanReport};
use crate::identity::Mnemonic;
use crate::link::LINK_CONTAINS;
use crate::node::NodeId;
use crate::projection::ForestIdentity;
use crate::storage::path_to_uri;

pub const STATE_DIR: &str = ".pvfs";
pub const DEFAULT_REGISTRY: &str = "/etc/pvfs";
/// Default directory for per-forest daemon sockets (world-traversable so other
/// users can reach a served forest). Override with `$PVFS_SOCKET_DIR`.
pub const DEFAULT_SOCKET_DIR: &str = "/tmp/pvfs";

/// The directory daemon sockets live in (`$PVFS_SOCKET_DIR` or [`DEFAULT_SOCKET_DIR`]).
pub fn daemon_socket_dir() -> PathBuf {
    std::env::var_os("PVFS_SOCKET_DIR")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_DIR))
}

/// The conventional socket path for a forest's daemon: `<socket-dir>/<forest_id>.sock`.
/// Both `pvfsd` (to bind) and clients (to find a running daemon) derive it.
pub fn daemon_socket_path(forest_id: &str) -> PathBuf {
    daemon_socket_dir().join(format!("{forest_id}.sock"))
}

fn bad(field: &str, reason: String) -> PvfsError {
    PvfsError::BadInput {
        field: field.into(),
        reason,
    }
}

/// `<mount>/.pvfs`
pub fn state_dir(mount: &Path) -> PathBuf {
    mount.join(STATE_DIR)
}

/// A directory is a mount when its `.pvfs/log.db` exists.
pub fn is_mount(path: &Path) -> bool {
    state_dir(path).join("log.db").is_file()
}

/// Read a forest's identity straight from its log (read-only, no engine open,
/// no recovery) — used by inventory listings.
pub fn peek_identity(mount: &Path) -> Result<ForestIdentity> {
    let log = state_dir(mount).join("log.db");
    let conn = Connection::open_with_flags(&log, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(map_db("open log read-only"))?;
    let row: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT kind, body FROM events WHERE seq = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(map_db("peek genesis"))?;
    let (kind, body) = row.ok_or_else(|| PvfsError::Corruption {
        db: "log.db".into(),
        detail: "no genesis event".into(),
        seq: Some(1),
    })?;
    match Event::decode(&kind, &body)? {
        Event::ForestCreated {
            instance_id,
            forest_id,
            root_node_id,
            author,
            ..
        } => Ok(ForestIdentity {
            instance_id,
            forest_id,
            root_node_id,
            root_pubkey: author,
        }),
        _ => Err(PvfsError::Corruption {
            db: "log.db".into(),
            detail: "first event is not ForestCreated".into(),
            seq: Some(1),
        }),
    }
}

// ---- mount-level engine lifecycle ---------------------------------------------

/// `pvfs forest init` (doc 05 §5.1): genesis under `<mount>/.pvfs/`, then
/// optionally import (bind + scan) the mount's own tree.
pub fn init_forest(
    mount: &Path,
    import: bool,
    hash_policy: HashPolicy,
) -> Result<(Engine, Mnemonic, Option<ScanReport>)> {
    // Refuse raw-root creation up front — before any state exists on disk —
    // so a library caller can't leave a half-created root-owned `.pvfs/` behind.
    mount_owner_credentials()?;
    std::fs::create_dir_all(mount).map_err(|e| PvfsError::io("create mount", e))?;
    let mount = std::fs::canonicalize(mount).map_err(|e| PvfsError::io("canonicalize mount", e))?;
    let (mut engine, mnemonic) = Engine::init(&state_dir(&mount))?;
    let report = if import {
        let root = engine.identity.root_node_id.clone();
        engine.bind_folder(
            &root,
            BindSpec {
                source_uri: path_to_uri(&mount)?,
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy,
            },
        )?;
        let mut reports = engine.scan(Some(&root))?;
        reports.pop()
    } else {
        None
    };
    ensure_mount_owned_by_operator(&mount)?;
    Ok((engine, mnemonic, report))
}

/// UID/GID that should own a mount's `.pvfs/` tree: real user when invoked via
/// `sudo`, otherwise the current process credentials.
#[cfg(unix)]
pub fn mount_owner_credentials() -> Result<(u32, u32)> {
    use nix::unistd::{geteuid, getgid, getuid};

    if geteuid().is_root() {
        if let (Ok(su), Ok(sg)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
            let uid: u32 = su
                .parse()
                .map_err(|_| bad("SUDO_UID", format!("{su:?} is not a uid")))?;
            let gid: u32 = sg
                .parse()
                .map_err(|_| bad("SUDO_GID", format!("{sg:?} is not a gid")))?;
            return Ok((uid, gid));
        }
        return Err(bad(
            "user",
            "refusing to create forest data as root — run `pvfs forest init` as your user, \
             then `sudo pvfs forest register` for system-wide listing"
                .into(),
        ));
    }
    Ok((getuid().as_raw(), getgid().as_raw()))
}

#[cfg(not(unix))]
pub fn mount_owner_credentials() -> Result<(u32, u32)> {
    // No POSIX ownership model off Unix; ownership repair is a no-op there.
    Ok((0, 0))
}

/// Recursively chown a path (used for `<mount>/.pvfs/` after init or repair).
///
/// **Symlink-safe:** never chowns *through* a symlink and never descends into a
/// symlinked directory, so a planted symlink can't redirect a root-run repair at
/// an arbitrary target (the classic `chown -R` escalation). Entries already owned
/// by the target uid/gid are skipped, making this a cheap no-op in the common
/// case where state is already operator-owned (and avoiding needless `EPERM`).
#[cfg(unix)]
pub fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use nix::unistd::{chown, Gid, Uid};
    use std::os::unix::fs::MetadataExt;

    let u = Uid::from_raw(uid);
    let g = Gid::from_raw(gid);
    fn recurse(p: &Path, u: Uid, g: Gid, uid: u32, gid: u32) -> Result<()> {
        let md = std::fs::symlink_metadata(p).map_err(|e| PvfsError::io("stat", e))?;
        if md.file_type().is_symlink() {
            return Ok(()); // skip symlinks entirely — never follow them
        }
        if md.uid() != uid || md.gid() != gid {
            chown(p, Some(u), Some(g))
                .map_err(|e| PvfsError::io("chown", std::io::Error::from(e)))?;
        }
        if md.is_dir() {
            for entry in std::fs::read_dir(p).map_err(|e| PvfsError::io("read dir", e))? {
                recurse(
                    &entry.map_err(|e| PvfsError::io("read dir", e))?.path(),
                    u,
                    g,
                    uid,
                    gid,
                )?;
            }
        }
        Ok(())
    }
    recurse(path, u, g, uid, gid)
}

#[cfg(not(unix))]
pub fn chown_tree(_path: &Path, _uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

/// Repair ownership so the operator owns the **engine state** (`<mount>/.pvfs/`),
/// plus the mount **directory entry** itself if some other account (e.g. a
/// mistaken `sudo init`) created it.
///
/// Deliberately scoped: it recurses only into `.pvfs/` (small, engine-controlled)
/// and touches the mount only as a single directory entry. It never recursively
/// rewrites the workspace files under the mount — those follow ordinary
/// filesystem ownership and are managed with ordinary tools (see doc 05 §5.4).
#[cfg(unix)]
pub fn ensure_mount_owned_by_operator(mount: &Path) -> Result<()> {
    use nix::unistd::{chown, Gid, Uid};
    use std::os::unix::fs::MetadataExt;

    let mount = std::fs::canonicalize(mount).map_err(|e| PvfsError::io("canonicalize mount", e))?;
    let sd = state_dir(&mount);
    if !sd.is_dir() {
        return Err(PvfsError::NotFound {
            kind: "mount",
            id: mount.to_string_lossy().into_owned(),
        });
    }
    let (uid, gid) = mount_owner_credentials()?;
    // Engine state — recurse, but only here.
    chown_tree(&sd, uid, gid)?;
    // The mount directory entry only (so the operator can write `.pvfs/` into it),
    // never its contents. Skip symlinks and anything already correctly owned.
    if let Ok(md) = std::fs::symlink_metadata(&mount) {
        if !md.file_type().is_symlink() && md.uid() != uid {
            chown(&mount, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)))
                .map_err(|e| PvfsError::io("chown mount", std::io::Error::from(e)))?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_mount_owned_by_operator(mount: &Path) -> Result<()> {
    if !state_dir(mount).is_dir() {
        return Err(PvfsError::NotFound {
            kind: "mount",
            id: mount.to_string_lossy().into_owned(),
        });
    }
    Ok(()) // no POSIX ownership model off Unix
}

pub fn open_mount(mount: &Path) -> Result<Engine> {
    if !is_mount(mount) {
        return Err(PvfsError::NotFound {
            kind: "mount",
            id: mount.to_string_lossy().into_owned(),
        });
    }
    Engine::open(&state_dir(mount))
}

// ---- registry (doc 05 §3) --------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RegisteredForest {
    pub alias: Option<String>,
    pub mount: PathBuf,
    pub enabled: bool,
}

pub struct Registry {
    dir: PathBuf,
}

impl Registry {
    pub fn new(dir: PathBuf) -> Registry {
        Registry { dir }
    }

    /// The host registry: `$PVFS_REGISTRY_DIR` or `/etc/pvfs`.
    pub fn system() -> Registry {
        let dir = std::env::var("PVFS_REGISTRY_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_REGISTRY));
        Registry { dir }
    }

    fn forests_dir(&self) -> PathBuf {
        self.dir.join("forests.d")
    }

    pub fn validate_alias(alias: &str) -> Result<()> {
        let ok = !alias.is_empty()
            && alias.len() <= 64
            && alias
                .bytes()
                .next()
                .map(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                .unwrap_or(false)
            && alias
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_');
        if ok {
            Ok(())
        } else {
            Err(bad(
                "alias",
                format!("{alias:?} — use lowercase [a-z0-9][a-z0-9_-]{{0,63}}"),
            ))
        }
    }

    pub fn list(&self) -> Result<Vec<RegisteredForest>> {
        let dir = self.forests_dir();
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(PvfsError::io("read registry", e)),
        };
        for entry in rd {
            let entry = entry.map_err(|e| PvfsError::io("read registry", e))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let body =
                std::fs::read_to_string(&path).map_err(|e| PvfsError::io("read registry file", e))?;
            if let Some(f) = parse_forest_toml(&body) {
                out.push(f);
            }
        }
        out.sort_by(|a, b| a.mount.cmp(&b.mount));
        Ok(out)
    }

    pub fn find(&self, alias_or_mount: &str) -> Result<Option<RegisteredForest>> {
        let wanted_path = Path::new(alias_or_mount);
        for f in self.list()? {
            if f.alias.as_deref() == Some(alias_or_mount) || f.mount == wanted_path {
                return Ok(Some(f));
            }
        }
        Ok(None)
    }

    /// `pvfs forest register` (doc 05 §5.2). Idempotent update keyed by mount.
    pub fn register(&self, mount: &Path, alias: Option<&str>) -> Result<RegisteredForest> {
        let mount = std::fs::canonicalize(mount)
            .map_err(|e| PvfsError::io("canonicalize mount", e))?;
        if !is_mount(&mount) {
            return Err(PvfsError::NotFound {
                kind: "mount",
                id: mount.to_string_lossy().into_owned(),
            });
        }
        if let Some(a) = alias {
            Self::validate_alias(a)?;
            if let Some(existing) = self.find(a)? {
                if existing.mount != mount {
                    return Err(bad(
                        "alias",
                        format!("{a:?} already points at {}", existing.mount.display()),
                    ));
                }
            }
        }
        std::fs::create_dir_all(self.forests_dir()).map_err(|e| {
            PvfsError::Io {
                op: format!(
                    "create registry {} (need root? set PVFS_REGISTRY_DIR for a user registry)",
                    self.dir.display()
                ),
                source: e,
            }
        })?;
        // drop any previous entry for this mount (idempotent re-register)
        self.remove_entries_for(&mount)?;
        let f = RegisteredForest {
            alias: alias.map(|s| s.to_string()),
            mount: mount.clone(),
            enabled: true,
        };
        let slug = alias
            .map(|s| s.to_string())
            .unwrap_or_else(|| slug_for_mount(&mount));
        let path = self.forests_dir().join(format!("{slug}.toml"));
        std::fs::write(&path, forest_toml(&f))
            .map_err(|e| PvfsError::io("write registry file", e))?;
        Ok(f)
    }

    /// Remove the registry entry only — never touches `.pvfs/` (doc 05 §5.2).
    pub fn unregister(&self, alias_or_mount: &str) -> Result<()> {
        let found = self.find(alias_or_mount)?.ok_or(PvfsError::NotFound {
            kind: "registered forest",
            id: alias_or_mount.to_string(),
        })?;
        self.remove_entries_for(&found.mount)
    }

    fn remove_entries_for(&self, mount: &Path) -> Result<()> {
        let dir = self.forests_dir();
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(PvfsError::io("read registry", e)),
        };
        for entry in rd {
            let entry = entry.map_err(|e| PvfsError::io("read registry", e))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            if let Ok(body) = std::fs::read_to_string(&path) {
                if let Some(f) = parse_forest_toml(&body) {
                    if f.mount == mount {
                        std::fs::remove_file(&path)
                            .map_err(|e| PvfsError::io("remove registry file", e))?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn slug_for_mount(mount: &Path) -> String {
    let s: String = mount
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect();
    format!("mount{s}")
}

/// Registry files are a tiny TOML subset (machine-written): `key = "string"`
/// and `key = true|false`, one per line, `#` comments.
fn parse_forest_toml(body: &str) -> Option<RegisteredForest> {
    let mut mount = None;
    let mut alias = None;
    let mut enabled = true;
    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "mount" => mount = Some(PathBuf::from(v.trim_matches('"'))),
            "alias" => alias = Some(v.trim_matches('"').to_string()),
            "enabled" => enabled = v != "false",
            _ => {}
        }
    }
    mount.map(|mount| RegisteredForest {
        alias,
        mount,
        enabled,
    })
}

fn forest_toml(f: &RegisteredForest) -> String {
    let mut s = format!("mount = \"{}\"\n", f.mount.display());
    if let Some(a) = &f.alias {
        s.push_str(&format!("alias = \"{a}\"\n"));
    }
    s.push_str(&format!("enabled = {}\n", f.enabled));
    s
}

// ---- target resolution (doc 05 §4) -------------------------------------------------

/// A resolved operator target: a mount plus a tree path inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub mount: PathBuf,
    pub segments: Vec<String>,
}

/// `pvfs://<forest>[@<server>]/<tree-path>` or an absolute path.
pub fn resolve_target(registry: &Registry, arg: &str) -> Result<ResolvedTarget> {
    if let Some(rest) = arg.strip_prefix("pvfs://") {
        if rest.starts_with('/') {
            // path form: pvfs:///abs/mount/tree...
            return resolve_abs_path(registry, rest);
        }
        let (head, tail) = rest.split_once('/').unwrap_or((rest, ""));
        let (forest, server) = head.split_once('@').unwrap_or((head, "local"));
        if server != "local" && !server.is_empty() {
            return Err(bad(
                "server",
                format!("remote resolution ({server:?}) arrives with federation (P4)"),
            ));
        }
        let reg = registry.find(forest)?.ok_or(PvfsError::NotFound {
            kind: "forest alias",
            id: forest.to_string(),
        })?;
        return Ok(ResolvedTarget {
            mount: reg.mount,
            segments: split_segments(tail),
        });
    }
    if arg.starts_with('/') {
        return resolve_abs_path(registry, arg);
    }
    Err(bad(
        "target",
        format!("{arg:?} — expected a pvfs:// URI or an absolute path under a mount"),
    ))
}

/// Longest mount prefix wins (doc 05 §4.4). Works for unregistered (portable)
/// mounts too — any ancestor with `.pvfs/log.db` qualifies.
fn resolve_abs_path(_registry: &Registry, path: &str) -> Result<ResolvedTarget> {
    let p = PathBuf::from(path);
    let mut candidate = Some(p.as_path());
    while let Some(c) = candidate {
        if is_mount(c) {
            let suffix = p.strip_prefix(c).unwrap_or(Path::new(""));
            let segments = suffix
                .components()
                .map(|s| s.as_os_str().to_string_lossy().into_owned())
                .collect();
            return Ok(ResolvedTarget {
                mount: c.to_path_buf(),
                segments,
            });
        }
        candidate = c.parent();
    }
    Err(PvfsError::NotFound {
        kind: "mount",
        id: format!("{path} (no ancestor contains {STATE_DIR}/log.db)"),
    })
}

fn split_segments(s: &str) -> Vec<String> {
    s.split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

/// Walk the tree by labels from the forest root (doc 05 §4.2 step 4).
/// Prefers `contains` children; falls back to `ref` children on label match.
pub fn node_at_path(engine: &Engine, segments: &[String]) -> Result<NodeId> {
    let mut current = engine.identity.root_node_id.clone();
    for seg in segments {
        let kids = engine.children(&current)?;
        let hit = kids
            .iter()
            .find(|c| c.link_type == LINK_CONTAINS && c.node.label == *seg)
            .or_else(|| kids.iter().find(|c| c.node.label == *seg));
        match hit {
            Some(c) => current = c.node.id.clone(),
            None => {
                return Err(PvfsError::NotFound {
                    kind: "tree path",
                    id: seg.clone(),
                })
            }
        }
    }
    Ok(current)
}

/// The mount enclosing `start`, if any (used for CWD-based forest context).
pub fn enclosing_mount(start: &Path) -> Option<PathBuf> {
    let mut candidate = Some(start);
    while let Some(c) = candidate {
        if is_mount(c) {
            return Some(c.to_path_buf());
        }
        candidate = c.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_validation() {
        assert!(Registry::validate_alias("pvfshome").is_ok());
        assert!(Registry::validate_alias("a-1_b").is_ok());
        assert!(Registry::validate_alias("").is_err());
        assert!(Registry::validate_alias("Caps").is_err());
        assert!(Registry::validate_alias("-lead").is_err());
        assert!(Registry::validate_alias("sp ace").is_err());
    }

    #[test]
    fn toml_roundtrip() {
        let f = RegisteredForest {
            alias: Some("home".into()),
            mount: PathBuf::from("/data/pvfs"),
            enabled: true,
        };
        let parsed = parse_forest_toml(&forest_toml(&f)).unwrap();
        assert_eq!(parsed.alias.as_deref(), Some("home"));
        assert_eq!(parsed.mount, PathBuf::from("/data/pvfs"));
        assert!(parsed.enabled);
    }
}
