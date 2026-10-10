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
    let conn = open_peek(&log).map_err(map_db("open log read-only"))?;
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

/// PVOS D182 — a data dir's top-log tip `(seq, chain hash)`, read-only: no
/// engine open, no recovery, safe beside a running daemon. What a replica
/// sends with its routed writes, and what `pvfs forest tip` prints.
pub fn peek_tip(data_dir: &Path) -> Result<(u64, Vec<u8>)> {
    let conn = open_peek(&data_dir.join("log.db")).map_err(map_db("open log read-only"))?;
    crate::log_store::tip_in(&conn, "main")
}

/// PVOS D185 — the forest's CURRENT root (the last `RootRotated`'s key, else
/// the genesis root), read-only beside a running daemon. It is the key a
/// companion must hold to promote (D182): genesis's alone is wrong once the
/// root has been rotated.
pub fn peek_current_root(data_dir: &Path, identity: &ForestIdentity) -> Result<Vec<u8>> {
    let conn = open_peek(&data_dir.join("index.db")).map_err(map_db("open projection read-only"))?;
    crate::projection::current_root(&conn, identity)
}

/// PVOS D192 — whether the forest binds its certificates (`genesis`, or the
/// seq of its `CertificatesBound`), read-only beside a running daemon.
pub fn peek_certs_bound(data_dir: &Path) -> Result<Option<String>> {
    let conn = open_peek(&data_dir.join("index.db")).map_err(map_db("open projection read-only"))?;
    crate::projection::certs_bound(&conn)
}

/// PVOS D232 — a read-only connection for a peek. As the forest's user, the
/// usual one. As any other user (root, under a `sudo` command D231 still
/// allows), `immutable`: SQLite then creates no `-shm` or `-wal` and takes
/// no lock on a forest that is not this process's. A read-only connection
/// to a WAL database otherwise creates those files when they are not there
/// (a daemon stopped and cleanly closed). Under root SQLite gives them to
/// the database file's owner (checked: D232 deviation 1), so this is
/// defense: for a non-root other user, and for locks. Immutable reads the
/// database file alone, so a write still in the WAL is not seen: the peeks
/// a root command makes read the genesis row and identity, long
/// checkpointed.
pub fn open_peek(db: &Path) -> rusqlite::Result<Connection> {
    let other_user = db.parent().is_some_and(|dir| check_forest_user(dir).is_err());
    if !other_user {
        return Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY);
    }
    Connection::open_with_flags(
        format!("file:{}?immutable=1", uri_path(db)),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
}

/// `path` for a `file:` URI: `%`, `?` and `#` escaped (SQLite's URI rules).
fn uri_path(path: &Path) -> String {
    let mut out = String::new();
    for c in path.to_string_lossy().chars() {
        match c {
            '%' => out.push_str("%25"),
            '?' => out.push_str("%3f"),
            '#' => out.push_str("%23"),
            c => out.push(c),
        }
    }
    out
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
    let report = finish_init_import(&mut engine, &mount, import, hash_policy)?;
    ensure_mount_owned_by_operator(&mount)?;
    Ok((engine, mnemonic, report))
}

/// Like [`init_forest`], but root-signs genesis with an external signer (e.g.
/// a running companion that already holds the recovery seed). No new mnemonic.
pub fn init_forest_with_root_signer(
    mount: &Path,
    import: bool,
    hash_policy: HashPolicy,
    root_pub: &[u8],
    sign_root: impl FnMut(&[u8; 32]) -> Result<Vec<u8>>,
) -> Result<(Engine, Option<ScanReport>)> {
    mount_owner_credentials()?;
    std::fs::create_dir_all(mount).map_err(|e| PvfsError::io("create mount", e))?;
    let mount = std::fs::canonicalize(mount).map_err(|e| PvfsError::io("canonicalize mount", e))?;
    let mut engine = Engine::init_with_root_signer(&state_dir(&mount), root_pub, sign_root)?;
    let report = finish_init_import(&mut engine, &mount, import, hash_policy)?;
    ensure_mount_owned_by_operator(&mount)?;
    Ok((engine, report))
}

fn finish_init_import(
    engine: &mut Engine,
    mount: &Path,
    import: bool,
    hash_policy: HashPolicy,
) -> Result<Option<ScanReport>> {
    if !import {
        return Ok(None);
    }
    let root = engine.identity.root_node_id.clone();
    engine.bind_folder(
        &root,
        BindSpec {
            source_uri: path_to_uri(mount)?,
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy,
        },
    )?;
    let mut reports = engine.scan(Some(&root))?;
    Ok(reports.pop())
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
///
/// PVOS D232 — by descriptors. The walk used to `symlink_metadata` a path
/// and then `chown(2)` the same path, which follows a link: the tree's user,
/// swapping an entry for a link to `/etc/shadow` between the two calls,
/// would be given that file by the root running `forest fix-permissions`.
/// Now every folder is opened `O_NOFOLLOW` (from `/`, then relative to its
/// parent), and each entry is changed with `fchownat(…, AT_SYMLINK_NOFOLLOW)`
/// relative to its folder: a link is never followed, whatever is swapped.
#[cfg(unix)]
pub fn chown_tree(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::fd::AsRawFd;
    let root = crate::sync::open_dir_nofollow(path).map_err(|e| PvfsError::io("open for chown", e))?;
    chown_dir(root.as_raw_fd(), uid, gid)
}

/// Change the folder open at `fd`, then everything in it (see `chown_tree`).
#[cfg(unix)]
fn chown_dir(fd: std::os::fd::RawFd, uid: u32, gid: u32) -> Result<()> {
    use nix::fcntl::{AtFlags, OFlag};
    use nix::sys::stat::{fstat, fstatat, Mode};
    use nix::unistd::{fchown, fchownat, Gid, Uid};
    let (u, g) = (Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
    let io = |what: &str, e: nix::errno::Errno| PvfsError::io(what, std::io::Error::from(e));
    let st = fstat(fd).map_err(|e| io("stat", e))?;
    if st.st_uid != uid || st.st_gid != gid {
        fchown(fd, u, g).map_err(|e| io("chown", e))?;
    }
    // a second descriptor for the listing: Dir takes and closes its own
    let list = nix::fcntl::openat(Some(fd), ".", OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC, Mode::empty())
        .map_err(|e| io("read dir", e))?;
    let mut dir = nix::dir::Dir::from_fd(list).map_err(|e| io("read dir", e))?;
    let names: Vec<std::ffi::CString> = dir
        .iter()
        .filter_map(|e| e.ok())
        .filter(|e| !matches!(e.file_name().to_bytes(), b"." | b".."))
        .map(|e| e.file_name().to_owned())
        .collect();
    for name in names {
        let Ok(st) = fstatat(Some(fd), name.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW) else { continue };
        match st.st_mode & nix::libc::S_IFMT {
            nix::libc::S_IFLNK => continue, // a link: never followed, never changed
            nix::libc::S_IFDIR => {
                let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
                match nix::fcntl::openat(Some(fd), name.as_c_str(), flags, Mode::empty()) {
                    Ok(sub) => {
                        // Safety: just opened, owned here only.
                        let sub = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(sub) };
                        chown_dir(std::os::fd::AsRawFd::as_raw_fd(&sub), uid, gid)?;
                    }
                    // swapped for a link (or a file) since the stat: left alone
                    Err(nix::errno::Errno::ELOOP) | Err(nix::errno::Errno::ENOTDIR) => {}
                    Err(e) => return Err(io("open dir", e)),
                }
            }
            _ => {
                if st.st_uid != uid || st.st_gid != gid {
                    fchownat(Some(fd), name.as_c_str(), u, g, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|e| io("chown", e))?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn chown_tree(_path: &Path, _uid: u32, _gid: u32) -> Result<()> {
    Ok(())
}

/// PVOS D231 — refuse to use a forest's files as a user other than the one
/// that owns them (its `.pvfs` data dir's owner: the user its daemon runs as).
///
/// Whatever this process made there would be its own: run as root (`sudo
/// pvfs …`), trash folders, index files, SQLite's `-wal`/`-shm`, job and
/// state files come out root's, and the daemon cannot change or remove them
/// later. On 2026-10-09 two root-made trash buckets stopped mediabox's purge
/// and paged as disk errors. Making the new entries the owner's instead (a
/// chown after each) was not chosen: root's writes skip the permission
/// checks the daemon itself is held to, SQLite and the standard library
/// create files PVFS never sees, and any path that missed its chown would
/// bring the fault back. Default-deny: nothing is opened, nothing written.
///
/// A data dir that does not exist yet passes (creating a forest is
/// `init_forest`'s business, which makes it the caller's, or the sudo
/// caller's). The system registry's commands (`forest register`, …) never
/// open a forest, so they still run as root.
#[cfg(unix)]
pub fn check_forest_user(data_dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::metadata(data_dir) else {
        return Ok(()); // not there yet: nothing of anyone's to spoil
    };
    let running = nix::unistd::geteuid().as_raw();
    check_forest_user_for(data_dir, md.uid(), running)
}

#[cfg(not(unix))]
pub fn check_forest_user(_data_dir: &Path) -> Result<()> {
    Ok(())
}

/// [`check_forest_user`]'s rule, for a data dir owned by `owner` and a
/// process running as `running`.
pub fn check_forest_user_for(data_dir: &Path, owner: u32, running: u32) -> Result<()> {
    if owner == running {
        return Ok(());
    }
    let owner_text = crate::sync::user_text(owner);
    let owner_name = owner_name(owner).unwrap_or_else(|| format!("#{owner}"));
    if owner == 0 {
        // the other way round: root's forest, a user running pvfs. Usually a
        // `sudo` init by mistake, which fix-permissions undoes.
        let mount = data_dir.parent().unwrap_or(data_dir);
        return Err(PvfsError::Forbidden {
            action: format!("use the forest at {} as {}", data_dir.display(), crate::sync::user_text(running)),
            reason: format!(
                "its files belong to root (uid 0). If that is a mistake (a `sudo` init), give them back with \
                 `sudo pvfs forest fix-permissions --mount {}`; otherwise run pvfs as root",
                mount.display()
            ),
        });
    }
    Err(PvfsError::Forbidden {
        action: format!("use the forest at {} as {}", data_dir.display(), crate::sync::user_text(running)),
        reason: format!(
            "its files belong to {owner_text}, the user its daemon runs as. Anything pvfs made there now \
             would be {}, and that daemon could not change or remove it later. Run it as that user: \
             sudo -u {owner_name} pvfs …",
            if running == 0 { "root's".to_string() } else { format!("uid {running}'s") }
        ),
    })
}

#[cfg(unix)]
fn owner_name(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok().flatten().map(|u| u.name)
}

#[cfg(not(unix))]
fn owner_name(_uid: u32) -> Option<String> {
    None
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
            .find(|c| c.link_type == LINK_CONTAINS && c.label == *seg)
            .or_else(|| kids.iter().find(|c| c.label == *seg));
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
