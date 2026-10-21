//! Default locations (doc 14 §2) so normal use needs no flags: the vault lives
//! in the user's config dir, the signer socket in their runtime dir. Environment
//! variables override for scripts; flags override everything (troubleshooting).

use std::path::PathBuf;

/// The default vault file: `$PVFS_COMPANION_VAULT`, else
/// `$XDG_CONFIG_HOME/pvfs/companion.vault`, else `~/.config/pvfs/companion.vault`
/// — the same config dir the `pvfs` CLI uses for its client identity.
pub fn default_vault_path() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("PVFS_COMPANION_VAULT").filter(|s| !s.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or_else(|| "cannot find a config dir (set HOME or XDG_CONFIG_HOME)".to_string())?;
    Ok(base.join("pvfs").join("companion.vault"))
}

/// PVOS D267 — whether a socket may be talked to as this user's companion:
/// it is a socket, and its owner is the process's effective uid. `/tmp` is
/// writable by every account, so another user can create the conventional
/// name first; the real companion's `0600` mode is only its own socket's.
pub fn socket_is_ours(is_socket: bool, owner: u32, euid: u32) -> bool {
    is_socket && owner == euid
}

/// [`socket_is_ours`] for the socket at `path` (a symlink is followed to what
/// it names), or why not.
pub fn check_socket(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let m = std::fs::metadata(path)?;
    let euid = nix::unistd::geteuid().as_raw();
    if socket_is_ours(m.file_type().is_socket(), m.uid(), euid) {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        if m.file_type().is_socket() {
            format!(
                "the companion socket at {} is not this user's (owner uid {}), so it is not used",
                path.display(),
                m.uid()
            )
        } else {
            format!("{} is not a socket, so it is not a companion", path.display())
        },
    ))
}

/// The conventional signer socket: `$PVFS_COMPANION_SOCKET`, else
/// `$XDG_RUNTIME_DIR/pvfs-companion.sock` (doc 14 §2), else a per-user path
/// under `/tmp` for systems without a runtime dir. The `pvfs` CLI auto-detects
/// the same path, so a bare `serve` and a bare `--via-companion` op agree.
pub fn default_socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("PVFS_COMPANION_SOCKET").filter(|s| !s.is_empty()) {
        return PathBuf::from(p);
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|s| !s.is_empty()) {
        return PathBuf::from(dir).join("pvfs-companion.sock");
    }
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "default".into());
    PathBuf::from(format!("/tmp/pvfs-companion-{user}.sock"))
}

#[cfg(test)]
mod d267_tests {
    use super::*;

    #[test]
    fn only_this_users_own_socket_is_a_companion() {
        assert!(socket_is_ours(true, 1000, 1000));
        assert!(!socket_is_ours(true, 1001, 1000), "another user's socket");
        assert!(!socket_is_ours(false, 1000, 1000), "not a socket");
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("c.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        check_socket(&sock).expect("a socket this test made is ours");
        let file = dir.path().join("not-a-socket");
        std::fs::write(&file, b"x").unwrap();
        assert!(check_socket(&file).unwrap_err().to_string().contains("not a socket"));
        let r = crate::client::request(&file, &crate::proto::AgentRequest::ApiVersion);
        assert!(r.is_err(), "the client does not connect to it");
    }
}
