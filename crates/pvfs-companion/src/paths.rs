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
