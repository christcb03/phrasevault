//! TLS for the loopback web agent (PVOS M3.6 §4a — the durable fix).
//!
//! The PVOS desktop is served over https; its page fetches this agent at
//! `127.0.0.1:7421`. Browsers currently exempt loopback from mixed-content
//! blocking, but that exemption is brittle (Private Network Access tightens
//! yearly, and non-Chromium browsers differ). The durable shape: the agent
//! serves **https** with a locally-generated `localhost`/`127.0.0.1` cert
//! that the companion installs as trusted in the user's login keychain
//! (macOS; one GUI prompt, once). The web port itself stays dual-mode — a
//! one-byte peek tells a TLS ClientHello (0x16) from plain HTTP — so older
//! callers keep working through the transition.
//!
//! Material lives next to the vault: `<vault dir>/webtls/{cert,key}.pem`,
//! key 0600 from creation. Regenerating is cheap (delete the dir); the
//! keychain trust is re-offered whenever the cert is newly generated.

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where the web-agent TLS material lives for a vault.
pub fn webtls_dir(vault_path: &Path) -> PathBuf {
    vault_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("webtls")
}

pub struct WebTls {
    pub config: Arc<rustls::ServerConfig>,
    /// True when the cert was created by THIS call (drives the one-time
    /// keychain-trust offer).
    pub fresh: bool,
    pub cert_path: PathBuf,
}

/// Load the web-agent cert, generating it on first use.
pub fn load_or_generate(vault_path: &Path) -> Result<WebTls, String> {
    let dir = webtls_dir(vault_path);
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    let fresh = !(cert_path.is_file() && key_path.is_file());
    if fresh {
        let ck = rcgen::generate_simple_self_signed(vec![
            "localhost".to_string(),
            "127.0.0.1".to_string(),
        ])
        .map_err(|e| format!("webtls: rcgen: {e}"))?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("webtls: mkdir: {e}"))?;
        std::fs::write(&cert_path, ck.cert.pem()).map_err(|e| format!("webtls: write cert: {e}"))?;
        write_secret(&key_path, ck.key_pair.serialize_pem().as_bytes())?;
    }

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(
        &mut BufReader::new(
            std::fs::File::open(&cert_path).map_err(|e| format!("webtls: read cert: {e}"))?,
        ),
    )
    .collect::<Result<_, _>>()
    .map_err(|e| format!("webtls: parse cert: {e}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(
        std::fs::File::open(&key_path).map_err(|e| format!("webtls: read key: {e}"))?,
    ))
    .map_err(|e| format!("webtls: parse key: {e}"))?
    .ok_or("webtls: no private key found")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("webtls: config: {e}"))?;
    Ok(WebTls {
        config: Arc::new(config),
        fresh,
        cert_path,
    })
}

/// Offer the cert to the OS trust store so the browser accepts it without
/// warnings. macOS: `security add-trusted-cert` into the login keychain (the
/// one-time GUI prompt). Elsewhere: print the manual step. Best-effort — the
/// agent serves TLS either way; an untrusted cert just means the browser
/// falls back to plain http (the page tries https first).
pub fn install_trust(cert_path: &Path) {
    #[cfg(target_os = "macos")]
    {
        let keychain = std::env::var("HOME")
            .map(|h| format!("{h}/Library/Keychains/login.keychain-db"))
            .unwrap_or_default();
        let out = std::process::Command::new("security")
            .args(["add-trusted-cert", "-r", "trustRoot", "-k", &keychain])
            .arg(cert_path)
            .output();
        match out {
            Ok(o) if o.status.success() => {
                eprintln!("companion: web-agent cert trusted in the login keychain");
            }
            Ok(o) => eprintln!(
                "companion: keychain trust not installed ({}) — https://127.0.0.1:7421 will \
                 show a warning; to trust manually: security add-trusted-cert -r trustRoot \
                 -k ~/Library/Keychains/login.keychain-db {}",
                String::from_utf8_lossy(&o.stderr).trim(),
                cert_path.display()
            ),
            Err(e) => eprintln!("companion: keychain trust not installed ({e})"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!(
            "companion: web-agent TLS cert at {} — add it to your browser/OS trust store \
             to serve the relay over https without warnings",
            cert_path.display()
        );
    }
}

/// A secret file that is 0600 FROM CREATION (no umask-readable window).
fn write_secret(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_reload_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let vault = tmp.path().join("companion.vault");
        let a = load_or_generate(&vault).unwrap();
        assert!(a.fresh, "first call generates");
        let b = load_or_generate(&vault).unwrap();
        assert!(!b.fresh, "second call reloads");
        assert!(a.cert_path.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(webtls_dir(&vault).join("key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key is 0600");
        }
    }
}
