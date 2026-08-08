//! F1 — the network listener's TLS identity (doc 17 §4).
//!
//! `pvfsd --listen` serves the same framed protocol over TCP+TLS. There is no
//! CA: the daemon generates a self-signed cert on first use and clients pin
//! its **transport pin** — the BLAKE3 hex of the certificate DER. The pin is
//! what an operator copies to a client (`pvfs instance add`), so a MITM needs
//! the private key, not a name. Rotating the material (delete the dir) mints
//! a new pin; peers re-pin — explicit, like re-pairing.
//!
//! Material lives in the forest state dir: `<data_dir>/nettls/{cert,key}.pem`
//! (key 0600 from creation) plus `pin` (the hex, for scripts).

use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where a forest's network-TLS material lives.
pub fn nettls_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("nettls")
}

pub struct NetTls {
    pub config: Arc<rustls::ServerConfig>,
    /// BLAKE3 hex of the certificate DER — what clients pin.
    pub pin: String,
}

/// Load the listener cert, generating it on first use.
pub fn load_or_generate(data_dir: &Path) -> Result<NetTls, String> {
    let dir = nettls_dir(data_dir);
    let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
    if !(cert_path.is_file() && key_path.is_file()) {
        // SANs are irrelevant under pinning — named for debuggability only.
        let ck = rcgen::generate_simple_self_signed(vec![
            "pvfsd".to_string(),
            "localhost".to_string(),
        ])
        .map_err(|e| format!("nettls: rcgen: {e}"))?;
        std::fs::create_dir_all(&dir).map_err(|e| format!("nettls: mkdir: {e}"))?;
        std::fs::write(&cert_path, ck.cert.pem()).map_err(|e| format!("nettls: write cert: {e}"))?;
        write_secret(&key_path, ck.key_pair.serialize_pem().as_bytes())?;
    }

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = rustls_pemfile::certs(
        &mut BufReader::new(
            std::fs::File::open(&cert_path).map_err(|e| format!("nettls: read cert: {e}"))?,
        ),
    )
    .collect::<Result<_, _>>()
    .map_err(|e| format!("nettls: parse cert: {e}"))?;
    let pin = match certs.first() {
        Some(c) => blake3::hash(c.as_ref()).to_hex().to_string(),
        None => return Err("nettls: no certificate found".into()),
    };
    // For scripts (the smoke suite, provisioning): the pin next to the cert.
    std::fs::write(dir.join("pin"), format!("{pin}\n"))
        .map_err(|e| format!("nettls: write pin: {e}"))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(
        std::fs::File::open(&key_path).map_err(|e| format!("nettls: read key: {e}"))?,
    ))
    .map_err(|e| format!("nettls: parse key: {e}"))?
    .ok_or("nettls: no private key found")?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("nettls: config: {e}"))?;
    Ok(NetTls {
        config: Arc::new(config),
        pin,
    })
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
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_reload_keeps_the_pin() {
        let tmp = tempfile::tempdir().unwrap();
        let a = load_or_generate(tmp.path()).unwrap();
        let b = load_or_generate(tmp.path()).unwrap();
        assert_eq!(a.pin, b.pin, "pin is stable across reloads");
        assert_eq!(a.pin.len(), 64);
        let on_disk = std::fs::read_to_string(nettls_dir(tmp.path()).join("pin")).unwrap();
        assert_eq!(on_disk.trim(), a.pin);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(nettls_dir(tmp.path()).join("key.pem"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key is 0600");
        }
    }
}
