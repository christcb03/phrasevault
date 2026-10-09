//! PVOS D226 — this Mac's log destinations, for the app's Settings → Logging
//! and `pvfs-companion log`: the same file the `pvfs` CLI uses
//! (`~/.config/pvfs/log-destinations.json`), with tokens in the Keychain as
//! `keychain:<name>` (service [`LOG_KEYCHAIN_SERVICE`]). The agent ships its
//! records to them (`serve`, through `pvfs_log::ship::watch_file`).

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use pvfs_log::ship::{Destination, InstallOpts, ShipConfig};
use serde::Serialize;

use crate::keychain::SecretStore;

/// The Keychain service the log tokens are filed under.
pub const LOG_KEYCHAIN_SERVICE: &str = "pvfs-companion-log";

/// One destination as the app lists it — never its token.
#[derive(Debug, Serialize)]
pub struct DestinationView {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    /// The URL, or host:port.
    pub target: String,
    pub privacy: String,
    pub min_severity: String,
    /// Empty = all.
    pub categories: Vec<String>,
    /// `keychain`, `file` or `none`.
    pub token: String,
    pub enabled: bool,
    pub problems: Vec<String>,
}

pub fn load(path: &Path) -> Result<ShipConfig, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => ShipConfig::parse(&t),
        // A new file is version 1 (the derived default is 0, which no reader takes).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ShipConfig { v: 1, ..Default::default() }),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn save(path: &Path, cfg: &ShipConfig) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, cfg.to_text()).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn list(path: &Path) -> Result<Vec<DestinationView>, String> {
    Ok(load(path)?
        .destinations
        .iter()
        .map(|d| DestinationView {
            name: d.name.clone(),
            kind: d.kind.as_str().to_string(),
            target: d.url.clone().or_else(|| d.address.clone()).unwrap_or_default(),
            privacy: d.privacy.clone(),
            min_severity: d.min_severity.clone(),
            categories: d.categories.clone(),
            token: match &d.secret {
                Some(s) if s.starts_with("keychain:") => "keychain".into(),
                Some(_) => "file".into(),
                None => "none".into(),
            },
            enabled: d.enabled,
            problems: d.problems(),
        })
        .collect())
}

/// Add `d` (its `secret` is set here): the token, if any, goes to `store`
/// under the destination's name, and a pseudonym key (0600) is made beside
/// the file if there is none. Refused if the name is taken or the
/// destination has problems — then nothing is written.
pub fn add(path: &Path, store: &dyn SecretStore, mut d: Destination, token: &str) -> Result<(), String> {
    let mut cfg = load(path)?;
    if cfg.destinations.iter().any(|x| x.name == d.name) {
        return Err(format!("there is already a destination named {}", d.name));
    }
    d.secret = None;
    let p = d.problems();
    if !p.is_empty() {
        return Err(p.join("; "));
    }
    let token = token.trim();
    if !token.is_empty() {
        store.set(&d.name, token.as_bytes()).map_err(|e| format!("the Keychain: {e}"))?;
        d.secret = Some(format!("keychain:{}", d.name));
    }
    if cfg.pseudonym_key_file.is_none() {
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let mut key = [0u8; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut key))
            .map_err(|e| format!("a pseudonym key: {e}"))?;
        let f = dir.join("pseudonym.key");
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&f)
            .map_err(|e| format!("{}: {e}", f.display()))?;
        writeln!(out, "{}", hex::encode(key)).map_err(|e| format!("{}: {e}", f.display()))?;
        cfg.pseudonym_key_file = Some("pseudonym.key".into());
    }
    cfg.destinations.push(d);
    save(path, &cfg)
}

/// Take `name` out of the file, and its token out of `store` (a missing
/// item is fine).
pub fn remove(path: &Path, store: &dyn SecretStore, name: &str) -> Result<(), String> {
    let mut cfg = load(path)?;
    let before = cfg.destinations.len();
    let keychain = cfg.destinations.iter().any(|d| d.name == name && d.secret.as_deref().is_some_and(|s| s.starts_with("keychain:")));
    cfg.destinations.retain(|d| d.name != name);
    if cfg.destinations.len() == before {
        return Err(format!("no destination named {name}"));
    }
    save(path, &cfg)?;
    if keychain {
        let _ = store.delete(name);
    }
    Ok(())
}

/// Send one test event to `name` now, with its token from `store` (or its
/// file).
pub fn test(path: &Path, store: &dyn SecretStore, name: &str, version: &str) -> Result<(), String> {
    let cfg = load(path)?;
    let d = cfg.destinations.iter().find(|d| d.name == name).ok_or_else(|| format!("no destination named {name}"))?;
    let mut opts = InstallOpts::new(&std::env::temp_dir(), "PVFS", version);
    if let Some(s) = &d.secret {
        let token = match s.strip_prefix("keychain:") {
            Some(item) => {
                let v = store.get(item).map_err(|e| format!("the Keychain: {e}"))?;
                String::from_utf8_lossy(&v).trim().to_string()
            }
            None => pvfs_log::ship::read_secret(path, s)?,
        };
        opts.secrets.insert(d.name.clone(), token);
    }
    if let Some(k) = &cfg.pseudonym_key_file {
        let p = path.parent().unwrap_or(Path::new(".")).join(k);
        opts.pseudonym_key = pvfs_log::read_key(&p).ok();
    }
    pvfs_log::ship::test_send(d, &opts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::MemoryStore;
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;

    fn loki(name: &str, url: &str) -> Destination {
        let cfg = ShipConfig::parse(&format!(r#"{{"v":1,"destinations":[{{"name":"{name}","type":"loki","url":"{url}"}}]}}"#)).unwrap();
        cfg.destinations[0].clone()
    }

    /// One HTTP request answered 204; returns (request line + headers, body).
    fn receiver() -> (String, std::thread::JoinHandle<(String, String)>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                r.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
                head.push_str(&line);
            }
            let mut body = vec![0u8; len];
            r.read_exact(&mut body).unwrap();
            let mut s = s;
            s.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").unwrap();
            (head, String::from_utf8_lossy(&body).to_string())
        });
        (url, t)
    }

    #[test]
    fn add_list_test_remove_with_the_token_in_the_store() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("log-destinations.json");
        let store = MemoryStore::new();
        let (url, t) = receiver();
        add(&path, &store, loki("mac", &url), " s3cret ").unwrap();
        // The file names the Keychain item, never the token; the key is 0600.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("keychain:mac") && !text.contains("s3cret"), "{text}");
        assert_eq!(&*store.get("mac").unwrap(), b"s3cret");
        let mode = std::fs::metadata(d.path().join("pseudonym.key")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // The listing says where the token is, not what it is.
        let v = list(&path).unwrap();
        assert_eq!((v[0].name.as_str(), v[0].kind.as_str(), v[0].token.as_str()), ("mac", "loki", "keychain"));
        assert!(serde_json::to_string(&v).unwrap().contains("\"type\":\"loki\""));
        // Taken names and bad destinations are refused, and write nothing.
        assert!(add(&path, &store, loki("mac", &url), "").unwrap_err().contains("already"));
        assert!(add(&path, &store, loki("bad name!", &url), "").is_err());
        assert_eq!(list(&path).unwrap().len(), 1);
        // The test event goes out with the token from the store.
        test(&path, &store, "mac", "1.4-test").unwrap();
        let (head, body) = t.join().unwrap();
        assert!(head.starts_with("POST /loki/api/v1/push"), "{head}");
        assert!(head.contains("Bearer s3cret") || head.contains("s3cret"), "{head}");
        assert!(body.contains("pvfs.log.test"), "{body}");
        // Removed: out of the file and out of the store.
        remove(&path, &store, "mac").unwrap();
        assert!(list(&path).unwrap().is_empty());
        assert!(store.get("mac").is_err());
        assert!(remove(&path, &store, "mac").unwrap_err().contains("no destination"));
    }

    use std::os::unix::fs::PermissionsExt;
}
