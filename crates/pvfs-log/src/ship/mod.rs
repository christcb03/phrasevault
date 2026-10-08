//! Log destinations (PVOS D222d): every record the logger emits is offered
//! to every enabled destination whose filter takes it; each has a spool on
//! disk and a sender thread. Built in the daemons only (`ship` feature).
//!
//! ```text
//! pvfs_log::ship::install(&config, &opts)      // pvosd, from its forest record
//! pvfs_log::ship::watch_file(state_dir, …)     // pvfsd, from log-destinations.json
//! ```

mod config;
pub mod format;
mod gelf;
mod http;
mod sender;
mod spool;
mod syslog;
mod tls;

pub use config::{config_path, Destination, HttpFormat, Kind, ShipConfig, SyslogFormat, SyslogTransport, TlsSettings};
pub use http::Url;
pub use sender::Health;
pub use spool::Spool;
pub use tls::parse_pin;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, RwLock};

use crate::{Record, Severity};

/// How long a destination fails before it is said to be failing.
pub const FAILING_AFTER_MS: u64 = 15 * 60 * 1000;

/// What a process installs its destinations with.
#[derive(Clone, Debug)]
pub struct InstallOpts {
    /// Spools live in `<state_dir>/<destination name>/`.
    pub state_dir: PathBuf,
    /// `PVFS` or `PVOS` (CEF's product).
    pub product: String,
    pub version: String,
    /// Keyed pseudonyms (D222 decision 3d); without one, `actor`/`content`
    /// values are taken out at `minimal`.
    pub pseudonym_key: Option<[u8; 32]>,
    /// Tokens by destination name (PVFS reads them from each `secret` file;
    /// PVOS from its keychain).
    pub secrets: HashMap<String, String>,
    pub failing_after_ms: u64,
}

impl InstallOpts {
    pub fn new(state_dir: &Path, product: &str, version: &str) -> InstallOpts {
        InstallOpts {
            state_dir: state_dir.to_path_buf(),
            product: product.into(),
            version: version.into(),
            pseudonym_key: None,
            secrets: HashMap::new(),
            failing_after_ms: FAILING_AFTER_MS,
        }
    }
}

static ACTIVE: RwLock<Vec<Arc<sender::Dest>>> = RwLock::new(Vec::new());

fn now_ms() -> u64 {
    crate::time::now_ms()
}

/// Replace this process's destinations. Returns the problems found; a
/// destination with a problem is left out, the rest run.
pub fn install(cfg: &ShipConfig, opts: &InstallOpts) -> Vec<String> {
    let mut problems = Vec::new();
    let mut fresh = Vec::new();
    for d in &cfg.destinations {
        let p = d.problems();
        if !p.is_empty() {
            problems.extend(p);
            continue;
        }
        if !d.enabled {
            continue;
        }
        let dir = opts.state_dir.join(&d.name);
        let spool = match Spool::open(&dir, d.spool_mb.max(1) * (1 << 20)) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("{}: spool {}: {e}", d.name, dir.display()));
                continue;
            }
        };
        fresh.push(Arc::new(sender::Dest {
            cfg: d.clone(),
            token: opts.secrets.get(&d.name).cloned(),
            key: opts.pseudonym_key,
            product: opts.product.clone(),
            version: opts.version.clone(),
            spool: Mutex::new(spool),
            health: Mutex::new(Health::default()),
            stop: std::sync::atomic::AtomicBool::new(false),
            started_ms: now_ms(),
            failing_after_ms: opts.failing_after_ms,
        }));
    }
    let old = {
        let mut a = ACTIVE.write().unwrap_or_else(|p| p.into_inner());
        std::mem::replace(&mut *a, fresh.clone())
    };
    for d in old {
        d.stop.store(true, Ordering::Relaxed);
    }
    for d in fresh {
        let name = format!("pvlog-{}", d.cfg.name);
        let _ = std::thread::Builder::new().name(name).spawn(move || sender::run(d));
    }
    problems
}

/// Stop every destination (their spools stay on disk).
pub fn uninstall() {
    install(&ShipConfig::default(), &InstallOpts::new(Path::new("/nonexistent"), "", ""));
}

/// Offered every record the logger emits.
pub(crate) fn offer(rec: &Record) {
    let a = ACTIVE.read().unwrap_or_else(|p| p.into_inner());
    for d in a.iter() {
        d.offer(rec);
    }
}

/// Each destination's name and health.
pub fn health() -> Vec<(String, Health)> {
    let a = ACTIVE.read().unwrap_or_else(|p| p.into_inner());
    a.iter().map(|d| (d.cfg.name.clone(), d.health())).collect()
}

/// One line for a census or a status report: `name: sent N, queued B bytes,
/// dropped D[, failing since …: error]`.
pub fn health_line() -> String {
    health()
        .into_iter()
        .map(|(n, h)| {
            let mut s = format!("{n}: sent {}, queued {} bytes, dropped {}", h.sent, h.pending_bytes, h.dropped);
            if h.failing_reported {
                s.push_str(&format!(", FAILING: {}", h.last_error.unwrap_or_default()));
            }
            s
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Send one `pvfs.log.test` record to `d` now, without its spool (`pvfs log
/// destinations test`, Settings' "Send test event").
pub fn test_send(d: &Destination, opts: &InstallOpts) -> Result<(), String> {
    let p = d.problems();
    if !p.is_empty() {
        return Err(p.join("; "));
    }
    let mut r = Record::now(Severity::Notice, "pvfs.log.test", format!("pvfs-log: a test event for destination {}", d.name));
    r.fields.push(crate::ToField::to_field(d.name.as_str(), "destination"));
    let dest = sender::Dest {
        cfg: d.clone(),
        token: opts.secrets.get(&d.name).cloned(),
        key: opts.pseudonym_key,
        product: opts.product.clone(),
        version: opts.version.clone(),
        spool: Mutex::new(Spool::open(&std::env::temp_dir().join(format!("pvlog-test-{}", std::process::id())), 1 << 20).map_err(|e| e.to_string())?),
        health: Mutex::new(Health::default()),
        stop: std::sync::atomic::AtomicBool::new(true),
        started_ms: now_ms(),
        failing_after_ms: opts.failing_after_ms,
    };
    let out = sender::deliver(&dest, &[r]);
    let _ = std::fs::remove_dir_all(std::env::temp_dir().join(format!("pvlog-test-{}", std::process::id())));
    out
}

type HealthHook = Box<dyn Fn(&str, bool, &str) + Send + Sync>;
static HOOK: std::sync::OnceLock<HealthHook> = std::sync::OnceLock::new();

/// Called with (destination, delivering again?, error) when a destination
/// starts failing (after [`FAILING_AFTER_MS`]) and when it recovers: pvosd
/// posts a notification. Set once per process.
pub fn on_health_change(f: impl Fn(&str, bool, &str) + Send + Sync + 'static) {
    let _ = HOOK.set(Box::new(f));
}

pub(crate) fn note_failing(name: &str, error: &str, for_ms: u64) {
    let mins = for_ms / 60_000;
    crate::pv_warn!("pvfs.log.destination_failing", destination = name, error = crate::content(error), minutes = mins;
        "pvfs-log: log destination {name} has failed for {mins} min: {error}");
    if let Some(h) = HOOK.get() {
        h(name, false, error);
    }
}

pub(crate) fn note_recovered(name: &str) {
    crate::pv_notice!("pvfs.log.destination_recovered", destination = name;
        "pvfs-log: log destination {name} is delivering again");
    if let Some(h) = HOOK.get() {
        h(name, true, "");
    }
}

/// PVFS (decision 11): read the destinations file and its secret files,
/// then install. A missing file is no destinations.
pub fn install_from_file(path: &Path, state_dir: &Path, product: &str, version: &str) -> Result<Vec<String>, String> {
    let cfg = match std::fs::read_to_string(path) {
        Ok(t) => ShipConfig::parse(&t)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ShipConfig::default(),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut opts = InstallOpts::new(state_dir, product, version);
    let mut problems = Vec::new();
    for d in &cfg.destinations {
        if let Some(f) = &d.secret {
            match std::fs::read_to_string(resolve(path, f)) {
                Ok(t) => {
                    opts.secrets.insert(d.name.clone(), t.trim().to_string());
                }
                Err(e) => problems.push(format!("{}: secret {f}: {e}", d.name)),
            }
        }
    }
    if let Some(k) = &cfg.pseudonym_key_file {
        match crate::read_key(&resolve(path, k)) {
            Ok(k) => opts.pseudonym_key = Some(k),
            Err(e) => problems.push(format!("pseudonym_key_file: {e}")),
        }
    }
    problems.extend(install(&cfg, &opts));
    Ok(problems)
}

/// A relative path in the file is relative to the file's own directory.
fn resolve(file: &Path, p: &str) -> PathBuf {
    let p = PathBuf::from(p);
    if p.is_absolute() {
        p
    } else {
        file.parent().unwrap_or(Path::new(".")).join(p)
    }
}

/// PVFS (decision 11): install from [`config_path`] now, and again within
/// 30 s of the file changing. Problems are logged.
pub fn watch_file(state_dir: PathBuf, product: &'static str, version: String) {
    let path = config_path();
    let apply = move |path: &Path| match install_from_file(path, &state_dir, product, &version) {
        Ok(problems) => {
            let n = ACTIVE.read().map(|a| a.len()).unwrap_or(0);
            if n > 0 || !problems.is_empty() {
                crate::pv_notice!("pvfs.log.destinations_loaded", file = crate::content(path.display()), destinations = n;
                    "pvfs-log: {n} log destination(s) from {}", path.display());
            }
            for p in problems {
                crate::pv_warn!("pvfs.log.destination_problem", problem = crate::content(&p);
                    "pvfs-log: log destination left out: {p}");
            }
        }
        Err(e) => {
            crate::pv_warn!("pvfs.log.destination_problem", problem = crate::content(&e);
                "pvfs-log: log destinations not loaded (the ones running are kept): {e}");
        }
    };
    let stamp = |p: &Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last = stamp(&path);
    apply(&path);
    let _ = std::thread::Builder::new().name("pvlog-watch".into()).spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        let now = stamp(&path);
        if now != last {
            last = now;
            apply(&path);
        }
    });
}

/// `whois` (decision 14): which of `candidates` (as the log shows them:
/// `key:<hex>`, a member's name) has this pseudonym under this key.
pub fn whois<'a>(key: &[u8; 32], pseudonym: &str, candidates: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
    let tag = pseudonym.chars().next().unwrap_or('a');
    candidates
        .into_iter()
        .filter(|c| crate::pseudonym(key, tag, c) == pseudonym)
        .collect()
}

#[cfg(test)]
mod tests;
