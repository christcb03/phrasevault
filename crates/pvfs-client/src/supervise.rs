//! D135 (PVOS D83 §8, preference 2) — the owner acts on silence. D131
//! observes; this module holds the one bounded action: when a supervised
//! peer has missed two polls, run `start` on it over an ssh key the peer
//! binds to one script (`pvfs-supervise.sh`) and nothing else. Never
//! `restart`: a daemon that is alive and working must not be killed by a
//! box that cannot see its progress (D83 §2). Backed off, recorded, and
//! reset the moment the peer answers again.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use pvfs_core::PvfsError;

use crate::health::{FleetHealth, PeerRecord};

const FILE: &str = "supervise";
const HEADER: &str = "pvfs-supervise 1";
/// First retry after a `start` that did not bring the peer back.
pub const BACKOFF_MIN_SECS: u64 = 600;
/// The cap the doubling stops at.
pub const BACKOFF_MAX_SECS: u64 = 7200;
/// How long one ssh round trip may take before it is abandoned.
const SSH_TIMEOUT_SECS: u64 = 90;
/// Actions kept per peer in the record.
const KEEP_ACTIONS: usize = 20;

/// One supervised peer: how the owner reaches its forced-command script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Channel {
    pub pin: String,
    /// `user@host` (an ssh destination; the port rides in `~/.ssh/config`
    /// or as `user@host` with `-p` unsupported on purpose — one line, one box).
    pub ssh: String,
    pub key: PathBuf,
}

/// One thing the owner did, as the record keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub at_ms: u64,
    pub verb: String,
    pub rc: i32,
    pub output: String,
}

/// `~/.ssh/pvfs-supervise` for the daemon's user.
pub fn default_key() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
    home.join(".ssh").join("pvfs-supervise")
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

pub fn load(data_dir: &Path) -> Result<Vec<Channel>, PvfsError> {
    let text = match std::fs::read_to_string(path(data_dir)) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(PvfsError::io("read supervise", e)),
    };
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(PvfsError::BadInput {
            field: "supervise".into(),
            reason: "unrecognized supervise file".into(),
        });
    }
    let mut out = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        let mut it = line.splitn(3, ' ');
        match (it.next(), it.next(), it.next()) {
            (Some(pin), Some(ssh), Some(key)) => out.push(Channel {
                pin: pin.into(),
                ssh: ssh.into(),
                key: PathBuf::from(key),
            }),
            _ => {
                return Err(PvfsError::BadInput {
                    field: "supervise".into(),
                    reason: format!("corrupt supervise line: {line:?}"),
                })
            }
        }
    }
    Ok(out)
}

fn save(data_dir: &Path, chans: &[Channel]) -> Result<(), PvfsError> {
    let mut text = String::from(HEADER);
    text.push('\n');
    for c in chans {
        text.push_str(&format!("{} {} {}\n", c.pin, c.ssh, c.key.display()));
    }
    pvfs_core::storage::atomic_overwrite(&path(data_dir), text.as_bytes())
}

/// Supervise `pin` through `ssh` with `key` (replaces an existing line).
pub fn set(data_dir: &Path, pin: &str, ssh: &str, key: &Path) -> Result<(), PvfsError> {
    let mut chans = load(data_dir)?;
    chans.retain(|c| c.pin != pin);
    chans.push(Channel {
        pin: pin.into(),
        ssh: ssh.into(),
        key: key.to_path_buf(),
    });
    save(data_dir, &chans)
}

pub fn unset(data_dir: &Path, pin: &str) -> Result<bool, PvfsError> {
    let mut chans = load(data_dir)?;
    let before = chans.len();
    chans.retain(|c| c.pin != pin);
    save(data_dir, &chans)?;
    Ok(chans.len() != before)
}

/// Run one verb of the peer's forced-command script; `(rc, output)`.
/// `PVFS_SSH` names the ssh binary (tests point it at a stand-in).
pub fn run_verb(ch: &Channel, verb: &str) -> (i32, String) {
    let ssh = std::env::var("PVFS_SSH").unwrap_or_else(|_| "ssh".into());
    let mut child = match std::process::Command::new(&ssh)
        .arg("-i")
        .arg(&ch.key)
        .args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"])
        .arg(&ch.ssh)
        .arg(verb)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (-1, format!("cannot run {ssh}: {e}")),
    };
    let started = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let out = child.wait_with_output().map(|o| {
                    let mut s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                    let e = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    if s.is_empty() {
                        s = e;
                    } else if !e.is_empty() {
                        s.push_str(" | ");
                        s.push_str(&e);
                    }
                    s
                });
                return (status.code().unwrap_or(-1), out.unwrap_or_default());
            }
            Ok(None) => {
                if started.elapsed().as_secs() > SSH_TIMEOUT_SECS {
                    let _ = child.kill();
                    return (-2, format!("ssh to {} gave no answer in {SSH_TIMEOUT_SECS}s", ch.ssh));
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            Err(e) => return (-1, e.to_string()),
        }
    }
}

/// Seconds to wait before the next `start` after `attempts` that did not
/// bring the peer back: 10 min, doubling, capped at 2 h.
pub fn backoff_secs(attempts: u32) -> u64 {
    let shift = attempts.saturating_sub(1).min(8);
    (BACKOFF_MIN_SECS << shift).min(BACKOFF_MAX_SECS)
}

fn due(rec: &PeerRecord, now_ms: u64) -> bool {
    match rec.actions.last() {
        None => true,
        Some(a) => now_ms >= a.at_ms + backoff_secs(rec.attempts) * 1000,
    }
}

/// For every peer that is DOWN and supervised and due: run `start`, record
/// it. Returns what was done this pass. The caller saves the record.
pub fn act_on_down(data_dir: &Path, record: &mut FleetHealth, now_ms: u64) -> Result<Vec<(String, Action)>, PvfsError> {
    let chans = load(data_dir)?;
    let mut done = Vec::new();
    for ch in chans {
        let Some(rec) = record.peers.get_mut(&ch.pin) else { continue };
        if !rec.is_down() || !due(rec, now_ms) {
            continue;
        }
        let (rc, output) = run_verb(&ch, "start");
        let action = Action {
            at_ms: now_ms,
            verb: "start".into(),
            rc,
            output: output.chars().take(400).collect(),
        };
        rec.attempts = rec.attempts.saturating_add(1);
        rec.actions.push(action.clone());
        if rec.actions.len() > KEEP_ACTIONS {
            let drop = rec.actions.len() - KEEP_ACTIONS;
            rec.actions.drain(..drop);
        }
        done.push((ch.pin.clone(), action));
    }
    Ok(done)
}
