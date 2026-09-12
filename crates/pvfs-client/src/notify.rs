//! D142 — the fleet tells a person when something changes (PVOS D83 §4.2,
//! piece 2).
//!
//! Everything is already observed (D131) and acted on (D135) in the owner's
//! `fleet-health.json`; this is the last metre. The owner POSTs a small JSON
//! event to a webhook — Home Assistant first — on TRANSITIONS only: a peer
//! going down, coming back, a `start` sent, a job's error appearing, and a
//! daily heartbeat so a silent owner is noticed by its absence. Transitions
//! only is the hysteresis D83 asked for; the two-miss rule supplies it.
//!
//! Transport is `curl` (the owner is a Linux box that has it), body on stdin,
//! ten-second timeout. A failure to notify is logged and never fails the
//! health pass. `PVFS_NOTIFY_CMD` replaces the command for tests.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use pvfs_core::PvfsError;

use crate::health::FleetHealth;

const FILE: &str = "notify";
const STATE_FILE: &str = "notify-state.json";
/// One heartbeat a day: enough for "the owner has gone quiet" to mean
/// something, not enough to be noise.
pub const HEARTBEAT_EVERY_MS: u64 = 24 * 3600 * 1000;
pub const FORMATS: [&str; 5] = ["ha", "json", "slack", "discord", "ntfy"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notify {
    pub url: String,
    pub format: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub last_heartbeat_ms: u64,
}

/// One thing worth saying. `event` is one of `peer_down`, `peer_up`,
/// `supervise`, `job_error`, `heartbeat`, `test`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub event: String,
    pub at_ms: u64,
    pub peer: Option<String>,
    pub addr: Option<String>,
    pub since_ms: Option<u64>,
    pub detail: Option<String>,
    pub up: u32,
    pub down: u32,
}

pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE)
}

pub fn load(data_dir: &Path) -> Result<Option<Notify>, PvfsError> {
    let p = path(data_dir);
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(PvfsError::io("read notify", e)),
    };
    serde_json::from_str(&text).map(Some).map_err(|e| PvfsError::BadInput {
        field: "notify".into(),
        reason: format!("unreadable ({e}) — `pvfs fleet notify --off` and set it again"),
    })
}

pub fn set(data_dir: &Path, url: &str, format: &str) -> Result<Notify, PvfsError> {
    if !FORMATS.contains(&format) {
        return Err(PvfsError::BadInput {
            field: "format".into(),
            reason: format!("{format} is not one of {}", FORMATS.join(", ")),
        });
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(PvfsError::BadInput { field: "url".into(), reason: "a webhook is an http(s) URL".into() });
    }
    let n = Notify { url: url.to_string(), format: format.to_string() };
    let text = serde_json::to_string_pretty(&n).map_err(|e| PvfsError::BadInput { field: "notify".into(), reason: e.to_string() })?;
    std::fs::write(path(data_dir), text).map_err(|e| PvfsError::io("write notify", e))?;
    Ok(n)
}

/// Returns whether anything was configured.
pub fn clear(data_dir: &Path) -> Result<bool, PvfsError> {
    match std::fs::remove_file(path(data_dir)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(PvfsError::io("remove notify", e)),
    }
}

fn load_state(data_dir: &Path) -> State {
    std::fs::read_to_string(data_dir.join(STATE_FILE))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(data_dir: &Path, st: &State) {
    if let Ok(text) = serde_json::to_string(st) {
        let _ = std::fs::write(data_dir.join(STATE_FILE), text);
    }
}

fn short(pin: &str) -> String {
    pin.chars().take(8).collect()
}

fn counts(rec: &FleetHealth) -> (u32, u32) {
    let down = rec.peers.values().filter(|r| r.is_down()).count() as u32;
    (rec.peers.len() as u32 - down, down)
}

/// What changed between the last record and this one — each thing once.
///
/// `prev` is `None` on the very first poll: nothing is a transition then,
/// except a peer that is ALREADY down (that is worth one message).
pub fn transitions(prev: Option<&FleetHealth>, next: &FleetHealth, now_ms: u64) -> Vec<Event> {
    let (up, down) = counts(next);
    let mut out = Vec::new();
    let base = |event: &str, pin: &str, r: &crate::health::PeerRecord| Event {
        event: event.into(),
        at_ms: now_ms,
        peer: Some(short(pin)),
        addr: Some(r.addr.clone()),
        since_ms: None,
        detail: None,
        up,
        down,
    };
    for (pin, r) in &next.peers {
        let p = prev.and_then(|p| p.peers.get(pin));
        let was_down = p.is_some_and(|p| p.is_down());
        if r.is_down() && !was_down {
            let mut e = base("peer_down", pin, r);
            e.since_ms = r.unreachable_since_ms;
            e.detail = r.last.error.clone();
            out.push(e);
        }
        if !r.is_down() && r.misses == 0 && was_down {
            let mut e = base("peer_up", pin, r);
            let since = p.and_then(|p| p.unreachable_since_ms);
            e.since_ms = since;
            e.detail = since.map(|s| format!("was down {} min", now_ms.saturating_sub(s) / 60_000));
            out.push(e);
        }
        let seen = p.map_or(0, |p| p.actions.len());
        for a in r.actions.iter().skip(seen) {
            let mut e = base("supervise", pin, r);
            e.since_ms = Some(a.at_ms);
            e.detail = Some(format!("{} → rc {}: {}", a.verb, a.rc, a.output.trim()));
            out.push(e);
        }
        if r.last.reachable {
            for j in r.last.jobs.iter().filter(|j| j.last_error.is_some()) {
                let before = p.and_then(|p| p.last.jobs.iter().find(|pj| pj.name == j.name)).and_then(|pj| pj.last_error.clone());
                if before.is_none() {
                    let mut e = base("job_error", pin, r);
                    e.detail = Some(format!("{}: {}", j.name, j.last_error.clone().unwrap_or_default()));
                    out.push(e);
                }
            }
        }
    }
    out
}

/// The daily heartbeat, if it is due.
pub fn heartbeat(state: &mut State, next: &FleetHealth, now_ms: u64) -> Option<Event> {
    // Never sent one (a fresh configuration): say hello on this poll, so the
    // person sees the channel work without waiting a day.
    let due = state.last_heartbeat_ms == 0 || now_ms.saturating_sub(state.last_heartbeat_ms) >= HEARTBEAT_EVERY_MS;
    if !due {
        return None;
    }
    state.last_heartbeat_ms = now_ms;
    let (up, down) = counts(next);
    let peers: Vec<String> = next
        .peers
        .iter()
        .map(|(pin, r)| format!("{} {} {}", short(pin), r.addr, if r.is_down() { "DOWN" } else { "up" }))
        .collect();
    Some(Event {
        event: "heartbeat".into(),
        at_ms: now_ms,
        peer: None,
        addr: None,
        since_ms: None,
        detail: Some(peers.join("; ")),
        up,
        down,
    })
}

pub fn test_event(now_ms: u64) -> Event {
    Event {
        event: "test".into(),
        at_ms: now_ms,
        peer: None,
        addr: None,
        since_ms: None,
        detail: Some("pvfs fleet notify --test".into()),
        up: 0,
        down: 0,
    }
}

/// One line a person can read, for the chat-shaped formats.
pub fn line(ev: &Event) -> String {
    let who = match (&ev.peer, &ev.addr) {
        (Some(p), Some(a)) => format!(" {p} ({a})"),
        _ => String::new(),
    };
    let detail = ev.detail.as_deref().map(|d| format!(" — {d}")).unwrap_or_default();
    format!("PVFS {}{who}{detail} [{} up, {} down]", ev.event, ev.up, ev.down)
}

/// The request body and its headers for the configured format.
pub fn payload(n: &Notify, ev: &Event) -> (String, Vec<(String, String)>) {
    let json = |v: serde_json::Value| (v.to_string(), vec![("Content-Type".to_string(), "application/json".to_string())]);
    match n.format.as_str() {
        "slack" => json(serde_json::json!({ "text": line(ev) })),
        "discord" => json(serde_json::json!({ "content": line(ev) })),
        "ntfy" => (
            line(ev),
            vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Title".to_string(), format!("PVFS {}", ev.event)),
            ],
        ),
        _ => json(serde_json::to_value(ev).unwrap_or(serde_json::Value::Null)),
    }
}

/// POST one event. `PVFS_NOTIFY_CMD` names the program (default `curl`);
/// it gets curl's arguments and the body on stdin.
pub fn send(n: &Notify, ev: &Event) -> Result<(), PvfsError> {
    use std::io::Write;
    let (body, headers) = payload(n, ev);
    let cmd = std::env::var("PVFS_NOTIFY_CMD").unwrap_or_else(|_| "curl".into());
    let mut c = std::process::Command::new(&cmd);
    c.args(["-fsS", "--max-time", "10", "-X", "POST"]);
    for (k, v) in &headers {
        c.arg("-H").arg(format!("{k}: {v}"));
    }
    c.args(["--data-binary", "@-"]).arg(&n.url);
    c.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = c.spawn().map_err(|e| PvfsError::io(&format!("run {cmd}"), e))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(body.as_bytes()).map_err(|e| PvfsError::io("notify body", e))?;
    }
    let out = child.wait_with_output().map_err(|e| PvfsError::io("notify wait", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(PvfsError::BadInput {
            field: "notify".into(),
            reason: format!(
                "{cmd} exited {}: {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        })
    }
}

/// The health job's call: everything that changed since `prev`, plus the
/// heartbeat if due, each sent once. Returns one line per event for the
/// daemon's log — sent or failed — and never fails the pass itself.
pub fn emit(data_dir: &Path, prev: Option<&FleetHealth>, next: &FleetHealth, now_ms: u64) -> Result<Vec<String>, PvfsError> {
    let Some(n) = load(data_dir)? else { return Ok(Vec::new()) };
    let mut state = load_state(data_dir);
    let mut events = transitions(prev, next, now_ms);
    if let Some(h) = heartbeat(&mut state, next, now_ms) {
        events.push(h);
    }
    let mut lines = Vec::new();
    for ev in &events {
        let what = format!("{}{}", ev.event, ev.peer.as_deref().map(|p| format!(" {p}")).unwrap_or_default());
        match send(&n, ev) {
            Ok(()) => lines.push(format!("{what} → sent")),
            Err(e) => lines.push(format!("{what} → NOT sent: {e}")),
        }
    }
    save_state(data_dir, &state);
    Ok(lines)
}
