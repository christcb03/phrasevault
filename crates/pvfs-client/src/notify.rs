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

use std::collections::BTreeMap;
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
    /// Names for the boxes, by host (the address without the port): the
    /// person reads "the NAS", not a pin and a port. `pvfs fleet notify
    /// --label 192.168.1.237=NAS`.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

impl Notify {
    /// The name a person knows a peer by, or its address when unnamed.
    pub fn name_for(&self, addr: &str) -> String {
        let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
        self.labels.get(host).cloned().unwrap_or_else(|| addr.to_string())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub last_heartbeat_ms: u64,
    /// Job errors already reported, `pin/job` → the error text, so a
    /// persisting error is said once and a changed one again.
    #[serde(default)]
    pub reported_job_errors: BTreeMap<String, String>,
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
    let labels = load(data_dir)?.map(|n| n.labels).unwrap_or_default();
    set_with_labels(data_dir, url, format, labels)
}

/// Add or replace names (`host=name`); the URL and format stay.
pub fn label(data_dir: &Path, pairs: &[(String, String)]) -> Result<Notify, PvfsError> {
    let Some(mut n) = load(data_dir)? else {
        return Err(PvfsError::BadInput { field: "notify".into(), reason: "set the webhook first: pvfs fleet notify <url>".into() });
    };
    for (host, name) in pairs {
        n.labels.insert(host.clone(), name.clone());
    }
    let labels = n.labels.clone();
    set_with_labels(data_dir, &n.url, &n.format, labels)
}

fn set_with_labels(data_dir: &Path, url: &str, format: &str, labels: BTreeMap<String, String>) -> Result<Notify, PvfsError> {
    if !FORMATS.contains(&format) {
        return Err(PvfsError::BadInput {
            field: "format".into(),
            reason: format!("{format} is not one of {}", FORMATS.join(", ")),
        });
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(PvfsError::BadInput { field: "url".into(), reason: "a webhook is an http(s) URL".into() });
    }
    let n = Notify { url: url.to_string(), format: format.to_string(), labels };
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
        // Job errors are handled by `job_errors` (they need memory across
        // polls: a restart's "connection refused" clears itself in a minute
        // and must not wake anyone).
    }
    out
}

/// A job's error is reported when it has been there for TWO consecutive
/// polls (four minutes — a daemon restart's transient never lasts that
/// long), once, and again only if the text changes; the memory clears when
/// the error does.
pub fn job_errors(state: &mut State, prev: Option<&FleetHealth>, next: &FleetHealth, now_ms: u64) -> Vec<Event> {
    let (up, down) = counts(next);
    let mut out = Vec::new();
    let mut live: BTreeMap<String, String> = BTreeMap::new();
    for (pin, r) in &next.peers {
        if !r.last.reachable {
            continue;
        }
        let p = prev.and_then(|p| p.peers.get(pin));
        for j in r.last.jobs.iter().filter(|j| j.last_error.is_some()) {
            let err = j.last_error.clone().unwrap_or_default();
            let key = format!("{}/{}", short(pin), j.name);
            let before = p.and_then(|p| p.last.jobs.iter().find(|pj| pj.name == j.name)).and_then(|pj| pj.last_error.clone());
            if before.as_deref() != Some(err.as_str()) {
                continue; // first sighting, or a different error: wait one more poll
            }
            live.insert(key.clone(), err.clone());
            if state.reported_job_errors.get(&key) == Some(&err) {
                continue; // already said
            }
            out.push(Event {
                event: "job_error".into(),
                at_ms: now_ms,
                peer: Some(short(pin)),
                addr: Some(r.addr.clone()),
                since_ms: None,
                detail: Some(format!("{}: {err}", j.name)),
                up,
                down,
            });
            state.reported_job_errors.insert(key, err);
        }
    }
    state.reported_job_errors.retain(|k, _| live.contains_key(k));
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

fn minutes(ms: u64) -> String {
    let m = ms / 60_000;
    if m < 1 { "under a minute".into() } else if m == 1 { "1 minute".into() } else if m < 120 { format!("{m} minutes") } else { format!("{} hours", m / 60) }
}

/// `critical` wakes a person, `warning` is worth a look, `info` is news.
pub fn severity(ev: &Event) -> &'static str {
    match ev.event.as_str() {
        "peer_down" => "critical",
        "supervise" => if ev.detail.as_deref().is_some_and(|d| d.contains("rc 0")) { "warning" } else { "critical" },
        "job_error" => "warning",
        _ => "info",
    }
}

/// The sentence a person reads. Names the box (by label when there is
/// one), says what happened, and what was done or is expected.
pub fn summary(n: &Notify, ev: &Event) -> String {
    let who = ev.addr.as_deref().map(|a| n.name_for(a)).unwrap_or_else(|| "a peer".into());
    match ev.event.as_str() {
        "peer_down" => {
            let since = ev.since_ms.map(|s| format!(" It has not answered for {}.", minutes(ev.at_ms.saturating_sub(s)))).unwrap_or_default();
            let why = ev.detail.as_deref().map(|d| format!(" Last error: {d}.")).unwrap_or_default();
            format!("{who} is down.{since}{why} The owner will try to restart it if it supervises that box.")
        }
        "supervise" => {
            let d = ev.detail.as_deref().unwrap_or("");
            if d.contains("rc 0") {
                format!("The owner restarted PVFS on {who} ({}).", d.split(": ").last().unwrap_or(d).trim())
            } else {
                format!("The owner tried to restart PVFS on {who} and it FAILED ({d}). It needs a hand.")
            }
        }
        "peer_up" => {
            let how_long = ev.since_ms.map(|s| format!(" after {} down", minutes(ev.at_ms.saturating_sub(s)))).unwrap_or_default();
            format!("{who} is back{how_long}.")
        }
        "job_error" => {
            let (job, err) = ev.detail.as_deref().and_then(|d| d.split_once(": ")).unwrap_or(("a job", ""));
            format!("On {who}, the {job} job reports an error: {err}")
        }
        "heartbeat" => {
            let peers = ev.detail.as_deref().unwrap_or("");
            format!("Daily check-in: {} up, {} down. {}", ev.up, ev.down, peers)
        }
        "test" => "PVFS can reach this webhook — notifications are working.".into(),
        other => format!("{other} on {who}"),
    }
}

/// One line a person can read, for the chat-shaped formats.
pub fn line(n: &Notify, ev: &Event) -> String {
    format!("PVFS: {}", summary(n, ev))
}

/// The request body and its headers for the configured format. The JSON
/// shapes carry the event's fields plus `summary` and `severity`, and the
/// peer's `name` when it has a label.
pub fn payload(n: &Notify, ev: &Event) -> (String, Vec<(String, String)>) {
    let json = |v: serde_json::Value| (v.to_string(), vec![("Content-Type".to_string(), "application/json".to_string())]);
    match n.format.as_str() {
        "slack" => json(serde_json::json!({ "text": line(n, ev) })),
        "discord" => json(serde_json::json!({ "content": line(n, ev) })),
        "ntfy" => (
            summary(n, ev),
            vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("Title".to_string(), format!("PVFS {}", ev.event)),
            ],
        ),
        _ => {
            let mut v = serde_json::to_value(ev).unwrap_or(serde_json::Value::Null);
            if let serde_json::Value::Object(m) = &mut v {
                m.insert("summary".into(), serde_json::Value::String(summary(n, ev)));
                m.insert("severity".into(), serde_json::Value::String(severity(ev).into()));
                m.insert("name".into(), serde_json::Value::String(ev.addr.as_deref().map(|a| n.name_for(a)).unwrap_or_default()));
            }
            json(v)
        }
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
    events.extend(job_errors(&mut state, prev, next, now_ms));
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
