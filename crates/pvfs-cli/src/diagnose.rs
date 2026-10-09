//! PVOS D230 — `pvfs diagnose`: one troubleshooting bundle for this box
//! and every box it knows. Each box's build, role and config, its clock
//! against this one's, its log level, jobs, mounts, stores, fence and
//! backup, its log destinations' health, and its warnings and errors since a
//! time (from its problems file, through `Diagnose`). A box that does not
//! answer is a section that says so.
//!
//! Never in it: a phrase, a key, a token or a destination's secret. Every
//! URL is cut to scheme, host and path (`pvfs_log::redact_urls`), since a user,
//! password or query can hold a token.

use std::collections::BTreeMap;
use std::time::Instant;

use pvfs_client::{Client, DiagnoseWire, ServeStatusReply};

/// What one box said, or why it said nothing.
#[derive(Debug, Default)]
pub struct BoxReport {
    /// The box's host name, once it answers; its address before.
    pub name: String,
    /// `local socket`, or the peer's `ip:port`.
    pub addr: String,
    pub this_box: bool,
    pub proto: Option<u32>,
    /// It could not be reached, or its status could not be read.
    pub error: Option<String>,
    pub status: Option<ServeStatusReply>,
    pub diag: Option<DiagnoseWire>,
    /// `Diagnose` failed on a box that answered otherwise (an older build).
    pub diag_error: Option<String>,
    /// The box's clock minus this one's, the round trip halved out.
    pub clock_offset_ms: Option<i64>,
    pub rtt_ms: Option<u64>,
}

/// The whole bundle.
#[derive(Debug, Default)]
pub struct Bundle {
    pub collected_ms: u64,
    pub by_host: String,
    pub cli_build: String,
    pub since_ms: u64,
    pub boxes: Vec<BoxReport>,
    /// This box's system facts: (what, value).
    pub system: Vec<(String, String)>,
}

/// A clock this far off its peer's is flagged.
pub const CLOCK_FLAG_MS: i64 = 2_000;

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Ask one box everything: its status, then `Diagnose` (timed, for the
/// clock). `client` is already connected.
pub fn collect_box(client: &mut Client, addr: &str, this_box: bool, since_ms: u64) -> BoxReport {
    let mut r = BoxReport { name: addr.to_string(), addr: addr.to_string(), this_box, ..Default::default() };
    r.proto = Some(client.daemon_proto());
    match client.serve_status_full() {
        Ok(s) => r.status = Some(s),
        Err(e) => r.error = Some(format!("serve status: {e}")),
    }
    let sent = now_ms();
    let t = Instant::now();
    match client.diagnose(since_ms) {
        Ok(d) => {
            let rtt = t.elapsed().as_millis() as u64;
            r.rtt_ms = Some(rtt);
            r.clock_offset_ms = Some(d.now_ms as i64 - (sent + rtt / 2) as i64);
            r.name = d.host.clone();
            r.diag = Some(d);
        }
        Err(e) => r.diag_error = Some(e.to_string()),
    }
    r
}

/// `30m`, `1h`, `2d`, `45s`; a bare number is minutes. In ms.
pub fn parse_since(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = match s.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => (&s[..i], s[i..].trim()),
        None => (s, "m"),
    };
    let n: u64 = num.parse().ok()?;
    let mul = match unit {
        "s" | "sec" | "secs" => 1_000,
        "m" | "min" | "mins" => 60_000,
        "h" | "hour" | "hours" => 3_600_000,
        "d" | "day" | "days" => 86_400_000,
        _ => return None,
    };
    (n > 0).then_some(n * mul)
}

fn ts(ms: u64) -> String {
    // `2026-10-09T21:52:01.123Z` → `2026-10-09 21:52:01 UTC`
    let t = pvfs_log::format_ts(ms);
    format!("{} UTC", t.get(..19).unwrap_or(&t).replace('T', " "))
}

fn hm(ms: u64) -> String {
    let t = pvfs_log::format_ts(ms);
    t.get(11..19).unwrap_or(&t).to_string()
}

fn span(ms: u64) -> String {
    let m = ms / 60_000;
    match m {
        0 => format!("{} s", ms / 1000),
        1..=59 => format!("{m} min"),
        60..=2879 => format!("{} h {} min", m / 60, m % 60),
        _ => format!("{} days {} h", m / 1440, (m % 1440) / 60),
    }
}

fn bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u < U.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", U[u])
    }
}

/// The bundle as a person (or Claude) reads it.
pub fn render_text(b: &Bundle) -> String {
    let mut o = String::new();
    let line = |o: &mut String, k: &str, v: &str| o.push_str(&format!("{k:<14}{v}\n"));
    o.push_str(&format!("PVFS diagnostics — {} (PVOS D230)\n", ts(b.collected_ms)));
    o.push_str(&format!(
        "collected on {} by pvfs {}; warnings and errors since {} ({} back)\n",
        b.by_host,
        b.cli_build,
        ts(b.since_ms),
        span(b.collected_ms.saturating_sub(b.since_ms))
    ));
    let names: Vec<String> = b
        .boxes
        .iter()
        .map(|r| if r.this_box { format!("{} (this box)", r.name) } else if r.error.is_some() { format!("{} (no answer)", r.name) } else { r.name.clone() })
        .collect();
    o.push_str(&format!("boxes: {}\n", names.join(", ")));
    for r in &b.boxes {
        o.push_str(&format!("\n== {}{} ==\n", r.name, if r.this_box { " (this box)" } else { "" }));
        line(&mut o, "address:", &format!("{}{}", r.addr, r.proto.map(|p| format!("  (proto {p})")).unwrap_or_default()));
        if let Some(e) = &r.error {
            line(&mut o, "NO ANSWER:", &format!("{e}  [{}]", pvfs_log::kind::from_text(e).unwrap_or("other")));
            continue;
        }
        let st = r.status.as_ref();
        if let Some(d) = &r.diag {
            line(&mut o, "build:", &d.build);
            line(&mut o, "role:", &format!(
                "{} of forest {}…  (jobs {}; regions {}; network {})",
                d.role,
                d.forest.get(..8).unwrap_or(&d.forest),
                d.jobs,
                d.regions,
                d.listen
            ));
            line(&mut o, "up since:", &format!("{} ({})", ts(d.started_ms), span(d.now_ms.saturating_sub(d.started_ms))));
            if !r.this_box {
                if let (Some(off), Some(rtt)) = (r.clock_offset_ms, r.rtt_ms) {
                    let flag = if off.abs() > CLOCK_FLAG_MS { "  ← CLOCK OFF" } else { "" };
                    line(&mut o, "clock:", &format!("{:+.1} s against this box (round trip {rtt} ms){flag}", off as f64 / 1000.0));
                }
            }
        } else if let Some(b) = st.and_then(|s| s.build.as_ref()) {
            line(&mut o, "build:", b);
        }
        if let Some(l) = st.and_then(|s| s.log_level.as_ref()) {
            let live = if l.until_ms > b.collected_ms {
                format!("{} for {} more, then {} (configured)", l.current, span(l.until_ms - b.collected_ms), l.configured)
            } else {
                format!("{} (configured)", l.current)
            };
            let privacy = r.diag.as_ref().map(|d| format!("   privacy: {}", d.privacy)).unwrap_or_default();
            line(&mut o, "log level:", &format!("{live}{privacy}"));
        }
        if let Some(s) = st {
            if let Some(f) = &s.fenced {
                line(&mut o, "FENCED:", &f.reason);
            }
            for d in &s.log_destinations {
                let last = if d.last_ok_ms == 0 {
                    "nothing delivered yet".to_string()
                } else {
                    format!("last delivered {} ago", span(b.collected_ms.saturating_sub(d.last_ok_ms)))
                };
                let err = d.last_error.as_deref().map(|e| format!("; last error: {e}")).unwrap_or_default();
                line(&mut o, "destination:", &format!(
                    "{} ({}): {}sent {}, queued {}, dropped {}; {last}{err}",
                    d.name,
                    d.kind,
                    if d.failing { "FAILING — " } else { "" },
                    d.sent,
                    bytes(d.queued_bytes),
                    d.dropped
                ));
            }
            if s.stores.is_empty() {
                if let Some(c) = &s.capacity {
                    line(&mut o, "store:", &format!("{} free of {}", bytes(c.free_bytes), bytes(c.total_bytes)));
                }
            }
            for st in &s.stores {
                line(&mut o, "store:", &format!("{}: {} free of {}", st.path, bytes(st.free_bytes), bytes(st.total_bytes)));
            }
            let jobs: Vec<String> = s
                .jobs
                .iter()
                .filter(|j| j.enabled)
                .map(|j| match &j.last_error {
                    Some(e) => format!("{} {} (last error: {e})", j.name, j.state),
                    None => format!("{} {}", j.name, j.state),
                })
                .collect();
            line(&mut o, "jobs:", &if jobs.is_empty() { format!("none ({})", s.runner) } else { jobs.join("; ") });
            for m in &s.mounts {
                line(&mut o, "mount:", &format!(
                    "{} on {}{}{}",
                    m.mountpoint,
                    m.build,
                    if m.behind { " (behind the daemon)" } else { "" },
                    m.stale.as_deref().map(|e| format!("; stale: {e}")).unwrap_or_default()
                ));
            }
            if let Some(t) = &s.log {
                line(&mut o, "log tip:", &format!("seq {}", t.seq));
            }
            if let Some(k) = &s.backup {
                line(&mut o, "backup:", &format!(
                    "{} {}{}",
                    ts(k.at_ms),
                    if k.ok { "verified" } else { "FAILED" },
                    k.error.as_deref().map(|e| format!(": {e}")).unwrap_or_default()
                ));
            }
            if s.conflicts > 0 || s.stale > 0 {
                line(&mut o, "view:", &format!("{} conflicting path(s), {} stale catalogue(s)", s.conflicts, s.stale));
            }
        }
        match (&r.diag, &r.diag_error) {
            (Some(d), _) => problems(&mut o, d, b.since_ms),
            (None, Some(e)) => line(&mut o, "problems:", &format!("not read — {e}")),
            (None, None) => {}
        }
    }
    if !b.system.is_empty() {
        o.push_str(&format!("\n== {} (this box's system) ==\n", b.by_host));
        for (k, v) in &b.system {
            line(&mut o, &format!("{k}:"), v);
        }
    }
    pvfs_log::redact_urls(&o)
}

fn problems(o: &mut String, d: &DiagnoseWire, since_ms: u64) {
    if !d.problems_note.is_empty() {
        o.push_str(&format!("{:<14}{}\n", "problems:", d.problems_note));
        return;
    }
    let mut by_sev: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_event: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for p in &d.problems {
        *by_sev.entry(p.severity.as_str()).or_default() += 1;
        *by_event.entry((p.event.as_str(), p.error_kind.as_str())).or_default() += 1;
    }
    let total = d.problems.len() as u64 + d.problems_left_out;
    if total == 0 {
        o.push_str(&format!("{:<14}none since {}\n", "problems:", hm(since_ms)));
        return;
    }
    let sev: Vec<String> = by_sev.iter().map(|(s, n)| format!("{s} {n}")).collect();
    o.push_str(&format!("{:<14}{total} since {} ({})\n", "problems:", hm(since_ms), sev.join(", ")));
    let mut ev: Vec<((&str, &str), usize)> = by_event.into_iter().collect();
    ev.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for ((e, k), n) in ev {
        o.push_str(&format!("{:<14}{e} ×{n}{}\n", "", if k.is_empty() { String::new() } else { format!(" [{k}]") }));
    }
    if d.problems_left_out > 0 {
        o.push_str(&format!("{:<14}({} older ones not shown; the newest {} are)\n", "", d.problems_left_out, d.problems.len()));
    }
    for p in &d.problems {
        let k = if p.error_kind.is_empty() { String::new() } else { format!(" [{}]", p.error_kind) };
        o.push_str(&format!("  {} {:<7} {}{k} {}\n", hm(p.ts_ms), p.severity, p.event, p.line));
    }
}

/// The bundle for a program: the same facts, as JSON.
pub fn render_json(b: &Bundle) -> String {
    let boxes: Vec<serde_json::Value> = b
        .boxes
        .iter()
        .map(|r| {
            let s = r.status.as_ref();
            serde_json::json!({
                "name": r.name,
                "addr": r.addr,
                "this_box": r.this_box,
                "proto": r.proto,
                "error": r.error,
                "diagnose_error": r.diag_error,
                "clock_offset_ms": r.clock_offset_ms,
                "rtt_ms": r.rtt_ms,
                "diagnose": r.diag,
                "status": s.map(|s| serde_json::json!({
                    "runner": s.runner, "build": s.build, "jobs": s.jobs, "mounts": s.mounts, "stores": s.stores,
                    "capacity": s.capacity, "trash": s.trash, "log": s.log, "fenced": s.fenced, "backup": s.backup,
                    "conflicts": s.conflicts, "stale": s.stale, "log_destinations": s.log_destinations,
                    "log_level": s.log_level,
                })),
            })
        })
        .collect();
    let system: serde_json::Map<String, serde_json::Value> =
        b.system.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
    let v = serde_json::json!({
        "collected_ms": b.collected_ms,
        "by_host": b.by_host,
        "cli_build": b.cli_build,
        "since_ms": b.since_ms,
        "boxes": boxes,
        "system": system,
    });
    pvfs_log::redact_urls(&v.to_string())
}

/// This box's own facts: the kernel, uptime and load, and whether its
/// clock is synchronised (`timedatectl`, where there is one). A command
/// that is missing (the NAS has no `timedatectl`) is left out.
pub fn system_facts() -> Vec<(String, String)> {
    let run = |cmd: &str, args: &[&str]| -> Option<String> {
        let out = std::process::Command::new(cmd)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (out.status.success() && !s.is_empty()).then_some(s)
    };
    let mut f = Vec::new();
    if let Some(s) = run("uname", &["-srm"]) {
        f.push(("kernel".into(), s));
    }
    if let Some(s) = run("uptime", &[]) {
        f.push(("uptime".into(), s));
    }
    if let Some(s) = run("timedatectl", &["show", "-p", "NTPSynchronized", "--value"]) {
        f.push(("ntp synced".into(), s));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn since_takes_units_and_minutes() {
        assert_eq!(parse_since("30m"), Some(30 * 60_000));
        assert_eq!(parse_since("1h"), Some(3_600_000));
        assert_eq!(parse_since("2d"), Some(2 * 86_400_000));
        assert_eq!(parse_since("45s"), Some(45_000));
        assert_eq!(parse_since("90"), Some(90 * 60_000));
        assert_eq!(parse_since("2 hours"), Some(2 * 3_600_000));
        for bad in ["", "h", "0", "1w", "-1h"] {
            assert_eq!(parse_since(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn a_box_with_no_answer_and_one_before_diagnose_say_so() {
        let b = Bundle {
            collected_ms: 1_791_000_000_000,
            by_host: "mediabox".into(),
            cli_build: "1.4.0 (v1.4-620)".into(),
            since_ms: 1_791_000_000_000 - 3_600_000,
            boxes: vec![
                BoxReport {
                    name: "192.168.1.20:7434".into(),
                    addr: "192.168.1.20:7434".into(),
                    error: Some("dial 192.168.1.20:7434: Connection refused (os error 111)".into()),
                    ..Default::default()
                },
                BoxReport {
                    name: "192.168.1.30:7434".into(),
                    addr: "192.168.1.30:7434".into(),
                    proto: Some(17),
                    diag_error: Some("unknown_op: this box's daemon speaks proto 17 … roll it first".into()),
                    ..Default::default()
                },
            ],
            system: vec![("kernel".into(), "Linux 6.8.0 x86_64".into())],
        };
        let t = render_text(&b);
        assert!(t.contains("NO ANSWER:    dial 192.168.1.20:7434: Connection refused (os error 111)  [network:refused]"), "{t}");
        assert!(t.contains("problems:     not read — unknown_op"), "{t}");
        assert!(t.contains("boxes: 192.168.1.20:7434 (no answer), 192.168.1.30:7434"), "{t}");
        assert!(t.contains("== mediabox (this box's system) ==\nkernel:       Linux 6.8.0 x86_64"), "{t}");
        let j: serde_json::Value = serde_json::from_str(&render_json(&b)).unwrap();
        assert_eq!(j["boxes"][0]["error"], "dial 192.168.1.20:7434: Connection refused (os error 111)");
        assert_eq!(j["boxes"][1]["proto"], 17);
    }

    #[test]
    fn problems_are_counted_by_event_and_kind_then_listed() {
        let p = |ts: u64, sev: &str, ev: &str, k: &str, line: &str| pvfs_client::ProblemWire {
            ts_ms: ts,
            severity: sev.into(),
            event: ev.into(),
            error_kind: k.into(),
            service: "pvfsd".into(),
            line: line.into(),
        };
        let now = 1_791_000_000_000;
        let d = DiagnoseWire {
            now_ms: now,
            started_ms: now - 7_200_000,
            host: "qnap".into(),
            build: "v1.4-620".into(),
            forest: "ae60b1db00".into(),
            role: "replica".into(),
            jobs: "follow,receive".into(),
            regions: "1 catalogue".into(),
            listen: "0.0.0.0:7434".into(),
            privacy: "full".into(),
            problems: vec![
                p(now - 600_000, "warning", "pvfs.writer.held", "slow:held", "pvfsd: the writer was held 2.4 s by scan"),
                p(now - 300_000, "error", "pvfs.job.failed", "network:refused", "pvfsd: follow failed: dial https://u:pw@x/y?t=1"),
                p(now - 60_000, "warning", "pvfs.writer.held", "slow:held", "pvfsd: the writer was held 3.1 s by scan"),
            ],
            problems_left_out: 2,
            ..Default::default()
        };
        let b = Bundle {
            collected_ms: now,
            by_host: "mediabox".into(),
            cli_build: "x".into(),
            since_ms: now - 3_600_000,
            boxes: vec![BoxReport {
                name: "qnap".into(),
                addr: "192.168.1.20:7434".into(),
                proto: Some(18),
                diag: Some(d),
                clock_offset_ms: Some(3_500),
                rtt_ms: Some(4),
                ..Default::default()
            }],
            system: vec![],
        };
        let t = render_text(&b);
        assert!(t.contains("role:         replica of forest ae60b1db…  (jobs follow,receive; regions 1 catalogue; network 0.0.0.0:7434)"), "{t}");
        assert!(t.contains("clock:        +3.5 s against this box (round trip 4 ms)  ← CLOCK OFF"), "{t}");
        assert!(t.contains("problems:     5 since"), "{t}");
        assert!(t.contains("(error 1, warning 2)"), "{t}");
        let held = t.find("pvfs.writer.held ×2 [slow:held]").expect("counted");
        let failed = t.find("pvfs.job.failed ×1 [network:refused]").expect("counted");
        assert!(held < failed, "most first: {t}");
        assert!(t.contains("(2 older ones not shown; the newest 3 are)"), "{t}");
        assert!(t.contains(" error   pvfs.job.failed [network:refused] pvfsd: follow failed: dial https://‹user›@x/y?‹…›"), "{t}");
        assert!(!t.contains("pw@"), "{t}");
    }
}
