//! PVOS D230 — `pvfs-companion diagnose`, and the app's "Copy diagnostics":
//! this Mac's companion in one block of text — its build, vault and agent,
//! its log destinations, and its warnings and errors since a time (from
//! `companion-problems.jsonl`, which the agent writes).
//!
//! Never in it: a phrase, a key (only the identity key's first 16
//! characters), a token, or a URL's user, password or query.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::logdest::DestinationView;

/// The agent's problems file, beside `companion.log`.
pub fn problems_path() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    home.join("Library/Logs/PVFS/companion-problems.jsonl")
}

/// What the bundle says, gathered by the caller.
#[derive(Debug, Default)]
pub struct Facts {
    pub now_ms: u64,
    pub since_ms: u64,
    pub build: String,
    pub host: String,
    pub system: String,
    /// (what, value): vault, key, agent, web, origins.
    pub lines: Vec<(String, String)>,
    pub destinations: Vec<DestinationView>,
    pub destinations_error: Option<String>,
    pub problems: Vec<pvfs_log::Record>,
    pub problems_left_out: u64,
}

fn ts(ms: u64) -> String {
    let t = pvfs_log::format_ts(ms);
    format!("{} UTC", t.get(..19).unwrap_or(&t).replace('T', " "))
}

fn hm(ms: u64) -> String {
    let t = pvfs_log::format_ts(ms);
    t.get(11..19).unwrap_or(&t).to_string()
}

pub fn render(f: &Facts) -> String {
    let mut o = String::new();
    let line = |o: &mut String, k: &str, v: &str| o.push_str(&format!("{k:<14}{v}\n"));
    o.push_str(&format!("PVFS companion diagnostics — {} (PVOS D230)\n", ts(f.now_ms)));
    line(&mut o, "build:", &f.build);
    line(&mut o, "host:", &format!("{} ({})", f.host, f.system));
    for (k, v) in &f.lines {
        line(&mut o, &format!("{k}:"), v);
    }
    match &f.destinations_error {
        Some(e) => line(&mut o, "destinations:", &format!("unreadable: {e}")),
        None if f.destinations.is_empty() => line(&mut o, "destinations:", "none (records stay in ~/Library/Logs/PVFS/companion.log)"),
        None => {
            for d in &f.destinations {
                line(
                    &mut o,
                    "destination:",
                    &format!(
                        "{} ({} → {}){}; min {}, privacy {}, token {}{}",
                        d.name,
                        d.kind,
                        d.target,
                        if d.enabled { "" } else { " DISABLED" },
                        d.min_severity,
                        d.privacy,
                        d.token,
                        if d.problems.is_empty() { String::new() } else { format!("; PROBLEMS: {}", d.problems.join("; ")) }
                    ),
                );
            }
        }
    }
    let total = f.problems.len() as u64 + f.problems_left_out;
    if total == 0 {
        line(&mut o, "problems:", &format!("none since {}", hm(f.since_ms)));
    } else {
        let mut by_sev: BTreeMap<&str, usize> = BTreeMap::new();
        let mut by_event: BTreeMap<(String, String), usize> = BTreeMap::new();
        let kind = |r: &pvfs_log::Record| {
            r.fields.iter().find(|x| x.name == pvfs_log::kind::FIELD).map(|x| x.value.to_string()).unwrap_or_default()
        };
        for r in &f.problems {
            *by_sev.entry(r.severity.as_str()).or_default() += 1;
            *by_event.entry((r.event.clone(), kind(r))).or_default() += 1;
        }
        let sev: Vec<String> = by_sev.iter().map(|(s, n)| format!("{s} {n}")).collect();
        line(&mut o, "problems:", &format!("{total} since {} ({})", hm(f.since_ms), sev.join(", ")));
        let mut ev: Vec<((String, String), usize)> = by_event.into_iter().collect();
        ev.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        for ((e, k), n) in ev {
            line(&mut o, "", &format!("{e} ×{n}{}", if k.is_empty() { String::new() } else { format!(" [{k}]") }));
        }
        if f.problems_left_out > 0 {
            line(&mut o, "", &format!("({} older ones not shown)", f.problems_left_out));
        }
        for r in &f.problems {
            let k = kind(r);
            let k = if k.is_empty() { String::new() } else { format!(" [{k}]") };
            o.push_str(&format!("  {} {:<7} {}{k} {}\n", hm(r.ts_ms), r.severity.as_str(), r.event, r.line()));
        }
    }
    pvfs_log::redact_urls(&o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundle_names_everything_and_leaks_no_secret() {
        let now = 1_791_000_000_000;
        let mut r = pvfs_log::Record::now(pvfs_log::Severity::Warning, "pvfs.agent.refused", "pvfs-companion: refused https://site.example/cb?code=SECRET1".into());
        r.ts_ms = now - 60_000;
        r.fields.push(pvfs_log::Field { name: "error_kind".into(), class: pvfs_log::Class::Meta, value: pvfs_log::Value::Str("auth:refused".into()) });
        let f = Facts {
            now_ms: now,
            since_ms: now - 3_600_000,
            build: "pvfs-companion 1.4.0 (v1.4-620)".into(),
            host: "mac".into(),
            system: "Darwin 27.0.0 arm64".into(),
            lines: vec![("agent".into(), "running (identity 02ab12cd34ef5678…)".into())],
            destinations: vec![DestinationView {
                name: "loki".into(),
                kind: "loki".into(),
                target: "https://bob:TOKEN2@logs.example/loki/api/v1/push?x=TOKEN3".into(),
                privacy: "minimal".into(),
                min_severity: "info".into(),
                categories: vec![],
                token: "keychain".into(),
                enabled: true,
                problems: vec![],
            }],
            problems: vec![r],
            ..Default::default()
        };
        let t = render(&f);
        for secret in ["SECRET1", "TOKEN2", "TOKEN3", "bob"] {
            assert!(!t.contains(secret), "{secret} in:\n{t}");
        }
        assert!(t.contains("destination:  loki (loki → https://‹user›@logs.example/loki/api/v1/push?‹…›); min info, privacy minimal, token keychain"), "{t}");
        assert!(t.contains("problems:     1 since"), "{t}");
        assert!(t.contains("pvfs.agent.refused ×1 [auth:refused]"), "{t}");
        assert!(t.contains(" warning pvfs.agent.refused [auth:refused] pvfs-companion: refused https://site.example/cb?‹…›"), "{t}");
        let none = render(&Facts { now_ms: now, since_ms: now - 3_600_000, ..Default::default() });
        assert!(none.contains("destinations: none (records stay in ~/Library/Logs/PVFS/companion.log)"), "{none}");
        assert!(none.contains("problems:     none since"), "{none}");
    }
}
