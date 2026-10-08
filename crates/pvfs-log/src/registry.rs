//! The event names are a contract (D222 decision 4): SIEM searches and
//! alerts are keyed on them. Each repo lists its names in one Markdown table
//! — PVFS `docs/32-log-events.md`, PVOS `docs/log-events.md` — and a test in
//! each repo runs [`check_repo`]: every name the code logs is listed, every
//! listed name is still in the code, names are unique and well formed, and a
//! call's category is the listed one. The same scan finds any `eprintln!`
//! left in the daemon crates, so no new line can go around the logger.
//!
//! Table rows: `| `pvfs.job.failed` | warning | system | One sentence. |`
//! under a header whose first cell is `Event`.

use std::path::{Path, PathBuf};

use crate::{Category, Severity};

#[derive(Clone, Debug, PartialEq)]
pub struct EventDef {
    pub name: String,
    pub severity: Severity,
    pub category: Category,
    pub meaning: String,
}

/// `pvfs.job.failed`: lowercase dotted words, at least three.
pub fn valid_name(n: &str) -> bool {
    let parts: Vec<&str> = n.split('.').collect();
    parts.len() >= 3
        && parts.iter().all(|p| {
            p.chars().next().is_some_and(|c| c.is_ascii_lowercase())
                && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

pub fn parse_table(md: &str) -> Result<Vec<EventDef>, Vec<String>> {
    let mut defs = Vec::new();
    let mut errs = Vec::new();
    let mut in_table = false;
    for (i, line) in md.lines().enumerate() {
        let t = line.trim();
        if !t.starts_with('|') {
            in_table = false;
            continue;
        }
        let cells: Vec<&str> = t.trim_matches('|').split('|').map(str::trim).collect();
        if cells.first().is_some_and(|c| c.eq_ignore_ascii_case("event")) {
            in_table = true;
            continue;
        }
        if !in_table || cells.iter().all(|c| c.chars().all(|ch| ch == '-' || ch == ':')) {
            continue;
        }
        if cells.len() < 4 {
            errs.push(format!("line {}: expected | event | severity | category | meaning |", i + 1));
            continue;
        }
        let name = cells[0].trim_matches('`').to_string();
        let Some(severity) = Severity::parse(cells[1]) else {
            errs.push(format!("line {}: {name}: severity {:?}", i + 1, cells[1]));
            continue;
        };
        let Some(category) = Category::parse(cells[2]) else {
            errs.push(format!("line {}: {name}: category {:?}", i + 1, cells[2]));
            continue;
        };
        defs.push(EventDef { name, severity, category, meaning: cells[3..].join("|").trim().to_string() });
    }
    if errs.is_empty() {
        Ok(defs)
    } else {
        Err(errs)
    }
}

/// One `pv_*!` call found in the source.
#[derive(Clone, Debug, PartialEq)]
pub struct Use {
    pub file: PathBuf,
    pub line: usize,
    pub event: String,
    pub category: Category,
}

const MACROS: &[&str] = &["pv_error!", "pv_warn!", "pv_notice!", "pv_info!", "pv_debug!"];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// Every Rust file under these directories, in a stable order.
pub fn sources(dirs: &[PathBuf]) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    for d in dirs {
        rs_files(d, &mut files);
    }
    files.into_iter().filter_map(|f| std::fs::read_to_string(&f).ok().map(|s| (f, s))).collect()
}

fn line_of(src: &str, byte: usize) -> usize {
    src[..byte].matches('\n').count() + 1
}

fn is_comment_line(src: &str, byte: usize) -> bool {
    let start = src[..byte].rfind('\n').map(|i| i + 1).unwrap_or(0);
    src[start..byte].trim_start().starts_with("//")
}

/// The `pv_*!` calls in these sources. A call whose first argument is not
/// a string literal (`pv_warn!($e …)` inside a macro) is not a use.
pub fn uses(sources: &[(PathBuf, String)]) -> Vec<Use> {
    let mut out = Vec::new();
    for (file, src) in sources {
        for mac in MACROS {
            let mut from = 0;
            while let Some(i) = src[from..].find(mac) {
                let at = from + i;
                from = at + mac.len();
                if is_comment_line(src, at) {
                    continue;
                }
                let rest = src[from..].trim_start();
                let Some(rest) = rest.strip_prefix('(') else { continue };
                let mut words = Vec::new();
                let mut r = rest.trim_start();
                while let Some(c) = r.chars().next() {
                    if c == '"' {
                        break;
                    }
                    if !c.is_ascii_alphabetic() {
                        break;
                    }
                    let end = r.find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')).unwrap_or(r.len());
                    words.push(&r[..end]);
                    r = r[end..].trim_start();
                }
                let Some(lit) = r.strip_prefix('"') else { continue };
                let Some(end) = lit.find('"') else { continue };
                let category = words.first().and_then(|w| Category::parse(w)).unwrap_or(Category::System);
                out.push(Use { file: file.clone(), line: line_of(src, at), event: lit[..end].to_string(), category });
            }
        }
    }
    out
}

/// `eprintln!` outside comments, unless the line says `pv-log: allow`.
pub fn stray_eprintlns(sources: &[(PathBuf, String)]) -> Vec<(PathBuf, usize)> {
    let mut out = Vec::new();
    for (file, src) in sources {
        let mut from = 0;
        while let Some(i) = src[from..].find("eprintln!") {
            let at = from + i;
            from = at + 9;
            if is_comment_line(src, at) {
                continue;
            }
            let ln = line_of(src, at);
            let text = src.lines().nth(ln - 1).unwrap_or("");
            if text.contains("pv-log: allow") {
                continue;
            }
            out.push((file.clone(), ln));
        }
    }
    out
}

/// Everything wrong with a repo's names, empty when it is right.
/// `prefix` is the repo's own (`pvfs.`, `pvos.`): a listed name must start
/// with it, and must still appear in the code as a string literal (a macro
/// call, or a record made by hand such as a relay's raw-line event).
pub fn check(defs: &[EventDef], uses: &[Use], sources: &[(PathBuf, String)], prefix: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for d in defs {
        if !valid_name(&d.name) {
            problems.push(format!("listed name {:?} is not lowercase dotted words (three or more)", d.name));
        }
        if !d.name.starts_with(prefix) {
            problems.push(format!("listed name {} does not start with {prefix}", d.name));
        }
        if !seen.insert(d.name.clone()) {
            problems.push(format!("listed twice: {}", d.name));
        }
        let lit = format!("\"{}\"", d.name);
        if !sources.iter().any(|(_, s)| s.contains(&lit)) {
            problems.push(format!("listed but never logged: {}", d.name));
        }
    }
    for u in uses {
        match defs.iter().find(|d| d.name == u.event) {
            None => problems.push(format!("{}:{}: {} is not in the event list", u.file.display(), u.line, u.event)),
            Some(d) if d.category != u.category => problems.push(format!(
                "{}:{}: {} logged as {} but listed as {}",
                u.file.display(),
                u.line,
                u.event,
                u.category.as_str(),
                d.category.as_str()
            )),
            Some(_) => {}
        }
    }
    problems
}

/// The whole check for one repo: the list at `root/doc`, the code under
/// `root/<crate>/src` for each daemon-side crate.
pub fn check_repo(root: &Path, doc: &str, crate_dirs: &[&str], prefix: &str) -> Vec<String> {
    let md = match std::fs::read_to_string(root.join(doc)) {
        Ok(s) => s,
        Err(e) => return vec![format!("{doc}: {e}")],
    };
    let defs = match parse_table(&md) {
        Ok(d) => d,
        Err(errs) => return errs.into_iter().map(|e| format!("{doc}: {e}")).collect(),
    };
    let dirs: Vec<PathBuf> = crate_dirs.iter().map(|c| root.join(c).join("src")).collect();
    let srcs = sources(&dirs);
    let mut problems = check(&defs, &uses(&srcs), &srcs, prefix);
    for (f, l) in stray_eprintlns(&srcs) {
        problems.push(format!("{}:{l}: eprintln! — log through pvfs-log's pv_* macros (D222)", f.display()));
    }
    problems
}
