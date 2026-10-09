//! One log record for PVFS and PVOS (PVOS D222).
//!
//! Every daemon line used to be a bare `eprintln!("<component>: <sentence>")`
//! — no time, no level, no fields — so a log server could only grep it. This
//! crate keeps that sentence exactly and puts a record around it:
//!
//! ```text
//! pv_warn!("pvfs.job.failed", job = "watch", error = content(&e);
//!          "pvfsd: watch pass failed: {e}; retrying");
//! ```
//!
//! - **severity** (RFC 5424), a stable dotted **event** name (a contract: SIEM
//!   searches key on it, `docs/32-log-events.md` lists them), an optional
//!   **category** (`audit`, `security`) and **outcome**;
//! - **fields**, each with a privacy [`Class`] so a destination can take
//!   personal data out of the record *and* the sentence ([`Privacy`]);
//! - **output** chosen by `PVFS_LOG_FORMAT`: under systemd the journal gets
//!   native fields (`PV_EVENT`, …) with today's line as `MESSAGE`; anywhere
//!   else the text is today's line byte for byte, so the NAS's awk wrapper,
//!   lab scripts and every test reading daemon stderr keep working.
//!
//! A process that never calls [`init`] / [`init_daemon`] (the CLIs) prints
//! today's text to stderr — pvfs-core's lines read the same at a terminal.

mod encode;
mod journal;
mod limit;
mod privacy;
pub mod registry;
#[cfg(feature = "ship")]
pub mod ship;
pub mod testing;
mod time;

pub use encode::{parse_json, to_json, to_logfmt};
pub use limit::{limit, Limiter};
#[doc(hidden)]
pub use journal::__send_record;
pub use privacy::{pseudonym, render, View};
pub use time::{format_ts, parse_ts};

use std::cell::RefCell;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

/// RFC 5424's eight severities; journald's PRIORITY is the number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Emergency => "emergency",
            Severity::Alert => "alert",
            Severity::Critical => "critical",
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Notice => "notice",
            Severity::Info => "info",
            Severity::Debug => "debug",
        }
    }

    /// The name, or the usual short forms (`warn`, `err`, `crit`, `emerg`).
    pub fn parse(s: &str) -> Option<Severity> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "emergency" | "emerg" => Severity::Emergency,
            "alert" => Severity::Alert,
            "critical" | "crit" => Severity::Critical,
            "error" | "err" => Severity::Error,
            "warning" | "warn" => Severity::Warning,
            "notice" => Severity::Notice,
            "info" => Severity::Info,
            "debug" => Severity::Debug,
            _ => return None,
        })
    }

    /// journald / syslog priority number.
    pub fn priority(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    System,
    Audit,
    Security,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::System => "system",
            Category::Audit => "audit",
            Category::Security => "security",
        }
    }
    pub fn parse(s: &str) -> Option<Category> {
        Some(match s.trim() {
            "system" => Category::System,
            "audit" => Category::Audit,
            "security" => Category::Security,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
        }
    }
    pub fn parse(s: &str) -> Option<Outcome> {
        Some(match s.trim() {
            "success" => Outcome::Success,
            "failure" => Outcome::Failure,
            _ => return None,
        })
    }
}

/// A field's privacy class (D222 decision 3a). What each [`Privacy`] level
/// does with it is in [`render`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Counts, durations, job names, ids, wire codes, box hostnames.
    Meta,
    /// A member's or device's key, a member id → a keyed pseudonym.
    Actor,
    /// A client address or user agent → only on audit/security events.
    Net,
    /// Paths, file names, titles, labels, URLs, error texts → never bare.
    Content,
    /// A person's name or email → only at `identified`.
    Identity,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Meta => "meta",
            Class::Actor => "actor",
            Class::Net => "net",
            Class::Content => "content",
            Class::Identity => "identity",
        }
    }
    pub fn parse(s: &str) -> Option<Class> {
        Some(match s.trim() {
            "meta" => Class::Meta,
            "actor" => Class::Actor,
            "net" => Class::Net,
            "content" => Class::Content,
            "identity" => Class::Identity,
            _ => return None,
        })
    }
}

/// How much personal data an output may carry (D222 decision 3b).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Privacy {
    /// Everything — the box's own log, today's text.
    Full,
    /// `Minimal` plus names, emails and addresses on every event.
    Identified,
    /// The default for every destination off the box.
    Minimal,
}

impl Privacy {
    pub fn as_str(self) -> &'static str {
        match self {
            Privacy::Full => "full",
            Privacy::Identified => "identified",
            Privacy::Minimal => "minimal",
        }
    }
    pub fn parse(s: &str) -> Option<Privacy> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "full" => Privacy::Full,
            "identified" => Privacy::Identified,
            "minimal" => Privacy::Minimal,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(String),
    Int(i64),
    UInt(u64),
    Bool(bool),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Str(s) => f.write_str(s),
            Value::Int(n) => write!(f, "{n}"),
            Value::UInt(n) => write!(f, "{n}"),
            Value::Bool(b) => write!(f, "{b}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: String,
    pub class: Class,
    pub value: Value,
}

/// A value with its privacy class: `content(&path.display())`,
/// `actor(&key_hex)`, `net(&addr)`, `identity(&email)`. A bare string or
/// number is `meta`.
pub struct Classed<T>(pub Class, pub T);

pub fn meta<T: fmt::Display>(v: T) -> Classed<T> {
    Classed(Class::Meta, v)
}
pub fn actor<T: fmt::Display>(v: T) -> Classed<T> {
    Classed(Class::Actor, v)
}
pub fn net<T: fmt::Display>(v: T) -> Classed<T> {
    Classed(Class::Net, v)
}
pub fn content<T: fmt::Display>(v: T) -> Classed<T> {
    Classed(Class::Content, v)
}
pub fn identity<T: fmt::Display>(v: T) -> Classed<T> {
    Classed(Class::Identity, v)
}

/// What a macro field's value may be. Secrets (phrases, keys, tokens) are
/// types without `Display`, so they cannot be wrapped and cannot be fields.
pub trait ToField {
    fn to_field(self, name: &str) -> Field;
}

impl<T: fmt::Display> ToField for Classed<T> {
    fn to_field(self, name: &str) -> Field {
        Field { name: name.to_string(), class: self.0, value: Value::Str(self.1.to_string()) }
    }
}

impl ToField for &str {
    fn to_field(self, name: &str) -> Field {
        Field { name: name.to_string(), class: Class::Meta, value: Value::Str(self.to_string()) }
    }
}
impl ToField for String {
    fn to_field(self, name: &str) -> Field {
        Field { name: name.to_string(), class: Class::Meta, value: Value::Str(self) }
    }
}
impl ToField for &String {
    fn to_field(self, name: &str) -> Field {
        Field { name: name.to_string(), class: Class::Meta, value: Value::Str(self.clone()) }
    }
}
impl ToField for bool {
    fn to_field(self, name: &str) -> Field {
        Field { name: name.to_string(), class: Class::Meta, value: Value::Bool(self) }
    }
}
impl ToField for &bool {
    fn to_field(self, name: &str) -> Field {
        (*self).to_field(name)
    }
}

macro_rules! int_fields {
    ($variant:ident, $as:ty; $($t:ty),*) => {$(
        impl ToField for $t {
            fn to_field(self, name: &str) -> Field {
                Field { name: name.to_string(), class: Class::Meta, value: Value::$variant(self as $as) }
            }
        }
        impl ToField for &$t {
            fn to_field(self, name: &str) -> Field {
                (*self).to_field(name)
            }
        }
    )*};
}
int_fields!(Int, i64; i8, i16, i32, isize);
int_fields!(UInt, u64; u8, u16, u32, usize);

impl ToField for i64 {
    fn to_field(self, name: &str) -> Field {
        Field { name: name.to_string(), class: Class::Meta, value: Value::Int(self) }
    }
}
impl ToField for &i64 {
    fn to_field(self, name: &str) -> Field {
        (*self).to_field(name)
    }
}
impl ToField for u64 {
    fn to_field(self, name: &str) -> Field {
        Field { name: name.to_string(), class: Class::Meta, value: Value::UInt(self) }
    }
}
impl ToField for &u64 {
    fn to_field(self, name: &str) -> Field {
        (*self).to_field(name)
    }
}

/// One log record. `component: msg` (with `via: ` in front for a relayed
/// child's line) is the text a person reads — today's line exactly.
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub id: String,
    pub seq: u64,
    pub ts_ms: u64,
    pub host: String,
    pub service: String,
    pub pid: u32,
    pub severity: Severity,
    pub event: String,
    pub category: Category,
    pub outcome: Option<Outcome>,
    /// The prefix before the first `": "`, when the line had one.
    pub component: Option<String>,
    /// Who relayed it: pvosd's `pvosd/app[<id>] err` for an app's line.
    pub via: Option<String>,
    pub msg: String,
    pub fields: Vec<Field>,
}

impl Record {
    /// A record stamped now by this process (id, seq, time, host, pid,
    /// service), its line split into component and sentence.
    pub fn now(severity: Severity, event: &str, line: String) -> Record {
        let lg = logger();
        let (component, msg) = split_component(line);
        Record {
            id: format!("{:032x}", rand::random::<u128>()),
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
            ts_ms: time::now_ms(),
            host: lg.host.clone(),
            service: lg.cfg.service.clone(),
            pid: std::process::id(),
            severity,
            event: event.to_string(),
            category: Category::System,
            outcome: None,
            component,
            via: None,
            msg,
            fields: Vec::new(),
        }
    }

    /// The line a person reads: `[via: ][component: ]msg`.
    pub fn line(&self) -> String {
        join_line(self.via.as_deref(), self.component.as_deref(), &self.msg)
    }
}

pub(crate) fn join_line(via: Option<&str>, component: Option<&str>, msg: &str) -> String {
    let mut s = String::with_capacity(msg.len() + 32);
    if let Some(v) = via {
        s.push_str(v);
        s.push_str(": ");
    }
    if let Some(c) = component {
        s.push_str(c);
        s.push_str(": ");
    }
    s.push_str(msg);
    s
}

/// `pvfsd: x` → (`pvfsd`, `x`). A prefix is at most 40 characters of
/// `[A-Za-z0-9_./\[\]-]` with at most one space (`pvfs mount`,
/// `pvosd/app[iac] err`); anything else is not a prefix and stays in the
/// sentence. `component + ": " + msg` is the input again, byte for byte.
pub fn split_component(line: String) -> (Option<String>, String) {
    if let Some(i) = line.find(": ") {
        let head = &line[..i];
        let ok_chars = head
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./[]- ".contains(c));
        let spaces = head.matches(' ').count();
        let first_ok = head.chars().next().is_some_and(|c| c.is_ascii_alphabetic());
        if !head.is_empty() && head.len() <= 40 && ok_chars && spaces <= 1 && first_ok && !head.ends_with(' ') {
            let msg = line[i + 2..].to_string();
            let mut head = line;
            head.truncate(i);
            return (Some(head), msg);
        }
    }
    (None, line)
}

/// Where this process's records go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// journal when stderr is the journal, else text.
    Auto,
    Text,
    Journal,
    Json,
    Logfmt,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => Format::Auto,
            "text" => Format::Text,
            "journal" => Format::Journal,
            "json" => Format::Json,
            "logfmt" => Format::Logfmt,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// `pvfsd`, `pvfs-mount`, `pvosd`, `pvfs-companion`, …
    pub service: String,
    pub format: Format,
    pub level: Severity,
    pub privacy: Privacy,
    pub pseudonym_key: Option<[u8; 32]>,
}

impl Config {
    pub fn new(service: &str) -> Config {
        Config {
            service: service.to_string(),
            format: Format::Text,
            level: Severity::Info,
            privacy: Privacy::Full,
            pseudonym_key: None,
        }
    }

    /// The daemon defaults, then `PVFS_LOG_FORMAT`, `PVFS_LOG_LEVEL`,
    /// `PVFS_LOG_PRIVACY` and `PVFS_LOG_PSEUDONYM_KEY_FILE` (D222 decision 8).
    /// A value it cannot read is named once on stderr and the default kept.
    pub fn from_env(service: &str) -> Config {
        let mut c = Config::new(service);
        c.format = Format::Auto;
        let mut bad = Vec::new();
        if let Ok(v) = std::env::var("PVFS_LOG_FORMAT") {
            match Format::parse(&v) {
                Some(f) => c.format = f,
                None => bad.push(format!("PVFS_LOG_FORMAT={v:?} (auto|text|journal|json|logfmt)")),
            }
        }
        if let Ok(v) = std::env::var("PVFS_LOG_LEVEL") {
            match Severity::parse(&v) {
                Some(s) => c.level = s,
                None => bad.push(format!("PVFS_LOG_LEVEL={v:?} (error|warning|notice|info|debug)")),
            }
        }
        if let Ok(v) = std::env::var("PVFS_LOG_PRIVACY") {
            match Privacy::parse(&v) {
                Some(p) => c.privacy = p,
                None => bad.push(format!("PVFS_LOG_PRIVACY={v:?} (full|identified|minimal)")),
            }
        }
        if let Some(path) = std::env::var_os("PVFS_LOG_PSEUDONYM_KEY_FILE") {
            match read_key(std::path::Path::new(&path)) {
                Ok(k) => c.pseudonym_key = Some(k),
                Err(e) => bad.push(format!("PVFS_LOG_PSEUDONYM_KEY_FILE: {e}")),
            }
        }
        for b in bad {
            eprintln!("{service}: log setting ignored: {b}");
        }
        c
    }
}

/// 32 raw bytes, or 64 hex characters (whitespace ignored).
pub fn read_key(path: &std::path::Path) -> Result<[u8; 32], String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(&bytes);
        return Ok(k);
    }
    let text: String = String::from_utf8_lossy(&bytes).split_whitespace().collect();
    if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
        }
        return Ok(k);
    }
    Err(format!("{}: not a 32-byte key (raw or 64 hex)", path.display()))
}

struct Logger {
    cfg: Config,
    /// `Auto` resolved at init.
    format: Format,
    host: String,
    /// journald's SYSLOG_IDENTIFIER: the binary's own name, as journald
    /// shows it for stderr today (`pvfs`, not `pvfs-mount`).
    ident: String,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();
static SEQ: AtomicU64 = AtomicU64::new(0);

fn program_name() -> String {
    std::env::args_os()
        .next()
        .and_then(|a| std::path::Path::new(&a).file_name().map(|f| f.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "pvfs".to_string())
}

fn hostname() -> String {
    nix::unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".to_string())
}

fn logger() -> &'static Logger {
    LOGGER.get_or_init(|| make_logger(Config::new(&program_name())))
}

fn make_logger(cfg: Config) -> Logger {
    let format = match cfg.format {
        Format::Auto => {
            if journal::stderr_is_journal() {
                Format::Journal
            } else {
                Format::Text
            }
        }
        f => f,
    };
    Logger { format, host: hostname(), ident: program_name(), cfg }
}

/// Set this process's logger. The first call wins; it returns false if a
/// logger was already in place (a line was logged before init, or init ran
/// twice).
pub fn init(cfg: Config) -> bool {
    LOGGER.set(make_logger(cfg)).is_ok()
}

/// A daemon's start: [`Config::from_env`] for `service`, then [`init`].
pub fn init_daemon(service: &str) -> bool {
    let set = init(Config::from_env(service));
    install_panic_hook();
    set
}

/// PVOS D225 — the build that writes this log, as the daemon's first record
/// once its arguments are parsed (`--version` and `--help` log nothing):
/// `pvfs.process.started` with `build` and `pid`, so a log read after an
/// upgrade or a crash says which build wrote it.
pub fn process_started(build: &str) {
    let service = logger().cfg.service.clone();
    let pid = std::process::id();
    crate::pv_notice!("pvfs.process.started", build = build, pid = pid; "{service}: build {build} starting (pid {pid})");
}

/// PVOS D225 — a panic is a record: `pvfs.thread.panicked` at critical (the thread,
/// where, and the message), to the journal or file and to every destination,
/// then Rust's own report as before (with its backtrace under
/// `RUST_BACKTRACE`). Without it a panic was one unlevelled stderr line no
/// query or alert could find. Installed once per process, by
/// [`init_daemon`]; a panic while recording one does not recurse.
pub fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            thread_local! {
                static IN_HOOK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
            }
            if !IN_HOOK.with(|f| f.replace(true)) {
                let thread = std::thread::current().name().unwrap_or("unnamed").to_string();
                let at = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
                let message = info
                    .payload()
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| info.payload().downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "(no message)".into());
                let line = format!("{}: PANIC in thread '{thread}' at {at}: {message}", logger().cfg.service);
                let fields = vec![thread.to_field("thread"), at.to_field("at"), content(&message).to_field("message")];
                __emit(Severity::Critical, Category::System, Some(Outcome::Failure), "pvfs.thread.panicked", line, fields);
                IN_HOOK.with(|f| f.set(false));
            }
            previous(info);
        }));
    });
}

/// The format this process resolved to (`Auto` becomes journal or text).
pub fn current_format() -> Format {
    logger().format
}

pub fn enabled(sev: Severity) -> bool {
    sev <= logger().cfg.level || CAPTURE.with(|c| c.borrow().is_some()) || testing::active()
}

thread_local! {
    static CAPTURE: RefCell<Option<Vec<Record>>> = const { RefCell::new(None) };
    /// PVOS D222b — fields every record made on this thread carries (a web
    /// connection's client address), set where the connection starts.
    static CONTEXT: RefCell<Vec<Field>> = const { RefCell::new(Vec::new()) };
}

/// Fields every record made on this thread from now on carries, unless the
/// record has a field of the same name: `set_thread_context(vec![net(addr).to_field("peer_addr")])`
/// at a connection's start, so each line it causes says where it came from.
pub fn set_thread_context(fields: Vec<Field>) {
    CONTEXT.with(|c| *c.borrow_mut() = fields);
}

/// Add one field to this thread's context (or replace the one of that
/// name): the member, once a web connection has signed in.
pub fn add_thread_context(field: Field) {
    CONTEXT.with(|c| {
        let mut c = c.borrow_mut();
        c.retain(|f| f.name != field.name);
        c.push(field);
    });
}

/// The value of one of this thread's context fields, as text.
pub fn thread_context_value(name: &str) -> Option<String> {
    CONTEXT.with(|c| c.borrow().iter().find(|f| f.name == name).map(|f| f.value.to_string()))
}

pub fn clear_thread_context() {
    CONTEXT.with(|c| c.borrow_mut().clear());
}

/// Run `f` and return the records this thread logged in it, instead of
/// writing them (tests).
pub fn capture<F: FnOnce()>(f: F) -> Vec<Record> {
    CAPTURE.with(|c| *c.borrow_mut() = Some(Vec::new()));
    f();
    CAPTURE.with(|c| c.borrow_mut().take().unwrap_or_default())
}

/// The macros' entry point.
#[doc(hidden)]
pub fn __emit(
    severity: Severity,
    category: Category,
    outcome: Option<Outcome>,
    event: &str,
    line: String,
    fields: Vec<Field>,
) {
    let mut r = Record::now(severity, event, line);
    r.category = category;
    r.outcome = outcome;
    r.fields = fields;
    CONTEXT.with(|c| {
        for f in c.borrow().iter() {
            if !r.fields.iter().any(|x| x.name == f.name) {
                r.fields.push(f.clone());
            }
        }
    });
    emit_record(r);
}

/// Write a whole record — a macro's, or one relayed from a child (pvosd's
/// apps and forests, D222 decision 12) with its own id, time and service.
pub fn emit_record(rec: Record) {
    let captured = CAPTURE.with(|c| {
        if let Some(v) = c.borrow_mut().as_mut() {
            v.push(rec.clone());
            true
        } else {
            false
        }
    });
    if captured {
        return;
    }
    testing::offer(&rec);
    // PVOS D222d — every destination whose filter takes it spools it (each
    // has its own minimum severity, so before this process's level check).
    #[cfg(feature = "ship")]
    ship::offer(&rec);
    let lg = logger();
    if rec.severity > lg.cfg.level {
        return;
    }
    let view = render(&rec, lg.cfg.privacy, lg.cfg.pseudonym_key.as_ref());
    let out = match lg.format {
        Format::Journal => {
            let fields = journal::fields(&rec, &view, &lg.ident);
            if journal::send(&fields).is_ok() {
                return;
            }
            // journald turns a leading `<N>` into the priority, so the level
            // survives a send that failed (socket gone, record too big).
            format!("<{}>{}", rec.severity.priority(), view.line())
        }
        Format::Json => to_json(&rec, &view),
        Format::Logfmt => to_logfmt(&rec, &view),
        Format::Text | Format::Auto => view.line(),
    };
    // `eprintln!` itself, as every line used to be: the test harness
    // captures it per test, where a write to `stderr()` would bypass that.
    eprintln!("{out}");
}

/// A child's stderr line, as pvosd relays it (D222 decision 12): a schema-1
/// JSON record keeps its severity, event and fields; anything else is
/// `raw_event` at info. Either way `via` and `service` are the relay's, and
/// `extra` fields are added — a value in `via` that is not `meta` (a
/// forest's mount path) must be one of them, so privacy can take it out.
pub fn relayed(line: &str, via: &str, service: &str, raw_event: &str, extra: Vec<Field>) -> Record {
    let mut r = match parse_json(line) {
        Some(r) => r,
        None => Record::now(Severity::Info, raw_event, line.to_string()),
    };
    r.via = Some(via.to_string());
    r.service = service.to_string();
    r.fields.extend(extra);
    r
}

#[doc(hidden)]
#[macro_export]
macro_rules! __pv_category {
    (system) => {
        $crate::Category::System
    };
    (audit) => {
        $crate::Category::Audit
    };
    (security) => {
        $crate::Category::Security
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __pv_outcome {
    (success) => {
        $crate::Outcome::Success
    };
    (failure) => {
        $crate::Outcome::Failure
    };
}

/// `pv_log!(Severity::Warning; [category [outcome]] "event", k = v, …; "fmt", args…)`.
/// Use the per-level macros.
#[macro_export]
macro_rules! pv_log {
    ($sev:expr; $cat:ident $out:ident $event:literal $(, $k:ident = $v:expr)* $(,)? ; $($fmt:tt)+) => {
        $crate::__pv_emit!($sev, $crate::__pv_category!($cat), ::std::option::Option::Some($crate::__pv_outcome!($out)), $event, [$($k = $v),*], $($fmt)+)
    };
    ($sev:expr; $cat:ident $event:literal $(, $k:ident = $v:expr)* $(,)? ; $($fmt:tt)+) => {
        $crate::__pv_emit!($sev, $crate::__pv_category!($cat), ::std::option::Option::None, $event, [$($k = $v),*], $($fmt)+)
    };
    ($sev:expr; $event:literal $(, $k:ident = $v:expr)* $(,)? ; $($fmt:tt)+) => {
        $crate::__pv_emit!($sev, $crate::Category::System, ::std::option::Option::None, $event, [$($k = $v),*], $($fmt)+)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __pv_emit {
    ($sev:expr, $cat:expr, $out:expr, $event:literal, [$($k:ident = $v:expr),*], $($fmt:tt)+) => {{
        let __sev = $sev;
        if $crate::enabled(__sev) {
            // The sentence first: it only borrows, so a field may then take
            // the same value by move.
            let __line = ::std::format!($($fmt)+);
            let __fields: ::std::vec::Vec<$crate::Field> =
                ::std::vec![$($crate::ToField::to_field($v, stringify!($k))),*];
            $crate::__emit(__sev, $cat, $out, $event, __line, __fields);
        }
    }};
}

#[macro_export]
macro_rules! pv_error {
    ($($t:tt)+) => { $crate::pv_log!($crate::Severity::Error; $($t)+) };
}
#[macro_export]
macro_rules! pv_warn {
    ($($t:tt)+) => { $crate::pv_log!($crate::Severity::Warning; $($t)+) };
}
#[macro_export]
macro_rules! pv_notice {
    ($($t:tt)+) => { $crate::pv_log!($crate::Severity::Notice; $($t)+) };
}
#[macro_export]
macro_rules! pv_info {
    ($($t:tt)+) => { $crate::pv_log!($crate::Severity::Info; $($t)+) };
}
#[macro_export]
macro_rules! pv_debug {
    ($($t:tt)+) => { $crate::pv_log!($crate::Severity::Debug; $($t)+) };
}

#[cfg(test)]
mod tests;
