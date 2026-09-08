//! StorageBackend trait + local filesystem backend — P1 spec (doc 04 §2).

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use crate::error::{PvfsError, Result};

pub const SCHEME_FILE: &str = "file";
pub const SCHEME_TMP: &str = "pvfs-tmp";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatInfo {
    pub exists: bool,
    pub is_dir: bool,
    pub size: u64,
    pub mtime_ms: u64,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime_ms: u64,
    /// When this entry last changed on THIS filesystem: `max(mtime, ctime)`.
    ///
    /// D112 — the settle window needs a "has it stopped moving" signal, and
    /// mtime is not one when the writer back-dates it. See [`changed_ms`].
    pub changed_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ByteRange {
    pub start: u64,
    /// exclusive; None = to EOF
    pub end: Option<u64>,
}

pub trait StorageBackend {
    fn scheme(&self) -> &str;
    fn stat(&self, uri: &str) -> Result<StatInfo>;
    fn read_range(&self, uri: &str, range: Option<ByteRange>) -> Result<Box<dyn Read>>;
    /// PVFS-managed bytes only (temp spool / content store) — never user dirs.
    fn write(&self, uri: &str, data: &mut dyn Read) -> Result<StatInfo>;
    fn list(&self, uri: &str) -> Result<Vec<DirEntry>>;
    fn hash(&self, uri: &str) -> Result<String>;
}

fn bad(field: &str, reason: String) -> PvfsError {
    PvfsError::BadInput {
        field: field.into(),
        reason,
    }
}

/// `file:///abs/path` → PathBuf. No percent-encoding in P1 (we generate these
/// URIs ourselves from real paths); documented limitation.
pub fn uri_to_path(uri: &str) -> Result<PathBuf> {
    let rest = uri
        .strip_prefix("file://")
        .ok_or_else(|| bad("uri", format!("not a file:// URI: {uri}")))?;
    if !rest.starts_with('/') {
        return Err(bad("uri", format!("file URI must be absolute: {uri}")));
    }
    Ok(PathBuf::from(rest))
}

pub fn path_to_uri(path: &Path) -> Result<String> {
    let p = path
        .to_str()
        .ok_or_else(|| bad("path", format!("non-UTF-8 path: {}", path.display())))?;
    if !p.starts_with('/') {
        return Err(bad("path", format!("path must be absolute: {p}")));
    }
    Ok(format!("file://{p}"))
}

// ---- instance-qualified locations (F5.1, doc 17 §7.2) -----------------------
//
// A `file://` location is host-implicit — it resolves wherever the path
// happens to exist, which is wrong the moment locations cross machines.
// `pvfs-host://<transport-pin>/<abs-path>` says WHICH instance holds the
// bytes: the pin is the instance's F1 transport pin (BLAKE3 hex of its
// listener cert — stable, verifiable, already what clients pin to connect).
// Resolution is local only when the pin is this data dir's own; a foreign
// pin is a remote candidate (fetched by sync / read-through, doc 17 §7.3).

/// Scheme of an instance-qualified location.
pub const HOST_URI_PREFIX: &str = "pvfs-host://";
/// Where the F1 listener material records this instance's pin.
const NETTLS_PIN_FILE: &str = "nettls/pin";

/// Build `pvfs-host://<pin>/<abs-path>`.
pub fn host_uri(pin: &str, path: &Path) -> Result<String> {
    let p = path
        .to_str()
        .ok_or_else(|| bad("path", format!("non-UTF-8 path: {}", path.display())))?;
    if !p.starts_with('/') {
        return Err(bad("path", format!("path must be absolute: {p}")));
    }
    if pin.len() != 64 || !pin.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(bad("pin", "expected the 64-hex transport pin".into()));
    }
    Ok(format!("{HOST_URI_PREFIX}{}{p}", pin.to_lowercase()))
}

/// Parse `pvfs-host://<pin>/<abs-path>` → `(pin, abs_path)`.
pub fn parse_host_uri(uri: &str) -> Option<(&str, &str)> {
    let rest = uri.strip_prefix(HOST_URI_PREFIX)?;
    let (pin, path) = rest.split_at(rest.find('/')?);
    if pin.len() == 64 && pin.chars().all(|c| c.is_ascii_hexdigit()) && path.starts_with('/') {
        Some((pin, path))
    } else {
        None
    }
}

/// The local path a location URI denotes **on this host**, if any.
///
/// D81. A location is recorded host-implicit (`file:///path`) when the box
/// holding the bytes writes its own log, and PIN-QUALIFIED
/// (`pvfs-host://<pin>/path`, D75) when a replica writes through to the owner —
/// because a bare `file://` path is host-implicit and a replica's copy lives on
/// a specific box. Both name the same bytes on the same disk when the pin is
/// ours.
///
/// Every caller that asks "is this location mine, and where" needs that
/// equivalence, and three of them derived it separately: `has_central` learned
/// it only because a dry run caught the mover re-placing files it had just
/// placed, and the scan's deletion pass never learned it at all — so a replica
/// silently retired nothing, for every move and every delete, while reporting
/// success. One implementation, so the next caller inherits it.
pub fn local_path_of(uri: &str, own_pin: Option<&str>) -> Option<PathBuf> {
    if let Ok(p) = uri_to_path(uri) {
        return Some(p);
    }
    match (parse_host_uri(uri), own_pin) {
        (Some((pin, path)), Some(mine)) if pin.eq_ignore_ascii_case(mine) => {
            Some(PathBuf::from(path))
        }
        _ => None,
    }
}

/// The path a location URI denotes, on WHICHEVER host holds it.
///
/// D81 4b. `local_path_of` answers "is this mine, and where"; this answers the
/// weaker question "what path does this name", which is what deciding whether a
/// file already sits at a library root requires — a copy held by ANOTHER box at
/// one of the library's roots satisfies the library just as well as our own.
/// Returns `None` for anything that is not a filesystem path (`pvfs-sync:///…`
/// blobs, say), which is the honest answer: those have no tree path to compare.
pub fn any_path_of(uri: &str) -> Option<PathBuf> {
    if let Ok(p) = uri_to_path(uri) {
        return Some(p);
    }
    parse_host_uri(uri).map(|(_, path)| PathBuf::from(path))
}

/// Do any of these locations put the bytes on a DIFFERENT host?
///
/// D82. The FUSE mount treats "unhashed with no local bytes" as an in-flight
/// ingest and proxies reads to the local daemon (P10.1). That test is too
/// loose: a file whose bytes live on another holder is not being ingested here,
/// it is simply elsewhere — and taking the proxy path for it dials a daemon
/// that has nothing, fails, and returns EIO without ever reaching the resolve
/// that would have fetched it.
///
/// Found staging the presentation layer: every file held only by the NAS was
/// unreadable through the mount while `pvfs cat` on the same node succeeded.
/// Under a mount serving Plex, that is the entire library returning I/O errors.
pub fn held_on_another_host(locations: &[String], own_pin: Option<&str>) -> bool {
    locations.iter().any(|u| {
        parse_host_uri(u)
            .map(|(pin, _)| match own_pin {
                // A pin that is not ours is another box, definitively.
                Some(mine) => !pin.eq_ignore_ascii_case(mine),
                // No pin of our own: any pin-qualified location is someone
                // else's, because we could not have written one.
                None => true,
            })
            .unwrap_or(false)
    })
}

/// This data dir's own transport pin, if it has ever served a network
/// listener (`pvfsd --listen` mints it). `None` until then — a host nobody
/// can dial has no meaningful location to offer.
pub fn host_pin(data_dir: &Path) -> Option<String> {
    let pin = std::fs::read_to_string(data_dir.join(NETTLS_PIN_FILE))
        .ok()?
        .trim()
        .to_string();
    (pin.len() == 64).then_some(pin)
}

/// Atomic in-place replace for a **secure blob's** location (doc 12 §8.3) — the
/// one deliberate exception to "location bytes are never overwritten": write to
/// a sibling temp file, fsync, rename over the target. The superseded bytes are
/// unlinked (logical deletion; physical remanence is documented out of scope —
/// crypto-shredding is the envelope's job).
pub fn atomic_overwrite(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| bad("path", format!("no parent directory: {}", path.display())))?;
    fs::create_dir_all(dir).map_err(|e| PvfsError::io("create blob dir", e))?;
    let tmp = dir.join(format!(
        ".pvfs-secure-{}-{}.tmp",
        std::process::id(),
        path.file_name().and_then(|n| n.to_str()).unwrap_or("blob")
    ));
    {
        use std::io::Write;
        let mut f = fs::File::create(&tmp).map_err(|e| PvfsError::io("write blob tmp", e))?;
        f.write_all(bytes).map_err(|e| PvfsError::io("write blob tmp", e))?;
        f.sync_all().map_err(|e| PvfsError::io("sync blob tmp", e))?;
    }
    fs::rename(&tmp, path).map_err(|e| PvfsError::io("replace blob", e))?;
    // fsync the directory so the RENAME itself survives power loss — without
    // this the file contents are durable but the swap might not be. (The
    // failure mode would be benign — old bytes ⇒ a detectable verify mismatch —
    // but strict durability is one syscall.)
    #[cfg(unix)]
    {
        let d = fs::File::open(dir).map_err(|e| PvfsError::io("open blob dir", e))?;
        d.sync_all().map_err(|e| PvfsError::io("sync blob dir", e))?;
    }
    Ok(())
}

/// When a file last changed on THIS filesystem — `max(mtime, ctime)`.
///
/// D112. The settle window asks "has it stopped moving?" and used mtime alone,
/// on the reasoning that a growing file's mtime keeps advancing. That holds for
/// a local copier like Sonarr. It is FALSE for anything that back-dates the
/// destination: rclone preserves the SOURCE mtime, so a file that landed thirty
/// seconds ago carries an mtime from two days back, clears a 15-second window
/// instantly, and gets catalogued mid-copy at a partial size.
///
/// Measured on the production holder 2026-09-08 — arrivals whose mtime sat
/// 41.8h and 56.5h BEHIND their ctime. Every one of them was ingested at the
/// wrong size, failed the name+size identity match against the node the ingest
/// box had already made, and minted a duplicate. That is where the forest's
/// 1,901 `missing` entries came from: not deletions, and not lag — the ORIGINAL
/// node of each pair, stripped of its location by its own twin.
///
/// ctime is set by the kernel on every content or metadata change and cannot be
/// back-dated from userspace (`utimes` moves mtime and atime, never ctime), so
/// it marks when the bytes really last moved here. Taking the max keeps mtime's
/// behaviour wherever mtime is the later of the two.
fn changed_ms(md: &fs::Metadata) -> u64 {
    let m = mtime_ms(md);
    #[cfg(unix)]
    let m = {
        use std::os::unix::fs::MetadataExt;
        let secs = md.ctime().max(0) as u64;
        let nanos = md.ctime_nsec().max(0) as u64;
        m.max(secs.saturating_mul(1_000).saturating_add(nanos / 1_000_000))
    };
    m
}

fn mtime_ms(md: &fs::Metadata) -> u64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The `file://` backend.
pub struct LocalBackend;

impl StorageBackend for LocalBackend {
    fn scheme(&self) -> &str {
        SCHEME_FILE
    }

    fn stat(&self, uri: &str) -> Result<StatInfo> {
        let path = uri_to_path(uri)?;
        match fs::metadata(&path) {
            Ok(md) => Ok(StatInfo {
                exists: true,
                is_dir: md.is_dir(),
                size: md.len(),
                mtime_ms: mtime_ms(&md),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(StatInfo {
                exists: false,
                is_dir: false,
                size: 0,
                mtime_ms: 0,
            }),
            Err(e) => Err(PvfsError::io("stat", e)),
        }
    }

    fn read_range(&self, uri: &str, range: Option<ByteRange>) -> Result<Box<dyn Read>> {
        let path = uri_to_path(uri)?;
        let mut f = fs::File::open(&path).map_err(|e| PvfsError::io("open for read", e))?;
        match range {
            None => Ok(Box::new(f)),
            Some(r) => {
                f.seek(SeekFrom::Start(r.start))
                    .map_err(|e| PvfsError::io("seek", e))?;
                match r.end {
                    None => Ok(Box::new(f)),
                    Some(end) => {
                        if end < r.start {
                            return Err(bad("range", format!("end {end} < start {}", r.start)));
                        }
                        Ok(Box::new(f.take(end - r.start)))
                    }
                }
            }
        }
    }

    fn write(&self, uri: &str, data: &mut dyn Read) -> Result<StatInfo> {
        let path = uri_to_path(uri)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| PvfsError::io("create dirs", e))?;
        }
        let mut f = fs::File::create(&path).map_err(|e| PvfsError::io("create for write", e))?;
        std::io::copy(data, &mut f).map_err(|e| PvfsError::io("write", e))?;
        self.stat(uri)
    }

    fn list(&self, uri: &str) -> Result<Vec<DirEntry>> {
        let path = uri_to_path(uri)?;
        let mut out = Vec::new();
        let rd = fs::read_dir(&path).map_err(|e| PvfsError::io("read dir", e))?;
        for entry in rd {
            let entry = entry.map_err(|e| PvfsError::io("read dir entry", e))?;
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue, // skip non-UTF-8 names (documented P1 limitation)
            };
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            out.push(DirEntry {
                name,
                is_dir: md.is_dir(),
                size: md.len(),
                mtime_ms: mtime_ms(&md),
                changed_ms: changed_ms(&md),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn hash(&self, uri: &str) -> Result<String> {
        let mut reader = self.read_range(uri, None)?;
        hash_stream(&mut reader)
    }
}

/// Streaming BLAKE3 over a reader (1 MiB chunks).
pub fn hash_stream(reader: &mut dyn Read) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| PvfsError::io("hash read", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Guess a MIME type from the file extension (best-effort, P1).
pub fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "mkv" => "video/x-matroska",
        "mp4" | "m4v" => "video/mp4",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "srt" => "application/x-subrip",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "xml" => "application/xml",
        "html" | "htm" => "text/html",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn uri_roundtrip() {
        let p = Path::new("/data/movies/x.mkv");
        let uri = path_to_uri(p).unwrap();
        assert_eq!(uri, "file:///data/movies/x.mkv");
        assert_eq!(uri_to_path(&uri).unwrap(), p);
        assert!(uri_to_path("https://x/y").is_err());
        assert!(path_to_uri(Path::new("relative/x")).is_err());
    }

    #[test]
    fn local_backend_contract() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::File::create(&file)
            .unwrap()
            .write_all(b"hello world")
            .unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        let b = LocalBackend;
        let dir_uri = path_to_uri(dir.path()).unwrap();
        let file_uri = path_to_uri(&file).unwrap();

        let st = b.stat(&file_uri).unwrap();
        assert!(st.exists && !st.is_dir && st.size == 11);
        assert!(!b.stat(&format!("{dir_uri}/missing")).unwrap().exists);

        let names: Vec<_> = b.list(&dir_uri).unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(names, vec!["a.txt".to_string(), "sub".to_string()]);

        let mut s = String::new();
        b.read_range(&file_uri, None).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello world");
        let mut s = String::new();
        b.read_range(&file_uri, Some(ByteRange { start: 6, end: Some(11) }))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "world");

        assert_eq!(b.hash(&file_uri).unwrap(), blake3::hash(b"hello world").to_hex().to_string());
    }
}
