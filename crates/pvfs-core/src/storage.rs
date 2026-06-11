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
