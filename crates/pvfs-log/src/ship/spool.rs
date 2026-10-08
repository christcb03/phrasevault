//! A destination's spool on disk (PVOS D222d decision 2): append-only
//! segments of schema-1 JSON lines (`seg-<n>.ndjson`, at most
//! [`SEGMENT_BYTES`] each), a cursor (`cursor`: "<segment> <offset>") the
//! sender moves only after a send succeeds, and a cap: over it, the oldest
//! segment goes and its unsent lines are counted as dropped.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const SEGMENT_BYTES: u64 = 8 << 20;

pub struct Spool {
    dir: PathBuf,
    cap: u64,
    seg_bytes: u64,
    /// segment number → its size.
    segs: BTreeMap<u64, u64>,
    writer: Option<File>,
    read_seg: u64,
    read_off: u64,
    /// Lines the cap has thrown away since this spool was opened.
    pub dropped: u64,
}

/// Where a read got to: hand it back to [`Spool::commit`] once the lines
/// before it have been sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pos {
    seg: u64,
    off: u64,
}

fn seg_path(dir: &Path, n: u64) -> PathBuf {
    dir.join(format!("seg-{n:010}.ndjson"))
}

impl Spool {
    pub fn open(dir: &Path, cap_bytes: u64) -> std::io::Result<Spool> {
        Self::open_with(dir, cap_bytes, SEGMENT_BYTES)
    }

    pub fn open_with(dir: &Path, cap_bytes: u64, seg_bytes: u64) -> std::io::Result<Spool> {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut segs = BTreeMap::new();
        for e in std::fs::read_dir(dir)?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(n) = name.strip_prefix("seg-").and_then(|r| r.strip_suffix(".ndjson")).and_then(|n| n.parse::<u64>().ok()) {
                segs.insert(n, e.metadata().map(|m| m.len()).unwrap_or(0));
            }
        }
        let (mut read_seg, mut read_off) = (segs.keys().next().copied().unwrap_or(0), 0);
        if let Ok(c) = std::fs::read_to_string(dir.join("cursor")) {
            let mut it = c.split_whitespace().filter_map(|t| t.parse::<u64>().ok());
            if let (Some(s), Some(o)) = (it.next(), it.next()) {
                if segs.contains_key(&s) {
                    read_seg = s;
                    read_off = o.min(segs[&s]);
                } else if segs.keys().next().is_some_and(|first| *first > s) {
                    // Its segment is gone (the cap took it): start at the oldest left.
                    read_seg = *segs.keys().next().unwrap();
                    read_off = 0;
                }
            }
        }
        Ok(Spool { dir: dir.to_path_buf(), cap: cap_bytes, seg_bytes, segs, writer: None, read_seg, read_off, dropped: 0 })
    }

    fn write_seg(&self) -> u64 {
        self.segs.keys().next_back().copied().unwrap_or(0)
    }

    /// Append one line (no newline in it). Over the cap afterwards, the
    /// oldest segments go.
    pub fn append(&mut self, line: &str) -> std::io::Result<()> {
        let mut n = self.write_seg();
        let size = self.segs.get(&n).copied().unwrap_or(0);
        if size > 0 && size + line.len() as u64 + 1 > self.seg_bytes {
            n += 1;
            self.writer = None;
        }
        if self.writer.is_none() {
            let f = OpenOptions::new().create(true).append(true).open(seg_path(&self.dir, n))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            self.segs.entry(n).or_insert(0);
            self.writer = Some(f);
        }
        let w = self.writer.as_mut().expect("opened above");
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        w.write_all(&buf)?;
        *self.segs.get_mut(&n).expect("inserted above") += buf.len() as u64;
        self.enforce_cap();
        Ok(())
    }

    fn total(&self) -> u64 {
        self.segs.values().sum()
    }

    fn enforce_cap(&mut self) {
        while self.total() > self.cap && self.segs.len() > 1 {
            let oldest = *self.segs.keys().next().expect("len > 1");
            if oldest >= self.read_seg {
                // Unsent lines go: count them.
                let from = if oldest == self.read_seg { self.read_off } else { 0 };
                self.dropped += count_lines(&seg_path(&self.dir, oldest), from);
            }
            let _ = std::fs::remove_file(seg_path(&self.dir, oldest));
            self.segs.remove(&oldest);
            if self.read_seg <= oldest {
                self.read_seg = *self.segs.keys().next().expect("len >= 1");
                self.read_off = 0;
                let _ = self.save_cursor();
            }
        }
    }

    /// Up to `max_lines` / about `max_bytes` of unsent lines, and where the
    /// read ended. A last line without its newline (a write cut short) is
    /// left for later.
    pub fn read_batch(&mut self, max_lines: usize, max_bytes: usize) -> (Vec<String>, Pos) {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        let (mut seg, mut off) = (self.read_seg, self.read_off);
        let last = self.write_seg();
        while let Some(&size) = self.segs.get(&seg) {
            if off < size {
                if let Ok(mut f) = File::open(seg_path(&self.dir, seg)) {
                    if f.seek(SeekFrom::Start(off)).is_ok() {
                        let mut r = BufReader::new(f);
                        let mut buf = Vec::new();
                        while out.len() < max_lines && bytes < max_bytes {
                            buf.clear();
                            match r.read_until(b'\n', &mut buf) {
                                Ok(0) => break,
                                Ok(n) if buf.ends_with(b"\n") => {
                                    off += n as u64;
                                    bytes += n;
                                    let line = String::from_utf8_lossy(&buf[..n - 1]).into_owned();
                                    if !line.trim().is_empty() {
                                        out.push(line);
                                    }
                                }
                                _ => break,
                            }
                        }
                    }
                }
            }
            if out.len() >= max_lines || bytes >= max_bytes || seg >= last || off < size {
                break;
            }
            // This segment is read to its end and a newer one exists.
            match self.segs.range(seg + 1..).next() {
                Some((&next, _)) => {
                    seg = next;
                    off = 0;
                }
                None => break,
            }
        }
        (out, Pos { seg, off })
    }

    /// The lines before `pos` were delivered: move the cursor, and remove
    /// the segments wholly behind it.
    pub fn commit(&mut self, pos: Pos) -> std::io::Result<()> {
        self.read_seg = pos.seg;
        self.read_off = pos.off;
        let done: Vec<u64> = self.segs.range(..pos.seg).map(|(k, _)| *k).collect();
        for n in done {
            let _ = std::fs::remove_file(seg_path(&self.dir, n));
            self.segs.remove(&n);
        }
        self.save_cursor()
    }

    fn save_cursor(&self) -> std::io::Result<()> {
        let tmp = self.dir.join("cursor.tmp");
        std::fs::write(&tmp, format!("{} {}\n", self.read_seg, self.read_off))?;
        std::fs::rename(tmp, self.dir.join("cursor"))
    }

    /// Bytes not yet sent.
    pub fn pending_bytes(&self) -> u64 {
        self.segs
            .iter()
            .filter(|(n, _)| **n >= self.read_seg)
            .map(|(n, size)| if *n == self.read_seg { size.saturating_sub(self.read_off) } else { *size })
            .sum()
    }
}

fn count_lines(path: &Path, from: u64) -> u64 {
    let Ok(mut f) = File::open(path) else { return 0 };
    if f.seek(SeekFrom::Start(from)).is_err() {
        return 0;
    }
    BufReader::new(f).split(b'\n').count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_come_back_in_order_across_segments_and_restarts() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open_with(d.path(), 1 << 20, 64).unwrap();
        for i in 0..20 {
            s.append(&format!("line-{i:02}-xxxxxxxxxxxx")).unwrap();
        }
        assert!(s.segs.len() > 3, "small segments rotate");
        let (a, pos) = s.read_batch(7, 1 << 20);
        assert_eq!(a.len(), 7);
        assert_eq!(a[0], "line-00-xxxxxxxxxxxx");
        // Not committed: a reopen reads them again (at least once).
        drop(s);
        let mut s = Spool::open_with(d.path(), 1 << 20, 64).unwrap();
        let (again, _) = s.read_batch(7, 1 << 20);
        assert_eq!(again, a);
        s.commit(pos).unwrap();
        drop(s);
        let mut s = Spool::open_with(d.path(), 1 << 20, 64).unwrap();
        let (rest, pos) = s.read_batch(100, 1 << 20);
        assert_eq!(rest.len(), 13);
        assert_eq!(rest[0], "line-07-xxxxxxxxxxxx");
        s.commit(pos).unwrap();
        assert_eq!(s.pending_bytes(), 0);
        let (none, _) = s.read_batch(100, 1 << 20);
        assert!(none.is_empty());
    }

    #[test]
    fn over_the_cap_the_oldest_unsent_lines_are_dropped_and_counted() {
        let d = tempfile::tempdir().unwrap();
        // 10 lines of 21 bytes per 64-byte segment = 3 per segment; cap 200.
        let mut s = Spool::open_with(d.path(), 200, 64).unwrap();
        for i in 0..30 {
            s.append(&format!("line-{i:02}-xxxxxxxxxxxx")).unwrap();
        }
        assert!(s.total() <= 200 + 64);
        assert!(s.dropped > 0);
        let (left, _) = s.read_batch(100, 1 << 20);
        assert_eq!(left.len() as u64 + s.dropped, 30, "every line is either kept or counted");
        assert_eq!(left.last().unwrap(), "line-29-xxxxxxxxxxxx", "the newest are kept");
    }

    #[test]
    fn a_line_cut_short_waits() {
        let d = tempfile::tempdir().unwrap();
        let mut s = Spool::open(d.path(), 1 << 20).unwrap();
        s.append("whole").unwrap();
        // Simulate a crash mid-append.
        let mut f = OpenOptions::new().append(true).open(seg_path(d.path(), 0)).unwrap();
        f.write_all(b"half").unwrap();
        let mut s = Spool::open(d.path(), 1 << 20).unwrap();
        let (got, _) = s.read_batch(10, 1 << 20);
        assert_eq!(got, vec!["whole".to_string()]);
    }
}
