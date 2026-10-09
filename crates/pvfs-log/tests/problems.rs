//! PVOS D230 — a process's failures, structured, in a file of their own:
//! warnings and errors go in, nothing quieter does; it rotates at its cap;
//! it reads back by time, skipping a torn line. One test: the file is
//! process-wide.

use std::io::Write;

use pvfs_log::problems::{self, CAP_BYTES};
use pvfs_log::{content, pv_error, pv_info, pv_notice, pv_warn};

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

#[test]
fn failures_go_to_the_problems_file_and_read_back_by_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sub").join(problems::FILE_NAME);
    let before = now();
    // Nothing is kept before a file is named.
    pv_warn!("pvfs.test.before_open", error_kind = "other"; "pvfsd: before");
    problems::open(path.clone());
    assert_eq!(problems::path().as_deref(), Some(path.as_path()));
    assert!(path.parent().unwrap().is_dir(), "its directory is made");

    let e = std::io::Error::from_raw_os_error(28);
    pv_warn!("pvfs.receive.failed", path = content("/data/a.mkv"), error = content(&e); "pvfsd: receive /data/a.mkv: {e}");
    pv_error!("pvfs.serve.fatal", error = content("boom"), error_kind = "internal:test"; "pvfsd: boom");
    pv_notice!("pvfs.test.notice"; "pvfsd: a notice");
    pv_info!("pvfs.test.info"; "pvfsd: an info");

    let (recs, left_out) = problems::read_since(&path, before, 300);
    assert_eq!(left_out, 0);
    let events: Vec<&str> = recs.iter().map(|r| r.event.as_str()).collect();
    assert_eq!(events, ["pvfs.receive.failed", "pvfs.serve.fatal"], "warnings and errors only, oldest first");
    assert_eq!(recs[0].line(), "pvfsd: receive /data/a.mkv: No space left on device (os error 28)", "the box's own (full) rendering");
    let kind = |r: &pvfs_log::Record| r.fields.iter().find(|f| f.name == "error_kind").map(|f| f.value.to_string());
    assert_eq!(kind(&recs[0]).as_deref(), Some("disk:no_space"));
    assert_eq!(kind(&recs[1]).as_deref(), Some("internal:test"));

    // Since a later time: none. The newest `max`, and how many were left out.
    assert!(problems::read_since(&path, now() + 60_000, 300).0.is_empty());
    let (one, left) = problems::read_since(&path, before, 1);
    assert_eq!((one.len(), left), (1, 1));
    assert_eq!(one[0].event, "pvfs.serve.fatal");

    // A torn last line (a write cut short) is skipped, the rest still read.
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{\"v\":1,\"id\":\"cut").unwrap();
    assert_eq!(problems::read_since(&path, before, 300).0.len(), 2);

    // Past the cap the file becomes `.1`; both are read, in time order.
    let big = "x".repeat(4096);
    let n = (CAP_BYTES as usize / 4096) + 8;
    for i in 0..n {
        pv_warn!("pvfs.test.filler", n = i, error_kind = "other"; "pvfsd: filler {i} {big}");
    }
    let older = problems::older(&path);
    assert!(older.is_file(), "rotated");
    assert!(std::fs::metadata(&path).unwrap().len() < CAP_BYTES);
    assert!(std::fs::metadata(&older).unwrap().len() <= CAP_BYTES + 8192);
    let (all, _) = problems::read_since(&path, before, 100_000);
    let fillers: Vec<u64> = all
        .iter()
        .filter(|r| r.event == "pvfs.test.filler")
        .filter_map(|r| r.fields.iter().find(|f| f.name == "n").and_then(|f| f.value.to_string().parse().ok()))
        .collect();
    assert!(fillers.windows(2).all(|w| w[0] < w[1]), "in order across the two files");
    assert_eq!(fillers.last().copied(), Some(n as u64 - 1), "the newest is there");
}
