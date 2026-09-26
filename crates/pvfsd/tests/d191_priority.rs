//! PVOS D191 — serving at the daemon's priority, background below it. The
//! hashing pool's workers and the job supervisor (whose passes start with
//! its priority) run at nice +10 in the idle disk class, while the thread
//! that hashes or starts them keeps its own; `PVFSD_BACKGROUND=normal` keeps
//! background at the daemon's priority. One test, in order, in its own
//! binary: the pool is made once per process and the switch is
//! process-wide.
#![cfg(target_os = "linux")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pvfs_core::Engine;
use pvfsd::jobs::JobsState;
use pvfsd::priority::{self, current_tid, thread_priority, BACKGROUND_ENV, BACKGROUND_NICE, IO_CLASS_IDLE};

/// The kernel id of this process's thread called `name`.
fn tid_named(name: &str) -> Option<i32> {
    for e in std::fs::read_dir("/proc/self/task").ok()?.flatten() {
        let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default();
        if comm.trim_end() == name {
            return e.file_name().to_str()?.parse().ok();
        }
    }
    None
}

/// The supervisor as pvfsd starts it, with its flag and its thread's id.
fn supervisor(data_dir: std::path::PathBuf) -> (i32, &'static AtomicBool, std::thread::JoinHandle<()>) {
    let jobs = Arc::new(JobsState::load(data_dir).unwrap());
    let shutdown: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let reload: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let handle = pvfsd::jobs::spawn_supervisor(jobs, shutdown, reload, None).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let tid = loop {
        if let Some(t) = tid_named("pvfsd-jobs") {
            break t;
        }
        assert!(Instant::now() < deadline, "no thread named pvfsd-jobs");
        std::thread::sleep(Duration::from_millis(20));
    };
    (tid, shutdown, handle)
}

#[test]
fn background_runs_below_serving_unless_told_otherwise() {
    std::env::remove_var(BACKGROUND_ENV);
    let base = thread_priority(current_tid()).unwrap();
    let lowered = ((base.0 + BACKGROUND_NICE).min(19), IO_CLASS_IDLE);

    // 1. The hashing pool, built first as pvfsd's start does: its workers are
    //    named and lowered, though a normal-priority thread is the first to
    //    hash on it.
    priority::build_hash_pool();
    let (name, on_pool) = rayon_core::scope(|_| {
        (std::thread::current().name().map(String::from), thread_priority(current_tid()).unwrap())
    });
    assert!(name.as_deref().is_some_and(|n| n.starts_with("pvfsd-hash-")), "ran on {name:?}");
    assert_eq!(on_pool, lowered, "a hashing worker runs below serving");
    let bytes = vec![7u8; 8 << 20];
    let mut hasher = blake3::Hasher::new();
    hasher.update_rayon(&bytes);
    assert_eq!(thread_priority(current_tid()).unwrap(), base, "the thread that hashed keeps its priority");

    // 2. The supervisor lowers itself before it spawns anything.
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    let (tid, stop, runner) = supervisor(data_dir.clone());
    let deadline = Instant::now() + Duration::from_secs(5);
    while thread_priority(tid).unwrap() != lowered {
        assert!(Instant::now() < deadline, "the supervisor never lowered itself: {:?}", thread_priority(tid));
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(thread_priority(current_tid()).unwrap(), base, "the thread that started it keeps its priority");
    stop.store(true, Ordering::SeqCst);
    runner.join().unwrap();

    // 3. PVFSD_BACKGROUND=normal: the supervisor stays at the daemon's.
    std::env::set_var(BACKGROUND_ENV, "normal");
    let (tid, stop, runner) = supervisor(data_dir);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(thread_priority(tid).unwrap(), base, "normal keeps background at the daemon's priority");
    stop.store(true, Ordering::SeqCst);
    runner.join().unwrap();
    std::env::remove_var(BACKGROUND_ENV);
}
