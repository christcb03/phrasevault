//! PVOS D191 — serving at the daemon's priority, background below it.
//!
//! mediabox's unit used to lower the WHOLE daemon (nice 10, best-effort 7):
//! its serving threads too (writes through the view mount, other boxes'
//! reads). And its disk half did nothing there — mq-deadline, the media disks'
//! scheduler, orders requests by class and ignores the level inside
//! best-effort. Now the daemon runs at the unit's priority and its
//! background lowers itself: the job supervisor before it spawns any pass
//! (a Linux thread starts with its creator's nice value and I/O priority, so
//! every pass inherits it), and each worker of the hashing pool, which a
//! write's commit on a connection thread shares with the passes.
//!
//! Lowered = nice +10 (capped at 19) and the idle I/O class, which
//! mq-deadline honours — its `prio_aging_expire` (10 s) keeps an idle
//! request from waiting forever. `PVFSD_BACKGROUND` changes the step: a
//! number from 1 to 19 (the NAS: 19, D88's level), or `normal` to leave the
//! background at the daemon's priority.

/// How far below the daemon's nice value background threads run, unless
/// [`BACKGROUND_ENV`] says otherwise.
pub const BACKGROUND_NICE: i32 = 10;

/// The environment switch: a step from 1 to 19, or `normal` to keep
/// background at the daemon's priority.
pub const BACKGROUND_ENV: &str = "PVFSD_BACKGROUND";

/// I/O priority classes as `ioprio_get` reports them.
pub const IO_CLASS_NONE: u32 = 0;
pub const IO_CLASS_BEST_EFFORT: u32 = 2;
pub const IO_CLASS_IDLE: u32 = 3;

/// How far below the daemon background work runs: [`BACKGROUND_NICE`], the
/// step [`BACKGROUND_ENV`] names, or `None` when it says `normal`.
pub fn background_step() -> Option<i32> {
    step_by(std::env::var(BACKGROUND_ENV).ok().as_deref())
}

/// Whether background work runs below the daemon.
pub fn background_lowered() -> bool {
    background_step().is_some()
}

fn step_by(value: Option<&str>) -> Option<i32> {
    match value.map(str::trim) {
        Some("normal") => None,
        Some(v) => match v.parse::<i32>() {
            Ok(n) if (1..=19).contains(&n) => Some(n),
            _ => Some(BACKGROUND_NICE),
        },
        None => Some(BACKGROUND_NICE),
    }
}

/// The journal's line for the policy in force.
pub fn policy_line() -> String {
    match background_step() {
        Some(step) => format!(
            "pvfsd: background work (jobs, hashing) at nice +{step} and the idle disk class, below \
             serving — {BACKGROUND_ENV}=normal keeps it at the daemon's priority"
        ),
        None => format!("pvfsd: background work at the daemon's priority ({BACKGROUND_ENV}=normal)"),
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io;

    const IOPRIO_WHO_PROCESS: libc::c_int = 1;
    const IOPRIO_CLASS_SHIFT: u32 = 13;
    const IOPRIO_IDLE: libc::c_int = (super::IO_CLASS_IDLE << IOPRIO_CLASS_SHIFT) as libc::c_int;

    pub fn current_tid() -> i32 {
        // SAFETY: gettid takes no arguments and cannot fail.
        unsafe { libc::syscall(libc::SYS_gettid) as i32 }
    }

    fn nice_of(tid: i32) -> io::Result<i32> {
        // -1 is a valid nice value, so only errno can say it failed.
        // SAFETY: errno is thread-local; getpriority reads no memory of ours.
        unsafe { *libc::__errno_location() = 0 };
        let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, tid as libc::id_t) };
        if nice == -1 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(0) {
                return Err(e);
            }
        }
        Ok(nice)
    }

    pub fn thread_priority(tid: i32) -> io::Result<(i32, u32)> {
        let nice = nice_of(tid)?;
        // SAFETY: ioprio_get takes two integers and reads no memory of ours.
        let io = unsafe { libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, tid as libc::c_int) };
        if io < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((nice, (io as u32) >> IOPRIO_CLASS_SHIFT))
    }

    pub fn lower_this_thread(step: i32) -> io::Result<()> {
        let tid = current_tid();
        let target = (nice_of(tid)? + step).min(19);
        // SAFETY: setpriority takes integers and reads no memory of ours;
        // with this thread's id it changes this thread alone.
        if unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, target) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: as above, for ioprio_set.
        if unsafe { libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, tid as libc::c_int, IOPRIO_IDLE) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;

    pub fn current_tid() -> i32 {
        0
    }

    pub fn thread_priority(_tid: i32) -> io::Result<(i32, u32)> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "thread priorities are read on Linux only"))
    }

    pub fn lower_this_thread(_step: i32) -> io::Result<()> {
        Ok(())
    }
}

/// The calling thread's kernel id (Linux; 0 elsewhere).
pub fn current_tid() -> i32 {
    imp::current_tid()
}

/// A thread's nice value and I/O priority class ([`IO_CLASS_IDLE`], …).
pub fn thread_priority(tid: i32) -> std::io::Result<(i32, u32)> {
    imp::thread_priority(tid)
}

/// Lower the calling thread to background priority: nice +`step` (capped
/// at 19) and the idle I/O class; threads it spawns afterwards inherit both.
/// There is no way back without privilege, so only threads that do nothing
/// but background work call this. A no-op off Linux.
pub fn lower_this_thread(step: i32) -> std::io::Result<()> {
    imp::lower_this_thread(step)
}

/// Lower the calling thread if the policy says so; a failure is said, never
/// fatal (the work runs, at the daemon's priority).
pub fn enter_background(what: &str) {
    if let Some(step) = background_step() {
        if let Err(e) = lower_this_thread(step) {
            eprintln!("pvfsd: {what} stays at the daemon's priority: {e}");
        }
    }
}

/// Build rayon's global pool — BLAKE3's parallel hashing runs on it — with
/// named workers (`pvfsd-hash-<n>`) that lower themselves. Call it before
/// anything hashes: otherwise the pool is made by its first user, and its
/// threads keep that thread's priority, whatever it is.
pub fn build_hash_pool() {
    let step = background_step();
    let built = rayon_core::ThreadPoolBuilder::new()
        .thread_name(|i| format!("pvfsd-hash-{i}"))
        .start_handler(move |_| {
            if let Some(step) = step {
                let _ = lower_this_thread(step);
            }
        })
        .build_global();
    if let Err(e) = built {
        eprintln!("pvfsd: hashing pool: {e} (its threads keep the priority of whatever made them)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_names_a_step_or_normal() {
        assert_eq!(step_by(None), Some(BACKGROUND_NICE));
        assert_eq!(step_by(Some("")), Some(BACKGROUND_NICE));
        assert_eq!(step_by(Some("low")), Some(BACKGROUND_NICE));
        assert_eq!(step_by(Some("19")), Some(19), "the NAS: D88's level");
        assert_eq!(step_by(Some(" 5\n")), Some(5));
        assert_eq!(step_by(Some("0")), Some(BACKGROUND_NICE), "out of range: the default");
        assert_eq!(step_by(Some("40")), Some(BACKGROUND_NICE));
        assert_eq!(step_by(Some("normal")), None);
        assert_eq!(step_by(Some(" normal\n")), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_lowered_thread_and_what_it_spawns_run_below_the_rest() {
        let me = thread_priority(current_tid()).unwrap();
        let (lowered, child) = std::thread::spawn(|| {
            lower_this_thread(BACKGROUND_NICE).unwrap();
            let lowered = thread_priority(current_tid()).unwrap();
            let child = std::thread::spawn(|| thread_priority(current_tid()).unwrap()).join().unwrap();
            (lowered, child)
        })
        .join()
        .unwrap();
        let want = ((me.0 + BACKGROUND_NICE).min(19), IO_CLASS_IDLE);
        assert_eq!(lowered, want, "the lowered thread");
        assert_eq!(child, want, "a thread it spawned inherits both");
        let sibling = std::thread::spawn(|| thread_priority(current_tid()).unwrap()).join().unwrap();
        assert_eq!(sibling, me, "a thread that never lowered keeps the process's priority");
        assert_eq!(thread_priority(current_tid()).unwrap(), me, "and so does the caller");
        assert_ne!(me.1, IO_CLASS_IDLE, "the test itself does not run in the idle class");
    }
}
