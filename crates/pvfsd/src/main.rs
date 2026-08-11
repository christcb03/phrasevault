//! `pvfsd` — serve one forest over a Unix socket (doc 07). Run as the forest's
//! owner; cross-user access is gated by ACLs, not socket bits.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use pvfs_core::mount;
use pvfsd::{serve_until, Daemon};

#[derive(Parser)]
#[command(name = "pvfsd", version, about = "PVFS per-user daemon")]
struct Cli {
    /// Mount directory of the forest to serve
    #[arg(long)]
    mount: PathBuf,
    /// Socket to listen on. Default: the conventional per-forest path
    /// (`$PVFS_SOCKET_DIR/<forest_id>.sock`) so clients can find it (doc 09 §3b).
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Also serve TCP+TLS on this address (e.g. `0.0.0.0:7420`) for network
    /// clients (F1, doc 17 §4). Prints the transport pin clients must pass to
    /// `pvfs instance add` / `pvfs remote --pin`.
    #[arg(long)]
    listen: Option<String>,
}

/// RAII guard: removes the socket file on any clean exit (normal return or unwind).
/// Stale sockets from hard kills are cleared at the next startup.
struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Set by the SIGTERM/SIGINT handler; polled by the accept loop so the daemon can
/// stop accepting, checkpoint the WAL, and exit cleanly (doc 08 §4 item 4).
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Set by the SIGHUP handler; the job runner re-reads `serve.jobs` (doc 18 §2).
static RELOAD: AtomicBool = AtomicBool::new(false);

/// Async-signal-safe: a lone atomic store is all the handler does.
extern "C" fn on_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Async-signal-safe: a lone atomic store is all the handler does.
extern "C" fn on_hup(_sig: i32) {
    RELOAD.store(true, Ordering::SeqCst);
}

/// Install `on_signal` for SIGTERM and SIGINT (no `SA_RESTART`, so the poll loop's
/// sleep is interrupted promptly), and `on_hup` for SIGHUP (job-config reload).
fn install_signal_handlers() -> Result<(), Box<dyn std::error::Error>> {
    let action = SigAction::new(SigHandler::Handler(on_signal), SaFlags::empty(), SigSet::empty());
    let hup = SigAction::new(SigHandler::Handler(on_hup), SaFlags::empty(), SigSet::empty());
    // Safety: both handlers only do an async-signal-safe atomic store.
    unsafe {
        sigaction(Signal::SIGTERM, &action)?;
        sigaction(Signal::SIGINT, &action)?;
        sigaction(Signal::SIGHUP, &hup)?;
    }
    Ok(())
}

/// Best-effort sd_notify READY=1 (std-only, no libsystemd): a no-op when
/// NOTIFY_SOCKET is absent (plain runs, tests, Type=simple units).
/// Abstract-namespace notify sockets (a leading '@', rare outside
/// containers) are skipped — Rust paths cannot carry the NUL those need,
/// and best-effort means exactly that.
fn notify_systemd_ready() {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    if path.starts_with('@') {
        return;
    }
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(b"READY=1", &path);
    }
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pvfsd: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let engine = mount::open_mount(&cli.mount)?;
    let data_dir = engine.data_dir().to_path_buf();

    // A fetch killed mid-stream (SIGKILL, power loss) never runs its sink's
    // Drop, leaving `.{id}.tmp` litter in the sync store that leaks disk if
    // the file is never re-fetched. Sinks are process-local, so nothing holds
    // a tmp across restarts — sweep before the job runner can begin a fetch.
    // Best-effort: a failed sweep is worth a warning, never a refused start.
    match pvfs_core::sync::sweep_orphan_tmps(&data_dir) {
        Ok(0) => {}
        Ok(n) => eprintln!("pvfsd: removed {n} orphaned sync tmp file(s)"),
        Err(e) => eprintln!("pvfsd: sync tmp sweep failed: {e}"),
    }

    let socket = match &cli.socket {
        Some(s) => s.clone(),
        None => {
            let dir = mount::daemon_socket_dir();
            // Create the socket dir on first use and make it world-traversable +
            // sticky (like /tmp), so other users can reach the socket but can't
            // delete each other's. If it already exists we leave its mode alone:
            // a root-managed `/run/pvfs` (tmpfiles.d, mode 1777) is shared by all
            // users' daemons, and a non-root daemon must not try to chmod it.
            if !dir.exists() {
                std::fs::create_dir_all(&dir)?;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777))?;
            }
            mount::daemon_socket_path(&engine.identity.forest_id)
        }
    };

    let daemon = Arc::new(Daemon::new(engine));
    let _ = std::fs::remove_file(&socket); // clear a stale socket from a previous hard kill
    let listener = UnixListener::bind(&socket)?;
    // World-connectable; the daemon enforces ACLs per request (doc 07 §1).
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;

    // Remove the socket on any clean exit (normal return, panic unwind, or error).
    let _guard = SocketGuard(socket.clone());

    // SIGTERM/SIGINT → stop accepting, checkpoint, exit cleanly (doc 08 §4 item 4).
    install_signal_handlers()?;

    // The P5 job runner (doc 18 §2): reads `serve.jobs`, reloads on SIGHUP.
    // A corrupt config refuses startup — loud beats silently jobless.
    let jobs = Arc::new(pvfsd::jobs::JobsState::load(data_dir.clone())?);
    daemon.attach_jobs(Arc::clone(&jobs));
    let jobs_thread = {
        let j = Arc::clone(&jobs);
        std::thread::spawn(move || pvfsd::jobs::run(j, &SHUTDOWN, &RELOAD))
    };

    // Network listener (F1, doc 17 §4): TCP+TLS alongside the Unix socket,
    // sharing the daemon and the shutdown flag.
    let mut tls_thread = None;
    if let Some(addr) = &cli.listen {
        let tls = pvfsd::nettls::load_or_generate(&data_dir)?;
        let tcp = std::net::TcpListener::bind(addr)?;
        eprintln!(
            "pvfsd: listening on {} (transport pin {})",
            tcp.local_addr()?,
            tls.pin
        );
        let d = Arc::clone(&daemon);
        let cfg = Arc::clone(&tls.config);
        tls_thread = Some(std::thread::spawn(move || {
            let _ = pvfsd::serve_tls_until(tcp, cfg, d, &SHUTDOWN);
        }));
    }

    eprintln!(
        "pvfsd: serving {} on {}",
        cli.mount.display(),
        socket.display()
    );
    // Tell systemd we are SERVING — a Type=notify unit holds dependents
    // (pvosd's After=pvfsd) until this moment, not "process exists". The
    // forest replay above can run minutes on a grown library; "started
    // but not yet serving" is exactly the window that crash-looped pvosd
    // three times (PVOS D49/D55/M4b close-outs).
    notify_systemd_ready();
    serve_until(listener, Arc::clone(&daemon), &SHUTDOWN)?;

    // Graceful stop: flush the WAL and record a clean shutdown so the next start is
    // fast. In-flight connection threads are best-effort; the socket is removed by
    // `_guard` on return. The TLS accept loop polls the same flag — join it so its
    // listener closes before the checkpoint.
    if let Some(t) = tls_thread {
        let _ = t.join();
    }
    let _ = jobs_thread.join();
    eprintln!("pvfsd: shutting down (checkpointing)");
    daemon.shutdown_checkpoint()?;
    Ok(())
}
