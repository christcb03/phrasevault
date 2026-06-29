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

/// Async-signal-safe: a lone atomic store is all the handler does.
extern "C" fn on_signal(_sig: i32) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

/// Install `on_signal` for SIGTERM and SIGINT (no `SA_RESTART`, so the poll loop's
/// sleep is interrupted promptly).
fn install_signal_handlers() -> Result<(), Box<dyn std::error::Error>> {
    let action = SigAction::new(SigHandler::Handler(on_signal), SaFlags::empty(), SigSet::empty());
    // Safety: `on_signal` only does an async-signal-safe atomic store.
    unsafe {
        sigaction(Signal::SIGTERM, &action)?;
        sigaction(Signal::SIGINT, &action)?;
    }
    Ok(())
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

    let socket = match &cli.socket {
        Some(s) => s.clone(),
        None => {
            let dir = mount::daemon_socket_dir();
            std::fs::create_dir_all(&dir)?;
            // World-traversable + sticky (like /tmp), so other users can reach the
            // socket but can't delete each other's.
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777))?;
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

    eprintln!(
        "pvfsd: serving {} on {}",
        cli.mount.display(),
        socket.display()
    );
    serve_until(listener, Arc::clone(&daemon), &SHUTDOWN)?;

    // Graceful stop: flush the WAL and record a clean shutdown so the next start is
    // fast. In-flight connection threads are best-effort; the socket is removed by
    // `_guard` on return.
    eprintln!("pvfsd: shutting down (checkpointing)");
    daemon.shutdown_checkpoint()?;
    Ok(())
}
