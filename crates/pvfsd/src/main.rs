//! `pvfsd` — serve one forest over a Unix socket (doc 07). Run as the forest's
//! owner; cross-user access is gated by ACLs, not socket bits.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use pvfs_core::mount;
use pvfsd::{serve, Daemon};

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
    let _ = std::fs::remove_file(&socket); // clear a stale socket
    let listener = UnixListener::bind(&socket)?;
    // World-connectable; the daemon enforces ACLs per request (doc 07 §1).
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666))?;
    eprintln!(
        "pvfsd: serving {} on {}",
        cli.mount.display(),
        socket.display()
    );
    serve(listener, daemon)?;
    Ok(())
}
