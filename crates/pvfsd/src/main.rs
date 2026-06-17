//! `pvfsd` — serve one forest over a Unix socket (doc 07). Run as the forest's
//! owner; cross-user access is gated by ACLs, not socket bits.

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
    /// Unix socket path to listen on
    #[arg(long)]
    socket: PathBuf,
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
    let daemon = Arc::new(Daemon::new(engine));

    let _ = std::fs::remove_file(&cli.socket); // clear a stale socket
    let listener = UnixListener::bind(&cli.socket)?;
    // World-connectable; the daemon enforces ACLs per request (doc 07 §1).
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&cli.socket, std::fs::Permissions::from_mode(0o666))?;
    }
    eprintln!(
        "pvfsd: serving {} on {}",
        cli.mount.display(),
        cli.socket.display()
    );
    serve(listener, daemon)?;
    Ok(())
}
