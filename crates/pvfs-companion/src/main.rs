//! `pvfs-companion` — the local key vault + signing agent (doc 14).
//!
//! `init` seals a recovery phrase (read from stdin) into a vault; `serve` unlocks
//! it and serves the signer socket. The vault passphrase comes from
//! `$PVFS_COMPANION_PASSPHRASE` (phase 3; OS-keychain unlock and an interactive
//! prompt are doc 14 §9 phases 4–5). Headless by default: a root device-cert
//! signature is only auto-approved with `--allow-root`.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use pvfs_companion::{serve, Agent, ApprovalPolicy, UnlockedSigner, Vault};

#[derive(Parser)]
#[command(name = "pvfs-companion", version, about = "PVFS companion — key vault + signing agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Seal a recovery phrase (read from stdin) into a new vault.
    /// Passphrase from $PVFS_COMPANION_PASSPHRASE.
    Init {
        #[arg(long)]
        vault: PathBuf,
    },
    /// Unlock the vault and serve the signer socket. Passphrase from
    /// $PVFS_COMPANION_PASSPHRASE. `--allow-root` opts a headless agent into
    /// signing root device certs (admit/revoke) without an interactive prompt.
    Serve {
        #[arg(long)]
        vault: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        allow_root: bool,
    },
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pvfs-companion: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn passphrase() -> Result<String, String> {
    std::env::var("PVFS_COMPANION_PASSPHRASE")
        .map_err(|_| "set $PVFS_COMPANION_PASSPHRASE".to_string())
}

fn run() -> Result<(), String> {
    match Cli::parse().cmd {
        Cmd::Init { vault } => {
            let pass = passphrase()?;
            let mut phrase = String::new();
            std::io::stdin()
                .read_to_string(&mut phrase)
                .map_err(|e| e.to_string())?;
            let phrase = phrase.trim();
            if phrase.is_empty() {
                return Err("no recovery phrase on stdin".into());
            }
            Vault::create(&vault, phrase.as_bytes(), pass.as_bytes()).map_err(|e| e.to_string())?;
            eprintln!("pvfs-companion: sealed vault at {}", vault.display());
            Ok(())
        }
        Cmd::Serve {
            vault,
            socket,
            allow_root,
        } => {
            let pass = passphrase()?;
            let secret = Vault::open(&vault)
                .map_err(|e| e.to_string())?
                .unseal(pass.as_bytes())
                .map_err(|e| e.to_string())?;
            let signer = UnlockedSigner::from_phrase(
                std::str::from_utf8(&secret).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            let policy = ApprovalPolicy {
                auto_root: allow_root,
                ..Default::default()
            };
            let agent = Arc::new(Agent::new(signer, policy));

            let _ = std::fs::remove_file(&socket); // clear a stale socket
            let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
            // Owner-only: the socket mode is the authentication (doc 14 §3).
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            eprintln!("pvfs-companion: serving on {}", socket.display());
            serve(listener, agent).map_err(|e| e.to_string())?;
            Ok(())
        }
    }
}
