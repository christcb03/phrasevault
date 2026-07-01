//! `pvfs-companion` — the local key vault + signing agent (doc 14).
//!
//! `init` seals a recovery phrase (read from stdin) into a vault; `serve` unlocks
//! it and serves the signer socket. Two sealings (doc 14 §5): `--keychain` holds
//! the data key in the OS secret store (unlock needs nothing), otherwise the
//! passphrase comes from `$PVFS_COMPANION_PASSPHRASE` (an interactive prompt is
//! doc 14 §9 phase 5). Headless by default: a root device-cert signature is only
//! auto-approved with `--allow-root`.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use pvfs_companion::{
    serve, serve_tenant, tenant_request, Agent, ApprovalPolicy, Sessions, TenantAgent,
    TenantRequest, TenantResponse, UnlockedSigner, Vault, VaultStore,
};

#[derive(Parser)]
#[command(name = "pvfs-companion", version, about = "PVFS companion — key vault + signing agent")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Seal a recovery phrase (read from stdin) into a new vault. Default:
    /// passphrase-sealed from $PVFS_COMPANION_PASSPHRASE; pass --keychain to
    /// hold the data key in the OS keychain instead (no passphrase at all).
    Init {
        #[arg(long)]
        vault: PathBuf,
        /// Seal via the OS secret store (macOS Keychain / Secret Service /
        /// Credential Manager) — doc 14 §5. Unlock then needs no env var.
        #[arg(long)]
        keychain: bool,
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
    /// Server / multi-tenant custody (doc 14 §13): seal a phrase (stdin) into the
    /// per-user store under `--user`. Passphrase = that user's from the env.
    TenantInit {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        user: String,
    },
    /// Serve the multi-tenant custody socket over a per-user vault store.
    ServeTenant {
        #[arg(long)]
        store: PathBuf,
        #[arg(long)]
        socket: PathBuf,
        /// Cap on how long a trusted session may cache an unlocked key.
        #[arg(long, default_value_t = 3600)]
        max_ttl_secs: u64,
    },
    /// Client/ops helper: print a user's public key via a running tenant agent.
    /// Passphrase from $PVFS_COMPANION_PASSPHRASE.
    TenantPubkey {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        user: String,
        #[arg(long, default_value = "identity")]
        role: String,
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

/// Seal into / unseal from the OS keychain — compiled out without `os-keychain`,
/// where a keychain vault is a clear error instead (the passphrase path is
/// always available; doc 14 §5 fallback).
fn keychain_create(vault: &std::path::Path, phrase: &[u8]) -> Result<(), String> {
    #[cfg(feature = "os-keychain")]
    {
        pvfs_companion::Vault::create_keychain(
            vault,
            phrase,
            &pvfs_companion::OsKeychain::new(),
        )
        .map_err(|e| e.to_string())
    }
    #[cfg(not(feature = "os-keychain"))]
    {
        let _ = (vault, phrase);
        Err("this build has no os-keychain support (rebuild with the default features)".into())
    }
}

fn keychain_unseal(vault: &pvfs_companion::Vault) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    #[cfg(feature = "os-keychain")]
    {
        vault
            .unseal_keychain(&pvfs_companion::OsKeychain::new())
            .map_err(|e| e.to_string())
    }
    #[cfg(not(feature = "os-keychain"))]
    {
        let _ = vault;
        Err("vault is keychain-sealed but this build has no os-keychain support".into())
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().cmd {
        Cmd::Init { vault, keychain } => {
            let mut phrase = String::new();
            std::io::stdin()
                .read_to_string(&mut phrase)
                .map_err(|e| e.to_string())?;
            let phrase = phrase.trim();
            if phrase.is_empty() {
                return Err("no recovery phrase on stdin".into());
            }
            if keychain {
                keychain_create(&vault, phrase.as_bytes())?;
                eprintln!(
                    "pvfs-companion: sealed vault at {} (data key in the OS keychain)",
                    vault.display()
                );
            } else {
                let pass = passphrase()?;
                Vault::create(&vault, phrase.as_bytes(), pass.as_bytes())
                    .map_err(|e| e.to_string())?;
                eprintln!("pvfs-companion: sealed vault at {}", vault.display());
            }
            Ok(())
        }
        Cmd::Serve {
            vault,
            socket,
            allow_root,
        } => {
            let v = Vault::open(&vault).map_err(|e| e.to_string())?;
            let secret = match v.sealing() {
                pvfs_companion::Sealing::Keychain => keychain_unseal(&v)?,
                pvfs_companion::Sealing::Passphrase => {
                    let pass = passphrase()?;
                    v.unseal(pass.as_bytes()).map_err(|e| e.to_string())?
                }
            };
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
        Cmd::TenantInit { store, user } => {
            let pass = passphrase()?;
            let mut phrase = String::new();
            std::io::stdin()
                .read_to_string(&mut phrase)
                .map_err(|e| e.to_string())?;
            let phrase = phrase.trim();
            if phrase.is_empty() {
                return Err("no recovery phrase on stdin".into());
            }
            let store = VaultStore::open(&store).map_err(|e| e.to_string())?;
            store
                .create(&user, phrase.as_bytes(), pass.as_bytes())
                .map_err(|e| e.to_string())?;
            eprintln!("pvfs-companion: provisioned tenant {user}");
            Ok(())
        }
        Cmd::ServeTenant {
            store,
            socket,
            max_ttl_secs,
        } => {
            let store = VaultStore::open(&store).map_err(|e| e.to_string())?;
            let agent = Arc::new(TenantAgent::new(
                Sessions::new(store),
                Duration::from_secs(max_ttl_secs),
            ));
            let _ = std::fs::remove_file(&socket);
            let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
            eprintln!("pvfs-companion: serving tenant custody on {}", socket.display());
            serve_tenant(listener, agent).map_err(|e| e.to_string())?;
            Ok(())
        }
        Cmd::TenantPubkey {
            socket,
            user,
            role,
        } => {
            let pass = passphrase()?;
            let resp = tenant_request(
                &socket,
                &TenantRequest::GetPubkey {
                    user_id: user,
                    passphrase: pass,
                    role,
                },
            )
            .map_err(|e| e.to_string())?;
            match resp {
                TenantResponse::Pubkey { pubkey } => {
                    println!("{pubkey}");
                    Ok(())
                }
                TenantResponse::Error { code, message } => Err(format!("{code}: {message}")),
                _ => Err("unexpected response".into()),
            }
        }
    }
}
