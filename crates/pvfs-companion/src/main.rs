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
    /// Seal your recovery phrase into a vault. Run it bare: it prompts for the
    /// phrase, validates it, prefers the OS keychain, and falls back to a
    /// prompted passphrase. Flags/env are for scripts and special setups.
    Init {
        /// Vault file (default: ~/.config/pvfs/companion.vault, or $PVFS_COMPANION_VAULT)
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Force OS-keychain sealing (fail rather than fall back)
        #[arg(long)]
        keychain: bool,
        /// Force passphrase sealing (opt out of the OS keychain)
        #[arg(long)]
        passphrase: bool,
    },
    /// Unlock the vault and serve the signer socket. Run it bare: keychain
    /// vaults unlock silently; passphrase vaults prompt (or use
    /// $PVFS_COMPANION_PASSPHRASE when scripted). `--allow-root` opts a
    /// headless agent into signing root device certs without a prompt.
    Serve {
        /// Vault file (default: ~/.config/pvfs/companion.vault, or $PVFS_COMPANION_VAULT)
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Socket path (default: $XDG_RUNTIME_DIR/pvfs-companion.sock, or $PVFS_COMPANION_SOCKET)
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long)]
        allow_root: bool,
        /// Drop the seed after this many idle seconds; it re-unlocks on demand
        /// (keychain/env silently, terminal by prompt). 0 disables.
        #[arg(long, default_value_t = 900)]
        idle_lock_secs: u64,
        /// Max signatures per minute (doc 14 §4 rate limit). 0 disables.
        #[arg(long, default_value_t = 60)]
        rate_limit: u32,
        /// Approval prompt backend. `auto` picks desktop/terminal/deny; scripts
        /// and services should pass `deny` so a prompt can never block them.
        #[arg(long, default_value = "auto", value_parser = ["auto", "deny", "terminal", "desktop"])]
        prompt: String,
        /// Loopback web-agent port (M3.1: stable so pages need no lookup;
        /// 0 = ephemeral, previous behavior).
        #[arg(long, default_value_t = 7421)]
        web_port: u16,
    },
    /// Lock a running agent now: the seed is dropped from memory. The next
    /// request re-unlocks it (keychain/env/prompt) — or is refused if it can't.
    Lock {
        /// Socket path (default: $XDG_RUNTIME_DIR/pvfs-companion.sock, or $PVFS_COMPANION_SOCKET)
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    /// List the web origins connected for "Sign in with PVFS" — or revoke one.
    Origins {
        #[command(subcommand)]
        cmd: Option<OriginsCmd>,
        /// Vault file (grants live next to it; default: the usual vault path)
        #[arg(long)]
        vault: Option<PathBuf>,
    },
    /// Show the vault and agent state: where the vault is and how it's sealed,
    /// whether the signing agent is running, and whether a keychain-sealed
    /// vault's data key is still present (an orphaned vault needs re-init).
    Status {
        /// Vault file (default: ~/.config/pvfs/companion.vault, or $PVFS_COMPANION_VAULT)
        #[arg(long)]
        vault: Option<PathBuf>,
        /// Socket path (default: $XDG_RUNTIME_DIR/pvfs-companion.sock, or $PVFS_COMPANION_SOCKET)
        #[arg(long)]
        socket: Option<PathBuf>,
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
    /// Print a fresh 24-word recovery phrase (for GUI setup: create-new flow).
    /// The phrase is not stored; the caller must seal it with `init` or show it
    /// once for the user to write down.
    PhraseNew,
    /// List paired servers (PVOS M3.1) — or revoke one.
    Pairings {
        #[command(subcommand)]
        cmd: Option<PairingsCmd>,
        /// Vault file (pairings live next to it; default: the usual vault path)
        #[arg(long)]
        vault: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum OriginsCmd {
    /// Disconnect an origin — takes effect immediately, even while serving.
    Revoke { origin: String },
}

#[derive(Subcommand)]
enum PairingsCmd {
    /// Remove a pairing by name — takes effect immediately, even while serving.
    Revoke { name: String },
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

fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Read the recovery phrase — a prompt on a terminal, stdin when piped — and
/// validate it, so a typo fails HERE, not later at `serve`.
fn read_phrase() -> Result<String, String> {
    let mut phrase = String::new();
    if interactive() {
        eprintln!("Paste your recovery phrase (shown when the forest was created):");
        std::io::stdin()
            .read_line(&mut phrase)
            .map_err(|e| e.to_string())?;
    } else {
        std::io::stdin()
            .read_to_string(&mut phrase)
            .map_err(|e| e.to_string())?;
    }
    let phrase = phrase.trim().to_string();
    if phrase.is_empty() {
        return Err("no recovery phrase provided".into());
    }
    pvfs_core::identity::parse_mnemonic(&phrase)
        .map_err(|_| "that is not a valid recovery phrase — check the words and their order")?;
    Ok(phrase)
}

/// Choose a new vault passphrase interactively (hidden input, confirmed).
fn prompt_new_passphrase() -> Result<String, String> {
    for _ in 0..3 {
        let a = rpassword::prompt_password("Choose a vault passphrase: ")
            .map_err(|e| e.to_string())?;
        if a.is_empty() {
            eprintln!("The passphrase cannot be empty — try again.");
            continue;
        }
        let b = rpassword::prompt_password("Confirm it: ").map_err(|e| e.to_string())?;
        if a == b {
            return Ok(a);
        }
        eprintln!("Those don't match — try again.");
    }
    Err("giving up after 3 attempts".into())
}

/// The passphrase for unlocking: the env var when scripted, a prompt on a terminal.
fn unlock_passphrase() -> Result<String, String> {
    if let Ok(p) = std::env::var("PVFS_COMPANION_PASSPHRASE") {
        return Ok(p);
    }
    if interactive() {
        return rpassword::prompt_password("Vault passphrase: ").map_err(|e| e.to_string());
    }
    Err("set $PVFS_COMPANION_PASSPHRASE".into())
}

fn default_vault() -> Result<std::path::PathBuf, String> {
    pvfs_companion::default_vault_path()
}

/// "expires in 29d" / "in 5h" / "in 12m" for the origins listing.
fn fmt_expiry(expires_at_ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let left = expires_at_ms.saturating_sub(now) / 1000;
    if left >= 86_400 {
        format!("in {}d", left / 86_400)
    } else if left >= 3_600 {
        format!("in {}h", left / 3_600)
    } else {
        format!("in {}m", left / 60)
    }
}

/// Open + unseal the vault (either sealing) into a signer. Also the body of the
/// agent's `Unlocker`, so a lock re-unlocks exactly the way `serve` unlocked.
fn unseal_signer(vault: &std::path::Path) -> Result<UnlockedSigner, String> {
    let v = Vault::open(vault).map_err(|e| e.to_string())?;
    let secret = match v.sealing() {
        pvfs_companion::Sealing::Keychain => keychain_unseal(&v)?,
        pvfs_companion::Sealing::Passphrase => {
            let pass = unlock_passphrase()?;
            v.unseal(pass.as_bytes()).map_err(|e| e.to_string())?
        }
    };
    Ok(
        UnlockedSigner::from_phrase(std::str::from_utf8(&secret).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
            // doc 15 §1: the vault names which 3'/<id>' key is the identity.
            .with_identity(v.identity_index()),
    )
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

/// Can the keychain-sealed vault's data key still be fetched? (`status`)
fn keychain_probe(vault: &pvfs_companion::Vault) -> Result<(), String> {
    #[cfg(feature = "os-keychain")]
    {
        use pvfs_companion::SecretStore;
        let id = vault.key_id().ok_or_else(|| "vault has no key id".to_string())?;
        pvfs_companion::OsKeychain::new()
            .get(id)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    #[cfg(not(feature = "os-keychain"))]
    {
        let _ = vault;
        Err("this build has no os-keychain support".into())
    }
}

fn run() -> Result<(), String> {
    match Cli::parse().cmd {
        Cmd::Init {
            vault,
            keychain,
            passphrase: passphrase_only,
        } => {
            if keychain && passphrase_only {
                return Err("--keychain and --passphrase are mutually exclusive".into());
            }
            let vault = match vault {
                Some(p) => p,
                None => default_vault()?,
            };
            if vault.exists() {
                return Err(format!(
                    "a vault already exists at {} — delete it first to re-seal from the phrase",
                    vault.display()
                ));
            }
            if let Some(dir) = vault.parent() {
                std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            }
            let phrase = read_phrase()?;

            // Sealing choice (doc 14 §5): forced by flag for scripts; interactive
            // prefers the OS keychain and falls back to a prompted passphrase;
            // non-interactive (piped) stays on the env passphrase, so pipelines
            // never touch a real keychain.
            if keychain {
                keychain_create(&vault, phrase.as_bytes())?;
                eprintln!(
                    "pvfs-companion: sealed vault at {} (data key in the OS keychain)",
                    vault.display()
                );
                return Ok(());
            }
            if !passphrase_only && interactive() {
                match keychain_create(&vault, phrase.as_bytes()) {
                    Ok(()) => {
                        eprintln!(
                            "pvfs-companion: sealed vault at {} (data key in the OS keychain)",
                            vault.display()
                        );
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("OS keychain unavailable ({e}); using a passphrase instead.");
                    }
                }
            }
            let pass = if interactive() {
                prompt_new_passphrase()?
            } else {
                passphrase()?
            };
            Vault::create(&vault, phrase.as_bytes(), pass.as_bytes())
                .map_err(|e| e.to_string())?;
            eprintln!("pvfs-companion: sealed vault at {}", vault.display());
            Ok(())
        }
        Cmd::Serve {
            vault,
            socket,
            allow_root,
            idle_lock_secs,
            rate_limit,
            prompt,
            web_port,
        } => {
            let vault = match vault {
                Some(p) => p,
                None => default_vault()?,
            };
            if !vault.exists() {
                return Err(format!(
                    "no vault at {} — run `pvfs-companion init` first",
                    vault.display()
                ));
            }
            let socket = socket.unwrap_or_else(pvfs_companion::default_socket_path);
            let signer = unseal_signer(&vault)?;
            let policy = ApprovalPolicy {
                auto_root: allow_root,
                ..Default::default()
            };

            // Phase 5 controls (doc 14 §4, §9): prompts, audit, rate limit, and
            // lock with on-demand re-unlock (the unlocker retains no secrets —
            // it re-opens the vault and unseals the same way serve just did).
            // `--prompt deny` makes a scripted agent deterministic: a prompt can
            // never block it (it denies instead), no matter what tty it holds.
            let (prompter, prompt_label): (Box<dyn pvfs_companion::Prompter>, &str) =
                match prompt.as_str() {
                    "deny" => (Box::new(pvfs_companion::DenyPrompter), "deny (forced)"),
                    "terminal" => match pvfs_companion::approve::TerminalPrompter::open() {
                        Some(p) => (Box::new(p), "terminal (forced)"),
                        None => return Err("--prompt terminal: no controlling terminal".into()),
                    },
                    "desktop" => match pvfs_companion::approve::DesktopPrompter::detect() {
                        Some(p) => (Box::new(p), "desktop dialog (forced)"),
                        None => return Err("--prompt desktop: no GUI session detected".into()),
                    },
                    _ => pvfs_companion::auto_prompter_labeled(),
                };
            let audit_path = vault.with_extension("audit.jsonl");
            let audit =
                pvfs_companion::AuditLog::open(&audit_path).map_err(|e| e.to_string())?;
            let unlock_vault = vault.clone();
            let unlocker: pvfs_companion::Unlocker =
                Box::new(move || unseal_signer(&unlock_vault));
            // Identity rotation (doc 15 §1) persists its index bump to the vault
            // envelope, so restarts and re-unlocks stay on the new identity.
            let rotate_vault = vault.clone();
            let rotator: pvfs_companion::IdentityRotator = Box::new(move |idx| {
                Vault::set_identity_index(&rotate_vault, idx).map_err(|e| e.to_string())
            });
            let idle = match idle_lock_secs {
                0 => None,
                n => Some(Duration::from_secs(n)),
            };
            let agent = Arc::new(
                Agent::new(signer, policy)
                    .with_prompter(prompter)
                    .with_audit(audit)
                    .with_unlocker(unlocker)
                    .with_identity_rotator(rotator)
                    .with_idle_timeout(idle)
                    .with_rate_limit(rate_limit)
                    .with_pairings(pvfs_companion::PairingRegistry::at(
                        &vault.with_extension("pairings.json"),
                    )),
            );

            let _ = std::fs::remove_file(&socket); // clear a stale socket
            let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
            // Owner-only: the socket mode is the authentication (doc 14 §3).
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;

            // The loopback identity agent (doc 14 §6): a STABLE 127.0.0.1 port
            // (M3.1 — pages find it with no port-file lookup; 0 = ephemeral),
            // per-launch token in a 0600 port file next to the socket.
            let origins =
                pvfs_companion::OriginRegistry::at(&vault.with_extension("origins.json"));
            let web = Arc::new(pvfs_companion::WebAgent::new(Arc::clone(&agent), origins));
            let http = std::net::TcpListener::bind(("127.0.0.1", web_port)).map_err(|e| {
                format!("web agent port {web_port} unavailable ({e}) — pass --web-port")
            })?;
            let addr = http.local_addr().map_err(|e| e.to_string())?.to_string();
            let port_file = socket.with_extension("http");
            web.write_port_file(&port_file, &addr)
                .map_err(|e| e.to_string())?;
            {
                let w = Arc::clone(&web);
                std::thread::spawn(move || w.serve(http));
            }

            eprintln!("pvfs-companion: serving on {}", socket.display());
            eprintln!(
                "pvfs-companion: approval prompts: {prompt_label}; idle lock: {}; audit: {}",
                match idle_lock_secs {
                    0 => "off".to_string(),
                    n => format!("{n}s"),
                },
                audit_path.display()
            );
            eprintln!(
                "pvfs-companion: identity agent on http://{addr} (port file {})",
                port_file.display()
            );
            serve(listener, agent).map_err(|e| e.to_string())?;
            Ok(())
        }
        Cmd::Lock { socket } => {
            let socket = socket.unwrap_or_else(pvfs_companion::default_socket_path);
            let resp = pvfs_companion::request(&socket, &pvfs_companion::AgentRequest::Lock)
                .map_err(|e| format!("no companion at {} ({e})", socket.display()))?;
            match resp {
                pvfs_companion::AgentResponse::Ok => {
                    eprintln!("pvfs-companion: locked (the seed is out of memory)");
                    Ok(())
                }
                pvfs_companion::AgentResponse::Error { code, message } => {
                    Err(format!("{code}: {message}"))
                }
                _ => Err("unexpected response".into()),
            }
        }
        Cmd::Status { vault, socket } => {
            let vault_path = match vault {
                Some(p) => p,
                None => default_vault()?,
            };
            let socket = socket.unwrap_or_else(pvfs_companion::default_socket_path);
            if !vault_path.exists() {
                println!(
                    "vault : none at {} — run `pvfs-companion init`",
                    vault_path.display()
                );
            } else {
                match Vault::open(&vault_path) {
                    Ok(v) => match v.sealing() {
                        pvfs_companion::Sealing::Passphrase => {
                            println!("vault : {} (passphrase-sealed)", vault_path.display());
                        }
                        pvfs_companion::Sealing::Keychain => {
                            println!("vault : {} (keychain-sealed)", vault_path.display());
                            match keychain_probe(&v) {
                                Ok(()) => println!("key   : present in the OS keychain"),
                                Err(e) => println!(
                                    "key   : not retrievable ({e}) — if it was deleted, remove \
                                     the vault and re-run `pvfs-companion init` with your phrase"
                                ),
                            }
                        }
                    },
                    Err(e) => println!("vault : {} (unreadable: {e})", vault_path.display()),
                }
            }
            match pvfs_companion::request(
                &socket,
                &pvfs_companion::AgentRequest::GetPubkey {
                    role: "identity".into(),
                },
            ) {
                Ok(pvfs_companion::AgentResponse::Pubkey { pubkey }) => {
                    println!("agent : running on {} (identity {pubkey})", socket.display());
                    let port_file = socket.with_extension("http");
                    if let Ok(s) = std::fs::read_to_string(&port_file) {
                        let addr = s
                            .split("\"addr\":\"")
                            .nth(1)
                            .and_then(|r| r.split('"').next())
                            .unwrap_or("?");
                        println!("web   : identity agent on http://{addr}");
                    }
                }
                Ok(_) => println!(
                    "agent : running on {} (unexpected reply)",
                    socket.display()
                ),
                Err(_) => println!(
                    "agent : not running (would serve on {})",
                    socket.display()
                ),
            }
            let reg = pvfs_companion::OriginRegistry::at(&vault_path.with_extension("origins.json"));
            let n = reg.list().len();
            println!("origins: {n} connected for sign-in");
            Ok(())
        }
        Cmd::Origins { cmd, vault } => {
            let vault_path = match vault {
                Some(p) => p,
                None => default_vault()?,
            };
            let reg = pvfs_companion::OriginRegistry::at(&vault_path.with_extension("origins.json"));
            match cmd {
                None => {
                    let grants = reg.list();
                    if grants.is_empty() {
                        println!("(no connected origins)");
                    } else {
                        for g in grants {
                            println!("{}  expires {}", g.origin, fmt_expiry(g.expires_at_ms()));
                        }
                    }
                    Ok(())
                }
                Some(OriginsCmd::Revoke { origin }) => {
                    if reg.revoke(&origin)? {
                        eprintln!("pvfs-companion: revoked {origin}");
                        Ok(())
                    } else {
                        Err(format!("{origin} was not connected"))
                    }
                }
            }
        }
        Cmd::Pairings { cmd, vault } => {
            let vault_path = match vault {
                Some(p) => p,
                None => default_vault()?,
            };
            let reg =
                pvfs_companion::PairingRegistry::at(&vault_path.with_extension("pairings.json"));
            match cmd {
                None => {
                    let list = reg.list();
                    if list.is_empty() {
                        println!("(no paired servers)");
                    } else {
                        for p in list {
                            println!(
                                "{}  key {}…  origins [{}]",
                                p.name,
                                &p.server_pubkey_hex[..p.server_pubkey_hex.len().min(12)],
                                p.origins.join(", ")
                            );
                        }
                    }
                    Ok(())
                }
                Some(PairingsCmd::Revoke { name }) => {
                    if reg.revoke(&name).map_err(|e| e.to_string())? {
                        eprintln!("pvfs-companion: revoked pairing {name}");
                        Ok(())
                    } else {
                        Err(format!("no pairing named {name}"))
                    }
                }
            }
        }
        Cmd::TenantInit { store, user } => {
            let pass = passphrase()?;
            let phrase = read_phrase()?;
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
        Cmd::PhraseNew => {
            let mn = pvfs_core::identity::generate_mnemonic().map_err(|e| e.to_string())?;
            println!("{mn}");
            Ok(())
        }
    }
}
