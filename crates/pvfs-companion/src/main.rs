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
use nix::sys::signal::{signal, SigHandler, Signal};
use pvfs_companion::{
    serve_tenant, tenant_request, Agent, ApprovalPolicy, Sessions, TenantAgent,
    TenantRequest, TenantResponse, UnlockedSigner, Vault, VaultStore,
};

/// D124 item 2 — the same build stamp the CLI and daemon carry (`build.rs`:
/// `PVFS_BUILD` from the pipeline, else `git describe`), so the companion
/// reports `1.4.0 (v1.4-…)` rather than the bare crate version.
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("PVFS_BUILD"), ")");

#[derive(Parser)]
#[command(name = "pvfs-companion", version = VERSION, about = "PVFS companion — key vault + signing agent")]
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
    /// Singleton per user: an existing instance on the socket is taken over
    /// (killed via its pidfile) before this one binds.
    Serve(ServeArgs),
    /// Take over from any running companion and serve fresh — the explicit
    /// restart affordance (same flags as `serve`, which also takes over).
    Restart(ServeArgs),
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
    /// PVOS D189 — the recovery phrases this companion holds and what each is
    /// used for: its public keys, the forests that used them (recorded as
    /// tools use them, or linked), the servers paired with it, the web origins
    /// it signs in to, and the approvals and root signatures it has given.
    /// Public data only. `link` records a forest made before the companion
    /// kept a ledger.
    Keys {
        #[command(subcommand)]
        cmd: Option<KeysCmd>,
        /// Machine-readable output (the Mac app's settings read it)
        #[arg(long)]
        json: bool,
        /// Socket path (default: $XDG_RUNTIME_DIR/pvfs-companion.sock, or $PVFS_COMPANION_SOCKET)
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Record that a forest uses one of this companion's keys — a forest this
    /// phrase roots, made before the ledger existed. Asks for what it needs;
    /// refused unless a phrase here holds the key. `pvfs --json forest tip
    /// <forest dir>`, on a box that has the forest, prints its id and root.
    Link {
        /// The key (hex) — the forest's current root
        #[arg(long)]
        key: Option<String>,
        /// The forest's id
        #[arg(long)]
        forest_id: Option<String>,
        /// The name to show for it
        #[arg(long)]
        label: Option<String>,
    },
}

#[derive(clap::Args)]
struct ServeArgs {
    /// Vault file (default: ~/.config/pvfs/companion.vault, or $PVFS_COMPANION_VAULT).
    /// PVOS D189: repeat it to serve several recovery phrases from one
    /// companion — the first is the default; a request picks another by
    /// naming one of its public keys.
    #[arg(long)]
    vault: Vec<PathBuf>,
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
    /// Pre-trust a url for a paired server (D27) — as if approved at first contact.
    Trust { name: String, url: String },
    /// Forget a trusted url (the next relay from it prompts again).
    Untrust { name: String, url: String },
}

fn main() -> std::process::ExitCode {
    // Unix filter contract for the query commands (`status | grep -q`,
    // `origins | head`): give SIGPIPE its default disposition so an
    // early-exiting pipe reader ends us quietly (shell rc 141) instead of
    // panicking println! on EPIPE. The serving paths re-ignore it — see
    // run_serve() and the ServeTenant arm — because there a vanished client
    // must be an io::Error on one connection, not process death.
    // Safety: SigDfl installs no handler code.
    unsafe {
        let _ = signal(Signal::SIGPIPE, SigHandler::SigDfl);
    }
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
        // `restart` is `serve` made explicit: serve already takes over any
        // running instance (the singleton posture), so both run the same code.
        Cmd::Serve(args) | Cmd::Restart(args) => run_serve(args),
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
        Cmd::Status { vault, socket } => run_status(vault, socket),
        Cmd::Origins { cmd, vault } => run_origins(cmd, vault),
        Cmd::Pairings { cmd, vault } => run_pairings(cmd, vault),
        Cmd::Keys { cmd, json, socket } => run_keys(cmd, json, socket),
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
            // Same posture as run_serve(): a disconnecting client is an EPIPE
            // io::Error, not process death.
            // Safety: SigIgn installs no handler code.
            unsafe {
                let _ = signal(Signal::SIGPIPE, SigHandler::SigIgn);
            }
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

fn run_serve(args: ServeArgs) -> Result<(), String> {
    // Serving now: re-ignore SIGPIPE (main gave it the default disposition for
    // the filter commands). A browser or CLI client that disconnects mid-write
    // must surface as EPIPE on that connection, not kill the signing agent.
    // Safety: SigIgn installs no handler code.
    unsafe {
        let _ = signal(Signal::SIGPIPE, SigHandler::SigIgn);
    }
    let ServeArgs {
        vault,
        socket,
        allow_root,
        idle_lock_secs,
        rate_limit,
        prompt,
        web_port,
    } = args;
    let vaults = if vault.is_empty() { vec![default_vault()?] } else { vault };
    for v in &vaults {
        if !v.exists() {
            return Err(format!("no vault at {} — run `pvfs-companion init` first", v.display()));
        }
    }
    let socket = socket.unwrap_or_else(pvfs_companion::default_socket_path);
    let policy = ApprovalPolicy {
        auto_root: allow_root,
        ..Default::default()
    };
    let idle = match idle_lock_secs {
        0 => None,
        n => Some(Duration::from_secs(n)),
    };

    // PVOS D189 — one agent per phrase (its own lock, prompts, audit and
    // pairings, exactly as a one-phrase companion runs), behind a router
    // that sends each request to the phrase holding the key it names. With
    // several, every signing prompt names the phrase that would sign.
    let several = vaults.len() > 1;
    let mut slots = Vec::new();
    let mut prompt_label = "";
    let mut audits = Vec::new();
    for (i, v) in vaults.iter().enumerate() {
        let name = v.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "vault".into());
        let (prompter, label) = make_prompter(&prompt)?;
        prompt_label = label;
        let prompter: Box<dyn pvfs_companion::Prompter> =
            if several { Box::new(pvfs_companion::NamedPrompter::new(name.clone(), prompter)) } else { prompter };
        // The default phrase must open; another that cannot (a different
        // password, a missing keychain item) is left out, said, and the
        // companion serves the rest rather than none.
        let slot = vault_agent(v, policy, prompter, idle, rate_limit)
            .and_then(|agent| pvfs_companion::router::Slot::new(name.clone(), agent))
            .map(|slot| slot.with_vault_path(v));
        match slot {
            Ok(slot) => {
                audits.push(v.with_extension("audit.jsonl"));
                slots.push(slot);
            }
            Err(e) if i > 0 => eprintln!("pvfs-companion: phrase {name} left out — {e}"),
            Err(e) => return Err(e),
        }
    }
    let router = Arc::new(pvfs_companion::Router::new(slots)?);
    // The web agent (the browser's sign-in) and its files follow the
    // default phrase.
    let agent = router.default_agent();
    let vault = vaults[0].clone();

    // Singleton per user (2026-07-21 request): take over from any existing
    // instance — kill it via its pidfile, clear the stale socket — then bind
    // and record ourselves as the one companion.
    let takeover = pvfs_companion::take_over(&socket);
    if let Some(pid) = takeover.killed {
        eprintln!("pvfs-companion: took over from a running instance (pid {pid})");
    }
    if takeover.orphaned {
        eprintln!(
            "pvfs-companion: WARNING: an older companion answers on {} but left no \
             pidfile — it cannot be killed and is now orphaned (quit it manually)",
            socket.display()
        );
    }
    let listener = UnixListener::bind(&socket).map_err(|e| e.to_string())?;
    // Owner-only: the socket mode is the authentication (doc 14 §3).
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    pvfs_companion::write_pidfile(&socket).map_err(|e| e.to_string())?;

    // The loopback identity agent (doc 14 §6): a STABLE 127.0.0.1 port
    // (M3.1 — pages find it with no port-file lookup; 0 = ephemeral),
    // per-launch token in a 0600 port file next to the socket. A just-killed
    // predecessor releases the port asynchronously, so retry briefly before
    // giving up — "keep serving the web relay port" is the whole point.
    let origins =
        pvfs_companion::OriginRegistry::at(&vault.with_extension("origins.json"));
    let web = Arc::new(pvfs_companion::WebAgent::new(Arc::clone(&agent), origins));
    let http = {
        let mut bound = None;
        for _ in 0..20 {
            match std::net::TcpListener::bind(("127.0.0.1", web_port)) {
                Ok(l) => {
                    bound = Some(l);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(250)),
            }
        }
        match bound {
            Some(l) => l,
            None => std::net::TcpListener::bind(("127.0.0.1", web_port)).map_err(|e| {
                format!("web agent port {web_port} unavailable ({e}) — pass --web-port")
            })?,
        }
    };
    let addr = http.local_addr().map_err(|e| e.to_string())?.to_string();
    let port_file = socket.with_extension("http");
    web.write_port_file(&port_file, &addr)
        .map_err(|e| e.to_string())?;
    {
        // Web-agent TLS (PVOS M3.6 §4a): serve https on the same port
        // (dual-mode peek keeps plain-http callers working). Best-effort —
        // a failure here keeps the agent up in http-only mode.
        let tls = match pvfs_companion::webtls::load_or_generate(&vault) {
            Ok(t) => {
                if t.fresh {
                    pvfs_companion::webtls::install_trust(&t.cert_path);
                }
                eprintln!("companion: web agent serves https (dual-mode) on port {web_port}");
                Some(t.config)
            }
            Err(e) => {
                eprintln!("companion: web-agent TLS unavailable ({e}) — serving plain http");
                None
            }
        };
        let w = Arc::clone(&web);
        std::thread::spawn(move || w.serve(http, tls));
    }

    eprintln!("pvfs-companion: serving on {}", socket.display());
    for k in router.keys() {
        eprintln!(
            "pvfs-companion: phrase {}{}: root {}",
            k.vault,
            if k.default { " (default)" } else { "" },
            &k.root[..k.root.len().min(12)]
        );
    }
    eprintln!(
        "pvfs-companion: approval prompts: {prompt_label}; idle lock: {}; audit: {}",
        match idle_lock_secs {
            0 => "off".to_string(),
            n => format!("{n}s"),
        },
        audits.iter().map(|a| a.display().to_string()).collect::<Vec<_>>().join(", ")
    );
    eprintln!(
        "pvfs-companion: identity agent on http(s)://{addr} (dual-mode; port file {})",
        port_file.display()
    );
    pvfs_companion::serve_router(listener, router).map_err(|e| e.to_string())?;
    Ok(())
}

/// The approval backend for one phrase's agent. `--prompt deny` makes a
/// scripted agent deterministic: a prompt can never block it (it denies
/// instead), no matter what tty it holds.
fn make_prompter(prompt: &str) -> Result<(Box<dyn pvfs_companion::Prompter>, &'static str), String> {
    Ok(match prompt {
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
    })
}

/// One phrase's agent, with the phase 5 controls (doc 14 §4, §9): prompts,
/// audit, rate limit, and lock with on-demand re-unlock (the unlocker keeps
/// no secret — it re-opens the vault and unseals it the way serve did).
fn vault_agent(
    vault: &std::path::Path,
    policy: ApprovalPolicy,
    prompter: Box<dyn pvfs_companion::Prompter>,
    idle: Option<Duration>,
    rate_limit: u32,
) -> Result<Arc<Agent>, String> {
    let signer = unseal_signer(vault)?;
    let audit = pvfs_companion::AuditLog::open(&vault.with_extension("audit.jsonl")).map_err(|e| e.to_string())?;
    let unlock_vault = vault.to_path_buf();
    let unlocker: pvfs_companion::Unlocker = Box::new(move || unseal_signer(&unlock_vault));
    // Identity rotation (doc 15 §1) persists its index bump to the vault
    // envelope, so restarts and re-unlocks stay on the new identity.
    let rotate_vault = vault.to_path_buf();
    let rotator: pvfs_companion::IdentityRotator =
        Box::new(move |idx| Vault::set_identity_index(&rotate_vault, idx).map_err(|e| e.to_string()));
    Ok(Arc::new(
        Agent::new(signer, policy)
            .with_prompter(prompter)
            .with_audit(audit)
            .with_unlocker(unlocker)
            .with_identity_rotator(rotator)
            .with_idle_timeout(idle)
            .with_rate_limit(rate_limit)
            .with_pairings(pvfs_companion::PairingRegistry::at(&vault.with_extension("pairings.json"))),
    ))
}

fn run_status(vault: Option<PathBuf>, socket: Option<PathBuf>) -> Result<(), String> {
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

fn run_origins(cmd: Option<OriginsCmd>, vault: Option<PathBuf>) -> Result<(), String> {
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

fn run_pairings(cmd: Option<PairingsCmd>, vault: Option<PathBuf>) -> Result<(), String> {
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
                        "{}  key {}…  trusted urls [{}]",
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
        Some(PairingsCmd::Trust { name, url }) => {
            let Some(p) = reg.list().into_iter().find(|p| p.name == name) else {
                return Err(format!("no pairing named {name}"));
            };
            reg.trust_origin(&p.server_pubkey_hex, &url)
                .map_err(|e| e.to_string())?;
            eprintln!("pvfs-companion: trusting {url} for {name}");
            Ok(())
        }
        Some(PairingsCmd::Untrust { name, url }) => {
            if reg.untrust_origin(&name, &url).map_err(|e| e.to_string())? {
                eprintln!("pvfs-companion: forgot {url} for {name}");
                Ok(())
            } else {
                Err(format!("{url} was not trusted for {name}"))
            }
        }
    }
}

// ---- PVOS D189: `keys` — what each phrase is used for ----------------------

#[derive(serde::Serialize)]
struct KeysReport {
    /// `running`, `not running`, or `older` (a companion before `list_keys`).
    agent: String,
    phrases: Vec<PhraseReport>,
}

#[derive(serde::Serialize)]
struct PhraseReport {
    vault: String,
    path: String,
    is_default: bool,
    /// Served by the running companion (its keys are known).
    served: bool,
    sealing: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<PublicKeys>,
    forests: Vec<pvfs_companion::ledger::ForestUse>,
    pairings: Vec<PairingRow>,
    origins: Vec<OriginRow>,
    approvals: Vec<ApprovalRow>,
    root_signatures: Vec<RootSignature>,
}

#[derive(serde::Serialize)]
struct PublicKeys {
    root: String,
    identity: String,
    encryption: String,
}

#[derive(serde::Serialize)]
struct PairingRow {
    name: String,
    server_pubkey: String,
    created_ms: u64,
    origins: Vec<String>,
}

#[derive(serde::Serialize)]
struct OriginRow {
    origin: String,
    expires_ms: u64,
}

/// Approved signatures of one kind for one app or server, from the audit log.
#[derive(serde::Serialize)]
struct ApprovalRow {
    kind: String,
    who: String,
    action: String,
    count: u64,
    last_ms: u64,
}

/// One approved root signature — a device admitted or revoked, a promotion.
#[derive(serde::Serialize)]
struct RootSignature {
    summary: String,
    at_ms: u64,
}

fn run_keys(cmd: Option<KeysCmd>, json: bool, socket: Option<PathBuf>) -> Result<(), String> {
    let socket = socket.unwrap_or_else(pvfs_companion::default_socket_path);
    if let Some(KeysCmd::Link { key, forest_id, label }) = cmd {
        return run_keys_link(&socket, key, forest_id, label);
    }
    let report = keys_report(&socket)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    } else {
        print_keys(&report);
    }
    Ok(())
}

fn run_keys_link(
    socket: &std::path::Path,
    key: Option<String>,
    forest_id: Option<String>,
    label: Option<String>,
) -> Result<(), String> {
    let key = match key {
        Some(k) => k,
        None => ask_line("The forest's root key (hex, from `pvfs --json forest tip <dir>`)")?,
    };
    let key = hex::decode(key.trim()).map_err(|_| "the key must be hex".to_string())?;
    let id = match forest_id {
        Some(f) => f,
        None => ask_line("The forest's id")?,
    };
    let label = match label {
        Some(l) => l,
        None => ask_line("A name to show for it")?,
    };
    let forest = pvfs_companion::ForestRef { id: id.trim().to_string(), label: label.trim().to_string() };
    let resp = pvfs_companion::request_routed(
        socket,
        &pvfs_companion::AgentRequest::LinkForest,
        Some(&key),
        Some(&forest),
    )
    .map_err(|e| format!("no companion at {} ({e})", socket.display()))?;
    match resp {
        pvfs_companion::AgentResponse::Ok => {
            eprintln!("pvfs-companion: linked {} ({}) to key {}…", forest.label, forest.id, &hex::encode(&key)[..12]);
            Ok(())
        }
        pvfs_companion::AgentResponse::Error { code, message } => Err(format!("{code}: {message}")),
        _ => Err("unexpected response".into()),
    }
}

/// One answer on a terminal; a script must pass the flag instead.
fn ask_line(question: &str) -> Result<String, String> {
    if !interactive() {
        return Err(format!("{question}: not given (pass the flag, or run it in a terminal)"));
    }
    eprint!("{question}: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    let line = line.trim().to_string();
    if line.is_empty() {
        return Err(format!("{question}: nothing given"));
    }
    Ok(line)
}

fn keys_report(socket: &std::path::Path) -> Result<KeysReport, String> {
    let (agent, served) = match pvfs_companion::request(socket, &pvfs_companion::AgentRequest::ListKeys) {
        Ok(pvfs_companion::AgentResponse::Keys { keys }) => ("running", keys),
        Ok(_) => ("older", Vec::new()),
        // A companion before v4 drops the connection on a request it cannot
        // read; one that still answers the version is running, just older.
        Err(_) => match pvfs_companion::request(socket, &pvfs_companion::AgentRequest::ApiVersion) {
            Ok(_) => ("older", Vec::new()),
            Err(_) => ("not running", Vec::new()),
        },
    };
    let dir = default_vault()?.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let mut phrases = Vec::new();
    for k in &served {
        let path = if k.path.is_empty() { dir.join(format!("{}.vault", k.vault)) } else { PathBuf::from(&k.path) };
        let mut p = phrase_report(&k.vault, &path, k.default, true);
        p.locked = Some(k.locked);
        p.keys = Some(PublicKeys { root: k.root.clone(), identity: k.identity.clone(), encryption: k.encryption.clone() });
        phrases.push(p);
    }
    // Vaults beside them that the companion does not serve (not running, or
    // left out): their files still say what they were used for.
    let mut others: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("vault"))
                .collect()
        })
        .unwrap_or_default();
    others.sort();
    for path in others {
        if phrases.iter().any(|p| std::path::Path::new(&p.path) == path.as_path()) {
            continue;
        }
        let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        let is_default = served.is_empty() && name == "companion";
        phrases.push(phrase_report(&name, &path, is_default, false));
    }
    Ok(KeysReport { agent: agent.into(), phrases })
}

fn phrase_report(vault: &str, path: &std::path::Path, is_default: bool, served: bool) -> PhraseReport {
    let sealing = match Vault::open(path) {
        Ok(v) => match v.sealing() {
            pvfs_companion::Sealing::Keychain => "keychain",
            pvfs_companion::Sealing::Passphrase => "passphrase",
        },
        Err(_) => "unreadable",
    }
    .to_string();
    let pairings = pvfs_companion::PairingRegistry::at(&path.with_extension("pairings.json"))
        .list()
        .into_iter()
        .map(|p| PairingRow { name: p.name, server_pubkey: p.server_pubkey_hex, created_ms: p.created_ms, origins: p.origins })
        .collect();
    let origins = pvfs_companion::OriginRegistry::at(&path.with_extension("origins.json"))
        .list()
        .into_iter()
        .map(|g| OriginRow { expires_ms: g.expires_at_ms(), origin: g.origin })
        .collect();
    let (approvals, root_signatures) = audit_summary(&path.with_extension("audit.jsonl"));
    PhraseReport {
        vault: vault.to_string(),
        path: path.display().to_string(),
        is_default,
        served,
        sealing,
        locked: None,
        keys: None,
        forests: pvfs_companion::ledger::read(&path.with_extension("forests.json")),
        pairings,
        origins,
        approvals,
        root_signatures,
    }
}

/// The approvals a phrase gave, grouped, and its root signatures, newest
/// first — read from its audit log.
fn audit_summary(path: &std::path::Path) -> (Vec<ApprovalRow>, Vec<RootSignature>) {
    let mut rows: Vec<ApprovalRow> = Vec::new();
    let mut roots = Vec::new();
    let body = std::fs::read_to_string(path).unwrap_or_default();
    for line in body.lines() {
        let Ok(e) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if e["event"] != "sign" || e["decision"] != "approved" {
            continue;
        }
        let at = e["ts_ms"].as_u64().unwrap_or(0);
        let rt = e["request_type"].as_str().unwrap_or("");
        let ctx = &e["context"];
        if rt == "root_device_cert" {
            let summary = ctx["summary"].as_str().unwrap_or("a root signature (no details recorded)").to_string();
            roots.push(RootSignature { summary, at_ms: at });
            continue;
        }
        let kind = match rt {
            "identity_assertion" => "sign-in",
            "user_action" => "approval",
            "identity_tag" => "identity tag",
            other => other,
        };
        let who = ctx["app_id"].as_str().or(e["origin"].as_str()).unwrap_or("local").to_string();
        let action = ctx["action"].as_str().unwrap_or("").to_string();
        match rows.iter_mut().find(|r| r.kind == kind && r.who == who && r.action == action) {
            Some(r) => {
                r.count += 1;
                r.last_ms = r.last_ms.max(at);
            }
            None => rows.push(ApprovalRow { kind: kind.to_string(), who, action, count: 1, last_ms: at }),
        }
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.last_ms));
    roots.sort_by_key(|r| std::cmp::Reverse(r.at_ms));
    roots.truncate(50);
    (rows, roots)
}

/// "3 d ago" / "5 h ago" / "12 min ago".
fn ago(ms: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let s = now.saturating_sub(ms) / 1000;
    if s >= 86_400 {
        format!("{} d ago", s / 86_400)
    } else if s >= 3_600 {
        format!("{} h ago", s / 3_600)
    } else {
        format!("{} min ago", s / 60)
    }
}

fn print_keys(r: &KeysReport) {
    println!("companion: {}", r.agent);
    if r.phrases.is_empty() {
        println!("(no phrases — run `pvfs-companion init`)");
    }
    for p in &r.phrases {
        println!();
        println!(
            "phrase {}{} — {}{} — {}",
            p.vault,
            if p.is_default { " (default)" } else { "" },
            p.sealing,
            match (p.served, p.locked) {
                (false, _) => " — not served now".to_string(),
                (true, Some(true)) => " — locked".to_string(),
                (true, _) => " — unlocked".to_string(),
            },
            p.path
        );
        match &p.keys {
            Some(k) => {
                println!("  root        {}", k.root);
                println!("  identity    {}", k.identity);
                println!("  encryption  {}", k.encryption);
            }
            None => println!("  keys        (shown while the companion serves this phrase)"),
        }
        if p.forests.is_empty() {
            println!("  forests     none recorded yet — pvfs records the forests it uses this phrase for;");
            println!("              `pvfs-companion keys link` records an older one");
        }
        for f in &p.forests {
            println!(
                "  forest      {} ({}) — {} {}… — {} use(s), last {} — {}",
                if f.label.is_empty() { "?" } else { f.label.as_str() },
                f.forest_id,
                f.role,
                &f.key[..f.key.len().min(12)],
                f.uses,
                ago(f.last_ms),
                f.last_action
            );
        }
        for s in &p.pairings {
            println!(
                "  paired      {} — server key {}… — since {}",
                s.name,
                &s.server_pubkey[..s.server_pubkey.len().min(12)],
                ago(s.created_ms)
            );
        }
        for o in &p.origins {
            println!("  origin      {} — expires {}", o.origin, fmt_expiry(o.expires_ms));
        }
        for a in &p.approvals {
            println!(
                "  approved    {} × {} — {}{} — last {}",
                a.kind,
                a.count,
                a.who,
                if a.action.is_empty() { String::new() } else { format!(" ({})", a.action) },
                ago(a.last_ms)
            );
        }
        for s in p.root_signatures.iter().take(10) {
            println!("  root signed {} — {}", s.summary, ago(s.at_ms));
        }
    }
}
