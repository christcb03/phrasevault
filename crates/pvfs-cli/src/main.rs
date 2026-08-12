//! pvfs — thin CLI over pvfs-core (spec §13.4).
//!
//! Exit codes (scriptable): 0 ok · 1 internal/io/db · 2 bad input ·
//! 3 not found · 4 conflict (exists/contained/not-orphan/cycle) ·
//! 5 integrity/identity · 6 corruption (recovery ladder).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pvfs_client::fetch::{sync_pull, Fetcher};
use pvfs_client::Client;
use pvfs_core::{
    acl, crypto, identity, mount, BindSpec, ByteRange, Engine, FilePayload, HashPolicy, NodeSpec,
    OrderKey, PvfsError, Registry, ResolveAction, VerifyOutcome, TYPE_FILE, TYPE_FOLDER,
};

#[derive(Parser)]
#[command(name = "pvfs", version, about = "PVFS — PhraseVault File System")]
struct Cli {
    /// Low-level state-dir override for tests/scripts (or $PVFS_DATA_DIR).
    /// Interactive use: run inside a mount or pass --forest.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Forest context: registered alias or mount path
    #[arg(long, global = true)]
    forest: Option<String>,

    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Forest lifecycle: init, register, unregister, info
    #[command(subcommand)]
    Forest(ForestCmd),
    /// Low-level: initialize a forest at the raw state dir (prefer `pvfs forest init`)
    Init,
    /// Recover onto this machine from a recovery phrase
    Recover {
        #[arg(long)]
        mnemonic: String,
        #[arg(long, default_value_t = 0)]
        device_index: u64,
    },
    /// Show forest identity
    Info,
    /// Tree operations
    #[command(subcommand)]
    Tree(TreeCmd),
    /// Add a node under a parent
    Add {
        parent: String,
        #[arg(long, value_parser = ["folder", "file"])]
        kind: String,
        #[arg(long)]
        label: String,
        #[arg(long)]
        temp: bool,
        #[arg(long)]
        nonce: Option<u64>,
        #[arg(long, default_value_t = 0)]
        size: u64,
        #[arg(long, default_value = "application/octet-stream")]
        mime: String,
        #[arg(long, default_value = "")]
        content_hash: String,
    },
    /// Create an explicit link (default type: ref)
    Link {
        parent: String,
        child: String,
        #[arg(long = "type", default_value = "ref")]
        link_type: String,
        #[arg(long, default_value_t = 0)]
        nonce: u64,
    },
    /// Soft-remove a link (triggers temp purge check)
    Unlink { link_id: String },
    /// Change a link's sibling order key
    Reorder {
        link_id: String,
        #[arg(long)]
        key: String,
    },
    /// No target: list registered forests. With target (pvfs:// URI, absolute
    /// path under a mount, or node id): list that location's children.
    Ls { target: Option<String> },
    /// Pre-order walk of a tree (target: URI / path / node id)
    Walk { target: String },
    /// Show one node (target: URI / path / node id)
    Node { target: String },
    /// File location operations
    #[command(subcommand)]
    Loc(LocCmd),
    /// Recompute id + check signature
    Verify { id: String },
    /// Authorization health check: list grants/memberships whose tag authority
    /// has been revoked (inert — masked live, cleaned up by compaction)
    Audit,
    /// List orphaned durable nodes
    Orphans,
    /// Hard-delete orphaned nodes (explicit)
    Purge { ids: Vec<String> },
    /// Device certificate operations
    #[command(subcommand)]
    Device(DeviceCmd),
    /// Identity-key lifecycle (doc 15): replace a compromised identity key
    /// and re-home its authority
    #[command(subcommand)]
    Identity(IdentityCmd),
    /// Member-key lifecycle (doc 15 §1 A4): swap a member's key from a
    /// dual-signed handoff
    #[command(subcommand)]
    Member(MemberCmd),
    /// Secure blobs (doc 12): encrypted-at-rest mutable content with a
    /// content-free signed ledger
    #[command(subcommand)]
    Secure(SecureCmd),
    /// Access-control list operations (doc 06 §4)
    #[command(subcommand)]
    Acl(AclCmd),
    /// Membership tag operations (doc 09 §1)
    #[command(subcommand)]
    Tag(TagCmd),
    /// Print this machine's PVFS client identity pubkey (doc 07 §2)
    Whoami,
    /// Talk to a forest's daemon — Unix socket, or TCP+TLS to a `pvfsd
    /// --listen` address (F1, doc 17 §4)
    Remote {
        /// Explicit socket path (otherwise resolved from --forest)
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Forest (alias or mount path) — finds the daemon's conventional socket
        #[arg(long)]
        forest: Option<String>,
        /// Network address of a `pvfsd --listen` daemon (host:port); needs --pin
        #[arg(long, conflicts_with_all = ["socket", "forest"])]
        connect: Option<String>,
        /// The server's transport pin (printed by `pvfsd --listen`)
        #[arg(long, requires = "connect")]
        pin: Option<String>,
        /// A named instance from `pvfs instance add` (address + pin)
        #[arg(long, conflicts_with_all = ["socket", "forest", "connect", "pin"])]
        instance: Option<String>,
        /// Connect as `public` instead of proving the client identity
        #[arg(long)]
        anon: bool,
        #[command(subcommand)]
        cmd: RemoteCmd,
    },
    /// Region boundaries (P7.0, doc 20): per-app replication/compaction units
    #[command(subcommand)]
    Region(RegionCmd),
    /// Mount a tree read-only as a real filesystem (P7.3, doc 20 §3):
    /// directories from the catalog, file reads resolve live — local bytes,
    /// the sync store, else verified read-through. Blocks until unmounted.
    #[cfg(target_os = "linux")]
    Mount { target: String, dir: PathBuf },
    /// Unmount a pvfs mount (fusermount -u)
    #[cfg(target_os = "linux")]
    Umount { dir: PathBuf },
    /// Fleet setup (P5.4, doc 18 §4): admit another box's client identity
    /// in one visible, logged, revocable step
    #[command(subcommand)]
    Fleet(FleetCmd),
    /// Manage named network instances: address + transport pin (F1)
    #[command(subcommand)]
    Instance(InstanceCmd),
    /// Replicate a served forest locally — verified log shipping (P4 F2, doc 17 §5)
    #[command(subcommand)]
    Replica(ReplicaCmd),
    /// Bind a folder node to a real directory (P1)
    Bind {
        folder: String,
        dir: PathBuf,
        #[arg(long)]
        no_recursive: bool,
        #[arg(long)]
        no_auto_index: bool,
        #[arg(long, default_value = "")]
        extensions: String,
        #[arg(long, default_value = "lazy", value_parser = ["lazy", "on_add", "never"])]
        hash_policy: String,
    },
    /// Remove a folder's directory binding
    Unbind { folder: String },
    /// Scan bound folders against their directories
    Scan { folder: Option<String> },
    /// Node + per-location availability (target: URI / path / node id)
    Stat { target: String },
    /// Stream a file node's bytes (verifies full reads)
    Cat {
        target: String,
        /// byte range START-END (END exclusive; END optional)
        #[arg(long)]
        range: Option<String>,
        /// write to FILE instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Materialize a tree as a native directory any app can read (doc 17 §3)
    Export {
        /// tree root: node id, mount-relative path, or pvfs:// URI
        target: String,
        /// destination directory (created; re-runs refresh it)
        dest: PathBuf,
        #[arg(long, default_value = "symlink", value_parser = ["symlink", "hardlink", "copy"])]
        mode: String,
        /// remove entries that have left the tree since the last export
        #[arg(long)]
        prune: bool,
        /// first fetch missing bytes from the replica's source (F3, doc 17 §6)
        #[arg(long)]
        fetch: bool,
        /// record this export for the daemon's export job to keep fresh
        /// (P5.2, doc 18 §5) — re-run with the same flags on content change
        #[arg(long)]
        keep_fresh: bool,
    },
    /// Set a subtree's placement: `sync` keeps bytes local (doc 17 §6);
    /// `central --to <dir>` makes the mover keep verified copies there
    /// (owner-side, doc 17 §7.4)
    Place {
        target: String,
        #[arg(value_parser = ["pointer", "sync", "central"])]
        mode: String,
        /// central-store directory (with `central`)
        #[arg(long, required_if_eq("mode", "central"))]
        to: Option<PathBuf>,
    },
    /// Fetch missing bytes from wherever they're reachable — for one
    /// subtree, or every subtree placed `sync`
    Sync {
        target: Option<String>,
        /// Sync-store root (P6.1, doc 19 §3): a directory to land fetched
        /// bytes in (the big disk), `default` to go back to `.pvfs/`, or
        /// bare `--to` to print the current root. Config-only — no fetch.
        #[arg(long, num_args = 0..=1, default_missing_value = "", value_name = "DIR")]
        to: Option<String>,
    },
    /// Owner-side mover (doc 17 §7.4): ensure central copies for
    /// `central`-placed subtrees, then retire edge locations
    Tier,
    /// Edge-side space reclaim (doc 17 §7.4): delete local bytes whose
    /// catalog location was retired by the mover — only ever with another
    /// live location recorded
    Evict,
    /// Fill a lazy content hash (creates a successor node — prints new id)
    Hash { target: String },
    /// List nodes flagged invalid: changed-on-disk
    Changes,
    /// Resolve a flagged node: accept the new contents or remove the node
    Resolve {
        id: String,
        #[arg(long, conflicts_with = "delete")]
        replace: bool,
        #[arg(long)]
        delete: bool,
        /// with --delete: hard-delete instead of leaving an orphan
        #[arg(long, requires = "delete")]
        purge: bool,
    },
    /// pvfsd's background jobs (doc 18): bare `pvfs serve` shows status;
    /// subcommands manage jobs, kept-fresh exports, and the foreground watcher
    Serve {
        #[command(subcommand)]
        cmd: Option<ServeCmd>,
    },
    /// SSH to a host with this machine's companion socket reverse-forwarded
    /// (desktop SSO). Remote `pvfs` sees a local companion socket that is
    /// actually your desktop agent — approvals appear on this machine.
    ///
    /// Examples:
    ///   pvfs ssh chris@presubuntu
    ///   pvfs ssh chris@presubuntu -- pvfs forest init --mount ~/media --via-companion
    Ssh {
        /// SSH destination (`user@host` or an ssh config Host)
        target: String,
        /// Local companion socket (default: auto-detect running agent)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
        /// Path of the forwarded socket on the remote host (default: unique under /tmp)
        #[arg(long)]
        remote_socket: Option<PathBuf>,
        /// Extra args passed to `ssh` before the destination (repeatable)
        #[arg(long = "ssh-option", short = 'o')]
        ssh_option: Vec<String>,
        /// Remote command + args. If empty, opens an interactive login shell
        /// with `PVFS_COMPANION_SOCKET` set. Use `--` before a remote `pvfs …`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        remote_cmd: Vec<String>,
    },
}

#[derive(Subcommand)]
enum TreeCmd {
    /// Create a new tree (root folder node)
    Create { label: String },
}

#[derive(Subcommand)]
enum ForestCmd {
    /// Create a forest at a mount directory (state in <mount>/.pvfs/);
    /// imports the directory's existing tree unless --no-import.
    ///
    /// If a local companion is running, you are asked whether to use its existing
    /// root key (no new recovery phrase). Pass `--via-companion` to require that
    /// path, or `--new-phrase` to always mint a fresh phrase.
    Init {
        /// Mount directory (default: current directory)
        #[arg(long)]
        mount: Option<PathBuf>,
        /// Skip binding + scanning the mount's own tree
        #[arg(long)]
        no_import: bool,
        /// Suggested alias for a later `pvfs forest register --alias` (does not register)
        #[arg(long)]
        alias: Option<String>,
        #[arg(long, default_value = "lazy", value_parser = ["lazy", "on_add", "never"])]
        hash_policy: String,
        /// Root-sign genesis with a running companion (existing seed; no new phrase)
        #[arg(long)]
        via_companion: bool,
        /// Companion signer socket (with --via-companion; default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
        /// Always create a new recovery phrase (ignore a running companion)
        #[arg(long)]
        new_phrase: bool,
    },
    /// Add an existing mount to this host's registry
    Register {
        mount: PathBuf,
        #[arg(long)]
        alias: Option<String>,
    },
    /// Remove a forest from the registry (never deletes .pvfs/)
    Unregister { name: String },
    /// Fix `.pvfs/` ownership after a mistaken `sudo forest init` (or run via sudo register)
    FixPermissions {
        /// Mount directory (default: current directory if it is a mount)
        #[arg(long)]
        mount: Option<PathBuf>,
    },
    /// Show a forest's identity (default: current context)
    Info { target: Option<String> },
    /// Register an offline **rotation recovery key** (doc 15 §C5) so you can
    /// rotate the root even after total seed compromise. Reads your current
    /// recovery phrase from stdin to authorize; prints a NEW recovery phrase to
    /// store on paper (never typed into a machine except to rotate).
    /// `--revoke <pubkey>` retires a registered recovery key instead.
    RecoveryKey {
        #[arg(long)]
        forest: Option<String>,
        /// Retire this registered recovery key (hex) instead of registering one.
        #[arg(long)]
        revoke: Option<String>,
    },
    /// **Rotate the root key** (doc 15 §C, disaster recovery for a compromised
    /// seed). Reads the authorizing phrase from stdin — your current recovery
    /// phrase, or the rotation recovery phrase — and prints a fresh recovery
    /// phrase. Re-anchors authority to the new root; `forest_id` and history are
    /// unchanged. Afterwards, revoke and re-admit device keys from the old seed.
    RotateRoot {
        #[arg(long)]
        forest: Option<String>,
    },
}

#[derive(Subcommand)]
enum LocCmd {
    /// Record where a file's bytes live: a URI, or --here <path> for an
    /// instance-qualified location on THIS host (pvfs-host://<pin>/<path>)
    Add {
        file: String,
        uri: Option<String>,
        /// record an absolute path on this instance (requires a transport
        /// pin — serve with `pvfsd --listen` once to mint it)
        #[arg(long, conflicts_with = "uri")]
        here: Option<PathBuf>,
    },
    Rm { file: String, uri: String },
    Ls { file: String },
    /// Re-hash locations; lift quarantine where bytes match again
    Verify { file: String },
}

#[derive(Subcommand)]
enum DeviceCmd {
    /// Authorize a new device key (requires the recovery phrase)
    Authorize {
        #[arg(long)]
        mnemonic: String,
        #[arg(long)]
        index: u64,
    },
    /// Authorize an external member's device key by public key (doc 09 §2.2).
    /// Signed by your admin device (no phrase); pass --mnemonic to root-sign, or
    /// --via-companion to root-sign through a running companion (doc 14).
    AuthorizeMember {
        /// Optional recovery phrase — root-signs instead of device-signing
        #[arg(long)]
        mnemonic: Option<String>,
        /// The member's compressed secp256k1 public key, hex (33-byte SEC1)
        #[arg(long)]
        pubkey: String,
        /// Root-sign via a running companion (no phrase typed)
        #[arg(long)]
        via_companion: bool,
        /// Companion signer socket path (with --via-companion; default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
    /// Authorize the human's **identity key** (doc 14 §1) as an owner: the key is
    /// fetched from a running companion and its cert root-signed through the same
    /// companion (no phrase typed). This is the stable cross-device authority
    /// behind the owner's tag grants (doc 10 §9.1).
    AuthorizeIdentity {
        /// Companion signer socket path (default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
    /// Revoke a device or member key for new appends. Signed by your admin
    /// device (no phrase); pass --mnemonic to root-sign, or --via-companion to
    /// root-sign through a running companion. History stays valid.
    Revoke {
        #[arg(long)]
        mnemonic: Option<String>,
        #[arg(long)]
        pubkey: String,
        /// Root-sign via a running companion (no phrase typed)
        #[arg(long)]
        via_companion: bool,
        /// Companion signer socket path (with --via-companion; default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Replace your identity key (doc 15 §1): rotates it in the companion,
    /// root-signs the revoke+admit swap, re-issues your grants under the new
    /// key, and prints the handoff for forests where you are a member.
    Replace {
        /// Companion signer socket path (default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
        /// Skip the confirmation prompt (automation)
        #[arg(long)]
        yes: bool,
    },
    /// Re-home grants authored by a replaced key onto your current identity
    /// key (repair — `replace` already does this in its own forest).
    Reissue {
        /// The replaced authority's public key (hex)
        old: String,
        /// Companion signer socket path (default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum MemberCmd {
    /// Swap a member's key after their identity replacement (doc 15 §1 A4):
    /// verifies the dual-signed handoff, revokes the old key, admits the new
    /// one, and re-grants the tags the old key held. Signed by your admin
    /// device — the handoff is evidence, your signature is the authority.
    Replace {
        /// Path to the handoff file (JSON printed by `pvfs identity replace`),
        /// or `-` to read it from stdin
        handoff: String,
    },
}

#[derive(Subcommand)]
enum SecureCmd {
    /// Create a secure node under a parent. Storage is managed by default
    /// (allocated on first write) so apps provision on the fly, even with the
    /// daemon running; `--path` pins an explicit ciphertext location instead.
    Create {
        /// Parent node (id, pvfs:// URI, or path under a mount)
        parent: String,
        label: String,
        /// Pin the ciphertext to an explicit absolute path (local/advanced;
        /// default is a managed location under the forest)
        #[arg(long)]
        path: Option<PathBuf>,
    },
    /// Write the blob's bytes (a file, or `-` for stdin) and advance the
    /// signed ledger. By default the bytes are encrypted to you via the
    /// companion envelope; old bytes are discarded — that's the point.
    Put {
        node: String,
        input: String,
        /// Store the bytes verbatim as app-managed ciphertext (doc 12 §5) —
        /// no companion, no envelope.
        #[arg(long)]
        raw: bool,
        /// Companion signer socket (default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
    /// Read the blob to stdout, verifying it against the signed ledger first,
    /// then decrypting via the companion (unless --raw)
    Cat {
        node: String,
        /// Emit the stored ciphertext verbatim, no companion decryption
        #[arg(long)]
        raw: bool,
        /// Companion signer socket (default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
    /// Share a blob with another key: add them as an envelope recipient
    /// (re-wraps the content key; the payload is untouched)
    Grant {
        node: String,
        /// The recipient's compressed secp256k1 public key (hex)
        pubkey: String,
        /// Companion signer socket (default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
    /// Check the location bytes against the signed ledger head
    Verify { node: String },
    /// Show the ledger head (hash, size, when, by whom)
    Status { node: String },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Set (or clear) a principal's rights on a node
    Set {
        /// Node id (64-hex), pvfs:// URI, or absolute path under a mount
        node: String,
        /// Principal: `public`, `any`, `tag:<name>`, or `key:<hex>`
        principal: String,
        /// Rights: letters from r,w,a (e.g. `rw`), or `-`/`none` to clear
        rights: String,
        /// Expire the grant after a duration (`45s`, `30m`, `12h`, `7d`, `2w`)
        /// or at an absolute instant (`@<unix-ms>`). Omit for no expiry.
        #[arg(long)]
        expires: Option<String>,
    },
    /// List the direct ACL grants on a node
    Ls {
        /// Node id (64-hex), pvfs:// URI, or absolute path under a mount
        node: String,
    },
    /// Show a principal's effective rights on a node (incl. inheritance)
    Check {
        /// Node id (64-hex), pvfs:// URI, or absolute path under a mount
        node: String,
        /// Principal: `public`, `any`, `tag:<name>`, or `key:<hex>`
        principal: String,
    },
}

#[derive(Subcommand)]
enum TagCmd {
    /// Grant a tag to a member (by pubkey hex). Pass --via-companion to sign
    /// with your **identity key** through a running companion (doc 14 §3), so
    /// the grant's authority is stable across your machines (doc 10 §9.1).
    Add {
        member: String,
        tag: String,
        /// Sign with your identity key via a running companion
        #[arg(long)]
        via_companion: bool,
        /// Companion signer socket path (with --via-companion; default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
    /// Remove a tag from a member. Pass --via-companion to sign with your
    /// identity key through a running companion (doc 14 §3).
    Rm {
        member: String,
        tag: String,
        /// Sign with your identity key via a running companion
        #[arg(long)]
        via_companion: bool,
        /// Companion signer socket path (with --via-companion; default: auto-detect)
        #[arg(long)]
        companion_socket: Option<PathBuf>,
    },
    /// List a member's tags
    Ls { member: String },
}

#[derive(Subcommand)]
enum ReplicaCmd {
    /// Fetch a forest's full signed log and build a read-only replica at a
    /// new mount dir. Requires admin rights on the source forest's root.
    Add {
        /// Destination mount directory (its .pvfs/ must not exist yet)
        dest: PathBuf,
        /// A named instance from `pvfs instance add`
        #[arg(long)]
        instance: Option<String>,
        /// Network address of a `pvfsd --listen` daemon (host:port); needs --pin
        #[arg(long, conflicts_with = "instance")]
        connect: Option<String>,
        /// The server's transport pin (with --connect)
        #[arg(long, requires = "connect")]
        pin: Option<String>,
        /// A local daemon socket (same-host replication)
        #[arg(long, conflicts_with_all = ["instance", "connect", "pin"])]
        socket: Option<PathBuf>,
        /// P7.2b (doc 20 §2.4): replicate one region only — the marked node's
        /// id. Ships the (small) top log plus that region's generations;
        /// sibling regions stay attested-but-unfetched. Needs admin on the
        /// region root rather than the forest root for the region logs.
        #[arg(long)]
        region: Option<String>,
    },
    /// Pull new events from the replica's recorded source and re-verify
    Sync { mount: PathBuf },
    /// Follow the source live (F5.4): long-poll for new events, ingest and
    /// fold them within seconds, reconnect on failure. Runs until killed.
    Follow { mount: PathBuf },
}

#[derive(Subcommand)]
enum ServeCmd {
    /// Enable a job in `serve.jobs` (follow|sync|export|tier|evict). The
    /// daemon picks it up on SIGHUP or restart.
    Enable { job: String },
    /// Disable a job in `serve.jobs`
    Disable { job: String },
    /// List the jobs this data dir is configured to run
    Ls,
    /// List the exports the export job keeps fresh (`pvfs export --keep-fresh`)
    Exports,
    /// Ask the running daemon for live job-runner state
    Status,
    /// Run the watcher in the foreground (live indexing + reconciliation) —
    /// ad-hoc; as a daemon job use `pvfs serve enable watch` (punch E)
    Watch {
        #[arg(long, default_value_t = 3600)]
        reconcile_secs: u64,
        #[arg(long, default_value_t = 2000)]
        debounce_ms: u64,
    },
}

#[derive(Subcommand)]
enum RegionCmd {
    /// Mark a node as a region boundary (its subtree becomes a unit)
    Mark { target: String },
    /// Remove a region boundary (the subtree folds back in)
    Unmark { target: String },
    /// List marked regions, and which region a node is in with a target
    Ls { target: Option<String> },
}

#[derive(Subcommand)]
enum FleetCmd {
    /// Authorize a box's client identity as a member AND grant it rights at
    /// the forest root — the one-step admit for private fleets (doc 17 §9
    /// Q5, resolution (c)). Run on the owner; prompts for anything omitted.
    /// The owner's OWN boxes need this too: every outbound fetch (the mover
    /// included) authenticates as a client identity, never the device key.
    Enroll {
        /// The box's client identity — `pvfs whoami` on that box
        pubkey: Option<String>,
        /// Rights at the root: r (consumer), rw (ingest), rwa (replicator)
        #[arg(long)]
        rights: Option<String>,
    },
}

#[derive(Subcommand)]
enum InstanceCmd {
    /// Remember a network instance: `pvfs remote --instance <name>` then dials it
    Add {
        /// Local nickname for the instance
        name: String,
        /// The `pvfsd --listen` address (host:port)
        addr: String,
        /// The server's transport pin (printed by `pvfsd --listen`; also in
        /// `<data-dir>/nettls/pin` on the server)
        pin: String,
    },
    /// List remembered instances
    Ls,
    /// Forget a remembered instance
    Rm { name: String },
}

#[derive(Subcommand)]
enum RemoteCmd {
    /// Forest identity behind the socket
    Info,
    /// List a node's children visible to you
    Ls { node: String },
    /// Show a node's metadata + your effective rights
    Stat { node: String },
    /// Stream a file node's bytes to stdout
    Cat { node: String },
    /// Create a folder under a parent node (requires your client identity)
    Mkdir { parent: String, label: String },
    /// Create a file node under a parent (requires your client identity)
    AddFile {
        parent: String,
        label: String,
        #[arg(long, default_value_t = 0)]
        size: u64,
        #[arg(long, default_value = "application/octet-stream")]
        mime: String,
    },
    /// Remove a node from its home parent (requires your client identity)
    Rm { node: String },
    /// Record where a file's bytes live (requires your client identity)
    AddLocation { file: String, uri: String },
    /// Move a node under a new parent (requires your client identity)
    Mv { node: String, new_parent: String },
    /// Create a custom-typed node with a small inline payload (doc 13 —
    /// log-resident records; reserved types file/folder/secure are refused;
    /// requires your client identity)
    AddNode {
        parent: String,
        label: String,
        /// The custom node type, e.g. `pvos.grant`
        node_type: String,
        /// Payload: a literal string, `@<file>` to read a file, `@-` for stdin
        #[arg(long, default_value = "")]
        payload: String,
    },
    /// Print a typed node's inline payload to stdout
    Payload { node: String },
}

/// A `remote` payload argument: literal text, `@<file>`, or `@-` (stdin).
fn remote_payload_bytes(arg: &str) -> Result<Vec<u8>, PvfsError> {
    match arg.strip_prefix('@') {
        None => Ok(arg.as_bytes().to_vec()),
        Some("-") => {
            use std::io::Read as _;
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| PvfsError::io("read payload from stdin", e))?;
            Ok(buf)
        }
        Some(path) => std::fs::read(path).map_err(|e| PvfsError::io("read payload file", e)),
    }
}

/// Load (or create on first use) this machine's client identity (doc 07 §2),
/// stored as a recovery phrase at `<config>/identity.phrase` (mode 0600). The
/// signing key is `device_key(0)` of that phrase.
/// The instance registry (F1, doc 17 §4): named `(address, transport pin)`
/// pairs in `<config>/instances`, one `name addr pin` line each. Manual,
/// explicit trust — adding an entry IS the pinning step.
fn instances_path() -> Result<PathBuf, PvfsError> {
    // Reads moved to pvfs-client (P5.2) so daemon jobs resolve holders the
    // same way; the CLI still owns writes, against the same path.
    pvfs_client::fetch::instances_path()
}

fn load_instances() -> Result<Vec<(String, String, String)>, PvfsError> {
    pvfs_client::fetch::load_instances()
}

fn save_instances(list: &[(String, String, String)]) -> Result<(), PvfsError> {
    let path = instances_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| PvfsError::io("create config dir", e))?;
    }
    let mut text = String::new();
    for (n, a, p) in list {
        text.push_str(&format!("{n} {a} {p}\n"));
    }
    std::fs::write(&path, text).map_err(|e| PvfsError::io("write instances", e))
}

fn lookup_instance(name: &str) -> Result<(String, String), PvfsError> {
    load_instances()?
        .into_iter()
        .find(|(n, _, _)| n == name)
        .map(|(_, addr, pin)| (addr, pin))
        .ok_or_else(|| PvfsError::NotFound {
            kind: "instance",
            id: name.into(),
        })
}

/// Resolve where a replica fetches from (`--instance` / `--connect --pin` /
/// `--socket`) into the source record the replica marker stores.
fn resolve_replica_dial(
    instance: Option<String>,
    connect: Option<String>,
    pin: Option<String>,
    socket: Option<PathBuf>,
) -> Result<pvfs_core::ReplicaSource, PvfsError> {
    if let Some(s) = socket {
        return Ok(pvfs_core::ReplicaSource {
            transport: "socket".into(),
            target: s.to_string_lossy().into_owned(),
            pin: String::new(),
            region: String::new(),
        });
    }
    if let Some(addr) = connect {
        let pin = pin.ok_or_else(|| PvfsError::BadInput {
            field: "replica".into(),
            reason: "pass --pin <hex> with --connect (printed by pvfsd --listen)".into(),
        })?;
        return Ok(pvfs_core::ReplicaSource {
            transport: "tcp".into(),
            target: addr,
            pin,
            region: String::new(),
        });
    }
    if let Some(name) = instance {
        let (addr, pin) = lookup_instance(&name)?;
        return Ok(pvfs_core::ReplicaSource {
            transport: "tcp".into(),
            target: addr,
            pin,
            region: String::new(),
        });
    }
    Err(PvfsError::BadInput {
        field: "replica".into(),
        reason: "pass --instance <name>, --connect <host:port> --pin <hex>, or --socket <path>"
            .into(),
    })
}

/// Dial a replica source as the client identity (log shipping is gated on
/// root-admin rights, so the connection must be signed).
fn replica_client(src: &pvfs_core::ReplicaSource) -> Result<Client, PvfsError> {
    let mn = client_identity_mnemonic()?;
    let key = identity::device_key(&mn, "", 0)?;
    let pubkey = crypto::pubkey_bytes(&key);
    let sign = |d: &[u8; 32]| crypto::sign_digest(&key, d).unwrap_or_default();
    match src.transport.as_str() {
        "tcp" => Client::connect_tcp_signed(&src.target, &src.pin, &pubkey, sign)
            .map_err(remote_err),
        _ => Client::connect_signed(std::path::Path::new(&src.target), &pubkey, sign)
            .map_err(remote_err),
    }
}


/// Pull the source log from `from` until caught up, ingesting verbatim rows
/// (chain-verified per batch). Returns the number of events ingested.
fn replica_pull(
    client: &mut Client,
    store: &mut pvfs_core::ReplicaStore,
    mut from: u64,
) -> Result<u64, PvfsError> {
    let mut total = 0u64;
    loop {
        let (_tip, events) = client.log_read(from, 512, "").map_err(remote_err)?;
        if events.is_empty() {
            return Ok(total);
        }
        let rows: Result<Vec<pvfs_core::log_store::EventRow>, PvfsError> = events
            .iter()
            .map(|w| {
                Ok(pvfs_core::log_store::EventRow {
                    seq: w.seq,
                    kind: w.kind.clone(),
                    body: hex::decode(&w.body).map_err(|_| PvfsError::BadInput {
                        field: "replica".into(),
                        reason: "shipped event body not hex".into(),
                    })?,
                    chain_hash: hex::decode(&w.chain_hash).map_err(|_| PvfsError::BadInput {
                        field: "replica".into(),
                        reason: "shipped chain hash not hex".into(),
                    })?,
                    written_at: w.written_at,
                })
            })
            .collect();
        let rows = rows?;
        total += rows.len() as u64;
        from = store.append(&rows)? + 1;
    }
}

fn client_identity_mnemonic() -> Result<pvfs_core::Mnemonic, PvfsError> {
    // Moved to core (P5.1) so pvfsd's background jobs share the identity.
    identity::client_identity_mnemonic()
}

/// Punch B: the identity-model refusals get actionable guidance.
fn enroll_hint(msg: &str) -> String {
    if msg.contains("author not authorized") || msg.contains("not an authorized member") {
        format!(
            "{msg} — this box's identity may not be enrolled: on the owner, run \
             `pvfs fleet enroll <this box's 'pvfs whoami' pubkey>`"
        )
    } else {
        msg.to_string()
    }
}

fn remote_err(e: pvfs_client::ClientError) -> PvfsError {
    // Preserve the daemon's error semantics so `pvfs remote …` exit codes stay
    // meaningful for scripts: a denied op exits 5 (Forbidden), a missing node 3
    // (NotFound), bad input 2 — not a blanket 2 (spec §13.4 / exit_code_for).
    if let pvfs_client::ClientError::Server { code, message } = &e {
        match code.as_str() {
            "forbidden" => {
                return PvfsError::Forbidden {
                    action: "remote".into(),
                    reason: enroll_hint(message),
                }
            }
            "not_found" => {
                return PvfsError::NotFound {
                    kind: "remote",
                    id: message.clone(),
                }
            }
            "already_exists" => {
                return PvfsError::AlreadyExists {
                    kind: "remote",
                    id: message.clone(),
                }
            }
            _ => {}
        }
    }
    PvfsError::BadInput {
        field: "remote".into(),
        reason: enroll_hint(&e.to_string()),
    }
}

/// Resolve the daemon socket: explicit `--socket`, else the conventional path for
/// the forest named by `--forest` (an alias or a mount path).
fn resolve_remote_socket(
    socket: Option<PathBuf>,
    forest: Option<String>,
) -> Result<PathBuf, PvfsError> {
    if let Some(s) = socket {
        return Ok(s);
    }
    let forest = forest.ok_or_else(|| PvfsError::BadInput {
        field: "remote".into(),
        reason: "pass --socket <path> or --forest <alias|mount>".into(),
    })?;
    let mount = match Registry::system().find(&forest)? {
        Some(f) => f.mount,
        None => PathBuf::from(&forest),
    };
    let forest_id = mount::peek_identity(&mount)?.forest_id;
    Ok(mount::daemon_socket_path(&forest_id))
}

fn needs_identity() -> PvfsError {
    PvfsError::BadInput {
        field: "remote".into(),
        reason: "writes require your client identity — do not pass --anon".into(),
    }
}

fn print_created(id: &str, json: bool) {
    if json {
        println!("{{\"created\":\"{}\"}}", json_escape(id));
    } else {
        println!("created {id}");
    }
}

/// Parse `--expires` (doc 13 Q-E1) into a ms-epoch instant: a duration from now
/// (`45s`, `30m`, `12h`, `7d`, `2w`) or an absolute `@<unix-ms>`.
fn parse_expires(s: &str) -> Result<u64, PvfsError> {
    let bad = |reason: String| PvfsError::BadInput {
        field: "expires".into(),
        reason,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if let Some(ms) = s.strip_prefix('@') {
        let t: u64 = ms
            .parse()
            .map_err(|_| bad(format!("{s:?} — @<unix-ms> must be an integer")))?;
        if t == 0 {
            return Err(bad("@0 — zero means \"never\"; omit --expires instead".into()));
        }
        return Ok(t);
    }
    let (num, unit) = s.split_at(s.len().saturating_sub(1));
    let n: u64 = num
        .parse()
        .map_err(|_| bad(format!("{s:?} — use <N>(s|m|h|d|w) or @<unix-ms>")))?;
    let ms_per = match unit {
        "s" => 1_000u64,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        "w" => 7 * 86_400_000,
        _ => return Err(bad(format!("{s:?} — use <N>(s|m|h|d|w) or @<unix-ms>"))),
    };
    n.checked_mul(ms_per)
        .and_then(|d| now.checked_add(d))
        .ok_or_else(|| bad(format!("{s:?} — duration overflows")))
}

/// Human note for a grant expiry: `""` for never, ` [expired]` once past, else
/// ` (expires in ~<coarse duration>)`.
fn expiry_suffix(expires_at: u64) -> String {
    if expires_at == 0 {
        return String::new();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if expires_at <= now {
        return " [expired]".into();
    }
    let left = expires_at - now;
    let (val, unit) = if left >= 7 * 86_400_000 {
        (left / (7 * 86_400_000), "w")
    } else if left >= 86_400_000 {
        (left / 86_400_000, "d")
    } else if left >= 3_600_000 {
        (left / 3_600_000, "h")
    } else if left >= 60_000 {
        (left / 60_000, "m")
    } else {
        (left.div_ceil(1_000), "s")
    };
    format!(" (expires in ~{val}{unit})")
}

/// ` (by <short-hex>)` for a non-empty tag authority (doc 10), else empty. Lets
/// `acl ls` / `tag ls` show *which key* scopes a `tag:` grant or membership.
fn authority_suffix(authority: &[u8]) -> String {
    if authority.is_empty() {
        String::new()
    } else {
        format!(" (by {})", hex::encode(&authority[..authority.len().min(4)]))
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn exit_code_for(e: &PvfsError) -> u8 {
    match e {
        PvfsError::BadInput { .. } | PvfsError::Encoding { .. } => 2,
        PvfsError::NotFound { .. } => 3,
        PvfsError::AlreadyExists { .. }
        | PvfsError::AlreadyContained { .. }
        | PvfsError::NotOrphan { .. }
        | PvfsError::CycleDetected { .. } => 4,
        PvfsError::Integrity { .. }
        | PvfsError::Identity { .. }
        | PvfsError::Forbidden { .. }
        | PvfsError::SchemaVersion { .. } => 5,
        PvfsError::Corruption { .. } | PvfsError::LogChainBroken { .. } => 6,
        _ => 1,
    }
}

fn variant_name(e: &PvfsError) -> &'static str {
    match e {
        PvfsError::Io { .. } => "Io",
        PvfsError::Db { .. } => "Db",
        PvfsError::Busy { .. } => "Busy",
        PvfsError::Encoding { .. } => "Encoding",
        PvfsError::NotFound { .. } => "NotFound",
        PvfsError::Integrity { .. } => "Integrity",
        PvfsError::LogChainBroken { .. } => "LogChainBroken",
        PvfsError::Corruption { .. } => "Corruption",
        PvfsError::CycleDetected { .. } => "CycleDetected",
        PvfsError::Identity { .. } => "Identity",
        PvfsError::BadInput { .. } => "BadInput",
        PvfsError::Forbidden { .. } => "Forbidden",
        PvfsError::AlreadyExists { .. } => "AlreadyExists",
        PvfsError::NotOrphan { .. } => "NotOrphan",
        PvfsError::AlreadyContained { .. } => "AlreadyContained",
        PvfsError::SchemaVersion { .. } => "SchemaVersion",
    }
}

fn print_error(e: &PvfsError, json: bool) {
    if json {
        eprintln!(
            "{{\"error\":\"{}\",\"message\":\"{}\"}}",
            variant_name(e),
            json_escape(&e.to_string())
        );
    } else {
        eprintln!("error: {e}");
        // print the cause chain (spec §13.4)
        let mut src = std::error::Error::source(e);
        while let Some(s) = src {
            eprintln!("  caused by: {s}");
            src = s.source();
        }
    }
}

/// Old-style state dir for the low-level `init` / `recover` commands.
fn legacy_state_dir(cli: &Cli) -> PathBuf {
    cli.data_dir.clone().unwrap_or_else(|| {
        std::env::var("PVFS_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(".pvfs"))
    })
}

/// Forest context for node-id commands (doc 05 §6.4):
/// --data-dir > --forest (alias or mount path) > $PVFS_DATA_DIR > enclosing mount of CWD.
fn context_state_dir(cli: &Cli) -> Result<PathBuf, PvfsError> {
    if let Some(d) = &cli.data_dir {
        return Ok(d.clone());
    }
    if let Some(f) = &cli.forest {
        if let Some(reg) = Registry::system().find(f)? {
            return Ok(mount::state_dir(&reg.mount));
        }
        let p = PathBuf::from(f);
        if mount::is_mount(&p) {
            return Ok(mount::state_dir(&p));
        }
        return Err(PvfsError::NotFound {
            kind: "forest",
            id: f.clone(),
        });
    }
    if let Ok(d) = std::env::var("PVFS_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    let cwd = std::env::current_dir().map_err(|e| PvfsError::io("getcwd", e))?;
    if let Some(m) = mount::enclosing_mount(&cwd) {
        return Ok(mount::state_dir(&m));
    }
    Err(PvfsError::BadInput {
        field: "forest".into(),
        reason: "no forest context — run inside a mount, pass --forest <alias|mount>, or set PVFS_DATA_DIR"
            .into(),
    })
}

fn is_node_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Resolve a command target: bare node id (uses forest context) or a
/// pvfs:// URI / absolute path under a mount (doc 05 §4).
fn engine_and_node(
    ctx: Result<PathBuf, PvfsError>,
    target: &str,
) -> Result<(Engine, String), PvfsError> {
    if is_node_id(target) {
        let dir = ctx?;
        Ok((Engine::open(&dir)?, target.to_string()))
    } else {
        let t = mount::resolve_target(&Registry::system(), target)?;
        let engine = mount::open_mount(&t.mount)?;
        let node = mount::node_at_path(&engine, &t.segments)?;
        Ok((engine, node))
    }
}

/// Resolve a target to a node id only, without keeping the engine open.
/// Uses `engine_and_node` for the path walk, then drops the engine.
fn resolve_node_id(ctx: Result<PathBuf, PvfsError>, target: &str) -> Result<String, PvfsError> {
    let (engine, id) = engine_and_node(ctx, target)?;
    engine.close()?;
    Ok(id)
}

/// Resolve a `remote` target (doc 08 §4 item 6 remainder): a bare node id
/// passes through; a `pvfs://` URI or absolute path parses its tree segments
/// locally (registry / mount-prefix only — the owner's engine is never opened)
/// and walks them **over the daemon** with ACL-filtered `ls`, so a caller can
/// only resolve what they could already list. An empty tail is the root.
fn remote_node(client: &mut Client, target: &str) -> Result<String, PvfsError> {
    if is_node_id(target) {
        return Ok(target.to_string());
    }
    let segments = mount::resolve_target(&Registry::system(), target)?.segments;
    let mut cur = client.info().map_err(remote_err)?.root;
    for seg in &segments {
        cur = client
            .ls(&cur)
            .map_err(remote_err)?
            .into_iter()
            .find(|c| c.label == *seg)
            .ok_or_else(|| PvfsError::NotFound {
                kind: "path segment",
                id: seg.clone(),
            })?
            .id;
    }
    Ok(cur)
}

/// Find the daemon socket for the current forest context, if a daemon is
/// running (doc 09 §2.1 auto-routing). Returns `None` when no socket exists,
/// which signals the caller to fall back to direct engine access.
fn try_daemon_socket(state_dir: &std::path::Path) -> Option<PathBuf> {
    // Peek the forest identity to derive the conventional socket path.
    // state_dir is <mount>/.pvfs/; its parent is the mount directory.
    let parent = state_dir.parent().filter(|p| !p.as_os_str().is_empty())?;
    // Canonicalize so that relative paths (PVFS_DATA_DIR=".pvfs") work too.
    let mount = std::fs::canonicalize(parent).ok()?;
    let identity = mount::peek_identity(&mount).ok()?;
    let sock = mount::daemon_socket_path(&identity.forest_id);
    // Only return the path if the socket file exists (daemon is running).
    if sock.exists() {
        Some(sock)
    } else {
        None
    }
}

/// Connect to the daemon if one is running for this forest, authenticated with
/// the best signing key available (doc 09 §3d auto-routing). Returns `None` when
/// no daemon socket exists, signalling the caller to fall back to direct engine
/// access. The returned closure is the per-mutation signer for the connected key.
///
/// **Signing identity (item 16 fix):** for *local owner* admin we must sign with
/// the forest's **authorized admin device key**, cached at `<mount>/.pvfs/device.key`
/// (`state_dir`) and authorized at `forest init`. The generic CLI client identity
/// (`<config>/identity.phrase`) is *not* an authorized admin by default, so signing
/// auto-routed `acl`/`tag`/`device` ops with it would be rejected by the daemon.
/// We therefore prefer the forest device key whenever it is readable here (only the
/// owner can read the `0600` `.pvfs/device.key`), and fall back to the client
/// identity otherwise (e.g. a member auto-routing against a forest they don't own).
/// The per-mutation signer for a connected key (what the daemon's two-phase
/// member writes call to sign each event digest).
type SignFn = Box<dyn Fn(&[u8; 32]) -> Vec<u8>>;

/// Write-through connection for a replica mount (F5.0, doc 17 §7): dial the
/// recorded source, signing as the **client identity** — a replica has no
/// forest device key, and the member model is exactly what remote writes use.
fn replica_write_client(data_dir: &std::path::Path) -> Result<(Client, SignFn), PvfsError> {
    let src = pvfs_core::ReplicaSource::load(data_dir)?;
    let mn = client_identity_mnemonic()?;
    let key = identity::device_key(&mn, "", 0)?;
    let pubkey = crypto::pubkey_bytes(&key);
    let client = match src.transport.as_str() {
        "tcp" => Client::connect_tcp_signed(&src.target, &src.pin, &pubkey, |d| {
            crypto::sign_digest(&key, d).unwrap_or_default()
        }),
        _ => Client::connect_signed(std::path::Path::new(&src.target), &pubkey, |d| {
            crypto::sign_digest(&key, d).unwrap_or_default()
        }),
    }
    .map_err(remote_err)?;
    let sign: SignFn = Box::new(move |d| crypto::sign_digest(&key, d).unwrap_or_default());
    Ok((client, sign))
}

/// Materialize a `loc add` target: an explicit URI, or `--here <path>` as an
/// instance-qualified location bearing this data dir's transport pin (F5.1,
/// doc 17 §7.2).
fn loc_add_uri(
    data_dir: &std::path::Path,
    uri: Option<String>,
    here: Option<PathBuf>,
) -> Result<String, PvfsError> {
    match (uri, here) {
        (Some(u), None) => Ok(u),
        (None, Some(p)) => {
            let abs =
                std::fs::canonicalize(&p).map_err(|e| PvfsError::io("resolve --here path", e))?;
            let pin =
                pvfs_core::storage::host_pin(data_dir).ok_or_else(|| PvfsError::BadInput {
                    field: "here".into(),
                    reason: "this forest has no transport pin yet — run `pvfsd --listen <addr>` \
                             once so other instances can dial these bytes (doc 17 §7.2)"
                        .into(),
                })?;
            pvfs_core::storage::host_uri(&pin, &abs)
        }
        _ => Err(PvfsError::BadInput {
            field: "loc".into(),
            reason: "pass a URI or --here <path>".into(),
        }),
    }
}

/// Read-your-writes, best-effort (F5.0): after a write-through, pull the
/// source's log tail so the change is visible locally right now. Log
/// shipping needs replication rights on this connection — when the identity
/// lacks them the pull is quietly skipped (the write landed; visibility
/// arrives with the next `replica sync`).
fn replica_catch_up(data_dir: &std::path::Path, client: &mut Client) {
    let _ = (|| -> Result<(), PvfsError> {
        let mut store = pvfs_core::ReplicaStore::open(data_dir)?;
        let from = store.tip()? + 1;
        replica_pull(client, &mut store, from)?;
        drop(store);
        let scope = pvfs_core::ReplicaSource::load(data_dir)
            .map(|s| s.region)
            .unwrap_or_default();
        let scope = if scope.is_empty() { None } else { Some(scope) };
        pvfs_client::regions::sync_generations(client, data_dir, scope.as_deref())?;
        // Fold the tail into the projection NOW — so this process's next
        // read and any daemon currently serving this replica (its readers
        // see committed projection rows) pick the change up immediately.
        Engine::open(data_dir)?.close()?;
        Ok(())
    })();
}

fn daemon_client(state_dir: &std::path::Path) -> Result<Option<(Client, SignFn)>, PvfsError> {
    // A replica mount's "daemon" is its recorded source (F5.0, doc 17 §7):
    // every auto-routed op writes through, member-signed, to the owner.
    if pvfs_core::replica::marker_path(state_dir).exists() {
        return replica_write_client(state_dir).map(Some);
    }
    let Some(sock) = try_daemon_socket(state_dir) else {
        return Ok(None);
    };
    let key = match identity::DeviceKeyCache::load(state_dir) {
        Ok(cache) => cache.signing_key,
        Err(_) => {
            let mn = client_identity_mnemonic()?;
            identity::device_key(&mn, "", 0)?
        }
    };
    let pubkey = crypto::pubkey_bytes(&key);
    // FnOnce borrow of key ends when connect_signed returns (NLL).
    let client = Client::connect_signed(&sock, &pubkey, |d| {
        crypto::sign_digest(&key, d).unwrap_or_default()
    })
    .map_err(remote_err)?;
    // key is free to move: the FnOnce above was consumed inside connect_signed.
    let sign: SignFn = Box::new(move |d| crypto::sign_digest(&key, d).unwrap_or_default());
    Ok(Some((client, sign)))
}

/// Resolve the companion signer socket (doc 14 §9 phase 3 auto-detection):
/// an explicit `--companion-socket` wins; otherwise the companion's own default
/// ($PVFS_COMPANION_SOCKET, else $XDG_RUNTIME_DIR/pvfs-companion.sock, else a
/// per-user /tmp path) — so a bare `pvfs-companion serve` and a bare
/// `--via-companion` op always agree on the path.
fn resolve_companion_socket(explicit: Option<PathBuf>) -> Result<PathBuf, PvfsError> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    let p = pvfs_companion::default_socket_path();
    if p.exists() {
        return Ok(p);
    }
    Err(PvfsError::BadInput {
        field: "companion-socket".into(),
        reason: format!(
            "no companion running at {} — start it with `pvfs-companion serve` \
             (or pass --companion-socket / set $PVFS_COMPANION_SOCKET)",
            p.display()
        ),
    })
}

/// Best-effort companion detection (socket present + answers `get_pubkey root`).
///
/// If `$PVFS_COMPANION_SOCKET` is set (desktop SSO / explicit env) but the agent
/// is unreachable, returns `Err` so we never silently mint a new phrase.
fn probe_companion(explicit: Option<PathBuf>) -> Result<Option<(PathBuf, Vec<u8>)>, PvfsError> {
    let env_set = std::env::var_os("PVFS_COMPANION_SOCKET")
        .filter(|s| !s.is_empty())
        .is_some();
    let required = env_set || explicit.is_some();
    let sock = if let Some(p) = explicit {
        p
    } else {
        let p = pvfs_companion::default_socket_path();
        if !p.exists() {
            if env_set {
                return Err(PvfsError::BadInput {
                    field: "companion-socket".into(),
                    reason: format!(
                        "PVFS_COMPANION_SOCKET is set but {} does not exist — \
                         is the desktop SSO SSH forward still up?",
                        p.display()
                    ),
                });
            }
            return Ok(None);
        }
        p
    };
    match companion_pubkey(&sock, "root") {
        Ok(pk) => Ok(Some((sock, pk))),
        Err(e) => {
            if required {
                Err(PvfsError::BadInput {
                    field: "companion".into(),
                    reason: format!(
                        "companion at {} did not answer ({e}) — start the desktop agent \
                         and keep the SSO SSH session open",
                        sock.display()
                    ),
                })
            } else {
                Ok(None)
            }
        }
    }
}

/// Interactive: use companion identity for this forest? Default yes.
fn confirm_use_companion(root_pub_hex: &str) -> Result<bool, PvfsError> {
    use std::io::{self, Write};
    eprint!(
        "Local companion is running (root key {root_pub_hex}…).\n\
         Use that identity for this forest (no new recovery phrase)? [Y/n] "
    );
    let _ = io::stderr().flush();
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| PvfsError::io("read confirm", e))?;
    let t = line.trim().to_ascii_lowercase();
    Ok(t.is_empty() || t == "y" || t == "yes")
}

/// The shared shape of a companion-signed admin op (doc 14 §3): open the engine,
/// prepare exactly one event, have the companion sign its digest for
/// `request_type`, and commit through the member-write verifier.
fn companion_commit(
    state_dir: &Path,
    socket: &Path,
    request_type: &str,
    prepare: impl FnOnce(&Engine) -> Result<pvfs_core::PreparedWrite, PvfsError>,
) -> Result<(), PvfsError> {
    let mut engine = Engine::open(state_dir)?;
    let prep = prepare(&engine)?;
    let mut ev = prep
        .events
        .into_iter()
        .next()
        .expect("companion ops prepare one event");
    let sig = companion_sign(socket, request_type, &ev.digest)?;
    ev.event.set_author_sig(sig);
    engine.commit_member_write(vec![ev.event])?;
    engine.close()
}

/// Ask a running companion (doc 14 §3) for the public key of `role` ("root" or
/// "identity").
fn companion_pubkey(socket: &Path, role: &str) -> Result<Vec<u8>, PvfsError> {
    let bad = |reason: String| PvfsError::BadInput {
        field: "companion".into(),
        reason,
    };
    let resp = pvfs_companion::request(
        socket,
        &pvfs_companion::AgentRequest::GetPubkey { role: role.into() },
    )
    .map_err(|e| bad(e.to_string()))?;
    match resp {
        pvfs_companion::AgentResponse::Pubkey { pubkey } => {
            hex::decode(&pubkey).map_err(|_| bad("companion returned bad pubkey hex".into()))
        }
        pvfs_companion::AgentResponse::Error { code, message } => Err(bad(format!("{code}: {message}"))),
        _ => Err(bad("unexpected companion response".into())),
    }
}

/// Ask a running companion to sign `digest` for a request type (doc 14 §3, §4).
fn companion_sign(socket: &Path, request_type: &str, digest: &[u8; 32]) -> Result<Vec<u8>, PvfsError> {
    let resp = pvfs_companion::request(
        socket,
        &pvfs_companion::AgentRequest::Sign {
            request_type: request_type.into(),
            digest: hex::encode(digest),
            origin: Some("local".into()),
            context: None,
        },
    )
    .map_err(|e| PvfsError::BadInput {
        field: "companion".into(),
        reason: e.to_string(),
    })?;
    match resp {
        pvfs_companion::AgentResponse::Signature { sig } => {
            hex::decode(&sig).map_err(|_| PvfsError::BadInput {
                field: "companion".into(),
                reason: "companion returned bad signature hex".into(),
            })
        }
        pvfs_companion::AgentResponse::Error { code, message } => Err(PvfsError::Forbidden {
            action: "companion sign".into(),
            reason: format!("{code}: {message}"),
        }),
        _ => Err(PvfsError::BadInput {
            field: "companion".into(),
            reason: "unexpected companion response".into(),
        }),
    }
}

/// Ask the companion to unwrap a secure-blob content key (doc 12 §8.5).
fn companion_unwrap(
    socket: &Path,
    wrap: &pvfs_core::envelope::Wrap,
) -> Result<[u8; 32], PvfsError> {
    let resp = pvfs_companion::request(
        socket,
        &pvfs_companion::AgentRequest::SecureUnwrap {
            ephemeral_pubkey: hex::encode(&wrap.ephemeral_pubkey),
            nonce: hex::encode(&wrap.nonce),
            wrapped_key: hex::encode(&wrap.wrapped_key),
        },
    )
    .map_err(|e| PvfsError::BadInput {
        field: "companion".into(),
        reason: e.to_string(),
    })?;
    match resp {
        pvfs_companion::AgentResponse::ContentKey { content_key } => hex::decode(&content_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| PvfsError::BadInput {
                field: "companion".into(),
                reason: "companion returned a bad content key".into(),
            }),
        pvfs_companion::AgentResponse::Error { code, message } => Err(PvfsError::Forbidden {
            action: "companion unwrap".into(),
            reason: format!("{code}: {message}"),
        }),
        _ => Err(PvfsError::BadInput {
            field: "companion".into(),
            reason: "unexpected companion response".into(),
        }),
    }
}

/// A `NodeSpec` for a secure node (doc 12) with the given label.
fn secure_spec(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: pvfs_core::TYPE_SECURE.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

fn run(cli: Cli) -> Result<(), PvfsError> {
    let legacy = legacy_state_dir(&cli);
    let ctx = context_state_dir(&cli);
    let json = cli.json;
    match cli.cmd {
        Cmd::Init => {
            let (engine, mnemonic) = Engine::init(&legacy)?;
            if json {
                println!(
                    "{{\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"mnemonic\":\"{}\"}}",
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    json_escape(&mnemonic.to_string()),
                );
            } else {
                println!("Forest initialized in {}", legacy.display());
                println!("  instance_id : {}", engine.identity.instance_id);
                println!("  forest_id   : {}", engine.identity.forest_id);
                println!("  root node   : {}", engine.identity.root_node_id);
                println!();
                println!("RECOVERY PHRASE — write this down now; it is shown ONCE and never stored:");
                println!();
                println!("  {mnemonic}");
                println!();
            }
            engine.close()
        }
        Cmd::Recover {
            mnemonic,
            device_index,
        } => {
            let m = identity::parse_mnemonic(&mnemonic)?;
            let engine = Engine::recover(&legacy, &m, device_index)?;
            if json {
                println!(
                    "{{\"recovered\":true,\"device_index\":{},\"device_pubkey\":\"{}\"}}",
                    device_index,
                    hex::encode(engine.device_pubkey())
                );
            } else {
                println!(
                    "Recovered as device {} ({})",
                    device_index,
                    hex::encode(engine.device_pubkey())
                );
            }
            engine.close()
        }
        Cmd::Info => {
            let engine = Engine::open(&ctx?)?;
            if json {
                println!(
                    "{{\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"device_pubkey\":\"{}\"}}",
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    hex::encode(engine.device_pubkey()),
                );
            } else {
                println!("instance_id : {}", engine.identity.instance_id);
                println!("forest_id   : {}", engine.identity.forest_id);
                println!("root node   : {}", engine.identity.root_node_id);
                println!("device key  : {}", hex::encode(engine.device_pubkey()));
            }
            engine.close()
        }
        Cmd::Tree(TreeCmd::Create { label }) => {
            let mut engine = Engine::open(&ctx?)?;
            let id = engine.create_tree(&label)?;
            emit_id(json, "root_node_id", &id);
            engine.close()
        }
        Cmd::Add {
            parent,
            kind,
            label,
            temp,
            nonce,
            size,
            mime,
            content_hash,
        } => {
            let mut engine = Engine::open(&ctx?)?;
            // F5.0 (doc 17 §7): on a replica mount, create through the
            // recorded source — member-signed, then caught up locally.
            if engine.is_replica() {
                if temp {
                    return Err(PvfsError::BadInput {
                        field: "temp".into(),
                        reason: "temp nodes are forest-local — a replica has no local writer"
                            .into(),
                    });
                }
                if !content_hash.is_empty() || nonce.is_some() {
                    return Err(PvfsError::BadInput {
                        field: "add".into(),
                        reason: "--content-hash/--nonce aren't carried by write-through — \
                                 add the node, then record bytes with `pvfs loc add`"
                            .into(),
                    });
                }
                let data_dir = engine.data_dir().to_path_buf();
                engine.close()?;
                let (mut client, sign) = replica_write_client(&data_dir)?;
                let id = if kind == "file" {
                    client.add_file(&parent, &label, size, &mime, |d| sign(d))
                } else {
                    client.mkdir(&parent, &label, |d| sign(d))
                }
                .map_err(remote_err)?;
                replica_catch_up(&data_dir, &mut client);
                emit_id(json, "node_id", &id);
                return Ok(());
            }
            let (node_type, payload) = if kind == "file" {
                (
                    TYPE_FILE.to_string(),
                    FilePayload {
                        content_hash,
                        size_bytes: size,
                        mime_type: mime,
                        original_name: label.clone(),
                    }
                    .encode(),
                )
            } else {
                (TYPE_FOLDER.to_string(), Vec::new())
            };
            let id = engine.add_node(
                &parent,
                NodeSpec {
                    node_type,
                    label,
                    payload,
                    is_temp: temp,
                    creation_nonce: nonce,
                },
            )?;
            emit_id(json, "node_id", &id);
            engine.close()
        }
        Cmd::Link {
            parent,
            child,
            link_type,
            nonce,
        } => {
            let mut engine = Engine::open(&ctx?)?;
            if engine.is_replica() {
                // P6.0 (doc 19 §2): link ops write through to the source.
                if nonce != 0 {
                    return Err(PvfsError::BadInput {
                        field: "nonce".into(),
                        reason: "nonce links are owner-local — omit --nonce on a replica".into(),
                    });
                }
                let data_dir = engine.data_dir().to_path_buf();
                engine.close()?;
                let (mut client, sign) = replica_write_client(&data_dir)?;
                let id = client
                    .link(&parent, &child, &link_type, "", |d| sign(d))
                    .map_err(remote_err)?;
                replica_catch_up(&data_dir, &mut client);
                emit_id(json, "link_id", &id);
                return Ok(());
            }
            let id = engine.link(&parent, &child, &link_type, None, nonce)?;
            emit_id(json, "link_id", &id);
            engine.close()
        }
        Cmd::Unlink { link_id } => {
            let mut engine = Engine::open(&ctx?)?;
            if engine.is_replica() {
                let data_dir = engine.data_dir().to_path_buf();
                engine.close()?;
                let (mut client, sign) = replica_write_client(&data_dir)?;
                client.unlink(&link_id, |d| sign(d)).map_err(remote_err)?;
                replica_catch_up(&data_dir, &mut client);
            } else {
                engine.remove_link(&link_id)?;
                engine.close()?;
            }
            if json {
                println!("{{\"removed\":true}}");
            } else {
                println!("removed {link_id}");
            }
            Ok(())
        }
        Cmd::Reorder { link_id, key } => {
            let mut engine = Engine::open(&ctx?)?;
            let key = OrderKey::parse(&key)?;
            if engine.is_replica() {
                let data_dir = engine.data_dir().to_path_buf();
                engine.close()?;
                let (mut client, sign) = replica_write_client(&data_dir)?;
                client
                    .reorder(&link_id, key.as_str(), |d| sign(d))
                    .map_err(remote_err)?;
                replica_catch_up(&data_dir, &mut client);
            } else {
                engine.reorder_link(&link_id, &key)?;
                engine.close()?;
            }
            if json {
                println!("{{\"reordered\":true}}");
            } else {
                println!("reordered {link_id}");
            }
            Ok(())
        }
        Cmd::Ls { target: None } => {
            // forest inventory (doc 05 §6.1)
            let forests = Registry::system().list()?;
            if json {
                let items: Vec<String> = forests
                    .iter()
                    .map(|f| {
                        let identity = mount::peek_identity(&f.mount).ok();
                        format!(
                            "{{\"alias\":{},\"mount\":\"{}\",\"enabled\":{},\"instance_id\":{},\"forest_id\":{}}}",
                            f.alias
                                .as_ref()
                                .map(|a| format!("\"{}\"", json_escape(a)))
                                .unwrap_or_else(|| "null".into()),
                            json_escape(&f.mount.to_string_lossy()),
                            f.enabled,
                            identity
                                .as_ref()
                                .map(|i| format!("\"{}\"", json_escape(&i.instance_id)))
                                .unwrap_or_else(|| "null".into()),
                            identity
                                .as_ref()
                                .map(|i| format!("\"{}\"", json_escape(&i.forest_id)))
                                .unwrap_or_else(|| "null".into()),
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else if forests.is_empty() {
                println!("no registered forests (see `pvfs forest init` / `pvfs forest register`)");
            } else {
                for f in forests {
                    let identity = mount::peek_identity(&f.mount);
                    println!(
                        "{:<16} {}  {}{}",
                        f.alias.as_deref().unwrap_or("-"),
                        f.mount.display(),
                        identity
                            .map(|i| format!("{} / {}", i.instance_id, i.forest_id))
                            .unwrap_or_else(|_| "(unreadable)".into()),
                        if f.enabled { "" } else { "  [disabled]" }
                    );
                }
            }
            Ok(())
        }
        Cmd::Ls { target: Some(target) } => {
            let (engine, node) = engine_and_node(ctx, &target)?;
            let kids = engine.children(&node)?;
            if json {
                let items: Vec<String> = kids
                    .iter()
                    .map(|k| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"type\":\"{}\",\"link_type\":\"{}\",\"temp\":{},\"link_id\":\"{}\"}}",
                            k.node.id,
                            json_escape(&k.node.label),
                            json_escape(&k.node.node_type),
                            json_escape(&k.link_type),
                            k.node.is_temp,
                            k.link_id,
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for k in kids {
                    println!(
                        "{}  {:<8} {:<8} {}{}",
                        k.node.id,
                        k.node.node_type,
                        k.link_type,
                        k.node.label,
                        if k.node.is_temp { "  [temp]" } else { "" }
                    );
                }
            }
            engine.close()
        }
        Cmd::Walk { target } => {
            let (engine, root) = engine_and_node(ctx, &target)?;
            let walk = engine.walk(&root)?;
            if json {
                let items: Vec<String> = walk
                    .iter()
                    .map(|e| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"depth\":{},\"link_type\":\"{}\"}}",
                            e.node.id,
                            json_escape(&e.node.label),
                            e.depth,
                            json_escape(&e.link_type),
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for e in walk.iter() {
                    println!(
                        "{}{} {}{}",
                        "  ".repeat(e.depth),
                        e.node.label,
                        if e.link_type == "ref" { "→ " } else { "" },
                        if e.node.is_temp { "[temp]" } else { "" }
                    );
                }
            }
            engine.close()
        }
        Cmd::Node { target } => {
            let (engine, id) = engine_and_node(ctx, &target)?;
            match engine.get_node(&id)? {
                None => {
                    engine.close()?;
                    return Err(PvfsError::NotFound { kind: "node", id });
                }
                Some(n) => {
                    if json {
                        println!(
                            "{{\"id\":\"{}\",\"type\":\"{}\",\"label\":\"{}\",\"temp\":{},\"created_at\":{},\"author\":\"{}\"}}",
                            n.id,
                            json_escape(&n.node_type),
                            json_escape(&n.label),
                            n.is_temp,
                            n.created_at,
                            hex::encode(&n.author),
                        );
                    } else {
                        println!("id         : {}", n.id);
                        println!("type       : {}", n.node_type);
                        println!("label      : {}", n.label);
                        println!("temp       : {}", n.is_temp);
                        println!("created_at : {}", n.created_at);
                        println!("author     : {}", hex::encode(&n.author));
                    }
                }
            }
            engine.close()
        }
        Cmd::Loc(loc) => {
            let mut engine = Engine::open(&ctx?)?;
            // F5.0 (doc 17 §7): location mutations on a replica write through.
            if engine.is_replica() {
                match &loc {
                    LocCmd::Add { file, uri, here } => {
                        let data_dir = engine.data_dir().to_path_buf();
                        engine.close()?;
                        let target = loc_add_uri(&data_dir, uri.clone(), here.clone())?;
                        let (mut client, sign) = replica_write_client(&data_dir)?;
                        client
                            .add_location(file, &target, |d| sign(d))
                            .map_err(remote_err)?;
                        replica_catch_up(&data_dir, &mut client);
                        if json {
                            println!("{{\"added\":true}}");
                        } else {
                            println!("added");
                        }
                        return Ok(());
                    }
                    LocCmd::Rm { file, uri } => {
                        // P6.0 (doc 19 §2): retraction writes through too.
                        let data_dir = engine.data_dir().to_path_buf();
                        engine.close()?;
                        let (mut client, sign) = replica_write_client(&data_dir)?;
                        client
                            .remove_location(file, uri, |d| sign(d))
                            .map_err(remote_err)?;
                        replica_catch_up(&data_dir, &mut client);
                        if json {
                            println!("{{\"removed\":true}}");
                        } else {
                            println!("removed");
                        }
                        return Ok(());
                    }
                    _ => {} // reads run locally
                }
            }
            match loc {
                LocCmd::Add { file, uri, here } => {
                    let target = loc_add_uri(engine.data_dir(), uri, here)?;
                    engine.add_location(&file, &target)?;
                    if json {
                        println!("{{\"added\":true}}");
                    } else {
                        println!("added");
                    }
                }
                LocCmd::Rm { file, uri } => {
                    engine.remove_location(&file, &uri)?;
                    if json {
                        println!("{{\"removed\":true}}");
                    } else {
                        println!("removed");
                    }
                }
                LocCmd::Ls { file } => {
                    let uris = engine.locations(&file)?;
                    if json {
                        let items: Vec<String> =
                            uris.iter().map(|u| format!("\"{}\"", json_escape(u))).collect();
                        println!("[{}]", items.join(","));
                    } else {
                        for u in uris {
                            println!("{u}");
                        }
                    }
                }
                LocCmd::Verify { file } => {
                    let results = engine.loc_verify(&file)?;
                    let mut bad = 0;
                    for (uri, outcome) in &results {
                        let s = match outcome {
                            VerifyOutcome::Ok => "ok",
                            VerifyOutcome::Mismatch => {
                                bad += 1;
                                "MISMATCH (quarantined)"
                            }
                            VerifyOutcome::Missing => "missing",
                        };
                        if json {
                            println!(
                                "{{\"uri\":\"{}\",\"outcome\":\"{}\"}}",
                                json_escape(uri),
                                s
                            );
                        } else {
                            println!("{s:<24} {uri}");
                        }
                    }
                    if bad > 0 {
                        engine.close()?;
                        return Err(PvfsError::Integrity {
                            kind: "location",
                            id: file,
                            reason: pvfs_core::IntegrityReason::IdMismatch {
                                expected: "recorded content hash".into(),
                                actual: format!("{bad} location(s) mismatched"),
                            },
                        });
                    }
                }
            }
            engine.close()
        }
        Cmd::Verify { id } => {
            let engine = Engine::open(&ctx?)?;
            let ok = engine.verify(&id)?;
            if json {
                println!("{{\"valid\":{ok}}}");
            } else {
                println!("valid");
            }
            engine.close()
        }
        Cmd::Audit => {
            // Read-only authorization health check (doc 08 §4 item 14 + follow-ons):
            // tag grants/memberships under a revoked authority, direct `key:` grants
            // to revoked device keys (doc 06 §5), and expired grants (doc 13 Q-E1).
            // All are inert (masked live), so this never changes access — it surfaces
            // dead rows a troubleshooter would otherwise have to hunt for. Compaction
            // removes them; this only reports them.
            let engine = Engine::open(&ctx?)?;
            let grants = engine.inert_tag_grants()?;
            let memberships = engine.inert_memberships()?;
            let key_grants = engine.inert_key_grants()?;
            let expired = engine.expired_grants()?;
            if json {
                let g: Vec<String> = grants
                    .iter()
                    .map(|(node, tag, authority, rights)| {
                        format!(
                            "{{\"node\":\"{}\",\"tag\":\"{}\",\"authority\":\"{}\",\"granted\":\"{}\"}}",
                            json_escape(node),
                            json_escape(tag),
                            hex::encode(authority),
                            acl::rights_to_str(*rights)
                        )
                    })
                    .collect();
                let m: Vec<String> = memberships
                    .iter()
                    .map(|(member, tag, authority)| {
                        format!(
                            "{{\"member\":\"{}\",\"tag\":\"{}\",\"authority\":\"{}\"}}",
                            hex::encode(member),
                            json_escape(tag),
                            hex::encode(authority)
                        )
                    })
                    .collect();
                let k: Vec<String> = key_grants
                    .iter()
                    .map(|(node, key, rights)| {
                        format!(
                            "{{\"node\":\"{}\",\"key\":\"{}\",\"granted\":\"{}\"}}",
                            json_escape(node),
                            hex::encode(key),
                            acl::rights_to_str(*rights)
                        )
                    })
                    .collect();
                let e: Vec<String> = expired
                    .iter()
                    .map(|(node, principal, authority, rights, expires_at)| {
                        format!(
                            "{{\"node\":\"{}\",\"principal\":\"{}\",\"authority\":\"{}\",\"granted\":\"{}\",\"expired_at\":{}}}",
                            json_escape(node),
                            json_escape(&principal.display()),
                            hex::encode(authority),
                            acl::rights_to_str(*rights),
                            expires_at
                        )
                    })
                    .collect();
                // Key order matters: scripts (and the smoke suite) match on the
                // first two arrays as a prefix; new sections are appended only.
                println!(
                    "{{\"inert_grants\":[{}],\"inert_memberships\":[{}],\"inert_key_grants\":[{}],\"expired_grants\":[{}]}}",
                    g.join(","),
                    m.join(","),
                    k.join(","),
                    e.join(",")
                );
            } else if grants.is_empty()
                && memberships.is_empty()
                && key_grants.is_empty()
                && expired.is_empty()
            {
                println!("no stale authorizations: every grant and membership has a live authority, a live key, and no lapsed expiry");
            } else {
                if !grants.is_empty() {
                    println!("inert tag grants (authority revoked) — {}:", grants.len());
                    for (node, tag, authority, rights) in &grants {
                        println!(
                            "  {}  tag:{}{}  (granted {})",
                            node,
                            tag,
                            authority_suffix(authority),
                            acl::rights_to_str(*rights)
                        );
                    }
                }
                if !memberships.is_empty() {
                    println!("inert tag memberships (authority revoked) — {}:", memberships.len());
                    for (member, tag, authority) in &memberships {
                        println!(
                            "  {}  tag:{}{}",
                            hex::encode(member),
                            tag,
                            authority_suffix(authority)
                        );
                    }
                }
                if !key_grants.is_empty() {
                    println!("inert key grants (device revoked) — {}:", key_grants.len());
                    for (node, key, rights) in &key_grants {
                        println!(
                            "  {}  key:{}  (granted {})",
                            node,
                            hex::encode(key),
                            acl::rights_to_str(*rights)
                        );
                    }
                }
                if !expired.is_empty() {
                    println!("expired grants — {}:", expired.len());
                    for (node, principal, authority, rights, _expires_at) in &expired {
                        println!(
                            "  {}  {}{}  (granted {}) [expired]",
                            node,
                            principal.display(),
                            authority_suffix(authority),
                            acl::rights_to_str(*rights)
                        );
                    }
                }
            }
            engine.close()
        }
        Cmd::Orphans => {
            let engine = Engine::open(&ctx?)?;
            let orphans = engine.list_orphans()?;
            if json {
                let items: Vec<String> = orphans
                    .iter()
                    .map(|n| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"type\":\"{}\"}}",
                            n.id,
                            json_escape(&n.label),
                            json_escape(&n.node_type)
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for n in orphans {
                    println!("{}  {:<8} {}", n.id, n.node_type, n.label);
                }
            }
            engine.close()
        }
        Cmd::Purge { ids } => {
            if ids.is_empty() {
                return Err(PvfsError::BadInput {
                    field: "ids".into(),
                    reason: "at least one node id required".into(),
                });
            }
            let mut engine = Engine::open(&ctx?)?;
            engine.purge(&ids)?;
            if json {
                println!("{{\"purged\":{}}}", ids.len());
            } else {
                println!("purged {} node(s)", ids.len());
            }
            engine.close()
        }
        Cmd::Device(dev) => {
            let state_dir = ctx?;
            match dev {
                DeviceCmd::Authorize { mnemonic, index } => {
                    // Root-signed — must go direct (phrase needed, can't proxy).
                    let mut engine = Engine::open(&state_dir)?;
                    let m = identity::parse_mnemonic(&mnemonic)?;
                    let pk = engine.authorize_device(&m, index)?;
                    engine.close()?;
                    if json {
                        println!(
                            "{{\"authorized\":true,\"device_index\":{index},\"device_pubkey\":\"{}\"}}",
                            hex::encode(pk)
                        );
                    } else {
                        println!("authorized device {index}: {}", hex::encode(pk));
                    }
                    Ok(())
                }
                DeviceCmd::AuthorizeMember {
                    mnemonic,
                    pubkey,
                    via_companion,
                    companion_socket,
                } => {
                    let pk = hex::decode(&pubkey).map_err(|_| PvfsError::BadInput {
                        field: "pubkey".into(),
                        reason: "must be hex".into(),
                    })?;
                    // Companion root-signing (doc 14 §3): the companion holds the
                    // seed; the CLI prepares the DeviceAuthorized, gets the root
                    // pubkey + signature from the companion, and commits — no phrase.
                    if via_companion {
                        let sock = resolve_companion_socket(companion_socket)?;
                        let root_pub = companion_pubkey(&sock, "root")?;
                        companion_commit(&state_dir, &sock, "root_device_cert", |engine| {
                            engine.prepare_authorize_member(&root_pub, &pk)
                        })?;
                        if json {
                            println!("{{\"authorized\":true,\"member_pubkey\":\"{pubkey}\"}}");
                        } else {
                            println!("authorized member {pubkey} (companion root-signed)");
                        }
                        return Ok(());
                    }
                    // Device-signed (no phrase): auto-route through daemon (doc 09 §3d).
                    // Root-signed (phrase given): must go direct.
                    if mnemonic.is_none() {
                        if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                            client
                                .authorize_member(&pubkey, |d| sign(d))
                                .map_err(remote_err)?;
                            if json {
                                println!("{{\"authorized\":true,\"member_pubkey\":\"{pubkey}\"}}");
                            } else {
                                println!("authorized member {pubkey}");
                            }
                            return Ok(());
                        }
                    }
                    let mut engine = Engine::open(&state_dir)?;
                    match mnemonic {
                        Some(mn) => engine.authorize_member(&identity::parse_mnemonic(&mn)?, &pk)?,
                        None => engine.authorize_member_by_device(&pk)?,
                    }
                    engine.close()?;
                    if json {
                        println!("{{\"authorized\":true,\"member_pubkey\":\"{pubkey}\"}}");
                    } else {
                        println!("authorized member {pubkey}");
                    }
                    Ok(())
                }
                DeviceCmd::AuthorizeIdentity { companion_socket } => {
                    // The companion holds both keys (doc 14 §1): fetch the identity
                    // pubkey, then root-sign its owner cert — no phrase typed.
                    let sock = resolve_companion_socket(companion_socket)?;
                    let id_pub = companion_pubkey(&sock, "identity")?;
                    let root_pub = companion_pubkey(&sock, "root")?;
                    companion_commit(&state_dir, &sock, "root_device_cert", |engine| {
                        engine.prepare_authorize_identity(&root_pub, &id_pub)
                    })?;
                    let id_hex = hex::encode(&id_pub);
                    if json {
                        println!("{{\"authorized\":true,\"identity_pubkey\":\"{id_hex}\"}}");
                    } else {
                        println!("authorized identity key {id_hex} (companion root-signed)");
                    }
                    Ok(())
                }
                DeviceCmd::Revoke {
                    mnemonic,
                    pubkey,
                    via_companion,
                    companion_socket,
                } => {
                    let pk = hex::decode(&pubkey).map_err(|_| PvfsError::BadInput {
                        field: "pubkey".into(),
                        reason: "must be hex".into(),
                    })?;
                    // Companion root-signing (doc 14 §3), same pattern as admit.
                    if via_companion {
                        let sock = resolve_companion_socket(companion_socket)?;
                        let root_pub = companion_pubkey(&sock, "root")?;
                        companion_commit(&state_dir, &sock, "root_device_cert", |engine| {
                            engine.prepare_revoke(&root_pub, &pk)
                        })?;
                        if json {
                            println!("{{\"revoked\":true}}");
                        } else {
                            println!("revoked {pubkey} (companion root-signed)");
                        }
                        return Ok(());
                    }
                    // Device-signed (no phrase): auto-route through daemon (doc 09 §3d).
                    // Root-signed (phrase given): must go direct.
                    if mnemonic.is_none() {
                        if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                            client
                                .revoke(&pubkey, |d| sign(d))
                                .map_err(remote_err)?;
                            if json {
                                println!("{{\"revoked\":true}}");
                            } else {
                                println!("revoked {pubkey}");
                            }
                            return Ok(());
                        }
                    }
                    let mut engine = Engine::open(&state_dir)?;
                    match mnemonic {
                        Some(mn) => engine.revoke_device(&identity::parse_mnemonic(&mn)?, &pk)?,
                        None => engine.revoke_by_device(&pk)?,
                    }
                    engine.close()?;
                    if json {
                        println!("{{\"revoked\":true}}");
                    } else {
                        println!("revoked {pubkey}");
                    }
                    Ok(())
                }
            }
        }
        Cmd::Identity(cmd) => {
            let state_dir = ctx?;
            match cmd {
                IdentityCmd::Replace {
                    companion_socket,
                    yes,
                } => {
                    let sock = resolve_companion_socket(companion_socket)?;
                    if !yes {
                        eprintln!(
                            "This REPLACES your identity key (doc 15): grants under the old key \
                             go inert and are re-issued under the new one; other forests need \
                             the printed handoff. Type yes to continue:"
                        );
                        let mut line = String::new();
                        std::io::stdin()
                            .read_line(&mut line)
                            .map_err(|e| PvfsError::io("read confirmation", e))?;
                        if !line.trim().eq_ignore_ascii_case("yes") {
                            return Err(PvfsError::BadInput {
                                field: "confirmation".into(),
                                reason: "aborted".into(),
                            });
                        }
                    }
                    // 1. Rotate inside the companion (root-tier approval there).
                    let resp = pvfs_companion::request(
                        &sock,
                        &pvfs_companion::AgentRequest::RotateIdentity,
                    )
                    .map_err(|e| PvfsError::BadInput {
                        field: "companion".into(),
                        reason: e.to_string(),
                    })?;
                    let (old_hex, new_hex, ts, sig_old, sig_new) = match resp {
                        pvfs_companion::AgentResponse::IdentityRotated {
                            old_pubkey,
                            new_pubkey,
                            replaced_at_ms,
                            sig_old,
                            sig_new,
                        } => (old_pubkey, new_pubkey, replaced_at_ms, sig_old, sig_new),
                        pvfs_companion::AgentResponse::Error { code, message } => {
                            return Err(PvfsError::Forbidden {
                                action: "rotate identity".into(),
                                reason: format!("{code}: {message}"),
                            })
                        }
                        _ => {
                            return Err(PvfsError::BadInput {
                                field: "companion".into(),
                                reason: "unexpected response".into(),
                            })
                        }
                    };
                    let bad_hex = |field: &'static str| PvfsError::BadInput {
                        field: field.into(),
                        reason: "companion returned bad hex".into(),
                    };
                    let old = hex::decode(&old_hex).map_err(|_| bad_hex("old"))?;
                    let new = hex::decode(&new_hex).map_err(|_| bad_hex("new"))?;
                    // 2. The atomic root-signed swap in this forest.
                    let root_pub = companion_pubkey(&sock, "root")?;
                    let mut engine = Engine::open(&state_dir)?;
                    let prep = engine.prepare_replace_identity(&root_pub, &old, &new)?;
                    let mut events = Vec::new();
                    for mut ev in prep.events {
                        let sig = companion_sign(&sock, "root_device_cert", &ev.digest)?;
                        ev.event.set_author_sig(sig);
                        events.push(ev.event);
                    }
                    engine.commit_member_write(events)?;
                    // 3. Re-home the old key's grants under the new identity.
                    let prep = engine.prepare_reissue_authority(&old, &new)?;
                    let reissued = prep.events.len();
                    if reissued > 0 {
                        let mut events = Vec::new();
                        for mut ev in prep.events {
                            let sig = companion_sign(&sock, "identity_tag", &ev.digest)?;
                            ev.event.set_author_sig(sig);
                            events.push(ev.event);
                        }
                        engine.commit_member_write(events)?;
                    }
                    engine.close()?;
                    // 4. The handoff for the forests we can't reach from here.
                    let handoff = format!(
                        "{{\"old_pubkey\":\"{old_hex}\",\"new_pubkey\":\"{new_hex}\",\
                         \"replaced_at_ms\":{ts},\"sig_old\":\"{sig_old}\",\"sig_new\":\"{sig_new}\"}}"
                    );
                    if json {
                        println!(
                            "{{\"replaced\":true,\"old\":\"{old_hex}\",\"new\":\"{new_hex}\",\
                             \"reissued\":{reissued},\"handoff\":{handoff}}}"
                        );
                    } else {
                        println!("identity replaced: {old_hex} -> {new_hex}");
                        println!("re-issued {reissued} grant(s) in this forest");
                        println!();
                        println!("HANDOFF — save as a file and send to owners of forests where");
                        println!("you are a member; they run: pvfs member replace <that-file>");
                        println!();
                        println!("{handoff}");
                    }
                    Ok(())
                }
                IdentityCmd::Reissue {
                    old,
                    companion_socket,
                } => {
                    let sock = resolve_companion_socket(companion_socket)?;
                    let old = hex::decode(&old).map_err(|_| PvfsError::BadInput {
                        field: "old".into(),
                        reason: "must be hex".into(),
                    })?;
                    let new = companion_pubkey(&sock, "identity")?;
                    let mut engine = Engine::open(&state_dir)?;
                    let prep = engine.prepare_reissue_authority(&old, &new)?;
                    let reissued = prep.events.len();
                    if reissued > 0 {
                        let mut events = Vec::new();
                        for mut ev in prep.events {
                            let sig = companion_sign(&sock, "identity_tag", &ev.digest)?;
                            ev.event.set_author_sig(sig);
                            events.push(ev.event);
                        }
                        engine.commit_member_write(events)?;
                    }
                    engine.close()?;
                    if json {
                        println!("{{\"reissued\":{reissued}}}");
                    } else {
                        println!("re-issued {reissued} grant(s)");
                    }
                    Ok(())
                }
            }
        }
        Cmd::Member(cmd) => {
            let state_dir = ctx?;
            match cmd {
                MemberCmd::Replace { handoff } => {
                    let blob = if handoff == "-" {
                        use std::io::Read as _;
                        let mut s = String::new();
                        std::io::stdin()
                            .read_to_string(&mut s)
                            .map_err(|e| PvfsError::io("read handoff", e))?;
                        s
                    } else {
                        std::fs::read_to_string(&handoff)
                            .map_err(|e| PvfsError::io("read handoff", e))?
                    };
                    let bad = |reason: &str| PvfsError::BadInput {
                        field: "handoff".into(),
                        reason: reason.into(),
                    };
                    let v: serde_json::Value =
                        serde_json::from_str(blob.trim()).map_err(|_| bad("not valid JSON"))?;
                    let field = |k: &str| -> Result<Vec<u8>, PvfsError> {
                        hex::decode(v[k].as_str().unwrap_or_default())
                            .map_err(|_| bad("missing or non-hex field"))
                    };
                    let (old, new) = (field("old_pubkey")?, field("new_pubkey")?);
                    let (sig_old, sig_new) = (field("sig_old")?, field("sig_new")?);
                    let ts = v["replaced_at_ms"]
                        .as_u64()
                        .ok_or_else(|| bad("missing replaced_at_ms"))?;
                    // The dual signature proves seed custody of BOTH keys.
                    identity::verify_handoff(&old, &new, ts, &sig_old, &sig_new)?;

                    let mut engine = Engine::open(&state_dir)?;
                    // Capture the old key's tags before revoking masks them.
                    let tags: std::collections::BTreeSet<String> = engine
                        .member_tags(&old)?
                        .into_iter()
                        .map(|(_authority, tag)| tag)
                        .collect();
                    engine.revoke_by_device(&old)?;
                    engine.authorize_member_by_device(&new)?;
                    for tag in &tags {
                        engine.set_member_tag(&new, tag, true)?;
                    }
                    engine.close()?;
                    if json {
                        println!(
                            "{{\"replaced\":true,\"new_member\":\"{}\",\"regranted\":{}}}",
                            hex::encode(&new),
                            tags.len()
                        );
                    } else {
                        println!(
                            "member replaced: {} -> {} ({} tag(s) re-granted)",
                            hex::encode(&old),
                            hex::encode(&new),
                            tags.len()
                        );
                    }
                    Ok(())
                }
            }
        }
        Cmd::Secure(cmd) => {
            let state_dir = ctx?;
            match cmd {
                SecureCmd::Create {
                    parent,
                    label,
                    path,
                } => {
                    let parent_id = resolve_node_id(Ok(state_dir.clone()), &parent)?;
                    // Auto-route through the daemon if one runs, so apps create
                    // stores on the fly without stopping the filesystem. A pinned
                    // --path forces the direct engine path (the daemon uses managed
                    // storage only).
                    let id = if let Some(p) = &path {
                        let uri = pvfs_core::storage::path_to_uri(p)?;
                        let mut engine = Engine::open(&state_dir)?;
                        let id = engine.add_node(&parent_id, secure_spec(&label))?;
                        engine.add_location(&id, &uri)?;
                        engine.close()?;
                        id
                    } else if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                        client
                            .secure_create(&parent_id, &label, |d| sign(d))
                            .map_err(remote_err)?
                    } else {
                        let mut engine = Engine::open(&state_dir)?;
                        let id = engine.add_node(&parent_id, secure_spec(&label))?;
                        engine.close()?;
                        id
                    };
                    if json {
                        println!("{{\"created\":\"{id}\",\"label\":\"{}\"}}", json_escape(&label));
                    } else {
                        println!("created secure node {id} ({label})");
                    }
                    Ok(())
                }
                SecureCmd::Put {
                    node,
                    input,
                    raw,
                    companion_socket,
                } => {
                    let plaintext = if input == "-" {
                        use std::io::Read as _;
                        let mut b = Vec::new();
                        std::io::stdin()
                            .read_to_end(&mut b)
                            .map_err(|e| PvfsError::io("read stdin", e))?;
                        b
                    } else {
                        std::fs::read(&input).map_err(|e| PvfsError::io("read input", e))?
                    };
                    // Default: encrypt to the owner's encryption key via the
                    // companion envelope. --raw stores app-managed bytes as-is.
                    let bytes = if raw {
                        plaintext
                    } else {
                        let sock = resolve_companion_socket(companion_socket)?;
                        let enc_pub = companion_pubkey(&sock, "encryption")?;
                        pvfs_core::envelope::seal(&plaintext, &[enc_pub])?
                    };
                    let node_id = resolve_node_id(Ok(state_dir.clone()), &node)?;
                    // Auto-route ciphertext + ledger through the daemon if one
                    // runs (doc 12 §8.5 daemon path); else engine-direct. Either
                    // way the plaintext was encrypted client-side above.
                    if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                        client.secure_put(&node_id, &bytes, |d| sign(d)).map_err(remote_err)?;
                    } else {
                        let mut engine = Engine::open(&state_dir)?;
                        engine.secure_put_local(&node_id, &bytes)?;
                        engine.close()?;
                    }
                    if json {
                        println!(
                            "{{\"updated\":\"{node_id}\",\"size\":{},\"encrypted\":{}}}",
                            bytes.len(),
                            !raw
                        );
                    } else {
                        println!(
                            "updated {node_id}: {} bytes ({})",
                            bytes.len(),
                            if raw { "raw" } else { "encrypted" }
                        );
                    }
                    Ok(())
                }
                SecureCmd::Cat {
                    node,
                    raw,
                    companion_socket,
                } => {
                    let node_id = resolve_node_id(Ok(state_dir.clone()), &node)?;
                    // Verified download: the daemon (or the engine) checks the
                    // ledger head before yielding a byte.
                    let stored = if let Some((mut client, _sign)) = daemon_client(&state_dir)? {
                        client.secure_cat(&node_id).map_err(remote_err)?
                    } else {
                        let engine = Engine::open(&state_dir)?;
                        let b = engine.secure_read(&node_id)?;
                        engine.close()?;
                        b
                    };
                    let out = if raw {
                        stored
                    } else {
                        let env = pvfs_core::envelope::parse(&stored)?;
                        let sock = resolve_companion_socket(companion_socket)?;
                        let enc_pub = companion_pubkey(&sock, "encryption")?;
                        let wrap = env.wrap_for(&enc_pub).ok_or_else(|| PvfsError::Forbidden {
                            action: "secure cat".into(),
                            reason: "this blob is not encrypted to your key".into(),
                        })?;
                        let ck = companion_unwrap(&sock, wrap)?;
                        pvfs_core::envelope::open_with_key(&env, &ck)?
                    };
                    use std::io::Write as _;
                    std::io::stdout()
                        .write_all(&out)
                        .map_err(|e| PvfsError::io("write stdout", e))?;
                    Ok(())
                }
                SecureCmd::Grant {
                    node,
                    pubkey,
                    companion_socket,
                } => {
                    let recipient = hex::decode(&pubkey).map_err(|_| PvfsError::BadInput {
                        field: "pubkey".into(),
                        reason: "must be hex".into(),
                    })?;
                    let node_id = resolve_node_id(Ok(state_dir.clone()), &node)?;
                    let daemon_up = try_daemon_socket(&state_dir).is_some();
                    // Read current ciphertext (daemon if up, else engine).
                    let stored = if daemon_up {
                        daemon_client(&state_dir)?
                            .expect("daemon up")
                            .0
                            .secure_cat(&node_id)
                            .map_err(remote_err)?
                    } else {
                        let engine = Engine::open(&state_dir)?;
                        let b = engine.secure_read(&node_id)?;
                        engine.close()?;
                        b
                    };
                    // Re-wrap client-side for the new recipient.
                    let sock = resolve_companion_socket(companion_socket)?;
                    let enc_pub = companion_pubkey(&sock, "encryption")?;
                    let env = pvfs_core::envelope::parse(&stored)?;
                    let wrap = env.wrap_for(&enc_pub).ok_or_else(|| PvfsError::Forbidden {
                        action: "secure grant".into(),
                        reason: "you must be a recipient to grant access".into(),
                    })?;
                    let ck = companion_unwrap(&sock, wrap)?;
                    let regranted =
                        pvfs_core::envelope::add_recipient(&stored, &ck, &recipient)?;
                    // Write back the same way (no two-writer hazard).
                    if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                        client.secure_put(&node_id, &regranted, |d| sign(d)).map_err(remote_err)?;
                    } else {
                        let mut engine = Engine::open(&state_dir)?;
                        engine.secure_put_local(&node_id, &regranted)?;
                        engine.close()?;
                    }
                    if json {
                        println!("{{\"granted\":\"{}\"}}", json_escape(&pubkey));
                    } else {
                        println!("granted {pubkey} access to {node_id}");
                    }
                    Ok(())
                }
                SecureCmd::Verify { node } => {
                    let node_id = resolve_node_id(Ok(state_dir.clone()), &node)?;
                    let engine = Engine::open(&state_dir)?;
                    let res = engine.secure_read(&node_id).map(|_| ());
                    engine.close()?;
                    let clean = res.is_ok();
                    if json {
                        println!("{{\"node\":\"{node_id}\",\"clean\":{clean}}}");
                    } else {
                        println!("{node_id}: {}", if clean { "clean" } else { "MISMATCH" });
                    }
                    res // the real Integrity error (expected vs actual hash) → rc 5
                }
                SecureCmd::Status { node } => {
                    let node_id = resolve_node_id(Ok(state_dir.clone()), &node)?;
                    let engine = Engine::open(&state_dir)?;
                    let head = engine.secure_current(&node_id)?;
                    engine.close()?;
                    match head {
                        Some((hash, size, at, author)) => {
                            if json {
                                println!(
                                    "{{\"node\":\"{node_id}\",\"content_hash\":\"{}\",\"size\":{size},\
                                     \"updated_at\":{at},\"author\":\"{}\"}}",
                                    hex::encode(&hash),
                                    hex::encode(&author)
                                );
                            } else {
                                println!("hash   : {}", hex::encode(&hash));
                                println!("size   : {size} bytes");
                                println!("updated: {at}");
                                println!("author : {}", hex::encode(&author));
                            }
                        }
                        None => {
                            if json {
                                println!("{{\"node\":\"{node_id}\",\"content_hash\":null}}");
                            } else {
                                println!("(no updates yet)");
                            }
                        }
                    }
                    Ok(())
                }
            }
        }
        Cmd::Acl(a) => {
            match a {
                AclCmd::Set {
                    node,
                    principal,
                    rights,
                    expires,
                } => {
                    // Resolve path/URI → node id (fix: was node-id only before).
                    let state_dir = ctx?;
                    let node_id = resolve_node_id(Ok(state_dir.clone()), &node)?;
                    let p = acl::Principal::parse(&principal)?;
                    let r = acl::parse_rights(&rights)?;
                    let expires_at = match &expires {
                        Some(s) => parse_expires(s)?,
                        None => 0,
                    };
                    if expires_at != 0 && r == 0 {
                        return Err(PvfsError::BadInput {
                            field: "expires".into(),
                            reason: "clearing a grant takes no expiry".into(),
                        });
                    }

                    // Auto-route through daemon when one is running (doc 09 §3d).
                    if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                        client
                            .set_acl_expiring(
                                &node_id,
                                &p.display(),
                                &acl::rights_to_str(r),
                                expires_at,
                                |d| sign(d),
                            )
                            .map_err(remote_err)?;
                    } else {
                        let mut engine = Engine::open(&state_dir)?;
                        engine.set_acl_expiring(&node_id, &p, r, expires_at)?;
                        engine.close()?;
                    }
                    if json {
                        println!(
                            "{{\"node\":\"{}\",\"principal\":\"{}\",\"rights\":\"{}\",\"expires_at\":{}}}",
                            json_escape(&node_id),
                            json_escape(&p.display()),
                            acl::rights_to_str(r),
                            expires_at
                        );
                    } else {
                        println!(
                            "set {} on {} = {}{}",
                            p.display(),
                            node_id,
                            acl::rights_to_str(r),
                            expiry_suffix(expires_at)
                        );
                    }
                    Ok(())
                }
                AclCmd::Ls { node } => {
                    // Resolve path/URI → node id.
                    let (engine, node_id) = engine_and_node(ctx, &node)?;
                    let entries = engine.acl_entries(&node_id)?;
                    // Report **effective** rights, never the stored value of a grant
                    // that isn't in force: a tag grant under a revoked authority is
                    // inert (masked on the read path, doc 10 §9.2), and so is an
                    // **expired** grant (doc 13 Q-E1) — so their effective rights are
                    // none (`-`). We surface the *granted* value only in the inert/
                    // expired annotation, so a troubleshooter reading the rights column
                    // never mistakes a dead grant for live access. Physical removal of
                    // the row is left to compaction (doc 11).
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    let mut rows = Vec::with_capacity(entries.len());
                    for (p, authority, granted, expires_at) in entries {
                        let inert = !engine.authority_active(&authority)?;
                        let expired = expires_at != 0 && expires_at <= now;
                        let effective = if inert || expired { 0 } else { granted };
                        rows.push((p, authority, granted, expires_at, effective, inert, expired));
                    }
                    if json {
                        let items: Vec<String> = rows
                            .iter()
                            .map(|(p, authority, granted, expires_at, effective, inert, expired)| {
                                format!(
                                    "{{\"principal\":\"{}\",\"authority\":\"{}\",\"rights\":\"{}\",\"granted\":\"{}\",\"expires_at\":{},\"active\":{}}}",
                                    json_escape(&p.display()),
                                    hex::encode(authority),
                                    acl::rights_to_str(*effective),
                                    acl::rights_to_str(*granted),
                                    expires_at,
                                    !*inert && !*expired
                                )
                            })
                            .collect();
                        println!("[{}]", items.join(","));
                    } else if rows.is_empty() {
                        println!("(no direct grants on {node_id})");
                    } else {
                        for (p, authority, granted, expires_at, effective, inert, expired) in rows {
                            let note = if inert {
                                format!(
                                    "  [inert: authority revoked; granted {}]",
                                    acl::rights_to_str(granted)
                                )
                            } else if expired {
                                format!("  [expired; granted {}]", acl::rights_to_str(granted))
                            } else {
                                expiry_suffix(expires_at)
                            };
                            println!(
                                "{:>3}  {}{}{}",
                                acl::rights_to_str(effective),
                                p.display(),
                                authority_suffix(&authority),
                                note
                            );
                        }
                    }
                    engine.close()
                }
                AclCmd::Check { node, principal } => {
                    // Resolve path/URI → node id.
                    let (engine, node_id) = engine_and_node(ctx, &node)?;
                    let p = acl::Principal::parse(&principal)?;
                    let r = engine.effective_rights(&p, &node_id)?;
                    if json {
                        println!(
                            "{{\"node\":\"{}\",\"principal\":\"{}\",\"effective\":\"{}\"}}",
                            json_escape(&node_id),
                            json_escape(&p.display()),
                            acl::rights_to_str(r)
                        );
                    } else {
                        println!(
                            "{} effective on {} = {}",
                            p.display(),
                            node_id,
                            acl::rights_to_str(r)
                        );
                    }
                    engine.close()
                }
            }
        }
        Cmd::Tag(t) => {
            let decode_member = |m: &str| -> Result<Vec<u8>, PvfsError> {
                hex::decode(m).map_err(|_| PvfsError::BadInput {
                    field: "member".into(),
                    reason: "member must be a hex pubkey".into(),
                })
            };
            match t {
                TagCmd::Add {
                    member,
                    tag,
                    via_companion,
                    companion_socket,
                } => {
                    let state_dir = ctx?;
                    let member_pk = decode_member(&member)?;

                    // Identity-key signing via the companion (doc 14 §3): the grant's
                    // authority is the human's stable identity key (doc 10 §9.1),
                    // not this machine's device key.
                    if via_companion {
                        let sock = resolve_companion_socket(companion_socket)?;
                        let id_pub = companion_pubkey(&sock, "identity")?;
                        companion_commit(&state_dir, &sock, "identity_tag", |engine| {
                            engine.prepare_set_member_tag(&id_pub, &member_pk, &tag, true)
                        })?;
                    } else if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                        // Auto-route through daemon when one is running (doc 09 §3d).
                        client
                            .tag_member(&hex::encode(&member_pk), &tag, true, |d| sign(d))
                            .map_err(remote_err)?;
                    } else {
                        let mut engine = Engine::open(&state_dir)?;
                        engine.set_member_tag(&member_pk, &tag, true)?;
                        engine.close()?;
                    }
                    if json {
                        println!("{{\"tagged\":true,\"tag\":\"{}\"}}", json_escape(&tag));
                    } else {
                        println!("tagged {member} with {tag}");
                    }
                    Ok(())
                }
                TagCmd::Rm {
                    member,
                    tag,
                    via_companion,
                    companion_socket,
                } => {
                    let state_dir = ctx?;
                    let member_pk = decode_member(&member)?;

                    // Identity-key signing via the companion (doc 14 §3) — the same
                    // authority that granted the tag removes it.
                    if via_companion {
                        let sock = resolve_companion_socket(companion_socket)?;
                        let id_pub = companion_pubkey(&sock, "identity")?;
                        companion_commit(&state_dir, &sock, "identity_tag", |engine| {
                            engine.prepare_set_member_tag(&id_pub, &member_pk, &tag, false)
                        })?;
                    } else if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                        // Auto-route through daemon when one is running (doc 09 §3d).
                        client
                            .tag_member(&hex::encode(&member_pk), &tag, false, |d| sign(d))
                            .map_err(remote_err)?;
                    } else {
                        let mut engine = Engine::open(&state_dir)?;
                        engine.set_member_tag(&member_pk, &tag, false)?;
                        engine.close()?;
                    }
                    if json {
                        println!("{{\"tagged\":false,\"tag\":\"{}\"}}", json_escape(&tag));
                    } else {
                        println!("removed tag {tag} from {member}");
                    }
                    Ok(())
                }
                TagCmd::Ls { member } => {
                    // Read-only: open engine directly (no mutation, no race with daemon).
                    let engine = Engine::open(&ctx?)?;
                    let tags = engine.member_tags(&decode_member(&member)?)?;
                    // A membership under a revoked authority is **inert** — masked on
                    // the read path (doc 10 §9.2). Flag it; compaction removes it.
                    let mut rows = Vec::with_capacity(tags.len());
                    for (authority, t) in tags {
                        let inert = !engine.authority_active(&authority)?;
                        rows.push((authority, t, inert));
                    }
                    if json {
                        let items: Vec<String> = rows
                            .iter()
                            .map(|(authority, t, inert)| {
                                format!(
                                    "{{\"tag\":\"{}\",\"authority\":\"{}\",\"active\":{}}}",
                                    json_escape(t),
                                    hex::encode(authority),
                                    !*inert
                                )
                            })
                            .collect();
                        println!("[{}]", items.join(","));
                    } else if rows.is_empty() {
                        println!("(no tags)");
                    } else {
                        for (authority, t, inert) in rows {
                            println!(
                                "{t}{}{}",
                                authority_suffix(&authority),
                                if inert { "  [inert: authority revoked]" } else { "" }
                            );
                        }
                    }
                    engine.close()
                }
            }
        }
        Cmd::Whoami => {
            let mn = client_identity_mnemonic()?;
            let key = identity::device_key(&mn, "", 0)?;
            let pubkey = hex::encode(crypto::pubkey_bytes(&key));
            if json {
                println!("{{\"pubkey\":\"{pubkey}\"}}");
            } else {
                println!("client identity : key:{pubkey}");
                println!("authorize it on a forest with:");
                println!("  pvfs device authorize-member --mnemonic <owner-phrase> --pubkey {pubkey}");
            }
            Ok(())
        }
        Cmd::Place { target, mode, to } => {
            let (engine, id) = engine_and_node(ctx, &target)?;
            let data_dir = engine.data_dir().to_path_buf();
            engine.close()?;
            if mode == "central" {
                let dest = to.expect("clap required_if_eq");
                std::fs::create_dir_all(&dest)
                    .map_err(|e| PvfsError::io("create central store", e))?;
                let dest = std::fs::canonicalize(&dest)
                    .map_err(|e| PvfsError::io("resolve central store", e))?;
                pvfs_core::sync::set_central(&data_dir, &id, &dest)?;
            } else {
                pvfs_core::sync::set_placement(&data_dir, &id, mode == "sync")?;
            }
            if json {
                println!("{{\"node\":\"{id}\",\"mode\":\"{mode}\"}}");
            } else {
                println!("{id} placed {mode}");
            }
            Ok(())
        }
        Cmd::Tier => {
            // The pass itself is shared with pvfsd's `tier` job (P5.3).
            let mut engine = Engine::open(&ctx?)?;
            let data_dir = engine.data_dir().to_path_buf();
            let mut fetcher = Fetcher::new(&data_dir);
            let report = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher)?;
            let Some(report) = report else {
                return Err(PvfsError::BadInput {
                    field: "tier".into(),
                    reason: "nothing placed central — run `pvfs place <target> central --to <dir>`"
                        .into(),
                });
            };
            let (migrated, satisfied, retired, failed) = (
                report.migrated,
                report.satisfied,
                report.retired,
                report.failed,
            );
            engine.close()?;
            if json {
                let fails: Vec<String> = failed
                    .iter()
                    .map(|(l, e)| {
                        format!(
                            "{{\"label\":\"{}\",\"error\":\"{}\"}}",
                            json_escape(l),
                            json_escape(e)
                        )
                    })
                    .collect();
                println!(
                    "{{\"migrated\":{migrated},\"satisfied\":{satisfied},\"retired\":{retired},\"failed\":[{}]}}",
                    fails.join(",")
                );
            } else {
                println!(
                    "migrated {migrated} into the central store ({satisfied} already central, {retired} edge locations retired)"
                );
                for (label, e) in &failed {
                    eprintln!("failed: {label} — {e}");
                }
            }
            if failed.is_empty() {
                Ok(())
            } else {
                Err(PvfsError::BadInput {
                    field: "tier".into(),
                    reason: format!("{} files failed to migrate (see above)", failed.len()),
                })
            }
        }
        Cmd::Evict => {
            // The pass itself is shared with pvfsd's `evict` job (P5.3).
            let engine = Engine::open(&ctx?)?;
            let report = pvfs_core::sync::evict_pass(&engine)?;
            let (evicted, freed, skipped) = (report.evicted, report.freed_bytes, report.skipped);
            engine.close()?;
            if json {
                let skips: Vec<String> = skipped
                    .iter()
                    .map(|(u, e)| {
                        format!(
                            "{{\"uri\":\"{}\",\"reason\":\"{}\"}}",
                            json_escape(u),
                            json_escape(e)
                        )
                    })
                    .collect();
                println!(
                    "{{\"evicted\":{evicted},\"freed_bytes\":{freed},\"skipped\":[{}]}}",
                    skips.join(",")
                );
            } else {
                println!("evicted {evicted} files ({freed} bytes reclaimed)");
                for (u, e) in &skipped {
                    eprintln!("skipped: {u} — {e}");
                }
            }
            Ok(())
        }
        Cmd::Serve { cmd: Some(cmd), .. } => {
            // enable/disable/ls edit the local `serve.jobs` (deployment state,
            // doc 18 §2); status asks the running daemon over its socket.
            // None of them needs an ENGINE — and opening one under a live
            // daemon forces a projection rebuild that can lose a busy race
            // and fail the command (found by the fleet test: a lost
            // `serve enable evict`). Validate the forest by its log file.
            let data_dir = ctx?;
            if !data_dir.join("log.db").exists() {
                return Err(PvfsError::NotFound {
                    kind: "forest",
                    id: data_dir.to_string_lossy().into_owned(),
                });
            }
            match cmd {
                ServeCmd::Enable { .. } | ServeCmd::Disable { .. } => {
                    let (job, enable) = match cmd {
                        ServeCmd::Enable { job } => (job, true),
                        ServeCmd::Disable { job } => (job, false),
                        _ => unreachable!(),
                    };
                    let changed = pvfs_core::serve::set_job(&data_dir, &job, enable)?;
                    let verb = if enable { "enabled" } else { "disabled" };
                    if json {
                        println!("{{\"job\":\"{job}\",\"{verb}\":true,\"changed\":{changed}}}");
                    } else if changed {
                        println!("{job} {verb} — the daemon picks it up on SIGHUP or restart");
                    } else {
                        println!("{job} already {verb}");
                    }
                    Ok(())
                }
                ServeCmd::Ls => {
                    let enabled = pvfs_core::serve::load_jobs(&data_dir)?;
                    if json {
                        let rows: Vec<String> = pvfs_core::serve::JOB_NAMES
                            .iter()
                            .map(|n| {
                                let en = enabled.iter().any(|j| j == n);
                                format!("{{\"job\":\"{n}\",\"enabled\":{en}}}")
                            })
                            .collect();
                        println!("[{}]", rows.join(","));
                    } else {
                        for n in pvfs_core::serve::JOB_NAMES {
                            let en = enabled.iter().any(|j| j == n);
                            println!("{n:<8} {}", if en { "enabled" } else { "-" });
                        }
                    }
                    Ok(())
                }
                ServeCmd::Exports => {
                    let entries = pvfs_core::serve::load_exports(&data_dir)?;
                    if json {
                        let rows: Vec<String> = entries
                            .iter()
                            .map(|e| {
                                format!(
                                    "{{\"node\":\"{}\",\"mode\":\"{}\",\"fetch\":{},\"prune\":{},\"dest\":\"{}\"}}",
                                    e.node,
                                    e.mode,
                                    e.fetch,
                                    e.prune,
                                    json_escape(&e.dest.display().to_string())
                                )
                            })
                            .collect();
                        println!("[{}]", rows.join(","));
                    } else if entries.is_empty() {
                        println!("no kept-fresh exports (record one: pvfs export <node> <dest> --keep-fresh)");
                    } else {
                        for e in &entries {
                            let mut flags = vec![e.mode.clone()];
                            if e.fetch {
                                flags.push("fetch".into());
                            }
                            if e.prune {
                                flags.push("prune".into());
                            }
                            println!("{}  {}  [{}]", e.node, e.dest.display(), flags.join(","));
                        }
                    }
                    Ok(())
                }
                ServeCmd::Watch {
                    reconcile_secs,
                    debounce_ms,
                } => {
                    let never = std::sync::atomic::AtomicBool::new(false);
                    pvfs_client::watch::run(
                        &data_dir,
                        reconcile_secs,
                        debounce_ms,
                        &never,
                        |ev| match ev {
                            pvfs_client::watch::WatchEvent::Ingested(f, a, c, r) => {
                                if !json && a + c + r > 0 {
                                    println!("ingested {f}: +{a} !{c} -{r}");
                                }
                            }
                            pvfs_client::watch::WatchEvent::ScanError(e) => {
                                eprintln!("scan error: {e}")
                            }
                            pvfs_client::watch::WatchEvent::Watching(n) => {
                                if !json {
                                    println!("watching {n} bound folder(s); Ctrl-C to stop");
                                }
                            }
                        },
                    )
                }
                ServeCmd::Status => {
                    let sock = try_daemon_socket(&data_dir).ok_or_else(|| PvfsError::BadInput {
                        field: "serve".into(),
                        reason: "no running daemon for this forest (status is live state)"
                            .into(),
                    })?;
                    serve_status_print(&data_dir, &sock, json)
                }
            }
        }
        Cmd::Sync { target, to: Some(to) } => {
            // store-root config (P6.1) — never fetches
            if target.is_some() {
                return Err(PvfsError::BadInput {
                    field: "sync".into(),
                    reason: "--to is config-only — run it without a target".into(),
                });
            }
            let dir = ctx?;
            match to.as_str() {
                "" => {
                    let root = pvfs_core::sync::sync_store_root(&dir)?;
                    match (&root, json) {
                        (Some(r), true) => {
                            println!("{{\"store\":\"{}\"}}", json_escape(&r.display().to_string()))
                        }
                        (Some(r), false) => println!("{}", r.display()),
                        (None, true) => println!("{{\"store\":null}}"),
                        (None, false) => println!("default (.pvfs/synced)"),
                    }
                }
                "default" => {
                    pvfs_core::sync::set_sync_store_root(&dir, None)?;
                    if json {
                        println!("{{\"store\":null}}");
                    } else {
                        println!("sync store back to default (.pvfs/synced); \
                                  files on the old root keep serving");
                    }
                }
                d => {
                    std::fs::create_dir_all(d).map_err(|e| PvfsError::io("create sync store", e))?;
                    let abs = std::fs::canonicalize(d)
                        .map_err(|e| PvfsError::io("resolve sync store", e))?;
                    pvfs_core::sync::set_sync_store_root(&dir, Some(&abs))?;
                    if json {
                        println!("{{\"store\":\"{}\"}}", json_escape(&abs.display().to_string()));
                    } else {
                        println!("new fetches land in {}; earlier files keep serving \
                                  from the default store", abs.display());
                    }
                }
            }
            Ok(())
        }
        Cmd::Sync { target, to: None } => {
            let (mut engine, roots) = match target {
                Some(t) => {
                    let (e, id) = engine_and_node(ctx, &t)?;
                    (e, vec![id])
                }
                None => {
                    let dir = ctx?;
                    let e = Engine::open(&dir)?;
                    let roots = pvfs_core::sync::load_placement(e.data_dir())?;
                    if roots.is_empty() {
                        return Err(PvfsError::BadInput {
                            field: "sync".into(),
                            reason: "nothing placed `sync` — run `pvfs place <target> sync` \
                                     or pass a target"
                                .into(),
                        });
                    }
                    (e, roots)
                }
            };
            let data_dir = engine.data_dir().to_path_buf();
            let mut fetcher = Fetcher::new(&data_dir);
            if !fetcher.has_any_source() {
                return Err(PvfsError::BadInput {
                    field: "sync".into(),
                    reason: "nothing to fetch from — this forest has no replica source and \
                             no instances are registered (`pvfs instance add`)"
                        .into(),
                });
            }
            let (fetched, failed) = sync_pull(&mut engine, &mut fetcher, &roots)?;
            engine.close()?;
            if json {
                let fails: Vec<String> = failed
                    .iter()
                    .map(|(l, e)| {
                        format!(
                            "{{\"label\":\"{}\",\"error\":\"{}\"}}",
                            json_escape(l),
                            json_escape(e)
                        )
                    })
                    .collect();
                println!(
                    "{{\"fetched\":{fetched},\"failed\":[{}]}}",
                    fails.join(",")
                );
            } else {
                println!("fetched {fetched} files into the sync store");
                for (label, e) in &failed {
                    eprintln!("failed: {label} — {e}");
                }
            }
            if failed.is_empty() {
                Ok(())
            } else {
                Err(PvfsError::BadInput {
                    field: "sync".into(),
                    reason: format!(
                        "{} of {} files failed to fetch (see above)",
                        failed.len(),
                        fetched + failed.len() as u64
                    ),
                })
            }
        }
        Cmd::Replica(cmd) => match cmd {
            ReplicaCmd::Add {
                dest,
                instance,
                connect,
                pin,
                socket,
                region,
            } => {
                let data_dir = dest.join(".pvfs");
                if region.as_deref().is_some_and(|r| r.len() != 64 || !r.chars().all(|c| c.is_ascii_hexdigit())) {
                    return Err(PvfsError::BadInput {
                        field: "region".into(),
                        reason: "--region takes the marked node's 64-hex id".into(),
                    });
                }
                if data_dir.exists() {
                    return Err(PvfsError::AlreadyExists {
                        kind: "forest",
                        id: data_dir.to_string_lossy().into_owned(),
                    });
                }
                let dial = resolve_replica_dial(instance, connect, pin, socket)?;
                let mut client = replica_client(&dial)?;
                let info = client.info().map_err(remote_err)?;
                let mut store = pvfs_core::ReplicaStore::open(&data_dir)?;
                let shipped = match replica_pull(&mut client, &mut store, 1) {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = std::fs::remove_dir_all(&data_dir);
                        return Err(e);
                    }
                };
                drop(store);
                // P7.2b (doc 20 §2.4): ship every region generation the top
                // log names, chain-verified against its committed baseline.
                let scope = region.as_deref().filter(|r| !r.is_empty());
                let shipped_region =
                    match pvfs_client::regions::sync_generations(&mut client, &data_dir, scope) {
                        Ok(n) => n as u64,
                        Err(e) => {
                            let _ = std::fs::remove_dir_all(&data_dir);
                            return Err(e);
                        }
                    };
                let shipped = shipped + shipped_region;
                let mut dial = dial;
                if let Some(r) = region.as_deref().filter(|r| !r.is_empty()) {
                    if shipped_region == 0 {
                        let _ = std::fs::remove_dir_all(&data_dir);
                        return Err(PvfsError::NotFound {
                            kind: "region",
                            id: format!("{r} (no generations shipped — is it marked on the source?)"),
                        });
                    }
                    dial.region = r.to_string();
                }
                dial.save(&data_dir)?;
                // The open replays the whole shipped log — chain, signatures,
                // replay authorization. A replica that opens is proven.
                let engine = match Engine::open(&data_dir) {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = std::fs::remove_dir_all(&data_dir);
                        return Err(e);
                    }
                };
                let root = engine.identity.root_node_id.clone();
                engine.close()?;
                if json {
                    println!(
                        "{{\"forest_id\":\"{}\",\"instance_id\":\"{}\",\"root\":\"{}\",\"events\":{}}}",
                        json_escape(&info.forest_id),
                        json_escape(&info.instance_id),
                        root,
                        shipped
                    );
                } else {
                    println!("replica of {} ({} events, verified)", info.forest_id, shipped);
                    println!("mount: {} (read-only; sync with `pvfs replica sync`)", dest.display());
                }
                Ok(())
            }
            ReplicaCmd::Sync { mount } => {
                let data_dir = mount.join(".pvfs");
                let dial = pvfs_core::ReplicaSource::load(&data_dir)?;
                let mut client = replica_client(&dial)?;
                let mut store = pvfs_core::ReplicaStore::open(&data_dir)?;
                let from = store.tip()? + 1;
                let shipped = replica_pull(&mut client, &mut store, from)?;
                drop(store);
                let scope = if dial.region.is_empty() { None } else { Some(dial.region.as_str()) };
                let shipped =
                    shipped + pvfs_client::regions::sync_generations(&mut client, &data_dir, scope)? as u64;
                // Re-open: the startup check verifies + folds the new tail.
                let engine = Engine::open(&data_dir)?;
                let tip = engine.log_tip()?;
                engine.close()?;
                if json {
                    println!("{{\"synced\":{shipped},\"tip\":{tip}}}");
                } else {
                    println!("synced {shipped} events (tip {tip})");
                }
                Ok(())
            }
            ReplicaCmd::Follow { mount } => {
                // The loop itself is shared with pvfsd's `follow` job (P5.1,
                // doc 18 §5) — this command is the ad-hoc, foreground driver.
                let data_dir = mount.join(".pvfs");
                let dial = pvfs_core::ReplicaSource::load(&data_dir)?;
                eprintln!(
                    "following {} from {} (long-poll; ctrl-c to stop)",
                    mount.display(),
                    dial.target
                );
                let never = std::sync::atomic::AtomicBool::new(false);
                pvfs_client::follow::run(&data_dir, 25_000, &never, |ev| match ev {
                    pvfs_client::follow::FollowEvent::Connected { .. } => {}
                    pvfs_client::follow::FollowEvent::CaughtUp { tip } => {
                        eprintln!("follow: caught up to seq {tip}")
                    }
                    pvfs_client::follow::FollowEvent::Retrying { reason } => {
                        eprintln!("follow: retrying ({reason})")
                    }
                })?;
                Ok(())
            }
        },
        #[cfg(target_os = "linux")]
        Cmd::Mount { target, dir } => {
            let (engine, id) = engine_and_node(ctx, &target)?;
            let data_dir = engine.data_dir().to_path_buf();
            engine.close()?;
            std::fs::create_dir_all(&dir).map_err(|e| PvfsError::io("create mountpoint", e))?;
            eprintln!(
                "mounting {id} at {} (read-only; `pvfs umount {}` to stop)",
                dir.display(),
                dir.display()
            );
            pvfs_fuse::mount(&data_dir, &id, &dir)?;
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Cmd::Umount { dir } => {
            let tried = std::process::Command::new("fusermount3")
                .arg("-u")
                .arg(&dir)
                .status()
                .or_else(|_| {
                    std::process::Command::new("fusermount").arg("-u").arg(&dir).status()
                })
                .map_err(|e| PvfsError::io("fusermount", e))?;
            if tried.success() {
                println!("unmounted {}", dir.display());
                Ok(())
            } else {
                Err(PvfsError::BadInput {
                    field: "umount".into(),
                    reason: format!("fusermount failed for {}", dir.display()),
                })
            }
        }
        Cmd::Region(cmd) => {
            match cmd {
                RegionCmd::Mark { target } => {
                    let (mut engine, id) = engine_and_node(ctx, &target)?;
                    engine.region_mark(&id)?;
                    if json {
                        println!("{{\"region\":\"{id}\",\"marked\":true}}");
                    } else {
                        println!("{id} is now a region boundary");
                    }
                    engine.close()
                }
                RegionCmd::Unmark { target } => {
                    let (mut engine, id) = engine_and_node(ctx, &target)?;
                    engine.region_unmark(&id)?;
                    if json {
                        println!("{{\"region\":\"{id}\",\"marked\":false}}");
                    } else {
                        println!("{id} is no longer a region boundary");
                    }
                    engine.close()
                }
                RegionCmd::Ls { target: Some(t) } => {
                    let (engine, id) = engine_and_node(ctx, &t)?;
                    let region = engine.region_of(&id)?;
                    if json {
                        println!("{{\"node\":\"{id}\",\"region\":\"{region}\"}}");
                    } else {
                        println!("{region}");
                    }
                    engine.close()
                }
                RegionCmd::Ls { target: None } => {
                    let engine = Engine::open(&ctx?)?;
                    let regions = engine.regions()?;
                    if json {
                        let rows: Vec<String> = regions
                            .iter()
                            .map(|(id, at)| format!("{{\"region\":\"{id}\",\"marked_at\":{at}}}"))
                            .collect();
                        println!("[{}]", rows.join(","));
                    } else if regions.is_empty() {
                        println!("no marked regions (the forest root is the implicit top region)");
                    } else {
                        for (id, _) in &regions {
                            println!("{id}");
                        }
                    }
                    engine.close()
                }
            }
        }
        Cmd::Fleet(FleetCmd::Enroll { pubkey, rights }) => {
            let state_dir = ctx?;
            let pubkey = match pubkey {
                Some(p) => p,
                None => prompt_line(
                    "the box's client identity (run `pvfs whoami` on the box)",
                    None,
                )?,
            };
            let pk = hex::decode(&pubkey).map_err(|_| PvfsError::BadInput {
                field: "pubkey".into(),
                reason: "must be hex (pvfs whoami prints it)".into(),
            })?;
            let rights = match rights {
                Some(r) => r,
                None => prompt_line("rights at the root — r (consumer), rw (ingest), rwa (replicator)", Some("r"))?,
            };
            let r = acl::parse_rights(&rights)?;
            if r == 0 {
                return Err(PvfsError::BadInput {
                    field: "rights".into(),
                    reason: "enrolling grants at least r — to revoke, use `pvfs acl set`".into(),
                });
            }
            let root = {
                let engine = Engine::open(&state_dir)?;
                let root = engine.identity.root_node_id.clone();
                engine.close()?;
                root
            };
            // 1) membership — the authoring/authentication capability. A key
            //    already enrolled is fine: idempotent re-runs just re-grant.
            let already = |e: &PvfsError| matches!(e, PvfsError::AlreadyExists { .. });
            if let Some((mut client, sign)) = daemon_client(&state_dir)? {
                match client.authorize_member(&pubkey, |d| sign(d)).map_err(remote_err) {
                    Ok(_) => {}
                    Err(e) if already(&e) => {}
                    Err(e) => return Err(e),
                }
                // 2) rights at the root, same connection
                client
                    .set_acl_expiring(
                        &root,
                        &format!("key:{pubkey}"),
                        &acl::rights_to_str(r),
                        0,
                        |d| sign(d),
                    )
                    .map_err(remote_err)?;
            } else {
                let mut engine = Engine::open(&state_dir)?;
                match engine.authorize_member_by_device(&pk) {
                    Ok(_) => {}
                    Err(e) if already(&e) => {}
                    Err(e) => {
                        let _ = engine.close();
                        return Err(e);
                    }
                }
                engine.set_acl_expiring(&root, &acl::Principal::Key(pk.clone()), r, 0)?;
                engine.close()?;
            }
            if json {
                println!(
                    "{{\"enrolled\":\"{pubkey}\",\"rights\":\"{}\"}}",
                    acl::rights_to_str(r)
                );
            } else {
                println!("enrolled {pubkey} with {} at the root", acl::rights_to_str(r));
                println!("revoke any time: pvfs acl set {root} key:{pubkey} \"\"");
            }
            Ok(())
        }
        Cmd::Instance(cmd) => {
            match cmd {
                InstanceCmd::Add { name, addr, pin } => {
                    if name.contains(char::is_whitespace) {
                        return Err(PvfsError::BadInput {
                            field: "name".into(),
                            reason: "must not contain whitespace".into(),
                        });
                    }
                    if !addr.contains(':') {
                        return Err(PvfsError::BadInput {
                            field: "addr".into(),
                            reason: "expected host:port".into(),
                        });
                    }
                    if pin.len() != 64 || hex::decode(&pin).is_err() {
                        return Err(PvfsError::BadInput {
                            field: "pin".into(),
                            reason: "expected the 64-hex transport pin printed by pvfsd --listen"
                                .into(),
                        });
                    }
                    let mut list = load_instances()?;
                    list.retain(|(n, _, _)| n != &name);
                    list.push((name.clone(), addr, pin));
                    save_instances(&list)?;
                    if !json {
                        println!("instance {name} pinned");
                    }
                    Ok(())
                }
                InstanceCmd::Ls => {
                    let list = load_instances()?;
                    if json {
                        let items: Vec<String> = list
                            .iter()
                            .map(|(n, a, p)| {
                                format!(
                                    "{{\"name\":\"{}\",\"addr\":\"{}\",\"pin\":\"{}\"}}",
                                    json_escape(n),
                                    json_escape(a),
                                    p
                                )
                            })
                            .collect();
                        println!("[{}]", items.join(","));
                    } else {
                        for (n, a, p) in &list {
                            println!("{n}  {a}  {p}");
                        }
                    }
                    Ok(())
                }
                InstanceCmd::Rm { name } => {
                    let mut list = load_instances()?;
                    let before = list.len();
                    list.retain(|(n, _, _)| n != &name);
                    if list.len() == before {
                        return Err(PvfsError::NotFound {
                            kind: "instance",
                            id: name,
                        });
                    }
                    save_instances(&list)?;
                    if !json {
                        println!("instance {name} forgotten");
                    }
                    Ok(())
                }
            }
        }
        Cmd::Remote {
            socket,
            forest,
            connect,
            pin,
            instance,
            anon,
            cmd,
        } => {
            // Where to dial: a network target (--connect/--instance, F1) or
            // the local Unix socket (--socket/--forest, as before).
            let net = match (connect, instance) {
                (Some(addr), _) => {
                    let pin = pin.ok_or_else(|| PvfsError::BadInput {
                        field: "remote".into(),
                        reason: "pass --pin <hex> with --connect (printed by pvfsd --listen)"
                            .into(),
                    })?;
                    Some((addr, pin))
                }
                (None, Some(name)) => Some(lookup_instance(&name)?),
                (None, None) => None,
            };
            let identity_key = if anon {
                None
            } else {
                let mn = client_identity_mnemonic()?;
                Some(identity::device_key(&mn, "", 0)?)
            };
            let mut client = match (&net, &identity_key) {
                (Some((addr, pin)), None) => {
                    Client::connect_tcp_public(addr, pin).map_err(remote_err)?
                }
                (Some((addr, pin)), Some(key)) => {
                    let pubkey = crypto::pubkey_bytes(key);
                    Client::connect_tcp_signed(addr, pin, &pubkey, |d| {
                        crypto::sign_digest(key, d).unwrap_or_default()
                    })
                    .map_err(remote_err)?
                }
                (None, key) => {
                    let socket = resolve_remote_socket(socket, forest)?;
                    match key {
                        None => Client::connect_public(&socket).map_err(remote_err)?,
                        Some(key) => {
                            let pubkey = crypto::pubkey_bytes(key);
                            Client::connect_signed(&socket, &pubkey, |d| {
                                crypto::sign_digest(key, d).unwrap_or_default()
                            })
                            .map_err(remote_err)?
                        }
                    }
                }
            };
            match cmd {
                RemoteCmd::Info => {
                    let i = client.info().map_err(remote_err)?;
                    if json {
                        println!(
                            "{{\"principal\":\"{}\",\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root\":\"{}\"}}",
                            json_escape(&client.principal),
                            json_escape(&i.instance_id),
                            json_escape(&i.forest_id),
                            json_escape(&i.root)
                        );
                    } else {
                        println!("principal   : {}", client.principal);
                        println!("instance_id : {}", i.instance_id);
                        println!("forest_id   : {}", i.forest_id);
                        println!("root node   : {}", i.root);
                    }
                }
                RemoteCmd::Ls { node } => {
                    let node = remote_node(&mut client, &node)?;
                    let kids = client.ls(&node).map_err(remote_err)?;
                    if json {
                        let items: Vec<String> = kids
                            .iter()
                            .map(|c| {
                                format!(
                                    "{{\"id\":\"{}\",\"label\":\"{}\",\"node_type\":\"{}\"}}",
                                    json_escape(&c.id),
                                    json_escape(&c.label),
                                    json_escape(&c.node_type)
                                )
                            })
                            .collect();
                        println!("[{}]", items.join(","));
                    } else {
                        for c in kids {
                            println!("{}  {}  {}", c.id, c.node_type, c.label);
                        }
                    }
                }
                RemoteCmd::Stat { node } => {
                    let node = remote_node(&mut client, &node)?;
                    let n = client.stat(&node).map_err(remote_err)?;
                    if json {
                        println!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"node_type\":\"{}\",\"rights\":\"{}\"}}",
                            json_escape(&n.id),
                            json_escape(&n.label),
                            json_escape(&n.node_type),
                            json_escape(&n.rights)
                        );
                    } else {
                        println!("{}  {}  {}  [{}]", n.id, n.node_type, n.label, n.rights);
                    }
                }
                RemoteCmd::Cat { node } => {
                    let node = remote_node(&mut client, &node)?;
                    let mut stdout = std::io::stdout().lock();
                    client.cat(&node, &mut stdout).map_err(remote_err)?;
                }
                RemoteCmd::Mkdir { parent, label } => {
                    let parent = remote_node(&mut client, &parent)?;
                    let key = identity_key.as_ref().ok_or_else(needs_identity)?;
                    let id = client
                        .mkdir(&parent, &label, |d| {
                            crypto::sign_digest(key, d).unwrap_or_default()
                        })
                        .map_err(remote_err)?;
                    print_created(&id, json);
                }
                RemoteCmd::AddFile {
                    parent,
                    label,
                    size,
                    mime,
                } => {
                    let parent = remote_node(&mut client, &parent)?;
                    let key = identity_key.as_ref().ok_or_else(needs_identity)?;
                    let id = client
                        .add_file(&parent, &label, size, &mime, |d| {
                            crypto::sign_digest(key, d).unwrap_or_default()
                        })
                        .map_err(remote_err)?;
                    print_created(&id, json);
                }
                RemoteCmd::AddLocation { file, uri } => {
                    let file = remote_node(&mut client, &file)?;
                    let key = identity_key.as_ref().ok_or_else(needs_identity)?;
                    let id = client
                        .add_location(&file, &uri, |d| {
                            crypto::sign_digest(key, d).unwrap_or_default()
                        })
                        .map_err(remote_err)?;
                    if json {
                        println!("{{\"file\":\"{}\"}}", json_escape(&id));
                    } else {
                        println!("added location to {id}");
                    }
                }
                RemoteCmd::Mv { node, new_parent } => {
                    let node = remote_node(&mut client, &node)?;
                    let new_parent = remote_node(&mut client, &new_parent)?;
                    let key = identity_key.as_ref().ok_or_else(needs_identity)?;
                    let id = client
                        .mv(&node, &new_parent, |d| {
                            crypto::sign_digest(key, d).unwrap_or_default()
                        })
                        .map_err(remote_err)?;
                    if json {
                        println!("{{\"moved\":\"{}\"}}", json_escape(&id));
                    } else {
                        println!("moved {id}");
                    }
                }
                RemoteCmd::Rm { node } => {
                    let node = remote_node(&mut client, &node)?;
                    let key = identity_key.as_ref().ok_or_else(needs_identity)?;
                    let removed = client
                        .rm(&node, |d| crypto::sign_digest(key, d).unwrap_or_default())
                        .map_err(remote_err)?;
                    if json {
                        println!("{{\"removed_link\":\"{}\"}}", json_escape(&removed));
                    } else {
                        println!("removed (link {removed})");
                    }
                }
                RemoteCmd::AddNode {
                    parent,
                    label,
                    node_type,
                    payload,
                } => {
                    let parent = remote_node(&mut client, &parent)?;
                    let bytes = remote_payload_bytes(&payload)?;
                    let key = identity_key.as_ref().ok_or_else(needs_identity)?;
                    let id = client
                        .add_node(&parent, &label, &node_type, &bytes, |d| {
                            crypto::sign_digest(key, d).unwrap_or_default()
                        })
                        .map_err(remote_err)?;
                    print_created(&id, json);
                }
                RemoteCmd::Payload { node } => {
                    let node = remote_node(&mut client, &node)?;
                    let bytes = client.payload(&node).map_err(remote_err)?;
                    use std::io::Write as _;
                    std::io::stdout()
                        .lock()
                        .write_all(&bytes)
                        .map_err(|e| PvfsError::io("write payload", e))?;
                }
            }
            Ok(())
        }
        Cmd::Bind {
            folder,
            dir: bind_dir,
            no_recursive,
            no_auto_index,
            extensions,
            hash_policy,
        } => {
            let mut engine = Engine::open(&ctx?)?;
            let abs = std::fs::canonicalize(&bind_dir)
                .map_err(|e| PvfsError::io("canonicalize dir", e))?;
            let source_uri = pvfs_core::storage::path_to_uri(&abs)?;
            engine.bind_folder(
                &folder,
                BindSpec {
                    source_uri: source_uri.clone(),
                    recursive: !no_recursive,
                    auto_index: !no_auto_index,
                    extensions,
                    hash_policy: HashPolicy::parse(&hash_policy)?,
                },
            )?;
            if json {
                println!("{{\"bound\":true,\"source_uri\":\"{}\"}}", json_escape(&source_uri));
            } else {
                println!("bound {folder} -> {source_uri}");
            }
            engine.close()
        }
        Cmd::Unbind { folder } => {
            let mut engine = Engine::open(&ctx?)?;
            engine.unbind_folder(&folder)?;
            if json {
                println!("{{\"unbound\":true}}");
            } else {
                println!("unbound {folder}");
            }
            engine.close()
        }
        Cmd::Scan { folder } => {
            let mut engine = Engine::open(&ctx?)?;
            let reports = engine.scan(folder.as_ref())?;
            if json {
                let items: Vec<String> = reports
                    .iter()
                    .map(|r| {
                        format!(
                            "{{\"folder_id\":\"{}\",\"added\":{},\"unchanged\":{},\"changed\":{},\"removed\":{},\"skipped\":{},\"unreadable\":{}}}",
                            r.folder_id,
                            r.stats.added,
                            r.stats.unchanged,
                            r.stats.changed,
                            r.stats.removed,
                            r.stats.skipped,
                            r.stats.unreadable
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for r in &reports {
                    println!(
                        "{}: +{} added, {} unchanged, {} changed, -{} removed, {} skipped, {} unreadable",
                        r.folder_id,
                        r.stats.added,
                        r.stats.unchanged,
                        r.stats.changed,
                        r.stats.removed,
                        r.stats.skipped,
                        r.stats.unreadable
                    );
                }
                let changed: u64 = reports.iter().map(|r| r.stats.changed).sum();
                if changed > 0 {
                    eprintln!("note: {changed} file(s) flagged changed — review with `pvfs changes`");
                }
                let unreadable: u64 = reports.iter().map(|r| r.stats.unreadable).sum();
                if unreadable > 0 {
                    eprintln!("note: {unreadable} path(s) skipped — not readable by your user");
                }
            }
            engine.close()
        }
        Cmd::Stat { target } => {
            let (mut engine, id) = engine_and_node(ctx, &target)?;
            let st = engine.stat_node(&id)?;
            if json {
                let locs: Vec<String> = st
                    .locations
                    .iter()
                    .map(|l| {
                        format!(
                            "{{\"uri\":\"{}\",\"exists\":{},\"size\":{},\"quarantined\":{},\"pending_change\":{}}}",
                            json_escape(&l.uri),
                            l.exists,
                            l.size,
                            l.quarantined
                                .as_ref()
                                .map(|q| format!("\"{}\"", json_escape(q)))
                                .unwrap_or_else(|| "null".into()),
                            l.pending_change
                        )
                    })
                    .collect();
                println!(
                    "{{\"id\":\"{}\",\"label\":\"{}\",\"type\":\"{}\",\"unavailable\":{},\"locations\":[{}]}}",
                    st.node.id,
                    json_escape(&st.node.label),
                    json_escape(&st.node.node_type),
                    st.unavailable,
                    locs.join(",")
                );
            } else {
                println!("id    : {}", st.node.id);
                println!("label : {}", st.node.label);
                println!("type  : {}", st.node.node_type);
                if st.unavailable {
                    println!("state : UNAVAILABLE (no readable, trusted location)");
                }
                for l in &st.locations {
                    let mut flags = Vec::new();
                    if !l.exists {
                        flags.push("missing".to_string());
                    }
                    if let Some(q) = &l.quarantined {
                        flags.push(format!("quarantined: {q}"));
                    }
                    if l.pending_change {
                        flags.push("changed-on-disk (pvfs resolve)".to_string());
                    }
                    println!(
                        "loc   : {} ({} bytes){}",
                        l.uri,
                        l.size,
                        if flags.is_empty() {
                            String::new()
                        } else {
                            format!("  [{}]", flags.join("; "))
                        }
                    );
                }
            }
            engine.close()
        }
        Cmd::Cat { target, range, output } => {
            let (mut engine, id) = engine_and_node(ctx, &target)?;
            let range = match range {
                None => None,
                Some(r) => Some(parse_range(&r)?),
            };
            // Read-through (F5.2, doc 17 §7.3): no local bytes → fetch them
            // from a reachable holder into the sync store, then serve. The
            // read blocks while the verified fetch streams; nothing lands on
            // failure and the original error surfaces.
            if engine.readable_path(&id)?.is_none()
                && engine.node(&id)?.map(|n| n.node_type) == Some(pvfs_core::TYPE_FILE.into())
            {
                let data_dir = engine.data_dir().to_path_buf();
                let mut fetcher = Fetcher::new(&data_dir);
                if let Err(e) = fetcher.fetch(&mut engine, &id) {
                    if !e.is_empty() {
                        eprintln!("read-through: {e}");
                    }
                }
            }
            let written = match output {
                Some(path) => {
                    let mut f = std::fs::File::create(&path)
                        .map_err(|e| PvfsError::io("create output", e))?;
                    engine.cat(&id, range, &mut f)?
                }
                None => {
                    let stdout = std::io::stdout();
                    let mut lock = stdout.lock();
                    engine.cat(&id, range, &mut lock)?
                }
            };
            if json {
                eprintln!("{{\"bytes\":{written}}}");
            }
            engine.close()
        }
        Cmd::Export {
            target,
            dest,
            mode,
            prune,
            fetch,
            keep_fresh,
        } => {
            let (mut engine, id) = engine_and_node(ctx, &target)?;
            if fetch {
                let data_dir = engine.data_dir().to_path_buf();
                let mut fetcher = Fetcher::new(&data_dir);
                let (fetched, failed) =
                    sync_pull(&mut engine, &mut fetcher, std::slice::from_ref(&id))?;
                for (label, e) in &failed {
                    eprintln!("fetch failed: {label} — {e}");
                }
                if !json && fetched > 0 {
                    eprintln!("fetched {fetched} files into the sync store");
                }
            }
            let spec = pvfs_core::ExportSpec {
                mode: pvfs_core::ExportMode::parse(&mode)?,
                prune,
            };
            let report = engine.export_tree(&id, &dest, &spec)?;
            if json {
                let skipped: Vec<String> = report
                    .skipped
                    .iter()
                    .map(|s| {
                        format!(
                            "{{\"path\":\"{}\",\"node\":\"{}\",\"reason\":\"{}\"}}",
                            json_escape(&s.path),
                            s.node,
                            json_escape(&s.reason)
                        )
                    })
                    .collect();
                let stale: Vec<String> = report
                    .stale
                    .iter()
                    .map(|p| format!("\"{}\"", json_escape(p)))
                    .collect();
                println!(
                    "{{\"dirs_created\":{},\"exported\":{},\"unchanged\":{},\"pruned\":{},\"stale\":[{}],\"skipped\":[{}]}}",
                    report.dirs_created,
                    report.exported,
                    report.unchanged,
                    report.pruned,
                    stale.join(","),
                    skipped.join(",")
                );
            } else {
                println!(
                    "exported {} ({} unchanged, {} dirs created, {} pruned)",
                    report.exported, report.unchanged, report.dirs_created, report.pruned
                );
                for p in &report.stale {
                    eprintln!("stale: {p} (re-run with --prune to remove)");
                }
                for s in &report.skipped {
                    eprintln!("skipped: {} — {}", s.path, s.reason);
                }
            }
            if keep_fresh {
                // record with an absolute dest — the daemon's job runs from
                // its own cwd, not this shell's
                let abs = std::fs::canonicalize(&dest)
                    .map_err(|e| PvfsError::io("resolve export dest", e))?;
                pvfs_core::serve::upsert_export(
                    engine.data_dir(),
                    pvfs_core::serve::ExportEntry {
                        node: id.clone(),
                        mode: mode.clone(),
                        fetch,
                        prune,
                        dest: abs,
                    },
                )?;
                if !json {
                    eprintln!("recorded for the export job (enable it: pvfs serve enable export)");
                }
            }
            engine.close()
        }
        Cmd::Hash { target } => {
            let (mut engine, id) = engine_and_node(ctx, &target)?;
            let new_id = engine.hash_node(&id)?;
            if json {
                println!(
                    "{{\"node_id\":\"{new_id}\",\"re_identified\":{}}}",
                    new_id != id
                );
            } else if new_id != id {
                println!("{new_id}");
                eprintln!("note: hashing re-identified the node (successor created; old id orphaned)");
            } else {
                println!("{new_id}");
            }
            engine.close()
        }
        Cmd::Changes => {
            let engine = Engine::open(&ctx?)?;
            let changes = engine.changes()?;
            if json {
                let items: Vec<String> = changes
                    .iter()
                    .map(|c| {
                        format!(
                            "{{\"id\":\"{}\",\"label\":\"{}\",\"uri\":\"{}\",\"old_size\":{},\"new_size\":{}}}",
                            c.file_id,
                            json_escape(&c.label),
                            json_escape(&c.uri),
                            c.old_size,
                            c.new_size
                        )
                    })
                    .collect();
                println!("[{}]", items.join(","));
            } else {
                for c in &changes {
                    println!(
                        "{}  {}  {} -> {} bytes  {}",
                        c.file_id, c.label, c.old_size, c.new_size, c.uri
                    );
                }
                if !changes.is_empty() {
                    eprintln!(
                        "resolve with: pvfs resolve <id> --replace   (accept new contents)");
                    eprintln!(
                        "          or: pvfs resolve <id> --delete [--purge]   (treat as untrusted)");
                }
            }
            engine.close()
        }
        Cmd::Resolve {
            id,
            replace,
            delete,
            purge,
        } => {
            if replace == delete {
                return Err(PvfsError::BadInput {
                    field: "action".into(),
                    reason: "pass exactly one of --replace / --delete".into(),
                });
            }
            let mut engine = Engine::open(&ctx?)?;
            let action = if replace {
                ResolveAction::Replace
            } else {
                ResolveAction::Delete { purge }
            };
            let result = engine.resolve(&id, action)?;
            if json {
                println!("{{\"resolved\":\"{result}\"}}");
            } else if replace {
                println!("{result}");
                eprintln!("replaced — new node id above; old node kept as reviewable orphan");
            } else {
                println!("resolved (deleted{})", if purge { ", purged" } else { "" });
            }
            engine.close()
        }
        Cmd::Serve { cmd: None } => {
            // punch E: bare `pvfs serve` answers the question people are
            // asking — what are the jobs doing (the watcher moved to
            // `serve watch` / the `watch` job; PVOS verified un-affected).
            // No engine open — see the subcommand arm's note.
            let data_dir = ctx?;
            if !data_dir.join("log.db").exists() {
                return Err(PvfsError::NotFound {
                    kind: "forest",
                    id: data_dir.to_string_lossy().into_owned(),
                });
            }
            match try_daemon_socket(&data_dir) {
                Some(sock) => serve_status_print(&data_dir, &sock, json),
                None => {
                    let enabled = pvfs_core::serve::load_jobs(&data_dir)?;
                    if json {
                        let rows: Vec<String> = pvfs_core::serve::JOB_NAMES
                            .iter()
                            .map(|n| {
                                let en = enabled.iter().any(|j| j == n);
                                format!("{{\"job\":\"{n}\",\"enabled\":{en}}}")
                            })
                            .collect();
                        println!("{{\"runner\":\"off\",\"jobs\":[{}]}}", rows.join(","));
                    } else {
                        eprintln!("no running daemon — configured jobs:");
                        for n in pvfs_core::serve::JOB_NAMES {
                            let en = enabled.iter().any(|j| j == n);
                            println!("{n:<8} {}", if en { "enabled" } else { "-" });
                        }
                    }
                    Ok(())
                }
            }
        }
        Cmd::Forest(cmd) => forest_cmd(cmd, ctx, json),
        Cmd::Ssh {
            target,
            companion_socket,
            remote_socket,
            ssh_option,
            remote_cmd,
        } => ssh_with_companion(target, companion_socket, remote_socket, ssh_option, remote_cmd),
    }
}

/// Desktop SSO: reverse-forward the local companion Unix socket over SSH so a
/// remote `pvfs` uses this machine's agent for root/identity signing.
fn ssh_with_companion(
    target: String,
    companion_socket: Option<PathBuf>,
    remote_socket: Option<PathBuf>,
    ssh_options: Vec<String>,
    remote_cmd: Vec<String>,
) -> Result<(), PvfsError> {
    let local = resolve_companion_socket(companion_socket)?;
    // Prove the agent answers before opening SSH.
    let root = companion_pubkey(&local, "root")?;
    let preview = hex::encode(&root[..root.len().min(8)]);

    // Unique path by default so a second session (or a stale socket) does not
    // hit "remote port forwarding failed for listen path …".
    let remote_sock = match remote_socket {
        Some(p) => p.to_string_lossy().into_owned(),
        None => {
            let mut b = [0u8; 4];
            // cheap unique suffix without extra deps
            use std::time::{SystemTime, UNIX_EPOCH};
            let n = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            b.copy_from_slice(&(n as u32).to_le_bytes());
            format!("/tmp/pvfs-companion-fwd-{:02x}{:02x}{:02x}{:02x}.sock", b[0], b[1], b[2], b[3])
        }
    };
    let forward = format!("{remote_sock}:{}", local.display());

    let mut cmd = std::process::Command::new("ssh");
    // Allocate a TTY for interactive shells so the remote prompt appears.
    if remote_cmd.is_empty() {
        cmd.arg("-t");
    }
    cmd.arg("-o").arg("ExitOnForwardFailure=yes");
    cmd.arg("-o").arg("StreamLocalBindUnlink=yes");
    for opt in &ssh_options {
        cmd.arg("-o").arg(opt);
    }
    cmd.arg("-R").arg(&forward);
    cmd.arg(&target);

    if remote_cmd.is_empty() {
        // Interactive shell with companion socket in the environment.
        let shell = format!(
            "export PVFS_COMPANION_SOCKET={sock}; \
             trap 'rm -f -- \"$PVFS_COMPANION_SOCKET\" 2>/dev/null' EXIT; \
             echo \"pvfs: companion SSO active (desktop root {preview}…) → $PVFS_COMPANION_SOCKET\"; \
             exec \"${{SHELL:-/bin/bash}}\" -il",
            sock = shell_single_quote(&remote_sock),
            preview = preview,
        );
        cmd.arg(shell);
    } else {
        let mut parts = Vec::with_capacity(remote_cmd.len());
        for a in &remote_cmd {
            parts.push(shell_single_quote(a));
        }
        let remote = format!(
            "export PVFS_COMPANION_SOCKET={sock}; exec {cmd}",
            sock = shell_single_quote(&remote_sock),
            cmd = parts.join(" "),
        );
        cmd.arg(remote);
    }

    let status = cmd.status().map_err(|e| PvfsError::io("ssh", e))?;
    if status.success() {
        Ok(())
    } else {
        Err(PvfsError::BadInput {
            field: "ssh".into(),
            reason: format!(
                "ssh exited with status {} (companion was local {}; remote {})",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into()),
                local.display(),
                remote_sock
            ),
        })
    }
}

/// Single-quote a string for safe embedding in a remote shell command.
fn shell_single_quote(s: &str) -> String {
    // 'foo'bar' → 'foo'"'"'bar'
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

fn print_forest_created(
    engine: &Engine,
    mount: &std::path::Path,
    alias: Option<&str>,
    report: Option<&pvfs_core::ScanReport>,
    mnemonic: Option<String>,
    json: bool,
) -> Result<(), PvfsError> {
    if json {
        let mnemonic_json = match &mnemonic {
            Some(m) => format!("\"{}\"", json_escape(m)),
            None => "null".into(),
        };
        println!(
            "{{\"mount\":\"{}\",\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"root_pubkey\":\"{}\",\"imported\":{},\"registered\":false,\"suggested_alias\":{},\"mnemonic\":{},\"via_companion\":{}}}",
            json_escape(&mount.to_string_lossy()),
            json_escape(&engine.identity.instance_id),
            json_escape(&engine.identity.forest_id),
            json_escape(&engine.identity.root_node_id),
            hex::encode(&engine.identity.root_pubkey),
            report.is_some(),
            alias
                .map(|a| format!("\"{}\"", json_escape(a)))
                .unwrap_or_else(|| "null".into()),
            mnemonic_json,
            mnemonic.is_none(),
        );
    } else {
        println!("Forest created at {}", mount.display());
        println!("  instance_id : {}", engine.identity.instance_id);
        println!("  forest_id   : {}", engine.identity.forest_id);
        println!("  root node   : {}", engine.identity.root_node_id);
        println!(
            "  root key    : {}",
            hex::encode(&engine.identity.root_pubkey)
        );
        if let Some(r) = report {
            println!(
                "  imported    : {} file(s) from the mount tree",
                r.stats.added
            );
            if r.stats.unreadable > 0 {
                println!(
                    "  skipped     : {} path(s) you cannot read (not imported)",
                    r.stats.unreadable
                );
            }
        }
        println!("  portable    : register for system-wide listing:");
        if let Some(a) = alias {
            println!(
                "    sudo pvfs forest register {} --alias {}",
                mount.display(),
                a
            );
        } else {
            println!("    sudo pvfs forest register {}", mount.display());
        }
        println!();
        if let Some(mnemonic) = mnemonic {
            println!("RECOVERY PHRASE — write this down now; it is shown ONCE and never stored:");
            println!();
            println!("  {mnemonic}");
            println!();
        } else {
            println!("Root identity: companion (existing seed; no new recovery phrase).");
            println!("This machine's device key is stored under .pvfs/device.key.");
            println!();
        }
    }
    Ok(())
}

fn forest_cmd(
    cmd: ForestCmd,
    ctx: Result<PathBuf, PvfsError>,
    json: bool,
) -> Result<(), PvfsError> {
    match cmd {
        ForestCmd::Init {
            mount: mount_arg,
            no_import,
            alias,
            hash_policy,
            via_companion,
            companion_socket,
            new_phrase,
        } => {
            if via_companion && new_phrase {
                return Err(PvfsError::BadInput {
                    field: "forest init".into(),
                    reason: "pass only one of --via-companion or --new-phrase".into(),
                });
            }
            mount::mount_owner_credentials()?; // fail before creating state as raw root
            let target = match mount_arg {
                Some(m) => m,
                None => std::env::current_dir().map_err(|e| PvfsError::io("getcwd", e))?,
            };
            if let Some(a) = &alias {
                Registry::validate_alias(a)?;
            }
            let policy = HashPolicy::parse(&hash_policy)?;
            let import = !no_import;

            // Prefer an existing companion identity when available (doc 14 genesis).
            // Desktop SSO exports PVFS_COMPANION_SOCKET — never ignore it silently.
            let env_sso = std::env::var_os("PVFS_COMPANION_SOCKET")
                .filter(|s| !s.is_empty())
                .is_some();
            let probed = probe_companion(companion_socket.clone())?;
            let use_companion = if new_phrase {
                false
            } else if via_companion {
                if probed.is_none() {
                    return Err(PvfsError::BadInput {
                        field: "companion".into(),
                        reason: "no companion running — start the agent (desktop SSO: keep \
                                 the SSH forward session open)"
                            .into(),
                    });
                }
                true
            } else if let Some((ref sock, ref root_pub)) = probed {
                let preview = hex::encode(&root_pub[..root_pub.len().min(8)]);
                if json {
                    return Err(PvfsError::BadInput {
                        field: "forest init".into(),
                        reason: format!(
                            "companion is running at {} (root {preview}…) — pass \
                             --via-companion to use it, or --new-phrase for a fresh seed \
                             (required with --json)",
                            sock.display()
                        ),
                    });
                }
                // Confirm for both local agent and desktop-SSO forwarded socket.
                if !confirm_use_companion(&preview)? {
                    if env_sso {
                        return Err(PvfsError::BadInput {
                            field: "forest init".into(),
                            reason: "declined companion identity — pass --new-phrase for a \
                                     separate seed, or re-run and accept"
                                .into(),
                        });
                    }
                    false
                } else {
                    true
                }
            } else {
                false
            };

            if use_companion {
                let sock = resolve_companion_socket(companion_socket)?;
                let root_pub = companion_pubkey(&sock, "root")?;
                let (engine, report) = mount::init_forest_with_root_signer(
                    &target,
                    import,
                    policy,
                    &root_pub,
                    |digest| companion_sign(&sock, "root_device_cert", digest),
                )?;
                let mount = std::fs::canonicalize(&target)
                    .map_err(|e| PvfsError::io("canonicalize mount", e))?;
                print_forest_created(
                    &engine,
                    &mount,
                    alias.as_deref(),
                    report.as_ref(),
                    None,
                    json,
                )?;
                engine.close()
            } else {
                let (engine, mnemonic, report) = mount::init_forest(&target, import, policy)?;
                let mount = std::fs::canonicalize(&target)
                    .map_err(|e| PvfsError::io("canonicalize mount", e))?;
                print_forest_created(
                    &engine,
                    &mount,
                    alias.as_deref(),
                    report.as_ref(),
                    Some(mnemonic.to_string()),
                    json,
                )?;
                engine.close()
            }
        }
        ForestCmd::Register { mount: m, alias } => {
            if let Some(a) = &alias {
                Registry::validate_alias(a)?;
            }
            let m = std::fs::canonicalize(&m).map_err(|e| PvfsError::io("canonicalize mount", e))?;
            mount::ensure_mount_owned_by_operator(&m)?;
            let f = Registry::system().register(&m, alias.as_deref())?;
            if json {
                println!(
                    "{{\"registered\":true,\"mount\":\"{}\",\"alias\":{}}}",
                    json_escape(&f.mount.to_string_lossy()),
                    f.alias
                        .as_ref()
                        .map(|a| format!("\"{}\"", json_escape(a)))
                        .unwrap_or_else(|| "null".into()),
                );
            } else {
                println!(
                    "registered {} ({})",
                    f.mount.display(),
                    f.alias.as_deref().unwrap_or("no alias")
                );
            }
            Ok(())
        }
        ForestCmd::Unregister { name } => {
            Registry::system().unregister(&name)?;
            if json {
                println!("{{\"unregistered\":true}}");
            } else {
                println!("unregistered {name} (mount and .pvfs/ untouched)");
            }
            Ok(())
        }
        ForestCmd::FixPermissions { mount: m } => {
            let target = match m {
                Some(p) => p,
                None => std::env::current_dir().map_err(|e| PvfsError::io("getcwd", e))?,
            };
            mount::ensure_mount_owned_by_operator(&target)?;
            if json {
                println!(
                    "{{\"fixed\":true,\"mount\":\"{}\"}}",
                    json_escape(&target.to_string_lossy())
                );
            } else {
                let canon = std::fs::canonicalize(&target)
                    .map_err(|e| PvfsError::io("canonicalize mount", e))?;
                println!(
                    "fixed ownership of {} (and .pvfs/) for your user",
                    canon.display()
                );
            }
            Ok(())
        }
        ForestCmd::Info { target } => {
            let (mount_path, state) = match target {
                Some(t) => {
                    let r = mount::resolve_target(&Registry::system(), &t)?;
                    (Some(r.mount.clone()), mount::state_dir(&r.mount))
                }
                None => (None, ctx?),
            };
            let engine = Engine::open(&state)?;
            if json {
                println!(
                    "{{\"mount\":{},\"instance_id\":\"{}\",\"forest_id\":\"{}\",\"root_node_id\":\"{}\",\"device_pubkey\":\"{}\"}}",
                    mount_path
                        .as_ref()
                        .map(|m| format!("\"{}\"", json_escape(&m.to_string_lossy())))
                        .unwrap_or_else(|| "null".into()),
                    json_escape(&engine.identity.instance_id),
                    json_escape(&engine.identity.forest_id),
                    json_escape(&engine.identity.root_node_id),
                    hex::encode(engine.device_pubkey()),
                );
            } else {
                if let Some(m) = &mount_path {
                    println!("mount       : {}", m.display());
                }
                println!("instance_id : {}", engine.identity.instance_id);
                println!("forest_id   : {}", engine.identity.forest_id);
                println!("root node   : {}", engine.identity.root_node_id);
                println!("device key  : {}", hex::encode(engine.device_pubkey()));
            }
            engine.close()
        }
        ForestCmd::RecoveryKey { forest, revoke } => {
            let state = forest_state_dir(forest, ctx)?;
            let auth_mn = read_phrase_stdin("current recovery phrase (to authorize)")?;
            let root_key = identity::root_key(&auth_mn, "")?;
            let root_pub = crypto::pubkey_bytes(&root_key);
            // --revoke: retire a registered recovery key, don't create one.
            if let Some(revoke_hex) = revoke {
                let rec_pub = hex::decode(&revoke_hex).map_err(|_| PvfsError::BadInput {
                    field: "revoke".into(),
                    reason: "must be hex".into(),
                })?;
                let mut engine = Engine::open(&state)?;
                let prep = engine.prepare_revoke_recovery(&root_pub, &rec_pub)?;
                commit_phrase_signed(&mut engine, prep, &root_key)?;
                engine.close()?;
                if json {
                    println!("{{\"revoked\":true,\"recovery_pubkey\":\"{revoke_hex}\"}}");
                } else {
                    println!("retired recovery key {revoke_hex}");
                }
                return Ok(());
            }
            // Fresh, independent recovery phrase — its root is the recovery key.
            let rec_mn = identity::generate_mnemonic()?;
            let rec_pub = crypto::pubkey_bytes(&identity::root_key(&rec_mn, "")?);
            let mut engine = Engine::open(&state)?;
            let prep = engine.prepare_register_recovery(&root_pub, &rec_pub)?;
            commit_phrase_signed(&mut engine, prep, &root_key)?;
            engine.close()?;
            if json {
                println!(
                    "{{\"registered\":true,\"recovery_pubkey\":\"{}\",\"recovery_phrase\":\"{}\"}}",
                    hex::encode(&rec_pub),
                    json_escape(&rec_mn.to_string())
                );
            } else {
                println!("registered recovery key {}", hex::encode(&rec_pub));
                println!();
                println!("ROTATION RECOVERY PHRASE — store on paper, never type into a machine");
                println!("except to rotate your root. Anyone with it can rotate your forest:");
                println!();
                println!("  {rec_mn}");
                println!();
            }
            Ok(())
        }
        ForestCmd::RotateRoot { forest } => {
            let state = forest_state_dir(forest, ctx)?;
            let auth_mn =
                read_phrase_stdin("authorizing phrase (current recovery or rotation-recovery)")?;
            let auth_key = identity::root_key(&auth_mn, "")?;
            let auth_pub = crypto::pubkey_bytes(&auth_key);
            // The new root is a fresh independent seed.
            let new_mn = identity::generate_mnemonic()?;
            let new_pub = crypto::pubkey_bytes(&identity::root_key(&new_mn, "")?);
            let mut engine = Engine::open(&state)?;
            let prep = engine.prepare_rotate_root(&auth_pub, &new_pub)?;
            commit_phrase_signed(&mut engine, prep, &auth_key)?;
            engine.close()?;
            if json {
                println!(
                    "{{\"rotated\":true,\"new_root_pubkey\":\"{}\",\"new_phrase\":\"{}\"}}",
                    hex::encode(&new_pub),
                    json_escape(&new_mn.to_string())
                );
            } else {
                println!("root rotated to {}", hex::encode(&new_pub));
                println!("forest identity (forest_id, history) is unchanged.");
                println!();
                println!("NEW RECOVERY PHRASE — write it down; it replaces the old one:");
                println!();
                println!("  {new_mn}");
                println!();
                println!("Next: revoke and re-admit any device/identity keys derived from the");
                println!("old (compromised) seed — they still work until you do.");
            }
            Ok(())
        }
    }
}

/// Resolve a forest's state dir from an optional `--forest` (else the context).
fn forest_state_dir(
    forest: Option<String>,
    ctx: Result<PathBuf, PvfsError>,
) -> Result<PathBuf, PvfsError> {
    match forest {
        Some(t) => {
            let r = mount::resolve_target(&Registry::system(), &t)?;
            Ok(mount::state_dir(&r.mount))
        }
        None => ctx,
    }
}

/// Fetch + print live job status from the local daemon, signed (punch F:
/// ServeStatus is member-gated) — the forest device key when this box owns
/// the forest, else the client identity (which must be enrolled).
fn serve_status_print(
    state_dir: &std::path::Path,
    sock: &std::path::Path,
    json: bool,
) -> Result<(), PvfsError> {
    let key = match identity::DeviceKeyCache::load(state_dir) {
        Ok(cache) => cache.signing_key,
        Err(_) => {
            let mn = client_identity_mnemonic()?;
            identity::device_key(&mn, "", 0)?
        }
    };
    let pubkey = crypto::pubkey_bytes(&key);
    let mut client = Client::connect_signed(sock, &pubkey, |d| {
        crypto::sign_digest(&key, d).unwrap_or_default()
    })
    .map_err(remote_err)?;
    let (runner, jobs) = client.serve_status().map_err(remote_err)?;
    if json {
        let rows: Vec<String> = jobs
            .iter()
            .map(|j| {
                format!(
                    "{{\"job\":\"{}\",\"enabled\":{},\"state\":\"{}\",\"last_ok_ms\":{},\"last_error\":{}}}",
                    json_escape(&j.name),
                    j.enabled,
                    json_escape(&j.state),
                    j.last_ok_ms.map(|m| m.to_string()).unwrap_or_else(|| "null".into()),
                    j.last_error
                        .as_ref()
                        .map(|e| format!("\"{}\"", json_escape(e)))
                        .unwrap_or_else(|| "null".into()),
                )
            })
            .collect();
        println!(
            "{{\"runner\":\"{}\",\"jobs\":[{}]}}",
            json_escape(&runner),
            rows.join(",")
        );
    } else {
        println!("runner: {runner}");
        for j in &jobs {
            let mut line = format!("{:<8} {}", j.name, j.state);
            if let Some(e) = &j.last_error {
                line.push_str(&format!("  (last error: {e})"));
            }
            println!("{line}");
        }
    }
    Ok(())
}

/// Prompt for a missing value (Chris's rule: bare commands ask, flags are
/// for scripts). Non-interactive runs must pass the argument instead.
fn prompt_line(what: &str, default: Option<&str>) -> Result<String, PvfsError> {
    use std::io::{IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(PvfsError::BadInput {
            field: "prompt".into(),
            reason: format!("missing {what} — pass it as an argument in non-interactive runs"),
        });
    }
    match default {
        Some(d) => eprint!("{what} [{d}]: "),
        None => eprint!("{what}: "),
    }
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| PvfsError::io("read input", e))?;
    let v = line.trim();
    match (v.is_empty(), default) {
        (false, _) => Ok(v.to_string()),
        (true, Some(d)) => Ok(d.to_string()),
        (true, None) => Err(PvfsError::BadInput {
            field: "prompt".into(),
            reason: format!("{what} is required"),
        }),
    }
}

/// Read + validate a recovery phrase from stdin (piped or typed).
fn read_phrase_stdin(what: &str) -> Result<pvfs_core::Mnemonic, PvfsError> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        eprintln!("Enter your {what}:");
    }
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| PvfsError::io("read phrase", e))?;
    let phrase = line.trim();
    if phrase.is_empty() {
        return Err(PvfsError::BadInput {
            field: "phrase".into(),
            reason: "no phrase provided".into(),
        });
    }
    identity::parse_mnemonic(phrase)
}

/// Sign each event of a prepared write with a phrase-derived key and commit.
fn commit_phrase_signed(
    engine: &mut Engine,
    prep: pvfs_core::PreparedWrite,
    key: &identity::SigningKey,
) -> Result<(), PvfsError> {
    let mut events = Vec::new();
    for pe in prep.events {
        let mut ev = pe.event;
        ev.set_author_sig(crypto::sign_digest(key, &pe.digest)?);
        events.push(ev);
    }
    engine.commit_member_write(events)
}

fn parse_range(s: &str) -> Result<ByteRange, PvfsError> {
    let (a, b) = s.split_once('-').ok_or_else(|| PvfsError::BadInput {
        field: "range".into(),
        reason: "expected START-END".into(),
    })?;
    let start: u64 = a.parse().map_err(|_| PvfsError::BadInput {
        field: "range".into(),
        reason: "bad start".into(),
    })?;
    let end = if b.is_empty() {
        None
    } else {
        Some(b.parse().map_err(|_| PvfsError::BadInput {
            field: "range".into(),
            reason: "bad end".into(),
        })?)
    };
    Ok(ByteRange { start, end })
}

fn emit_id(json: bool, key: &str, id: &str) {
    if json {
        println!("{{\"{key}\":\"{id}\"}}");
    } else {
        println!("{id}");
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            print_error(&e, json);
            ExitCode::from(exit_code_for(&e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    // doc 13 Q-E1: `--expires` accepts a duration (relative to now) or an
    // absolute `@<unix-ms>`; zero and garbage are refused with `bad_input`.
    #[test]
    fn parse_expires_durations_and_absolute() {
        let before = now_ms();
        let t = parse_expires("45s").unwrap();
        assert!(t >= before + 45_000 && t <= now_ms() + 45_000);
        let t = parse_expires("2w").unwrap();
        assert!(t >= before + 14 * 86_400_000);
        assert_eq!(parse_expires("@1753000000000").unwrap(), 1_753_000_000_000);

        for bad in ["@0", "@x", "5", "5y", "", "s", "99999999999999999999w"] {
            assert!(
                matches!(parse_expires(bad), Err(PvfsError::BadInput { .. })),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn expiry_suffix_marks_never_expired_and_coarse_remaining() {
        assert_eq!(expiry_suffix(0), "");
        assert_eq!(expiry_suffix(1), " [expired]");
        let s = expiry_suffix(now_ms() + 2 * 86_400_000 + 60_000);
        assert!(s.contains("expires in ~2d"), "{s}");
        let s = expiry_suffix(now_ms() + 30 * 60_000 + 1_000);
        assert!(s.contains("expires in ~30m"), "{s}");
    }
}
