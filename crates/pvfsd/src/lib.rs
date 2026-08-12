//! PVFS per-user daemon (doc 07): serves one forest over a Unix socket with
//! challenge-response auth (§2) and per-node ACL enforcement (§4).
//!
//! Control plane (metadata), split per doc 07 §6: mutations serialize behind
//! the single writer Mutex; **reads run concurrently** over a pool of
//! read-only WAL views (`Engine::open_read_view`), checked out round-robin.
//! Data plane (bytes): engine lock released before streaming raw bytes so
//! concurrent cat transfers don't block each other.

pub mod jobs;
pub mod nettls;

use std::collections::HashMap;
use std::io;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pvfs_core::acl::{self, Principal};
use pvfs_core::{
    crypto, Engine, FilePayload, NodeId, NodeSpec, PreparedEvent, PvfsError, TYPE_FILE, TYPE_FOLDER,
};
use pvfs_proto::{
    auth_digest, read_data_frame, read_msg, write_data_frame, write_msg, ChildInfo, ClientMsg,
    NodeInfo, ServerMsg, WriteOp, DATA_CHUNK, PROTO_VERSION,
};
use rand::RngCore;

/// How long a challenge stays valid.
const CHALLENGE_TTL_MS: u64 = 30_000;
/// How long a prepared (phase-1) write awaits its signatures.
const PREPARE_TTL_MS: u64 = 30_000;
/// Max decoded size of an `AddNode` inline payload — these live in the event
/// log, so they must stay small (records, not files).
const PAYLOAD_CAP: usize = 64 * 1024;

/// A phase-1 write held server-side until the member sends signatures.
struct PreparedState {
    author_pub: Vec<u8>,
    events: Vec<PreparedEvent>,
    result_id: String,
    expiry_ms: u64,
}

/// How many read-only views back the metadata read pool (doc 07 §6). Small on
/// purpose — personal/small-team scale; each view is one SQLite connection.
const READ_POOL: usize = 4;

/// One forest served by the daemon: the writer engine, a pool of read-only
/// views, its forest id (challenge binding), and in-flight prepared writes.
pub struct Daemon {
    engine: Mutex<Engine>,
    /// Read-only WAL views for concurrent metadata reads. May be empty (view
    /// open failed) — then reads fall back to the writer lock, the pre-pool
    /// behavior.
    readers: Vec<Mutex<Engine>>,
    next_reader: AtomicUsize,
    forest_id: String,
    prepared: Mutex<HashMap<String, PreparedState>>,
    /// Outstanding challenge nonces (hex → expiry). A nonce is issued once per
    /// connection and **consumed on first use** (doc 08 §4 item 7): a captured
    /// auth signature can never be replayed, even against a network listener.
    nonces: Mutex<HashMap<String, u64>>,
    /// The P5 job runner's state, when the binary attached one (doc 18 §2).
    /// Absent in embedded/test daemons — `ServeStatus` then reports `"off"`.
    jobs: std::sync::OnceLock<Arc<jobs::JobsState>>,
}

impl Daemon {
    pub fn new(engine: Engine) -> Daemon {
        let forest_id = engine.identity.forest_id.clone();
        // Best-effort pool: stop at the first view that fails to open rather
        // than failing the daemon — correctness never depends on the pool.
        let readers: Vec<Mutex<Engine>> = (0..READ_POOL)
            .map_while(|_| Engine::open_read_view(engine.data_dir()).ok())
            .map(Mutex::new)
            .collect();
        Daemon {
            engine: Mutex::new(engine),
            readers,
            next_reader: AtomicUsize::new(0),
            forest_id,
            prepared: Mutex::new(HashMap::new()),
            nonces: Mutex::new(HashMap::new()),
            jobs: std::sync::OnceLock::new(),
        }
    }

    /// Attach the job runner's state so `ServeStatus` answers live (set once,
    /// by the binary, before serving).
    pub fn attach_jobs(&self, jobs: Arc<jobs::JobsState>) {
        let _ = self.jobs.set(jobs);
    }

    /// Issue a fresh challenge nonce, registered for single use.
    fn issue_nonce(&self) -> ([u8; 16], u64) {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let expiry_ms = now_ms() + CHALLENGE_TTL_MS;
        let mut map = self.nonces.lock().unwrap();
        // Opportunistic purge so abandoned handshakes don't accumulate.
        if map.len() >= 64 {
            let now = now_ms();
            map.retain(|_, exp| *exp > now);
        }
        map.insert(hex::encode(nonce), expiry_ms);
        (nonce, expiry_ms)
    }

    /// Consume a nonce: true exactly once per issued, unexpired nonce.
    fn consume_nonce(&self, nonce: &[u8]) -> bool {
        match self.nonces.lock().unwrap().remove(&hex::encode(nonce)) {
            Some(expiry_ms) => now_ms() <= expiry_ms,
            None => false,
        }
    }

    /// P7.2b heads tick (doc 20 §2.4): attest dirty region heads through the
    /// daemon's OWN writer engine. A transient second engine would run a full
    /// projection rebuild under a live daemon (`clean_shutdown` is 0 while it
    /// runs) and starve concurrent commits on a slow box — found by the
    /// pvos-test pipeline.
    pub fn commit_region_heads(&self) -> pvfs_core::Result<usize> {
        self.engine.lock().unwrap().commit_region_heads()
    }

    /// Check out an engine for a **read**: round-robin over the read pool, so
    /// up to `READ_POOL` metadata reads run concurrently (plus writes on the
    /// writer). Falls back to the writer lock when the pool is empty.
    fn reader(&self) -> MutexGuard<'_, Engine> {
        if self.readers.is_empty() {
            return self.engine.lock().unwrap();
        }
        let i = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        self.readers[i].lock().unwrap()
    }

    /// Flush the WAL and record a clean shutdown (doc 08 §4 item 4). Called by the
    /// daemon binary after the accept loop stops on SIGTERM/SIGINT, while in-flight
    /// connection threads are best-effort allowed to finish.
    pub fn shutdown_checkpoint(&self) -> Result<(), PvfsError> {
        self.engine.lock().unwrap().shutdown_checkpoint()
    }
}

/// How often the accept loop wakes to check the shutdown flag.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// Accept connections until the listener closes — one thread per connection.
/// Runs until the process is torn down; for a stoppable loop use [`serve_until`].
pub fn serve(listener: UnixListener, daemon: Arc<Daemon>) -> io::Result<()> {
    // A flag that is never set: the loop runs until the process exits.
    serve_until(listener, daemon, &AtomicBool::new(false))
}

/// Accept connections until `shutdown` flips true, then return so the caller can
/// checkpoint and clean up (doc 08 §4 item 4). The listener is polled non-blocking
/// every [`ACCEPT_POLL`] so a signal-driven flag is noticed promptly without a busy
/// loop; accepted streams are handed to per-connection threads in blocking mode.
pub fn serve_until(
    listener: UnixListener,
    daemon: Arc<Daemon>,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Per-connection I/O is blocking; only the accept loop polls.
                stream.set_nonblocking(false)?;
                let d = Arc::clone(&daemon);
                std::thread::spawn(move || {
                    let _ = serve_connection(&d, stream);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// F1 (doc 17 §4): accept TCP connections and serve the same protocol over
/// TLS until `shutdown` flips. Same poll loop as [`serve_until`]; each
/// connection handshakes lazily inside its own thread (`StreamOwned` drives
/// TLS on first read/write), so a stalled handshake never blocks the accept
/// loop. Clients verify the cert by pin ([`nettls`]); the daemon still
/// authenticates *principals* per connection with the challenge-response —
/// TLS is transport privacy + server identity, never authorization.
pub fn serve_tls_until(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    daemon: Arc<Daemon>,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    listener.set_nonblocking(true)?;
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                stream.set_nonblocking(false)?;
                let d = Arc::clone(&daemon);
                let cfg = Arc::clone(&tls);
                std::thread::spawn(move || {
                    let conn = match rustls::ServerConnection::new(cfg) {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    let tls_stream = rustls::StreamOwned::new(conn, stream);
                    let _ = serve_connection(&d, tls_stream);
                });
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Handshake then request loop for one connection. Generic over the stream —
/// a Unix socket and a TLS-wrapped TCP stream serve identically (F1).
pub fn serve_connection<S: io::Read + io::Write>(daemon: &Daemon, mut stream: S) -> io::Result<()> {
    // 1. challenge (nonce registered single-use, doc 08 §4 item 7)
    let (nonce, expiry_ms) = daemon.issue_nonce();
    write_msg(
        &mut stream,
        &ServerMsg::Challenge {
            nonce: hex::encode(nonce),
            forest_id: daemon.forest_id.clone(),
            expiry_ms,
            version: PROTO_VERSION,
        },
    )?;

    // 2. resolve the principal from the client's response
    let principal = match read_msg::<_, ClientMsg>(&mut stream)? {
        None => {
            daemon.consume_nonce(&nonce); // client hung up — retire the nonce
            return Ok(());
        }
        Some(ClientMsg::Anonymous) => {
            daemon.consume_nonce(&nonce);
            Principal::Public
        }
        Some(ClientMsg::Auth { pubkey, sig }) => {
            if !daemon.consume_nonce(&nonce) {
                write_msg(&mut stream, &err("forbidden", "challenge already used or expired"))?;
                return Ok(());
            }
            match resolve_auth(&nonce, &daemon.forest_id, expiry_ms, &pubkey, &sig) {
                Ok(p) => p,
                Err(msg) => {
                    write_msg(&mut stream, &msg)?;
                    return Ok(());
                }
            }
        }
        Some(_) => {
            daemon.consume_nonce(&nonce);
            write_msg(&mut stream, &err("bad_input", "expected auth or anonymous"))?;
            return Ok(());
        }
    };
    write_msg(
        &mut stream,
        &ServerMsg::Ready {
            principal: principal.display(),
        },
    )?;

    // 3. request loop
    while let Some(req) = read_msg::<_, ClientMsg>(&mut stream)? {
        // Cat uses the data plane: it writes multiple frames to the stream
        // directly rather than returning a single ServerMsg.
        match req {
            ClientMsg::Cat { node } => {
                do_cat(daemon, &principal, &mut stream, &node)?;
                continue;
            }
            ClientMsg::SecureCat { node } => {
                do_secure_cat(daemon, &principal, &mut stream, &node)?;
                continue;
            }
            ClientMsg::SecurePut { node } => {
                do_secure_put(daemon, &principal, &mut stream, &node)?;
                continue;
            }
            req => {
                let resp = handle(daemon, &principal, req);
                write_msg(&mut stream, &resp)?;
            }
        }
    }
    Ok(())
}

/// Verify a client's signature over the challenge → the proven key is the principal.
fn resolve_auth(
    nonce: &[u8],
    forest_id: &str,
    expiry_ms: u64,
    pubkey: &str,
    sig: &str,
) -> Result<Principal, ServerMsg> {
    if now_ms() > expiry_ms {
        return Err(err("bad_input", "challenge expired"));
    }
    let pk = hex::decode(pubkey).map_err(|_| err("bad_input", "pubkey not hex"))?;
    let sigb = hex::decode(sig).map_err(|_| err("bad_input", "sig not hex"))?;
    let digest = auth_digest(nonce, forest_id, expiry_ms);
    crypto::verify_digest(&pk, &digest, &sigb).map_err(|_| err("forbidden", "bad signature"))?;
    Ok(Principal::Key(pk))
}

fn handle(daemon: &Daemon, principal: &Principal, req: ClientMsg) -> ServerMsg {
    match req {
        ClientMsg::Info => {
            let e = daemon.reader();
            ServerMsg::Info {
                instance_id: e.identity.instance_id.clone(),
                forest_id: e.identity.forest_id.clone(),
                root: e.identity.root_node_id.clone(),
            }
        }
        // Punch F (Chris, 2026-08-11): member-gated — job states and error
        // strings are operational detail, not public metadata.
        ClientMsg::ServeStatus => {
            let member = match principal {
                Principal::Key(pk) => daemon.reader().is_active_member(pk).unwrap_or(false),
                _ => false,
            };
            if !member {
                err("forbidden", "serve status is member-gated (enroll this box)")
            } else {
                match daemon.jobs.get() {
                    Some(j) => ServerMsg::ServeJobs {
                        runner: "on".into(),
                        jobs: j.snapshot(),
                    },
                    None => ServerMsg::ServeJobs {
                        runner: "off".into(),
                        jobs: Vec::new(),
                    },
                }
            }
        }
        ClientMsg::Ls { node } => match do_ls(daemon, principal, &node) {
            Ok(children) => ServerMsg::Ls { children },
            Err(msg) => msg,
        },
        ClientMsg::Stat { node } => match do_stat(daemon, principal, &node) {
            Ok(node) => ServerMsg::Stat { node },
            Err(msg) => msg,
        },
        ClientMsg::Payload { node } => do_payload(daemon, principal, &node),
        ClientMsg::LogInfo { region } => match check_replication_gate(daemon, principal, &region) {
            Ok(scope) => {
                let e = daemon.reader();
                let tip = match &scope {
                    None => e.log_tip(),
                    // an active generation's file appears at its first write —
                    // absent reads as tip 0, not an error
                    Some((_, rel_file)) => match e.region_log_events(rel_file, 1, 1) {
                        Ok((t, _)) => Ok(t),
                        Err(pvfs_core::PvfsError::NotFound { .. }) => Ok(0),
                        Err(pve) => Err(pve),
                    },
                };
                match tip {
                    Ok(tip_seq) => ServerMsg::LogInfo { tip_seq },
                    Err(pve) => err_from(pve),
                }
            }
            Err(msg) => msg,
        },
        ClientMsg::LogRead {
            from_seq,
            max,
            region,
        } => do_log_read(daemon, principal, from_seq, max, &region),
        ClientMsg::LogWait {
            from_seq,
            max,
            timeout_ms,
            region,
        } => do_log_wait(daemon, principal, from_seq, max, timeout_ms, &region),
        ClientMsg::PrepareWrite { op } => do_prepare_write(daemon, principal, op),
        ClientMsg::Commit { prepared_id, sigs } => do_commit(daemon, principal, &prepared_id, sigs),
        // Cat / SecureCat / SecurePut are handled in serve_connection (data plane).
        ClientMsg::Cat { .. }
        | ClientMsg::SecureCat { .. }
        | ClientMsg::SecurePut { .. }
        | ClientMsg::Auth { .. }
        | ClientMsg::Anonymous => err("bad_input", "unexpected message in request loop"),
    }
}

/// Most rows one `LogRead` batch returns; the server also stops a batch when
/// the accumulated bodies pass ~4 MiB, so a frame never nears `MAX_FRAME`.
const LOG_BATCH_ROWS: usize = 512;
const LOG_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Log shipping is an owner/admin capability (doc 17 §5): the full log holds
/// the whole forest's history, so the caller must hold **admin rights on the
/// forest root**. P7.2b (doc 20 §2.4): a region-scoped request is gated on
/// admin rights on **that region's root** instead — a region maps to an
/// authority, so its holder replicates it without whole-forest rights.
/// Returns the parsed scope: `None` = top log, `Some((root, rel_file))` = one
/// region generation.
fn check_replication_gate(
    daemon: &Daemon,
    principal: &Principal,
    region: &str,
) -> Result<Option<(String, String)>, ServerMsg> {
    let e = daemon.reader();
    let (gate_node, scope) = if region.is_empty() {
        (e.identity.root_node_id.clone(), None)
    } else {
        match pvfs_core::replica::parse_region_addr(region) {
            Some((root, rel_file)) => (root.clone(), Some((root, rel_file))),
            None => return Err(err("bad_input", "malformed region generation address")),
        }
    };
    match e.effective_rights(principal, &gate_node) {
        Ok(r) if r & acl::ACL_A != 0 => Ok(scope),
        Ok(_) => Err(err(
            "forbidden",
            if region.is_empty() {
                "log replication requires admin rights on the forest root"
            } else {
                "region log replication requires admin rights on the region root"
            },
        )),
        Err(pve) => Err(err_from(pve)),
    }
}

/// Ship raw log rows (F2). The replica re-verifies everything, so this is a
/// plain gated read of the events table.
fn do_log_read(
    daemon: &Daemon,
    principal: &Principal,
    from_seq: u64,
    max: u32,
    region: &str,
) -> ServerMsg {
    match check_replication_gate(daemon, principal, region) {
        Err(msg) => msg,
        Ok(scope) => log_rows_msg(daemon, from_seq, max, scope.as_ref()),
    }
}

/// The longest a `LogWait` may block (the client re-polls after an empty
/// reply, so a short cap costs nothing but a round trip).
const LOG_WAIT_CAP_MS: u64 = 60_000;
/// How often a blocked `LogWait` re-checks the tip. Never holds an engine
/// lock while sleeping.
const LOG_WAIT_POLL: Duration = Duration::from_millis(200);

/// Long-poll log shipping (F5.4, doc 17 §7.5): block — on this connection's
/// own thread, engine locks taken only for the instantaneous tip check —
/// until the log reaches `from_seq` or the timeout lapses, then answer like
/// `LogRead` (empty events = nothing yet, poll again).
fn do_log_wait(
    daemon: &Daemon,
    principal: &Principal,
    from_seq: u64,
    max: u32,
    timeout_ms: u64,
    region: &str,
) -> ServerMsg {
    let scope = match check_replication_gate(daemon, principal, region) {
        Err(msg) => return msg,
        Ok(s) => s,
    };
    let deadline = now_ms() + timeout_ms.min(LOG_WAIT_CAP_MS);
    // P7.2b: a top-scoped wait also wakes when ANY log advances (the
    // applied-marks activity signal) — the empty reply tells the follower to
    // sweep its region generations (doc 20 §2.4), keeping region freshness in
    // seconds without per-region long-polls.
    let activity0 = daemon.reader().log_activity().unwrap_or(0);
    loop {
        let (tip, activity) = {
            let e = daemon.reader();
            let tip = match &scope {
                None => match e.log_tip() {
                    Ok(t) => t,
                    Err(pve) => return err_from(pve),
                },
                Some((_, rel_file)) => match e.region_log_events(rel_file, 1, 1) {
                    Ok((t, _)) => t,
                    // active-but-unwritten generation: wait for its first write
                    Err(pvfs_core::PvfsError::NotFound { .. }) => 0,
                    Err(pve) => return err_from(pve),
                },
            };
            (tip, e.log_activity().unwrap_or(activity0))
        }; // lock released before any sleep
        if tip >= from_seq {
            return log_rows_msg(daemon, from_seq, max, scope.as_ref());
        }
        if scope.is_none() && activity != activity0 {
            return ServerMsg::LogEvents {
                tip_seq: tip,
                events: Vec::new(),
            };
        }
        if now_ms() >= deadline {
            return ServerMsg::LogEvents {
                tip_seq: tip,
                events: Vec::new(),
            };
        }
        std::thread::sleep(LOG_WAIT_POLL);
    }
}

/// Read + convert one batch of rows (shared by `LogRead` / `LogWait`; the
/// caller has already passed the replication gate). `scope` = `None` for the
/// top log, else the region generation to serve.
fn log_rows_msg(
    daemon: &Daemon,
    from_seq: u64,
    max: u32,
    scope: Option<&(String, String)>,
) -> ServerMsg {
    let e = daemon.reader();
    let cap = (max as usize).clamp(1, LOG_BATCH_ROWS);
    let (tip_seq, rows) = match scope {
        None => {
            let rows = match e.log_events(from_seq, cap) {
                Ok(r) => r,
                Err(pve) => return err_from(pve),
            };
            let tip = match e.log_tip() {
                Ok(t) => t,
                Err(pve) => return err_from(pve),
            };
            (tip, rows)
        }
        Some((_, rel_file)) => match e.region_log_events(rel_file, from_seq, cap) {
            Ok(v) => v,
            Err(pvfs_core::PvfsError::NotFound { .. }) => {
                return err("region_not_held", "this instance does not hold that region log")
            }
            Err(pve) => return err_from(pve),
        },
    };
    let mut events = Vec::with_capacity(rows.len());
    let mut bytes = 0usize;
    for row in rows {
        bytes += row.body.len();
        events.push(pvfs_proto::LogEventWire {
            seq: row.seq,
            kind: row.kind,
            body: hex::encode(row.body),
            chain_hash: hex::encode(row.chain_hash),
            written_at: row.written_at,
        });
        if bytes > LOG_BATCH_BYTES {
            break; // client continues from the next seq
        }
    }
    ServerMsg::LogEvents { tip_seq, events }
}

/// A node's inline payload (control plane; read-ACL-gated like `stat`).
fn do_payload(daemon: &Daemon, principal: &Principal, node: &str) -> ServerMsg {
    let e = daemon.reader();
    match e.effective_rights(principal, &node.to_string()) {
        Ok(r) if r & acl::ACL_R != 0 => {}
        Ok(_) => return forbidden(),
        Err(pve) => return err_from(pve),
    }
    match e.node(&node.to_string()) {
        Ok(Some(n)) => ServerMsg::Payload {
            payload: hex::encode(n.payload),
        },
        Ok(None) => err("not_found", "no such node"),
        Err(pve) => err_from(pve),
    }
}

/// Stream a file's bytes to the client (data plane, doc 07 §6).
///
/// 1. Hold the engine lock only for ACL check + path resolution (fast metadata ops).
/// 2. Release the lock — the data transfer never touches the engine.
/// 3. Stream raw binary data frames: CatStart → data frames → CatDone.
///
/// Concurrent cat transfers on separate connections therefore run truly in parallel
/// (each on its own thread, engine lock free for the whole streaming phase).
fn do_cat<S: io::Read + io::Write>(
    daemon: &Daemon,
    principal: &Principal,
    stream: &mut S,
    node: &str,
) -> io::Result<()> {
    let id: NodeId = node.to_string();

    // --- control plane: ACL check + path resolution (read view, doc 07 §6) ---
    let path = {
        let e = daemon.reader();
        // ACL: caller needs read access.
        match e.effective_rights(principal, &id) {
            Ok(r) if r & acl::ACL_R != 0 => {}
            Ok(_) => {
                write_msg(stream, &err("forbidden", "access denied"))?;
                return Ok(());
            }
            Err(pve) => {
                write_msg(stream, &err_from(pve))?;
                return Ok(());
            }
        }
        // Resolve the first readable local path (no lock held during I/O).
        match e.readable_path(&id) {
            Ok(Some(p)) => p,
            Ok(None) => {
                write_msg(stream, &err("not_found", "no readable location for file"))?;
                return Ok(());
            }
            Err(pve) => {
                write_msg(stream, &err_from(pve))?;
                return Ok(());
            }
        }
    }; // engine lock released here

    // --- data plane: stream raw bytes, engine lock free ---
    let size = match std::fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(e) => {
            write_msg(stream, &err("internal", &format!("stat failed: {e}")))?;
            return Ok(());
        }
    };
    write_msg(stream, &ServerMsg::CatStart { size })?;

    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            // CatStart already sent — write a zero-length frame to signal abort.
            write_data_frame(stream, &[])?;
            return Err(e);
        }
    };

    let mut buf = vec![0u8; DATA_CHUNK];
    let mut written: u64 = 0;
    loop {
        use std::io::Read as _;
        let got = file.read(&mut buf).map_err(|e| {
            io::Error::new(e.kind(), format!("cat read: {e}"))
        })?;
        if got == 0 {
            break;
        }
        write_data_frame(stream, &buf[..got])?;
        written += got as u64;
    }
    write_msg(stream, &ServerMsg::CatDone { written })?;
    Ok(())
}

/// The most ciphertext the daemon will accept for one secure blob (v1 cap).
const SECURE_BLOB_CAP: usize = 256 * 1024 * 1024;

/// Stream a secure blob's ciphertext (doc 12 §8), **verified against the signed
/// ledger** before a byte leaves. Like `do_cat` but the daemon never decrypts —
/// it serves the opaque bytes. Verify happens under the lock (`secure_read`), so
/// a tampered or half-written blob is refused, not served.
fn do_secure_cat<S: io::Read + io::Write>(
    daemon: &Daemon,
    principal: &Principal,
    stream: &mut S,
    node: &str,
) -> io::Result<()> {
    let id: NodeId = node.to_string();
    let bytes = {
        let e = daemon.reader();
        match e.effective_rights(principal, &id) {
            Ok(r) if r & acl::ACL_R != 0 => {}
            Ok(_) => {
                write_msg(stream, &err("forbidden", "access denied"))?;
                return Ok(());
            }
            Err(pve) => {
                write_msg(stream, &err_from(pve))?;
                return Ok(());
            }
        }
        match e.secure_read(&id) {
            Ok(b) => b,
            Err(pve) => {
                write_msg(stream, &err_from(pve))?;
                return Ok(());
            }
        }
    }; // lock released before streaming

    write_msg(stream, &ServerMsg::CatStart { size: bytes.len() as u64 })?;
    for chunk in bytes.chunks(DATA_CHUNK) {
        write_data_frame(stream, chunk)?;
    }
    write_msg(stream, &ServerMsg::CatDone { written: bytes.len() as u64 })?;
    Ok(())
}

/// Receive a secure blob's new ciphertext (data frames, zero-length terminator),
/// write it in place, and prepare the member-signed `SecureBlobUpdated` (doc 12
/// §8.5 daemon path). The client then `Commit`s the returned prepared write. The
/// daemon handles only ciphertext — it has no key and never decrypts.
fn do_secure_put<S: io::Read + io::Write>(
    daemon: &Daemon,
    principal: &Principal,
    stream: &mut S,
    node: &str,
) -> io::Result<()> {
    let author = match principal {
        Principal::Key(pk) => pk.clone(),
        _ => {
            write_msg(stream, &err("forbidden", "writes require an authenticated identity"))?;
            return Ok(());
        }
    };
    // Read the uploaded ciphertext (frames until a zero-length frame).
    let mut ciphertext = Vec::new();
    loop {
        match read_data_frame(stream)? {
            Some(chunk) if chunk.is_empty() => break,
            Some(chunk) => {
                if ciphertext.len() + chunk.len() > SECURE_BLOB_CAP {
                    write_msg(stream, &err("bad_input", "secure blob exceeds the size cap"))?;
                    return Ok(());
                }
                ciphertext.extend_from_slice(&chunk);
            }
            None => return Ok(()), // client hung up mid-upload
        }
    }
    let id: NodeId = node.to_string();
    let hash: [u8; 32] = blake3::hash(&ciphertext).into();

    // Under the lock: validate (author holds w + node is secure), allocate the
    // managed location on first write, and resolve the path. Prepare BEFORE any
    // bytes move, so an unauthorized write is rejected without touching storage.
    let (prepared, path) = {
        let e = daemon.engine.lock().unwrap();
        match e.prepare_secure_write(&author, &id, &hash, ciphertext.len() as u64) {
            Ok(pw) => pw,
            Err(pve) => {
                write_msg(stream, &err_from(pve))?;
                return Ok(());
            }
        }
    }; // lock released before the write

    if let Err(pve) = pvfs_core::storage::atomic_overwrite(&path, &ciphertext) {
        write_msg(stream, &err_from(pve))?;
        return Ok(());
    }

    // Stash the prepared ledger event; the client signs + Commits as usual.
    let preimages = prepared.events.iter().map(|pe| hex::encode(pe.digest)).collect();
    let result_id = prepared.result_id.clone();
    let prepared_id = random_id();
    daemon.prepared.lock().unwrap().insert(
        prepared_id.clone(),
        PreparedState {
            author_pub: author,
            events: prepared.events,
            result_id: result_id.clone(),
            expiry_ms: now_ms() + PREPARE_TTL_MS,
        },
    );
    write_msg(
        stream,
        &ServerMsg::Prepared {
            prepared_id,
            preimages,
            result_id,
        },
    )?;
    Ok(())
}

/// Phase 1: build the signable events for `op` and stash them under a fresh id.
fn do_prepare_write(daemon: &Daemon, principal: &Principal, op: WriteOp) -> ServerMsg {
    let author = match principal {
        Principal::Key(pk) => pk.clone(),
        _ => return err("forbidden", "writes require an authenticated identity"),
    };
    let prepared = {
        let e = daemon.engine.lock().unwrap();
        match op {
            WriteOp::Mkdir { parent, label } => e.prepare_add_node(
                &author,
                &parent,
                NodeSpec {
                    node_type: TYPE_FOLDER.into(),
                    label,
                    payload: Vec::new(),
                    is_temp: false,
                    creation_nonce: None,
                },
            ),
            WriteOp::SecureCreate { parent, label } => e.prepare_add_node(
                &author,
                &parent,
                NodeSpec {
                    node_type: pvfs_core::TYPE_SECURE.into(),
                    label,
                    payload: Vec::new(),
                    is_temp: false,
                    creation_nonce: None,
                },
            ),
            WriteOp::AddFile {
                parent,
                label,
                size,
                mime,
            } => {
                let payload = FilePayload {
                    content_hash: String::new(),
                    size_bytes: size,
                    mime_type: mime,
                    original_name: label.clone(),
                }
                .encode();
                e.prepare_add_node(
                    &author,
                    &parent,
                    NodeSpec {
                        node_type: TYPE_FILE.into(),
                        label,
                        payload,
                        is_temp: false,
                        creation_nonce: None,
                    },
                )
            }
            WriteOp::AddNode {
                parent,
                label,
                node_type,
                payload,
            } => {
                if node_type.is_empty()
                    || node_type == pvfs_core::TYPE_SECURE
                    || node_type == TYPE_FILE
                    || node_type == TYPE_FOLDER
                {
                    Err(PvfsError::BadInput {
                        field: "node_type".into(),
                        reason: "must be a custom type (file/folder/secure have their own ops)"
                            .into(),
                    })
                } else {
                    match hex::decode(&payload) {
                        Ok(p) if p.len() <= PAYLOAD_CAP => e.prepare_add_node(
                            &author,
                            &parent,
                            NodeSpec {
                                node_type,
                                label,
                                payload: p,
                                is_temp: false,
                                creation_nonce: None,
                            },
                        ),
                        Ok(_) => Err(PvfsError::BadInput {
                            field: "payload".into(),
                            reason: format!("exceeds {PAYLOAD_CAP} bytes (use AddFile/Secure)"),
                        }),
                        Err(_) => Err(bad_hex("payload")),
                    }
                }
            }
            WriteOp::Rm { node } => e.prepare_remove_node(&author, &node),
            WriteOp::AddLocation { file, uri } => e.prepare_add_location(&author, &file, &uri),
            WriteOp::RemoveLocation { file, uri } => {
                e.prepare_remove_location(&author, &file, &uri)
            }
            WriteOp::Link {
                parent,
                child,
                link_type,
                order_key,
            } => {
                let key = if order_key.is_empty() {
                    None
                } else {
                    Some(order_key.as_str())
                };
                e.prepare_link(&author, &parent, &child, &link_type, key)
            }
            WriteOp::Unlink { link_id } => e.prepare_remove_link(&author, &link_id),
            WriteOp::Reorder { link_id, key } => e.prepare_reorder_link(&author, &link_id, &key),
            WriteOp::Mv { node, new_parent } => e.prepare_move_node(&author, &node, &new_parent),
            WriteOp::SetAcl {
                node,
                principal,
                rights,
                expires_at,
            } => match (Principal::parse(&principal), acl::parse_rights(&rights)) {
                (Ok(p), Ok(r)) => e.prepare_set_acl_expiring(&author, &node, &p, r, expires_at),
                (Err(err), _) | (_, Err(err)) => Err(err),
            },
            WriteOp::TagMember {
                member,
                tag,
                granted,
            } => match hex::decode(&member) {
                Ok(pk) => e.prepare_set_member_tag(&author, &pk, &tag, granted),
                Err(_) => Err(bad_hex("member")),
            },
            WriteOp::AuthorizeMember { pubkey } => match hex::decode(&pubkey) {
                Ok(pk) => e.prepare_authorize_member(&author, &pk),
                Err(_) => Err(bad_hex("pubkey")),
            },
            WriteOp::Revoke { pubkey } => match hex::decode(&pubkey) {
                Ok(pk) => e.prepare_revoke(&author, &pk),
                Err(_) => Err(bad_hex("pubkey")),
            },
        }
    };
    let prepared = match prepared {
        Ok(p) => p,
        Err(e) => return err_from(e),
    };
    let preimages = prepared.events.iter().map(|pe| hex::encode(pe.digest)).collect();
    let result_id = prepared.result_id.clone();
    let prepared_id = random_id();
    daemon.prepared.lock().unwrap().insert(
        prepared_id.clone(),
        PreparedState {
            author_pub: author,
            events: prepared.events,
            result_id: result_id.clone(),
            expiry_ms: now_ms() + PREPARE_TTL_MS,
        },
    );
    ServerMsg::Prepared {
        prepared_id,
        preimages,
        result_id,
    }
}

/// Phase 2: attach the member's signatures to the stashed events and append.
fn do_commit(daemon: &Daemon, principal: &Principal, prepared_id: &str, sigs: Vec<String>) -> ServerMsg {
    let author = match principal {
        Principal::Key(pk) => pk,
        _ => return err("forbidden", "writes require an authenticated identity"),
    };
    let state = match daemon.prepared.lock().unwrap().remove(prepared_id) {
        Some(s) => s,
        None => return err("not_found", "no such prepared write (expired?)"),
    };
    if now_ms() > state.expiry_ms {
        return err("bad_input", "prepared write expired");
    }
    if &state.author_pub != author {
        return err("forbidden", "prepared write belongs to another principal");
    }
    if sigs.len() != state.events.len() {
        return err("bad_input", "wrong number of signatures");
    }
    let mut events = Vec::with_capacity(state.events.len());
    for (pe, sig_hex) in state.events.into_iter().zip(sigs) {
        let sig = match hex::decode(&sig_hex) {
            Ok(s) => s,
            Err(_) => return err("bad_input", "signature not hex"),
        };
        let mut ev = pe.event;
        ev.set_author_sig(sig);
        events.push(ev);
    }
    let mut e = daemon.engine.lock().unwrap();
    match e.commit_member_write(events) {
        Ok(()) => {
            // Punch H: a committed write is new content on the owner — wake
            // the mover instead of waiting out its interval.
            if let Some(j) = daemon.jobs.get() {
                j.nudge_tier();
            }
            ServerMsg::Committed { id: state.result_id }
        }
        Err(e) => err_from(e),
    }
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn do_ls(daemon: &Daemon, principal: &Principal, node: &str) -> Result<Vec<ChildInfo>, ServerMsg> {
    let e = daemon.reader();
    let id: NodeId = node.to_string();
    if !e.can(principal, &id, acl::ACL_R).map_err(err_from)? {
        return Err(forbidden());
    }
    let kids = e.readable_children(principal, &id).map_err(err_from)?;
    Ok(kids
        .into_iter()
        .map(|c| ChildInfo {
            id: c.node.id,
            label: c.node.label,
            node_type: c.node.node_type,
        })
        .collect())
}

fn do_stat(daemon: &Daemon, principal: &Principal, node: &str) -> Result<NodeInfo, ServerMsg> {
    let e = daemon.reader();
    let id: NodeId = node.to_string();
    let rights = e.effective_rights(principal, &id).map_err(err_from)?;
    if rights & acl::ACL_R == 0 {
        return Err(forbidden());
    }
    let n = e
        .node(&id)
        .map_err(err_from)?
        .ok_or_else(|| err("not_found", "no such node"))?;
    let parent = e.parent_of(&id).map_err(err_from)?;
    Ok(NodeInfo {
        id: n.id,
        label: n.label,
        node_type: n.node_type,
        rights: acl::rights_to_str(rights),
        parent,
    })
}

fn err(code: &str, message: &str) -> ServerMsg {
    ServerMsg::Error {
        code: code.into(),
        message: message.into(),
    }
}

fn bad_hex(field: &str) -> PvfsError {
    PvfsError::BadInput {
        field: field.into(),
        reason: "must be hex".into(),
    }
}

fn forbidden() -> ServerMsg {
    err("forbidden", "access denied")
}

fn err_from(e: PvfsError) -> ServerMsg {
    let code = match &e {
        PvfsError::NotFound { .. } => "not_found",
        PvfsError::BadInput { .. } => "bad_input",
        PvfsError::Forbidden { .. } => "forbidden",
        PvfsError::Integrity { .. } => "integrity",
        PvfsError::AlreadyExists { .. } => "already_exists",
        _ => "internal",
    };
    err(code, &e.to_string())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // doc 08 §4 item 7 — a challenge nonce authorizes exactly one auth attempt
    #[test]
    fn nonce_is_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let (engine, _mn) = Engine::init(dir.path()).unwrap();
        let daemon = Daemon::new(engine);
        let (nonce, _expiry) = daemon.issue_nonce();
        assert!(daemon.consume_nonce(&nonce), "first use passes");
        assert!(!daemon.consume_nonce(&nonce), "replay is refused");
        assert!(!daemon.consume_nonce(&[0u8; 16]), "unissued nonce is refused");
    }
}
