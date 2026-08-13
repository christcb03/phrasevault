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
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pvfs_core::acl::{self, Principal};
use pvfs_core::ingest::{self, IngestClose, IngestSessionRec};
use pvfs_core::{
    crypto, Engine, FilePayload, NodeId, NodeSpec, PreparedEvent, PvfsError, TYPE_FILE, TYPE_FOLDER,
};
use pvfs_proto::{
    auth_digest, read_data_frame, read_msg, write_data_frame, write_msg, ChildInfo, ClientMsg,
    IngestFileSpecWire, IngestFileWire, IngestSessionWire, NodeInfo, ServerMsg, WriteOp,
    DATA_CHUNK, PROTO_VERSION,
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
    /// P10.0 (doc 23 §9.4): deployment-state work the daemon performs after
    /// this prepared write commits — sessions activate, partials publish,
    /// aborts clean up. `None` for every non-ingest write.
    followup: Option<IngestFollowup>,
}

/// What lands when an ingest-flavored prepared write commits (doc 23 §9.4).
enum IngestFollowup {
    /// `IngestBegin` committed — the session goes live.
    Activate(Box<IngestSessionRec>),
    /// `IngestCommit` committed — publish the partial into the store and
    /// mark the file done (the successor id re-identifies it).
    Publish {
        session: String,
        old: String,
        new: String,
        manifest: Vec<[u8; 32]>,
    },
    /// `IngestAbort` committed — partials and progress removed, session gone.
    Abort { session: String },
}

/// In-memory mirror of `ingest.sessions` plus commit freezes. Lock order:
/// **never take the engine lock while holding this one** (handlers resolve
/// under this lock, drop it, then touch the engine).
struct IngestState {
    sessions: Vec<IngestSessionRec>,
    /// file node id → freeze expiry: a prepared `IngestCommit` froze writes
    /// so the hash it computed stays true; expiry mirrors `PREPARE_TTL_MS`
    /// so an abandoned prepare unfreezes by itself.
    committing: HashMap<String, u64>,
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
    /// P10.0: the forest's data dir, for ingest partial/sidecar paths
    /// without taking an engine lock.
    data_dir: PathBuf,
    /// P10.0: live ingest sessions (mirror of `ingest.sessions`).
    ingest: Mutex<IngestState>,
}

impl Daemon {
    pub fn new(engine: Engine) -> Daemon {
        let forest_id = engine.identity.forest_id.clone();
        let data_dir = engine.data_dir().to_path_buf();
        // The serve.jobs startup rule (doc 23 §9.3): a corrupt sessions file
        // refuses to guess — running with silently dropped sessions is the
        // failure mode we refuse. Missing file = no sessions, normal.
        let sessions = match ingest::load_sessions(&data_dir) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("pvfsd: ingest.sessions unreadable ({e}) — fix or remove the file");
                std::process::exit(2);
            }
        };
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
            data_dir,
            ingest: Mutex::new(IngestState {
                sessions,
                committing: HashMap::new(),
            }),
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
            ClientMsg::Cat { node, offset, len } => {
                do_cat(daemon, &principal, &mut stream, &node, offset, len)?;
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
            ClientMsg::IngestWrite {
                session,
                file,
                offset,
            } => {
                do_ingest_write(daemon, &principal, &mut stream, &session, &file, offset)?;
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
        // P9 (doc 22): the chunk manifest — read-gated exactly like Cat.
        ClientMsg::ChunkManifest { node } => {
            let e = daemon.reader();
            match e.effective_rights(principal, &node) {
                Ok(r) if r & acl::ACL_R != 0 => {}
                Ok(_) => return err("forbidden", "access denied"),
                Err(pve) => return err_from(pve),
            }
            match e.chunk_manifest(&node) {
                Ok((size, chunk_size, hashes)) => ServerMsg::ChunkManifest {
                    size,
                    chunk_size,
                    hashes: hashes.iter().map(hex::encode).collect(),
                },
                Err(pve) => err_from(pve),
            }
        }
        // P10.0 (doc 23 §3): the external-ingest session ops.
        ClientMsg::IngestBegin {
            parent,
            name,
            kind,
            infohash,
            piece_size,
            files,
            allow_shortfall,
        } => do_ingest_begin(
            daemon,
            principal,
            &parent,
            &name,
            &kind,
            &infohash,
            piece_size,
            files,
            allow_shortfall,
        ),
        ClientMsg::IngestVerified {
            session,
            file,
            ranges,
        } => do_ingest_verified(daemon, principal, &session, &file, &ranges),
        ClientMsg::IngestCommit { session, file } => {
            do_ingest_commit(daemon, principal, &session, &file)
        }
        ClientMsg::IngestAbort {
            session,
            keep_catalog,
        } => do_ingest_abort(daemon, principal, &session, keep_catalog),
        ClientMsg::IngestList => do_ingest_list(daemon, principal),
        // Cat / SecureCat / SecurePut / IngestWrite are handled in
        // serve_connection (data plane).
        ClientMsg::Cat { .. }
        | ClientMsg::SecureCat { .. }
        | ClientMsg::SecurePut { .. }
        | ClientMsg::IngestWrite { .. }
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
    offset: u64,
    len: u64,
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
    // P9 (doc 22): (0,0) = the whole file (old peers unchanged); a range
    // must lie within the file. `size` in CatStart is what WILL be sent.
    let want = if offset == 0 && len == 0 {
        size
    } else if offset.checked_add(len).is_some_and(|end| end <= size) && len > 0 {
        len
    } else {
        write_msg(stream, &err("bad_input", "range outside the file"))?;
        return Ok(());
    };
    write_msg(stream, &ServerMsg::CatStart { size: want })?;

    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            // CatStart already sent — write a zero-length frame to signal abort.
            write_data_frame(stream, &[])?;
            return Err(e);
        }
    };
    if offset > 0 {
        use std::io::Seek as _;
        if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)) {
            write_data_frame(stream, &[])?;
            return Err(e);
        }
    }

    let mut buf = vec![0u8; DATA_CHUNK];
    let mut written: u64 = 0;
    while written < want {
        use std::io::Read as _;
        let cap = (DATA_CHUNK as u64).min(want - written) as usize;
        let got = file.read(&mut buf[..cap]).map_err(|e| {
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
            followup: None,
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

// ---- P10.0: external-ingest sessions (doc 23 §3/§9) -----------------------------

fn ingest_author(principal: &Principal) -> Result<Vec<u8>, ServerMsg> {
    match principal {
        Principal::Key(pk) => Ok(pk.clone()),
        _ => Err(err("forbidden", "ingest requires an authenticated identity")),
    }
}

fn closed_label(session: &str) -> String {
    let tag8: String = session.chars().take(8).collect();
    format!(".pvos.download.closed-{tag8}")
}

/// Resolve one session file for a write-side op: session exists, caller owns
/// it, file exists and is neither committed nor commit-frozen. Returns the
/// declared size.
fn ingest_file_open(
    daemon: &Daemon,
    session: &str,
    file: &str,
    author: &[u8],
) -> Result<u64, ServerMsg> {
    let st = daemon.ingest.lock().unwrap();
    let s = st
        .sessions
        .iter()
        .find(|s| s.id == session)
        .ok_or_else(|| err("not_found", "no such ingest session"))?;
    if s.owner_pub != author {
        return Err(err("forbidden", "session belongs to another principal"));
    }
    let f = s
        .files
        .iter()
        .find(|f| f.node == file)
        .ok_or_else(|| err("not_found", "no such file in the session"))?;
    if f.committed.is_some() {
        return Err(err("bad_input", "file already committed"));
    }
    if st.committing.get(file).is_some_and(|exp| now_ms() < *exp) {
        return Err(err("bad_input", "commit in progress — writes are frozen"));
    }
    Ok(f.size)
}

/// `IngestBegin` (doc 23 §9.4): space preflight, then one prepared batch for
/// the whole catalog + origin record. The session activates when the
/// member's `Commit` lands (the `Activate` followup).
#[allow(clippy::too_many_arguments)]
fn do_ingest_begin(
    daemon: &Daemon,
    principal: &Principal,
    parent: &str,
    name: &str,
    kind: &str,
    infohash: &str,
    piece_size: u64,
    files: Vec<IngestFileSpecWire>,
    allow_shortfall: bool,
) -> ServerMsg {
    let author = match ingest_author(principal) {
        Ok(a) => a,
        Err(m) => return m,
    };
    let specs: Vec<ingest::IngestFileSpec> = files
        .iter()
        .map(|f| ingest::IngestFileSpec {
            rel_path: f.rel_path.clone(),
            size: f.size,
        })
        .collect();
    // The §8.3 preflight: refuse when the declared bytes cannot land. The
    // margin keeps the box breathing; `allow_shortfall` is the caller's
    // explicit "space will free in time" risk.
    let total: u64 = specs.iter().map(|f| f.size).sum();
    let store_dir = match pvfs_core::sync::sync_store_dir(&daemon.data_dir) {
        Ok(d) => d,
        Err(pve) => return err_from(pve),
    };
    match ingest::free_space_at(&store_dir) {
        Ok(free) => {
            if !allow_shortfall && total.saturating_add(ingest::INGEST_SPACE_MARGIN) > free {
                return err(
                    "bad_input",
                    &format!(
                        "declared {total} B (+{} B margin) exceeds {free} B free at {} — free space, choose another store, or pass allow_shortfall",
                        ingest::INGEST_SPACE_MARGIN,
                        store_dir.display()
                    ),
                );
            }
        }
        Err(pve) => return err_from(pve),
    }
    let session = random_id();
    let (prepared, plan) = {
        let e = daemon.engine.lock().unwrap();
        match e.prepare_ingest_begin(
            &author, &parent.to_string(), name, kind, infohash, piece_size, &session, &specs,
        ) {
            Ok(x) => x,
            Err(pve) => return err_from(pve),
        }
    };
    let rec = IngestSessionRec {
        id: session.clone(),
        owner_pub: author.clone(),
        parent: parent.to_string(),
        root: plan.root.clone(),
        origin: plan.origin.clone(),
        files: plan.files.clone(),
    };
    let file_wires: Vec<IngestFileWire> = plan
        .files
        .iter()
        .map(|f| IngestFileWire {
            node: f.node.clone(),
            rel_path: f.rel_path.clone(),
            size: f.size,
            bytes_verified: 0,
            chunks_done: 0,
            chunks_total: f.size.div_ceil(pvfs_core::sync::SWARM_CHUNK),
            committed: None,
        })
        .collect();
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
            followup: Some(IngestFollowup::Activate(Box::new(rec))),
        },
    );
    ServerMsg::IngestPrepared(Box::new(pvfs_proto::IngestPreparedWire {
        session,
        root: plan.root,
        origin: plan.origin,
        files: file_wires,
        prepared_id,
        preimages,
        result_id,
    }))
}

/// `IngestWrite` (data plane): bytes land sparse at `offset` in the file's
/// partial — out-of-order and duplicates are fine. Disk-full is a clean
/// pause, never poison (doc 23 §8.3): the error goes back, the partial and
/// the session stay resumable.
fn do_ingest_write<S: io::Read + io::Write>(
    daemon: &Daemon,
    principal: &Principal,
    stream: &mut S,
    session: &str,
    file: &str,
    offset: u64,
) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    // Resolve everything up front; on failure the frames are still drained
    // to the terminator so the connection stays in sync for the next op.
    let setup = (|| -> Result<(u64, std::fs::File), ServerMsg> {
        let author = ingest_author(principal)?;
        let size = ingest_file_open(daemon, session, file, &author)?;
        if offset > size {
            return Err(err("bad_input", "offset past the declared size"));
        }
        let part = ingest::part_path(&daemon.data_dir, file).map_err(err_from)?;
        if let Some(dir) = part.parent() {
            std::fs::create_dir_all(dir).map_err(|e| err("io", &format!("create store dir: {e}")))?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&part)
            .map_err(|e| err("io", &format!("open partial: {e}")))?;
        let len = f.metadata().map_err(|e| err("io", &format!("stat partial: {e}")))?.len();
        if len < size {
            f.set_len(size) // sparse: full length, no bytes written
                .map_err(|e| err("io", &format!("size partial: {e}")))?;
        }
        Ok((size, f))
    })();
    let (size, mut f) = match setup {
        Ok(x) => (x.0, Some(x.1)),
        Err(m) => {
            // drain to the terminator, then answer
            loop {
                match read_data_frame(stream)? {
                    Some(c) if c.is_empty() => break,
                    Some(_) => {}
                    None => return Ok(()),
                }
            }
            return write_msg(stream, &m);
        }
    };
    let mut f = f.take().unwrap();
    let mut pos = offset;
    let mut fail: Option<ServerMsg> = None;
    loop {
        match read_data_frame(stream)? {
            Some(chunk) if chunk.is_empty() => break,
            Some(_) if fail.is_some() => {} // drain to terminator
            Some(chunk) => {
                if pos + chunk.len() as u64 > size {
                    fail = Some(err("bad_input", "write past the declared size"));
                    continue;
                }
                f.seek(SeekFrom::Start(pos))?;
                if let Err(e) = f.write_all(&chunk) {
                    if e.raw_os_error() == Some(28) {
                        // ENOSPC — §8.3's pause: partial kept, resumable.
                        fail = Some(err(
                            "io",
                            "no space left — session paused; resume after space frees",
                        ));
                        continue;
                    }
                    return Err(e);
                }
                pos += chunk.len() as u64;
            }
            None => return Ok(()), // client hung up mid-upload; partial stays
        }
    }
    match fail {
        Some(m) => write_msg(stream, &m),
        None => write_msg(stream, &ServerMsg::IngestWritten { bytes: pos - offset }),
    }
}

/// `IngestVerified`: merge app-verified ranges into the progress sidecar and
/// BLAKE3 the newly covered chunks from the partial (doc 23 §9.3). Held
/// under the ingest lock so sidecar updates serialize.
fn do_ingest_verified(
    daemon: &Daemon,
    principal: &Principal,
    session: &str,
    file: &str,
    ranges: &[(u64, u64)],
) -> ServerMsg {
    use std::io::{Read, Seek, SeekFrom};
    let author = match ingest_author(principal) {
        Ok(a) => a,
        Err(m) => return m,
    };
    let size = match ingest_file_open(daemon, session, file, &author) {
        Ok(s) => s,
        Err(m) => return m,
    };
    let _st = daemon.ingest.lock().unwrap();
    let ppath = match ingest::progress_path(&daemon.data_dir, file) {
        Ok(p) => p,
        Err(pve) => return err_from(pve),
    };
    let mut prog = match ingest::load_progress(&ppath, size) {
        Ok(p) => p,
        Err(pve) => return err_from(pve),
    };
    if let Err(pve) = prog.add_ranges(ranges) {
        return err_from(pve);
    }
    let newly = prog.newly_covered();
    if !newly.is_empty() {
        let part = match ingest::part_path(&daemon.data_dir, file) {
            Ok(p) => p,
            Err(pve) => return err_from(pve),
        };
        let mut f = match std::fs::File::open(&part) {
            Ok(f) => f,
            Err(_) => return err("bad_input", "verified ranges but no bytes written yet"),
        };
        for idx in newly {
            let (s, e) = prog.chunk_span(idx);
            let mut buf = vec![0u8; (e - s) as usize];
            if f.seek(SeekFrom::Start(s)).is_err() || f.read_exact(&mut buf).is_err() {
                return err("io", "partial shorter than a verified range");
            }
            prog.done.insert(idx, *blake3::hash(&buf).as_bytes());
        }
    }
    if let Err(pve) = ingest::save_progress(&ppath, &prog) {
        return err_from(pve);
    }
    ServerMsg::IngestProgress {
        bytes_verified: prog.bytes_verified(),
        chunks_done: prog.done.len() as u64,
        chunks_total: prog.chunks_total(),
    }
}

/// `IngestCommit` (doc 23 §9.4): freeze writes, hash the partial with no
/// locks held, prepare the member-signed successor + attestation (+ closed
/// record iff last file). The `Publish` followup lands the bytes when the
/// member's `Commit` does. Crash-retry paths re-verify through
/// `swarm_commit` and answer `Committed` directly (no second log write).
fn do_ingest_commit(daemon: &Daemon, principal: &Principal, session: &str, file: &str) -> ServerMsg {
    let author = match ingest_author(principal) {
        Ok(a) => a,
        Err(m) => return m,
    };
    // Resolve + freeze under the ingest lock.
    enum CommitPath {
        Normal { close: Option<IngestClose> },
        Retry { new: String },
    }
    let path = {
        let mut st = daemon.ingest.lock().unwrap();
        let s = match st.sessions.iter().find(|s| s.id == session) {
            Some(s) => s,
            None => return err("not_found", "no such ingest session"),
        };
        if s.owner_pub != author {
            return err("forbidden", "session belongs to another principal");
        }
        let (origin, parent) = (s.origin.clone(), s.parent.clone());
        let fi = match s.files.iter().find(|f| f.node == file) {
            Some(f) => f,
            None => return err("not_found", "no such file in the session"),
        };
        match &fi.committed {
            Some(new) => CommitPath::Retry { new: new.clone() },
            None => {
                let others_open = s
                    .files
                    .iter()
                    .any(|f| f.node != file && f.committed.is_none());
                let close = (!others_open).then(|| IngestClose {
                    parent,
                    label: closed_label(session),
                    payload: ingest::closed_payload(&origin, "complete"),
                });
                st.committing.insert(file.to_string(), now_ms() + PREPARE_TTL_MS);
                CommitPath::Normal { close }
            }
        }
    };
    let part = match ingest::part_path(&daemon.data_dir, file) {
        Ok(p) => p,
        Err(pve) => return err_from(pve),
    };
    let unfreeze = || {
        daemon.ingest.lock().unwrap().committing.remove(file);
    };
    match path {
        CommitPath::Retry { new } => ingest_retry_publish(daemon, session, file, &new, &part),
        CommitPath::Normal { close } => {
            if !part.exists() {
                unfreeze();
                return err("bad_input", "no bytes written yet");
            }
            // The whole-file hash + manifest, one read, no locks (doc 23 §9.4).
            let (hash, chunks) = match pvfs_core::sync::hash_with_manifest(&part) {
                Ok(x) => x,
                Err(pve) => {
                    unfreeze();
                    return err_from(pve);
                }
            };
            let size = match std::fs::metadata(&part) {
                Ok(m) => m.len(),
                Err(e) => {
                    unfreeze();
                    return err("io", &format!("stat partial: {e}"));
                }
            };
            let prepared = {
                let e = daemon.engine.lock().unwrap();
                e.prepare_ingest_commit(&author, &file.to_string(), &hash, size, &chunks, close.as_ref())
            };
            match prepared {
                Ok((pw, new)) => {
                    let preimages = pw.events.iter().map(|pe| hex::encode(pe.digest)).collect();
                    let result_id = pw.result_id.clone();
                    let prepared_id = random_id();
                    daemon.prepared.lock().unwrap().insert(
                        prepared_id.clone(),
                        PreparedState {
                            author_pub: author,
                            events: pw.events,
                            result_id: result_id.clone(),
                            expiry_ms: now_ms() + PREPARE_TTL_MS,
                            followup: Some(IngestFollowup::Publish {
                                session: session.to_string(),
                                old: file.to_string(),
                                new,
                                manifest: chunks,
                            }),
                        },
                    );
                    ServerMsg::Prepared {
                        prepared_id,
                        preimages,
                        result_id,
                    }
                }
                Err(PvfsError::BadInput { field, reason })
                    if field == "file" && reason.starts_with("already hashed") =>
                {
                    // Crash window: the log commit landed but the sessions
                    // file missed it. Resolve the successor and retry-publish.
                    unfreeze();
                    let successor = {
                        let e = daemon.engine.lock().unwrap();
                        e.ingest_successor(&file.to_string())
                    };
                    match successor {
                        Ok(Some(new)) => {
                            {
                                let mut st = daemon.ingest.lock().unwrap();
                                if let Some(s) = st.sessions.iter_mut().find(|s| s.id == session) {
                                    if let Some(f) = s.files.iter_mut().find(|f| f.node == file) {
                                        f.committed = Some(new.clone());
                                    }
                                }
                                let sessions = st.sessions.clone();
                                if let Err(e2) = ingest::save_sessions(&daemon.data_dir, &sessions) {
                                    eprintln!("pvfsd: ingest.sessions save failed ({e2})");
                                }
                            }
                            ingest_retry_publish(daemon, session, file, &new, &part)
                        }
                        Ok(None) => err("bad_input", "file already hashed outside this session"),
                        Err(pve) => err_from(pve),
                    }
                }
                Err(pve) => {
                    unfreeze();
                    err_from(pve)
                }
            }
        }
    }
}

/// The publish-retry path (doc 23 §9.4): the log already carries the
/// successor; only the bytes still need to land. Full `swarm_commit`
/// verification — this partial survived a crash, so it earns the re-read.
fn ingest_retry_publish(
    daemon: &Daemon,
    session: &str,
    file: &str,
    new: &str,
    part: &std::path::Path,
) -> ServerMsg {
    if part.exists() {
        let manifest = match pvfs_core::sync::compute_manifest(part) {
            Ok(m) => m,
            Err(pve) => return err_from(pve),
        };
        let mut e = daemon.engine.lock().unwrap();
        if let Err(pve) = e.swarm_commit(&new.to_string(), part, &manifest) {
            return err_from(pve);
        }
    }
    // Bookkeeping: progress gone, session dropped once every file is done.
    let mut st = daemon.ingest.lock().unwrap();
    st.committing.remove(file);
    if let Ok(pp) = ingest::progress_path(&daemon.data_dir, file) {
        let _ = std::fs::remove_file(pp);
    }
    st.sessions
        .retain(|s| !(s.id == session && s.files.iter().all(|f| f.committed.is_some())));
    if let Err(pve) = ingest::save_sessions(&daemon.data_dir, &st.sessions) {
        eprintln!("pvfsd: ingest.sessions save failed ({pve})");
    }
    ServerMsg::Committed { id: new.to_string() }
}

/// `IngestAbort`: the closing record (+ unlink of the subtree root unless
/// `keep_catalog`) as one prepared batch; the `Abort` followup removes the
/// partials and the session when the member's `Commit` lands (§8.4).
fn do_ingest_abort(
    daemon: &Daemon,
    principal: &Principal,
    session: &str,
    keep_catalog: bool,
) -> ServerMsg {
    let author = match ingest_author(principal) {
        Ok(a) => a,
        Err(m) => return m,
    };
    let (parent, root, origin) = {
        let st = daemon.ingest.lock().unwrap();
        let s = match st.sessions.iter().find(|s| s.id == session) {
            Some(s) => s,
            None => return err("not_found", "no such ingest session"),
        };
        if s.owner_pub != author {
            return err("forbidden", "session belongs to another principal");
        }
        (s.parent.clone(), s.root.clone(), s.origin.clone())
    };
    let prepared = {
        let e = daemon.engine.lock().unwrap();
        let mut pw = match e.prepare_add_node(
            &author,
            &parent,
            NodeSpec {
                node_type: ingest::TYPE_DOWNLOAD_CLOSED.into(),
                label: closed_label(session),
                payload: ingest::closed_payload(&origin, "aborted"),
                is_temp: false,
                creation_nonce: None,
            },
        ) {
            Ok(p) => p,
            Err(pve) => return err_from(pve),
        };
        if !keep_catalog {
            match e.prepare_remove_node(&author, &root) {
                Ok(rm) => pw.events.extend(rm.events),
                // Root already unlinked (or never linked) — close-only.
                Err(PvfsError::NotFound { .. }) => {}
                Err(pve) => return err_from(pve),
            }
        }
        pw
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
            followup: Some(IngestFollowup::Abort {
                session: session.to_string(),
            }),
        },
    );
    ServerMsg::Prepared {
        prepared_id,
        preimages,
        result_id,
    }
}

/// `IngestList`: the live sessions with per-file progress. Active-member
/// gated (the ServeStatus bar): operational state, not public metadata.
fn do_ingest_list(daemon: &Daemon, principal: &Principal) -> ServerMsg {
    let member = match principal {
        Principal::Key(pk) => daemon.reader().is_active_member(pk).unwrap_or(false),
        _ => false,
    };
    if !member {
        return err("forbidden", "ingest list is member-gated (enroll this box)");
    }
    let sessions = daemon.ingest.lock().unwrap().sessions.clone();
    let mut out = Vec::with_capacity(sessions.len());
    for s in sessions {
        let mut files = Vec::with_capacity(s.files.len());
        for f in &s.files {
            let chunks_total = f.size.div_ceil(pvfs_core::sync::SWARM_CHUNK);
            let (bytes_verified, chunks_done) = if f.committed.is_some() {
                (f.size, chunks_total)
            } else {
                match ingest::progress_path(&daemon.data_dir, &f.node)
                    .and_then(|p| ingest::load_progress(&p, f.size))
                {
                    Ok(p) => (p.bytes_verified(), p.done.len() as u64),
                    Err(_) => (0, 0),
                }
            };
            files.push(IngestFileWire {
                node: f.node.clone(),
                rel_path: f.rel_path.clone(),
                size: f.size,
                bytes_verified,
                chunks_done,
                chunks_total,
                committed: f.committed.clone(),
            });
        }
        out.push(IngestSessionWire {
            session: s.id,
            root: s.root,
            origin: s.origin,
            files,
        });
    }
    ServerMsg::IngestSessions { sessions: out }
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
            followup: None,
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
            match state.followup {
                None => ServerMsg::Committed { id: state.result_id },
                Some(f) => finish_ingest_followup(daemon, e, f, state.result_id),
            }
        }
        Err(pve) => {
            // A failed ingest commit unfreezes its file so writes resume.
            if let Some(IngestFollowup::Publish { old, .. }) = &state.followup {
                daemon.ingest.lock().unwrap().committing.remove(old);
            }
            err_from(pve)
        }
    }
}

/// The deployment-state half of a committed ingest write (doc 23 §9.4). The
/// engine guard is still held for the publish rename (O(1) — the hash was
/// computed at prepare time with writes frozen), then dropped before the
/// sessions file is touched.
fn finish_ingest_followup(
    daemon: &Daemon,
    mut e: MutexGuard<'_, Engine>,
    followup: IngestFollowup,
    result_id: String,
) -> ServerMsg {
    match followup {
        IngestFollowup::Activate(rec) => {
            drop(e);
            let mut st = daemon.ingest.lock().unwrap();
            st.sessions.push(*rec);
            if let Err(pve) = ingest::save_sessions(&daemon.data_dir, &st.sessions) {
                // The catalog commit landed; the session works until restart.
                eprintln!("pvfsd: ingest.sessions save failed ({pve}) — session is live but not persisted");
            }
            ServerMsg::Committed { id: result_id }
        }
        IngestFollowup::Publish {
            session,
            old,
            new,
            manifest,
        } => {
            let part = match ingest::part_path(&daemon.data_dir, &old) {
                Ok(p) => p,
                Err(pve) => return err_from(pve),
            };
            let published = e.ingest_publish(&new, &part, &manifest);
            drop(e);
            let mut st = daemon.ingest.lock().unwrap();
            st.committing.remove(&old);
            if let Some(s) = st.sessions.iter_mut().find(|s| s.id == session) {
                if let Some(f) = s.files.iter_mut().find(|f| f.node == old) {
                    f.committed = Some(new.clone());
                }
            }
            match published {
                Ok(_) => {
                    if let Ok(pp) = ingest::progress_path(&daemon.data_dir, &old) {
                        let _ = std::fs::remove_file(pp);
                    }
                    // Last publish done → the session's deployment state goes
                    // (§8.4 — the closed record rode this very commit).
                    st.sessions
                        .retain(|s| !(s.id == session && s.files.iter().all(|f| f.committed.is_some())));
                    if let Err(pve) = ingest::save_sessions(&daemon.data_dir, &st.sessions) {
                        eprintln!("pvfsd: ingest.sessions save failed ({pve})");
                    }
                    ServerMsg::Committed { id: result_id }
                }
                Err(pve) => {
                    // The log commit landed; the partial is still in place.
                    // The retry path re-verifies through swarm_commit.
                    if let Err(e2) = ingest::save_sessions(&daemon.data_dir, &st.sessions) {
                        eprintln!("pvfsd: ingest.sessions save failed ({e2})");
                    }
                    err(
                        "io",
                        &format!("committed but publish failed ({pve}) — re-run ingest commit to retry"),
                    )
                }
            }
        }
        IngestFollowup::Abort { session } => {
            drop(e);
            let mut st = daemon.ingest.lock().unwrap();
            if let Some(i) = st.sessions.iter().position(|s| s.id == session) {
                let s = st.sessions.remove(i);
                for f in s.files.iter().filter(|f| f.committed.is_none()) {
                    st.committing.remove(&f.node);
                    if let Ok(p) = ingest::part_path(&daemon.data_dir, &f.node) {
                        let _ = std::fs::remove_file(p);
                    }
                    if let Ok(p) = ingest::progress_path(&daemon.data_dir, &f.node) {
                        let _ = std::fs::remove_file(p);
                    }
                }
                if let Err(pve) = ingest::save_sessions(&daemon.data_dir, &st.sessions) {
                    eprintln!("pvfsd: ingest.sessions save failed ({pve})");
                }
            }
            ServerMsg::Committed { id: result_id }
        }
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
