//! PVFS per-user daemon (doc 07): serves one forest over a Unix socket with
//! challenge-response auth (§2) and per-node ACL enforcement (§4).
//!
//! Control plane (metadata): serialized writer behind a Mutex; reads serialize
//! for now (WAL read-pool is a later optimization).
//! Data plane (bytes): engine lock released before streaming raw bytes so
//! concurrent cat transfers don't block each other (doc 07 §6).

use std::collections::HashMap;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

/// One forest served by the daemon: the engine, its forest id (challenge
/// binding), and in-flight prepared writes.
pub struct Daemon {
    engine: Mutex<Engine>,
    forest_id: String,
    prepared: Mutex<HashMap<String, PreparedState>>,
}

impl Daemon {
    pub fn new(engine: Engine) -> Daemon {
        let forest_id = engine.identity.forest_id.clone();
        Daemon {
            engine: Mutex::new(engine),
            forest_id,
            prepared: Mutex::new(HashMap::new()),
        }
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

/// Handshake then request loop for one connection.
pub fn serve_connection(daemon: &Daemon, mut stream: UnixStream) -> io::Result<()> {
    // 1. challenge
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let expiry_ms = now_ms() + CHALLENGE_TTL_MS;
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
        None => return Ok(()), // client hung up
        Some(ClientMsg::Anonymous) => Principal::Public,
        Some(ClientMsg::Auth { pubkey, sig }) => {
            match resolve_auth(&nonce, &daemon.forest_id, expiry_ms, &pubkey, &sig) {
                Ok(p) => p,
                Err(msg) => {
                    write_msg(&mut stream, &msg)?;
                    return Ok(());
                }
            }
        }
        Some(_) => {
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
            let e = daemon.engine.lock().unwrap();
            ServerMsg::Info {
                instance_id: e.identity.instance_id.clone(),
                forest_id: e.identity.forest_id.clone(),
                root: e.identity.root_node_id.clone(),
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

/// A node's inline payload (control plane; read-ACL-gated like `stat`).
fn do_payload(daemon: &Daemon, principal: &Principal, node: &str) -> ServerMsg {
    let e = daemon.engine.lock().unwrap();
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
fn do_cat(daemon: &Daemon, principal: &Principal, stream: &mut UnixStream, node: &str) -> io::Result<()> {
    let id: NodeId = node.to_string();

    // --- control plane: ACL check + path resolution (lock held briefly) ---
    let path = {
        let e = daemon.engine.lock().unwrap();
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
fn do_secure_cat(
    daemon: &Daemon,
    principal: &Principal,
    stream: &mut UnixStream,
    node: &str,
) -> io::Result<()> {
    let id: NodeId = node.to_string();
    let bytes = {
        let e = daemon.engine.lock().unwrap();
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
fn do_secure_put(
    daemon: &Daemon,
    principal: &Principal,
    stream: &mut UnixStream,
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
            WriteOp::Mv { node, new_parent } => e.prepare_move_node(&author, &node, &new_parent),
            WriteOp::SetAcl {
                node,
                principal,
                rights,
            } => match (Principal::parse(&principal), acl::parse_rights(&rights)) {
                (Ok(p), Ok(r)) => e.prepare_set_acl(&author, &node, &p, r),
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
        Ok(()) => ServerMsg::Committed { id: state.result_id },
        Err(e) => err_from(e),
    }
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn do_ls(daemon: &Daemon, principal: &Principal, node: &str) -> Result<Vec<ChildInfo>, ServerMsg> {
    let e = daemon.engine.lock().unwrap();
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
    let e = daemon.engine.lock().unwrap();
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
