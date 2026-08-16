//! PVFS daemon client (doc 07): connect to a forest's `pvfsd`, perform the
//! challenge-response handshake, and issue read requests.
//!
//! Two transports, one protocol (F1, doc 17 §4): the local Unix socket, and
//! TCP+TLS to a `pvfsd --listen` address — verified by **pinning** the
//! server's transport pin (BLAKE3 hex of its certificate DER), no CA.
//!
//! Signing is injected as a closure so this crate needs no key library — the
//! caller (CLI/app) holds the identity key and provides how to sign the 32-byte
//! challenge digest.

use std::io;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;

use pvfs_proto::{
    auth_digest, read_data_frame, read_msg, write_data_frame, write_msg, ClientMsg,
    IngestFileSpecWire, ServerMsg, WriteOp,
};

pub use pvfs_proto::{
    ChildInfo, IngestFileWire, IngestSessionWire, LogEventWire, NodeInfo, ServeJobWire,
};

pub mod fetch;
pub mod follow;
pub mod regions;
pub mod watch;

/// The client's transport: both arms speak identical frames.
enum Stream {
    Unix(UnixStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Unix(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Unix(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// Identity + root of the forest behind the socket.
#[derive(Debug, Clone)]
pub struct ForestInfo {
    pub instance_id: String,
    pub forest_id: String,
    pub root: String,
}

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    /// The peer sent something unexpected for the protocol.
    Protocol(String),
    /// A typed error returned by the daemon.
    Server { code: String, message: String },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(e) => write!(f, "io: {e}"),
            ClientError::Protocol(m) => write!(f, "protocol: {m}"),
            ClientError::Server { code, message } => write!(f, "{code}: {message}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        ClientError::Io(e)
    }
}

type Result<T> = std::result::Result<T, ClientError>;

/// The server's parsed challenge: a nonce bound to the forest, with an
/// expiry and the daemon's wire-protocol version.
struct Challenge {
    nonce: Vec<u8>,
    forest_id: String,
    expiry_ms: u64,
    version: u32,
}

/// A connected, authenticated session with a forest's daemon.
pub struct Client {
    stream: Stream,
    /// The principal the daemon resolved us to ("public" or "key:<hex>").
    pub principal: String,
    /// The daemon's `PROTO_VERSION`, learned from the connect challenge —
    /// what a consumer checks a minimum against (PVOS D63).
    daemon_proto: u32,
}

impl Client {
    /// Connect and authenticate as `public` (no key proven).
    pub fn connect_public(path: &Path) -> Result<Client> {
        let (mut stream, ch) = Self::open(path)?;
        write_msg(&mut stream, &ClientMsg::Anonymous)?;
        Self::finish(stream, ch.version)
    }

    /// Connect and prove possession of `pubkey` by signing the challenge digest
    /// with `sign` (e.g. `|d| crypto::sign_digest(&key, d).unwrap()`).
    pub fn connect_signed<F>(path: &Path, pubkey: &[u8], sign: F) -> Result<Client>
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        let (stream, ch) = Self::open(path)?;
        Self::auth(stream, ch, pubkey, sign)
    }

    /// Connect to a `pvfsd --listen` address over TLS, verified against `pin`
    /// (the server's transport pin), and authenticate as `public` (F1).
    pub fn connect_tcp_public(addr: &str, pin: &str) -> Result<Client> {
        let (mut stream, ch) = Self::open_tcp(addr, pin)?;
        write_msg(&mut stream, &ClientMsg::Anonymous)?;
        Self::finish(stream, ch.version)
    }

    /// [`connect_signed`](Self::connect_signed) over pinned TLS (F1).
    pub fn connect_tcp_signed<F>(addr: &str, pin: &str, pubkey: &[u8], sign: F) -> Result<Client>
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        let (stream, ch) = Self::open_tcp(addr, pin)?;
        Self::auth(stream, ch, pubkey, sign)
    }

    /// Sign the challenge and complete the handshake.
    fn auth<F>(mut stream: Stream, ch: Challenge, pubkey: &[u8], sign: F) -> Result<Client>
    where
        F: FnOnce(&[u8; 32]) -> Vec<u8>,
    {
        let digest = auth_digest(&ch.nonce, &ch.forest_id, ch.expiry_ms);
        let proto = ch.version;
        write_msg(
            &mut stream,
            &ClientMsg::Auth {
                pubkey: hex::encode(pubkey),
                sig: hex::encode(sign(&digest)),
            },
        )?;
        Self::finish(stream, proto)
    }

    /// Connect the Unix socket and read the server's challenge.
    fn open(path: &Path) -> Result<(Stream, Challenge)> {
        let mut stream = Stream::Unix(UnixStream::connect(path)?);
        let ch = Self::read_challenge(&mut stream)?;
        Ok((stream, ch))
    }

    /// Dial TCP, wrap in pinned TLS, and read the server's challenge (F1).
    fn open_tcp(addr: &str, pin: &str) -> Result<(Stream, Challenge)> {
        let mut stream = Stream::Tls(Box::new(tls_connect(addr, pin)?));
        let ch = Self::read_challenge(&mut stream)?;
        Ok((stream, ch))
    }

    fn read_challenge(stream: &mut Stream) -> Result<Challenge> {
        match read_msg::<_, ServerMsg>(stream)? {
            Some(ServerMsg::Challenge {
                nonce,
                forest_id,
                expiry_ms,
                version,
            }) => {
                let nonce = hex::decode(&nonce)
                    .map_err(|_| ClientError::Protocol("challenge nonce not hex".into()))?;
                Ok(Challenge {
                    nonce,
                    forest_id,
                    expiry_ms,
                    version,
                })
            }
            Some(other) => Err(unexpected("Challenge", &other)),
            None => Err(ClientError::Protocol("closed before challenge".into())),
        }
    }

    /// Read the `Ready` (or error) that completes the handshake.
    fn finish(mut stream: Stream, daemon_proto: u32) -> Result<Client> {
        match read_msg::<_, ServerMsg>(&mut stream)? {
            Some(ServerMsg::Ready { principal }) => {
                Ok(Client { stream, principal, daemon_proto })
            }
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(other) => Err(unexpected("Ready", &other)),
            None => Err(ClientError::Protocol("closed during handshake".into())),
        }
    }

    /// The daemon's wire-protocol version (`PROTO_VERSION`), from the
    /// connect challenge — a consumer checks its minimum against this
    /// (PVOS D63). Present before any op is sent.
    pub fn daemon_proto(&self) -> u32 {
        self.daemon_proto
    }

    fn request(&mut self, req: ClientMsg) -> Result<ServerMsg> {
        write_msg(&mut self.stream, &req)?;
        match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(msg) => Ok(msg),
            None => Err(ClientError::Protocol("connection closed".into())),
        }
    }

    pub fn info(&mut self) -> Result<ForestInfo> {
        match self.request(ClientMsg::Info)? {
            ServerMsg::Info {
                instance_id,
                forest_id,
                root,
            } => Ok(ForestInfo {
                instance_id,
                forest_id,
                root,
            }),
            other => Err(unexpected("Info", &other)),
        }
    }

    /// The daemon's live job-runner state (P5, doc 18 §2): `("on"|"off", rows)`.
    pub fn serve_status(&mut self) -> Result<(String, Vec<ServeJobWire>)> {
        match self.request(ClientMsg::ServeStatus)? {
            ServerMsg::ServeJobs { runner, jobs } => Ok((runner, jobs)),
            other => Err(unexpected("ServeJobs", &other)),
        }
    }

    pub fn ls(&mut self, node: &str) -> Result<Vec<ChildInfo>> {
        match self.request(ClientMsg::Ls { node: node.into() })? {
            ServerMsg::Ls { children } => Ok(children),
            other => Err(unexpected("Ls", &other)),
        }
    }

    pub fn stat(&mut self, node: &str) -> Result<NodeInfo> {
        match self.request(ClientMsg::Stat { node: node.into() })? {
            ServerMsg::Stat { node } => Ok(node),
            other => Err(unexpected("Stat", &other)),
        }
    }

    /// P9 (doc 22): a holder's chunk manifest for `node` — advisory, unsigned
    /// (the catalog hash stays the trust anchor). Errors when the holder has
    /// no bytes or predates the swarm.
    pub fn chunk_manifest(&mut self, node: &str) -> Result<(u64, u64, Vec<String>)> {
        match self.request(ClientMsg::ChunkManifest { node: node.into() })? {
            ServerMsg::ChunkManifest {
                size,
                chunk_size,
                hashes,
            } => Ok((size, chunk_size, hashes)),
            other => Err(unexpected("ChunkManifest", &other)),
        }
    }

    /// The served log's chain tip (F2 log shipping). Requires admin rights on
    /// the forest root — or, for a region-scoped request (P7.2b: `region` =
    /// the generation address, `""` = top), on that region's root.
    pub fn log_info(&mut self, region: &str) -> Result<u64> {
        match self.request(ClientMsg::LogInfo {
            region: region.into(),
        })? {
            ServerMsg::LogInfo { tip_seq } => Ok(tip_seq),
            other => Err(unexpected("LogInfo", &other)),
        }
    }

    /// One batch of raw signed log rows from `from_seq` (F2). Returns
    /// `(tip_seq, events)`; keep calling from `last.seq + 1` until caught up.
    /// Gated like [`log_info`](Self::log_info).
    pub fn log_read(
        &mut self,
        from_seq: u64,
        max: u32,
        region: &str,
    ) -> Result<(u64, Vec<LogEventWire>)> {
        match self.request(ClientMsg::LogRead {
            from_seq,
            max,
            region: region.into(),
        })? {
            ServerMsg::LogEvents { tip_seq, events } => Ok((tip_seq, events)),
            other => Err(unexpected("LogEvents", &other)),
        }
    }

    /// [`log_read`](Self::log_read) that long-polls (F5.4): the server holds
    /// the request up to `timeout_ms` (server-capped) waiting for the log to
    /// reach `from_seq`; empty events = nothing yet, call again.
    pub fn log_wait(
        &mut self,
        from_seq: u64,
        max: u32,
        timeout_ms: u64,
        region: &str,
    ) -> Result<(u64, Vec<LogEventWire>)> {
        match self.request(ClientMsg::LogWait {
            from_seq,
            max,
            timeout_ms,
            region: region.into(),
        })? {
            ServerMsg::LogEvents { tip_seq, events } => Ok((tip_seq, events)),
            other => Err(unexpected("LogEvents", &other)),
        }
    }

    /// Stream a file node's bytes to `out` using the raw binary data plane
    /// (doc 07 §6, PROTO_VERSION 2). Returns the total number of bytes written.
    pub fn cat(&mut self, node: &str, out: &mut dyn std::io::Write) -> Result<u64> {
        self.cat_range(node, 0, 0, out)
    }

    /// P9 (doc 22): stream a byte range — `(0, 0)` = the whole file. The
    /// swarm fetcher pulls chunks with this; old servers only understand the
    /// whole-file form (the caller falls back on error).
    pub fn cat_range(
        &mut self,
        node: &str,
        offset: u64,
        len: u64,
        out: &mut dyn std::io::Write,
    ) -> Result<u64> {
        write_msg(
            &mut self.stream,
            &ClientMsg::Cat {
                node: node.into(),
                offset,
                len,
            },
        )?;
        // Server responds: CatStart (JSON) → binary data frames → CatDone (JSON).
        let size = match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::CatStart { size }) => size,
            Some(ServerMsg::Error { code, message }) => return Err(ClientError::Server { code, message }),
            Some(other) => return Err(unexpected("CatStart", &other)),
            None => return Err(ClientError::Protocol("connection closed before CatStart".into())),
        };
        let mut written: u64 = 0;
        while written < size {
            match read_data_frame(&mut self.stream)? {
                Some(chunk) if chunk.is_empty() => break, // abort signal
                Some(chunk) => {
                    out.write_all(&chunk).map_err(ClientError::Io)?;
                    written += chunk.len() as u64;
                }
                None => break,
            }
        }
        // Read CatDone (JSON) to return the stream to control-plane state.
        match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::CatDone { written: w }) => Ok(w),
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(other) => Err(unexpected("CatDone", &other)),
            None => Ok(written), // server closed cleanly after data
        }
    }

    /// Create a secure node under `parent` (doc 12) with a managed ciphertext
    /// location — provision storage on the fly without stopping the daemon.
    /// Returns the new node id.
    pub fn secure_create<F>(&mut self, parent: &str, label: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::SecureCreate {
                parent: parent.into(),
                label: label.into(),
            },
            sign,
        )
    }

    /// Download a secure blob's ciphertext (doc 12 §8) — the daemon verifies it
    /// against the signed ledger before streaming; decryption is the caller's job.
    pub fn secure_cat(&mut self, node: &str) -> Result<Vec<u8>> {
        write_msg(&mut self.stream, &ClientMsg::SecureCat { node: node.into() })?;
        let size = match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::CatStart { size }) => size,
            Some(ServerMsg::Error { code, message }) => return Err(ClientError::Server { code, message }),
            Some(other) => return Err(unexpected("CatStart", &other)),
            None => return Err(ClientError::Protocol("connection closed before CatStart".into())),
        };
        let mut out = Vec::with_capacity(size as usize);
        while (out.len() as u64) < size {
            match read_data_frame(&mut self.stream)? {
                Some(chunk) if chunk.is_empty() => break,
                Some(chunk) => out.extend_from_slice(&chunk),
                None => break,
            }
        }
        match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::CatDone { .. }) => Ok(out),
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(other) => Err(unexpected("CatDone", &other)),
            None => Ok(out),
        }
    }

    /// Upload a secure blob's new ciphertext and commit its ledger advance
    /// (doc 12 §8.5 daemon path). `sign` signs the `SecureBlobUpdated` digest
    /// with the caller's device key. Returns the blob id.
    pub fn secure_put<F>(&mut self, node: &str, ciphertext: &[u8], sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        write_msg(&mut self.stream, &ClientMsg::SecurePut { node: node.into() })?;
        for chunk in ciphertext.chunks(pvfs_proto::DATA_CHUNK) {
            write_data_frame(&mut self.stream, chunk)?;
        }
        write_data_frame(&mut self.stream, &[])?; // zero-length terminator
        let (prepared_id, preimages) = match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::Prepared { prepared_id, preimages, .. }) => (prepared_id, preimages),
            Some(ServerMsg::Error { code, message }) => return Err(ClientError::Server { code, message }),
            Some(other) => return Err(unexpected("Prepared", &other)),
            None => return Err(ClientError::Protocol("connection closed before Prepared".into())),
        };
        let mut sigs = Vec::with_capacity(preimages.len());
        for preimage in &preimages {
            let bytes = hex::decode(preimage)
                .map_err(|_| ClientError::Protocol("preimage not hex".into()))?;
            let digest: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::Protocol("preimage not 32 bytes".into()))?;
            sigs.push(hex::encode(sign(&digest)));
        }
        match self.request(ClientMsg::Commit { prepared_id, sigs })? {
            ServerMsg::Committed { id } => Ok(id),
            other => Err(unexpected("Committed", &other)),
        }
    }

    /// Sign each hex preimage and send the phase-2 `Commit` (doc 07 §5).
    fn sign_and_commit<F>(
        &mut self,
        prepared_id: String,
        preimages: &[String],
        sign: F,
    ) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        let mut sigs = Vec::with_capacity(preimages.len());
        for preimage in preimages {
            let bytes = hex::decode(preimage)
                .map_err(|_| ClientError::Protocol("preimage not hex".into()))?;
            let digest: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::Protocol("preimage not 32 bytes".into()))?;
            sigs.push(hex::encode(sign(&digest)));
        }
        match self.request(ClientMsg::Commit { prepared_id, sigs })? {
            ServerMsg::Committed { id } => Ok(id),
            other => Err(unexpected("Committed", &other)),
        }
    }

    // ---- P10.0: external-ingest sessions (doc 23 §3) ---------------------------

    /// Open an ingest session (doc 23 §3): catalogs the whole torrent now —
    /// unhashed pointer nodes plus the `pvos.download` origin record — in one
    /// member-signed commit. Returns the session layout; the daemon's session
    /// is live when this returns.
    #[allow(clippy::too_many_arguments)]
    pub fn ingest_begin<F>(
        &mut self,
        parent: &str,
        name: &str,
        kind: &str,
        infohash: &str,
        piece_size: u64,
        files: &[(String, u64)],
        allow_shortfall: bool,
        sign: F,
    ) -> Result<IngestSessionWire>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        let resp = self.request(ClientMsg::IngestBegin {
            parent: parent.into(),
            name: name.into(),
            kind: kind.into(),
            infohash: infohash.into(),
            piece_size,
            files: files
                .iter()
                .map(|(rel_path, size)| IngestFileSpecWire {
                    rel_path: rel_path.clone(),
                    size: *size,
                })
                .collect(),
            allow_shortfall,
        })?;
        let p = match resp {
            ServerMsg::IngestPrepared(p) => *p,
            other => return Err(unexpected("IngestPrepared", &other)),
        };
        self.sign_and_commit(p.prepared_id, &p.preimages, sign)?;
        Ok(IngestSessionWire {
            session: p.session,
            root: p.root,
            origin: p.origin,
            files: p.files,
        })
    }

    /// Upload bytes into a session file's partial at `offset` (sparse;
    /// out-of-order and duplicate writes are fine). Returns bytes landed.
    pub fn ingest_write(
        &mut self,
        session: &str,
        file: &str,
        offset: u64,
        data: &[u8],
    ) -> Result<u64> {
        write_msg(
            &mut self.stream,
            &ClientMsg::IngestWrite {
                session: session.into(),
                file: file.into(),
                offset,
            },
        )?;
        for chunk in data.chunks(pvfs_proto::DATA_CHUNK) {
            write_data_frame(&mut self.stream, chunk)?;
        }
        write_data_frame(&mut self.stream, &[])?; // zero-length terminator
        match read_msg::<_, ServerMsg>(&mut self.stream)? {
            Some(ServerMsg::IngestWritten { bytes }) => Ok(bytes),
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(other) => Err(unexpected("IngestWritten", &other)),
            None => Err(ClientError::Protocol("connection closed mid-upload".into())),
        }
    }

    /// Report app-verified byte ranges; the daemon marks newly covered
    /// chunks. Returns `(bytes_verified, chunks_done, chunks_total)`.
    pub fn ingest_verified(
        &mut self,
        session: &str,
        file: &str,
        ranges: &[(u64, u64)],
    ) -> Result<(u64, u64, u64)> {
        match self.request(ClientMsg::IngestVerified {
            session: session.into(),
            file: file.into(),
            ranges: ranges.to_vec(),
        })? {
            ServerMsg::IngestProgress {
                bytes_verified,
                chunks_done,
                chunks_total,
            } => Ok((bytes_verified, chunks_done, chunks_total)),
            other => Err(unexpected("IngestProgress", &other)),
        }
    }

    /// Commit one file: hash-fill successor + attestation (+ the closing
    /// record on the session's last file), then publish. Returns the
    /// successor's node id — commits re-identify. A retry after a crash may
    /// answer `Committed` directly (already in the log); handled here.
    pub fn ingest_commit<F>(&mut self, session: &str, file: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        match self.request(ClientMsg::IngestCommit {
            session: session.into(),
            file: file.into(),
        })? {
            ServerMsg::Prepared {
                prepared_id,
                preimages,
                ..
            } => self.sign_and_commit(prepared_id, &preimages, sign),
            ServerMsg::Committed { id } => Ok(id), // retry path: already in the log
            other => Err(unexpected("Prepared", &other)),
        }
    }

    /// Abort a session: closing record (+ unlink of the subtree root unless
    /// `keep_catalog`), partials removed. Returns the closing record's id.
    pub fn ingest_abort<F>(&mut self, session: &str, keep_catalog: bool, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        match self.request(ClientMsg::IngestAbort {
            session: session.into(),
            keep_catalog,
        })? {
            ServerMsg::Prepared {
                prepared_id,
                preimages,
                ..
            } => self.sign_and_commit(prepared_id, &preimages, sign),
            other => Err(unexpected("Prepared", &other)),
        }
    }

    /// The live ingest sessions with per-file progress (active-member gated).
    pub fn ingest_list(&mut self) -> Result<Vec<IngestSessionWire>> {
        match self.request(ClientMsg::IngestList)? {
            ServerMsg::IngestSessions { sessions } => Ok(sessions),
            other => Err(unexpected("IngestSessions", &other)),
        }
    }

    /// Claim the WRITE LEASE over `roots` and everything beneath them (PVOS
    /// D67 C3): while THIS connection holds it, writes under those subtrees
    /// are refused from every other connection. Held for the connection's
    /// life and released when it ends, so a crashed holder blocks nothing.
    ///
    /// Idempotent for the holder; `forbidden` while another live connection
    /// holds an overlapping root.
    pub fn claim_write_lease(&mut self, roots: &[String]) -> Result<()> {
        match self.request(ClientMsg::ClaimWriteLease {
            roots: roots.to_vec(),
        })? {
            ServerMsg::Ready { .. } => Ok(()),
            other => Err(unexpected("Ready", &other)),
        }
    }

    /// Create a folder named `label` under `parent`. Returns the new node id.
    pub fn mkdir<F>(&mut self, parent: &str, label: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::Mkdir {
                parent: parent.into(),
                label: label.into(),
            },
            sign,
        )
    }

    /// Create a file node named `label` under `parent` (metadata). Returns its id.
    pub fn add_file<F>(
        &mut self,
        parent: &str,
        label: &str,
        size: u64,
        mime: &str,
        sign: F,
    ) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::AddFile {
                parent: parent.into(),
                label: label.into(),
                size,
                mime: mime.into(),
            },
            sign,
        )
    }

    /// Create a typed node with an inline payload (small, log-resident record —
    /// e.g. a PVOS grant event). Returns the new node id.
    pub fn add_node<F>(
        &mut self,
        parent: &str,
        label: &str,
        node_type: &str,
        payload: &[u8],
        sign: F,
    ) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::AddNode {
                parent: parent.into(),
                label: label.into(),
                node_type: node_type.into(),
                payload: hex::encode(payload),
            },
            sign,
        )
    }

    /// Read a node's inline payload (read-ACL-gated).
    pub fn payload(&mut self, node: &str) -> Result<Vec<u8>> {
        match self.request(ClientMsg::Payload { node: node.into() })? {
            ServerMsg::Payload { payload } => hex::decode(&payload)
                .map_err(|_| ClientError::Protocol("payload not hex".into())),
            other => Err(unexpected("Payload", &other)),
        }
    }

    /// Unlink `node` from its home parent. Returns the removed link id.
    pub fn rm<F>(&mut self, node: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(WriteOp::Rm { node: node.into() }, sign)
    }

    /// Record where a file node's bytes live. Returns the file id.
    pub fn add_location<F>(&mut self, file: &str, uri: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::AddLocation {
                file: file.into(),
                uri: uri.into(),
            },
            sign,
        )
    }

    /// Retract a recorded location (P6.0). Returns the file id.
    pub fn remove_location<F>(&mut self, file: &str, uri: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::RemoveLocation {
                file: file.into(),
                uri: uri.into(),
            },
            sign,
        )
    }

    /// Create a link `parent → child` (P6.0). Empty `order_key` = append.
    /// Returns the new link id.
    pub fn link<F>(
        &mut self,
        parent: &str,
        child: &str,
        link_type: &str,
        order_key: &str,
        sign: F,
    ) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::Link {
                parent: parent.into(),
                child: child.into(),
                link_type: link_type.into(),
                order_key: order_key.into(),
            },
            sign,
        )
    }

    /// Soft-remove a link (P6.0). Returns the link id.
    pub fn unlink<F>(&mut self, link_id: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::Unlink {
                link_id: link_id.into(),
            },
            sign,
        )
    }

    /// Change a link's sibling order (P6.0). Returns the link id.
    pub fn reorder<F>(&mut self, link_id: &str, key: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::Reorder {
                link_id: link_id.into(),
                key: key.into(),
            },
            sign,
        )
    }

    /// Re-home `node` under `new_parent`. Returns the node id.
    pub fn mv<F>(&mut self, node: &str, new_parent: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::Mv {
                node: node.into(),
                new_parent: new_parent.into(),
            },
            sign,
        )
    }

    /// Set a principal's rights on a node (admin op, doc 09 §3c). `principal` =
    /// `public`|`any`|`tag:<name>`|`key:<hex>`; `rights` = `rwa` letters or `-`.
    pub fn set_acl<F>(&mut self, node: &str, principal: &str, rights: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.set_acl_expiring(node, principal, rights, 0, sign)
    }

    /// [`set_acl`](Self::set_acl) with an expiry (doc 13 Q-E1): ms epoch after
    /// which the grant is inert; `0` = never. A pre-1.1 daemon ignores the field
    /// (JSON, unknown-field tolerant) and records a permanent grant — pair a 1.1
    /// client with a 1.1 daemon when expiry matters.
    pub fn set_acl_expiring<F>(
        &mut self,
        node: &str,
        principal: &str,
        rights: &str,
        expires_at: u64,
        sign: F,
    ) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::SetAcl {
                node: node.into(),
                principal: principal.into(),
                rights: rights.into(),
                expires_at,
            },
            sign,
        )
    }

    /// Grant (`granted`) or remove a membership tag from a member key (hex).
    pub fn tag_member<F>(&mut self, member: &str, tag: &str, granted: bool, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(
            WriteOp::TagMember {
                member: member.into(),
                tag: tag.into(),
                granted,
            },
            sign,
        )
    }

    /// Admit a member's key (hex). Signed by an admin device.
    pub fn authorize_member<F>(&mut self, pubkey: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(WriteOp::AuthorizeMember { pubkey: pubkey.into() }, sign)
    }

    /// Revoke a device/member key (hex). Signed by an admin device.
    pub fn revoke<F>(&mut self, pubkey: &str, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        self.write_op(WriteOp::Revoke { pubkey: pubkey.into() }, sign)
    }

    /// The two-phase write flow (doc 07 §5): prepare → sign each preimage → commit.
    /// `sign` produces a signature over each 32-byte preimage with the member's key.
    fn write_op<F>(&mut self, op: WriteOp, sign: F) -> Result<String>
    where
        F: Fn(&[u8; 32]) -> Vec<u8>,
    {
        let (prepared_id, preimages) = match self.request(ClientMsg::PrepareWrite { op })? {
            ServerMsg::Prepared {
                prepared_id,
                preimages,
                ..
            } => (prepared_id, preimages),
            other => return Err(unexpected("Prepared", &other)),
        };
        let mut sigs = Vec::with_capacity(preimages.len());
        for preimage in &preimages {
            let bytes = hex::decode(preimage)
                .map_err(|_| ClientError::Protocol("preimage not hex".into()))?;
            let digest: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| ClientError::Protocol("preimage not 32 bytes".into()))?;
            sigs.push(hex::encode(sign(&digest)));
        }
        match self.request(ClientMsg::Commit { prepared_id, sigs })? {
            ServerMsg::Committed { id } => Ok(id),
            other => Err(unexpected("Committed", &other)),
        }
    }
}

fn unexpected(want: &str, got: &ServerMsg) -> ClientError {
    ClientError::Protocol(format!("expected {want}, got {got:?}"))
}

// ---- pinned TLS (F1, doc 17 §4) ---------------------------------------------
//
// No CA, no roots: the operator copies the server's transport pin (BLAKE3 hex
// of its certificate DER, printed by `pvfsd --listen`) and the client accepts
// exactly that certificate. Server *identity* is the pin; user identity is
// still the challenge-response handshake on top.

/// Verifier that accepts exactly one certificate: the pinned one.
#[derive(Debug)]
struct PinnedCert {
    pin: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if blake3::hash(end_entity.as_ref()).as_bytes() == &self.pin {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned transport pin".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Dial `addr` and wrap it in TLS verified only by the transport pin.
fn tls_connect(
    addr: &str,
    pin_hex: &str,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let pin_bytes = hex::decode(pin_hex)
        .map_err(|_| ClientError::Protocol("transport pin must be hex".into()))?;
    let pin: [u8; 32] = pin_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientError::Protocol("transport pin must be 32 bytes of hex".into()))?;

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert { pin }))
        .with_no_client_auth();

    // SNI name is irrelevant under pinning; still give rustls the host part.
    let host = addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_start_matches('[').trim_end_matches(']'))
        .unwrap_or(addr);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| ClientError::Protocol(format!("bad server name in address {addr:?}")))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| ClientError::Protocol(format!("tls: {e}")))?;
    let tcp = TcpStream::connect(addr)?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}
