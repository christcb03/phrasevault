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
    auth_digest, read_data_frame, read_msg, write_data_frame, write_msg, ClientMsg, ServerMsg,
    WriteOp,
};

pub use pvfs_proto::{ChildInfo, LogEventWire, NodeInfo};

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

/// The server's parsed challenge: a nonce bound to the forest, with an expiry.
struct Challenge {
    nonce: Vec<u8>,
    forest_id: String,
    expiry_ms: u64,
}

/// A connected, authenticated session with a forest's daemon.
pub struct Client {
    stream: Stream,
    /// The principal the daemon resolved us to ("public" or "key:<hex>").
    pub principal: String,
}

impl Client {
    /// Connect and authenticate as `public` (no key proven).
    pub fn connect_public(path: &Path) -> Result<Client> {
        let (mut stream, _challenge) = Self::open(path)?;
        write_msg(&mut stream, &ClientMsg::Anonymous)?;
        Self::finish(stream)
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
        let (mut stream, _challenge) = Self::open_tcp(addr, pin)?;
        write_msg(&mut stream, &ClientMsg::Anonymous)?;
        Self::finish(stream)
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
        write_msg(
            &mut stream,
            &ClientMsg::Auth {
                pubkey: hex::encode(pubkey),
                sig: hex::encode(sign(&digest)),
            },
        )?;
        Self::finish(stream)
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
                ..
            }) => {
                let nonce = hex::decode(&nonce)
                    .map_err(|_| ClientError::Protocol("challenge nonce not hex".into()))?;
                Ok(Challenge {
                    nonce,
                    forest_id,
                    expiry_ms,
                })
            }
            Some(other) => Err(unexpected("Challenge", &other)),
            None => Err(ClientError::Protocol("closed before challenge".into())),
        }
    }

    /// Read the `Ready` (or error) that completes the handshake.
    fn finish(mut stream: Stream) -> Result<Client> {
        match read_msg::<_, ServerMsg>(&mut stream)? {
            Some(ServerMsg::Ready { principal }) => Ok(Client { stream, principal }),
            Some(ServerMsg::Error { code, message }) => Err(ClientError::Server { code, message }),
            Some(other) => Err(unexpected("Ready", &other)),
            None => Err(ClientError::Protocol("closed during handshake".into())),
        }
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

    /// The served log's chain tip (F2 log shipping). Requires admin rights on
    /// the forest root.
    pub fn log_info(&mut self) -> Result<u64> {
        match self.request(ClientMsg::LogInfo)? {
            ServerMsg::LogInfo { tip_seq } => Ok(tip_seq),
            other => Err(unexpected("LogInfo", &other)),
        }
    }

    /// One batch of raw signed log rows from `from_seq` (F2). Returns
    /// `(tip_seq, events)`; keep calling from `last.seq + 1` until caught up.
    /// Requires admin rights on the forest root.
    pub fn log_read(&mut self, from_seq: u64, max: u32) -> Result<(u64, Vec<LogEventWire>)> {
        match self.request(ClientMsg::LogRead { from_seq, max })? {
            ServerMsg::LogEvents { tip_seq, events } => Ok((tip_seq, events)),
            other => Err(unexpected("LogEvents", &other)),
        }
    }

    /// Stream a file node's bytes to `out` using the raw binary data plane
    /// (doc 07 §6, PROTO_VERSION 2). Returns the total number of bytes written.
    pub fn cat(&mut self, node: &str, out: &mut dyn std::io::Write) -> Result<u64> {
        write_msg(&mut self.stream, &ClientMsg::Cat { node: node.into() })?;
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
