//! The loopback identity agent (doc 14 §6): "Sign in with PVFS".
//!
//! A deliberately tiny HTTP/1.1 server bound to `127.0.0.1:0` only. Security
//! model, in order: **loopback binding** (never a routable address), a
//! **per-launch token** published in a `0600` port file (so only processes that
//! can read the owner's runtime dir can call at all), and **origin gating** —
//! every request must carry a browser-enforced `Origin` header, first contact
//! needs an explicit wallet-style connect approval, and a connect grant covers
//! **identity assertions only** (doc 14 §4: the web path has no route to a root
//! event, by construction).
//!
//! Routes (JSON in/out, `connection: close`):
//! - `POST /connect`  — ask the human to connect the calling origin.
//! - `GET  /identity` — the identity pubkey, for a connected origin.
//! - `POST /sign-in`  — `{challenge: <64-hex>}` → `{sig, pubkey}`, connected only.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;

use rand::RngCore;

use crate::agent::Agent;
use crate::origins::{OriginRegistry, DEFAULT_CONNECT_TTL_SECS};
use crate::proto::AgentResponse;

const MAX_BODY: usize = 16 * 1024;

/// The loopback web agent: the signer agent + the origin grants + this
/// launch's token.
pub struct WebAgent {
    agent: Arc<Agent>,
    origins: OriginRegistry,
    token: String,
}

impl WebAgent {
    pub fn new(agent: Arc<Agent>, origins: OriginRegistry) -> WebAgent {
        let mut t = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut t);
        WebAgent {
            agent,
            origins,
            token: hex::encode(t),
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Write the well-known port file (`0600`): `{"addr":"...","token":"..."}`.
    pub fn write_port_file(&self, path: &Path, addr: &str) -> std::io::Result<()> {
        let json = format!("{{\"addr\":\"{addr}\",\"token\":\"{}\"}}", self.token);
        let mut f = std::fs::File::create(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(json.as_bytes())
    }

    /// Serve until the listener closes — one thread per connection. With TLS
    /// material (PVOS M3.6 §4a) the port is DUAL-MODE: a one-byte peek tells
    /// a TLS ClientHello (0x16) from plain HTTP, so an https desktop page
    /// and an older http caller share the same 7421 through the transition.
    pub fn serve(
        self: Arc<Self>,
        listener: TcpListener,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let me = Arc::clone(&self);
            let tls = tls.clone();
            std::thread::spawn(move || {
                let mut first = [0u8; 1];
                let is_tls = matches!(stream.peek(&mut first), Ok(1) if first[0] == 0x16);
                match (is_tls, tls) {
                    (true, Some(cfg)) => {
                        let Ok(conn) = rustls::ServerConnection::new(cfg) else { return };
                        let _ = me.handle_conn(rustls::StreamOwned::new(conn, stream));
                    }
                    _ => {
                        let _ = me.handle_conn(stream);
                    }
                }
            });
        }
    }

    fn handle_conn<S: Read + Write>(&self, stream: S) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream);

        // Request line.
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("").to_string();

        // Headers.
        let mut origin: Option<String> = None;
        let mut token: Option<String> = None;
        let mut content_length: usize = 0;
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h)? == 0 {
                return Ok(()); // client hung up mid-headers
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            let Some((name, value)) = h.split_once(':') else { continue };
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "origin" => origin = Some(value.to_string()),
                "x-pvfs-token" => token = Some(value.to_string()),
                "content-length" => content_length = value.parse().unwrap_or(0),
                _ => {}
            }
        }

        // CORS preflight needs no token (the browser sends it without headers).
        if method == "OPTIONS" {
            return respond(reader.get_mut(), 204, "No Content", origin.as_deref(), "");
        }
        // `/relay` is deliberately token-exempt (M3.1): its authentication is
        // the paired-server signature + the Origin↔pairing binding, so a page
        // needs no port-file secret — which is the whole point of pairing.
        if path != "/relay" && token.as_deref() != Some(self.token.as_str()) {
            return respond_json(
                reader.get_mut(),
                401,
                "Unauthorized",
                origin.as_deref(),
                "{\"error\":\"bad_token\"}",
            );
        }
        let Some(origin) = origin else {
            return respond_json(
                reader.get_mut(),
                400,
                "Bad Request",
                None,
                "{\"error\":\"missing_origin\"}",
            );
        };

        // Body.
        if content_length > MAX_BODY {
            return respond_json(
                reader.get_mut(),
                413,
                "Payload Too Large",
                Some(&origin),
                "{\"error\":\"body_too_large\"}",
            );
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body)?;
        let body = String::from_utf8_lossy(&body);

        let (status, reason, out) = self.route(&method, &path, &origin, &body);
        respond_json(reader.get_mut(), status, reason, Some(&origin), &out)
    }

    fn route(&self, method: &str, path: &str, origin: &str, body: &str) -> (u16, &'static str, String) {
        match (method, path) {
            ("POST", "/connect") => {
                if self.origins.connected(origin) || self.approve_and_grant(origin) {
                    (200, "OK", "{\"connected\":true}".into())
                } else {
                    (403, "Forbidden", "{\"error\":\"denied\"}".into())
                }
            }
            ("GET", "/identity") => {
                if !self.origins.connected(origin) {
                    return (403, "Forbidden", "{\"error\":\"not_connected\"}".into());
                }
                match self.agent.identity_pubkey() {
                    AgentResponse::Pubkey { pubkey } => {
                        (200, "OK", format!("{{\"pubkey\":\"{pubkey}\"}}"))
                    }
                    other => error_response(other),
                }
            }
            ("POST", "/sign-in") => {
                if !self.origins.connected(origin) {
                    return (403, "Forbidden", "{\"error\":\"not_connected\"}".into());
                }
                let Some(challenge) = json_str_field(body, "challenge") else {
                    return (400, "Bad Request", "{\"error\":\"missing_challenge\"}".into());
                };
                let Ok(bytes) = hex::decode(&challenge) else {
                    return (400, "Bad Request", "{\"error\":\"challenge_not_hex\"}".into());
                };
                let Ok(digest) = <[u8; 32]>::try_from(bytes.as_slice()) else {
                    return (400, "Bad Request", "{\"error\":\"challenge_must_be_32_bytes\"}".into());
                };
                let pubkey = match self.agent.identity_pubkey() {
                    AgentResponse::Pubkey { pubkey } => pubkey,
                    other => return error_response(other),
                };
                match self.agent.sign_connected_assertion(origin, &digest) {
                    AgentResponse::Signature { sig } => (
                        200,
                        "OK",
                        format!("{{\"sig\":\"{sig}\",\"pubkey\":\"{pubkey}\"}}"),
                    ),
                    other => error_response(other),
                }
            }
            ("POST", "/relay") => {
                // A paired-server envelope (M3.1): {payload: "<json>", server_sig}.
                let (Some(payload), Some(sig)) = (
                    json_str_field(body, "payload"),
                    json_str_field(body, "server_sig"),
                ) else {
                    return (400, "Bad Request", "{\"error\":\"missing_envelope\"}".into());
                };
                match self.agent.relay(origin, &payload, &sig) {
                    AgentResponse::Signature { sig } => match self.agent.identity_pubkey() {
                        AgentResponse::Pubkey { pubkey } => (
                            200,
                            "OK",
                            format!("{{\"sig\":\"{sig}\",\"pubkey\":\"{pubkey}\"}}"),
                        ),
                        other => error_response(other),
                    },
                    other => error_response(other),
                }
            }
            _ => (404, "Not Found", "{\"error\":\"no_such_route\"}".into()),
        }
    }

    fn approve_and_grant(&self, origin: &str) -> bool {
        self.agent.approve_connect(origin)
            && self
                .origins
                .connect(origin, DEFAULT_CONNECT_TTL_SECS)
                .is_ok()
    }
}

fn error_response(resp: AgentResponse) -> (u16, &'static str, String) {
    match resp {
        AgentResponse::Error { code, message } => {
            let status: (u16, &'static str) = match code.as_str() {
                "rate_limited" => (429, "Too Many Requests"),
                "locked" => (503, "Service Unavailable"),
                _ => (403, "Forbidden"),
            };
            (
                status.0,
                status.1,
                format!(
                    "{{\"error\":\"{code}\",\"message\":\"{}\"}}",
                    message.replace('\\', "\\\\").replace('"', "\\\"")
                ),
            )
        }
        _ => (500, "Internal Server Error", "{\"error\":\"unexpected\"}".into()),
    }
}

/// Extract a string field from a tiny flat JSON body without a full parser.
fn json_str_field(body: &str, field: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get(field)?.as_str().map(|s| s.to_string())
}

fn respond_json<W: Write>(
    stream: &mut W,
    status: u16,
    reason: &str,
    origin: Option<&str>,
    body: &str,
) -> std::io::Result<()> {
    respond(stream, status, reason, origin, body)
}

fn respond<W: Write>(
    stream: &mut W,
    status: u16,
    reason: &str,
    origin: Option<&str>,
    body: &str,
) -> std::io::Result<()> {
    let mut headers = String::new();
    // CORS: reflect the caller's origin — the token + connect gates are the
    // security boundary; CORS only lets a browser page read its answer.
    if let Some(o) = origin {
        headers.push_str(&format!(
            "Access-Control-Allow-Origin: {o}\r\n\
             Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n\
             Access-Control-Allow-Headers: content-type, x-pvfs-token\r\n\
             Vary: Origin\r\n"
        ));
    }
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         {headers}Connection: close\r\n\r\n{body}",
        body.len()
    )?;
    stream.flush()
}
