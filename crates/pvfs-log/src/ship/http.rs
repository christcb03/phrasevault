//! A small HTTP/1.1 POST over TCP or TLS (PVOS D222d): one request per
//! connection (`Connection: close`), the response read to its end. Enough
//! for Splunk HEC, Loki and an HTTPS JSON receiver, without an HTTP crate in
//! the daemons.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::config::TlsSettings;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq)]
pub struct Url {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(u: &str) -> Result<Url, String> {
        let u = u.trim();
        let (tls, rest) = if let Some(r) = u.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = u.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("{u:?} does not start with http:// or https://"));
        };
        let (hostport, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_string()),
            None => (rest, String::new()),
        };
        let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
            let (h, after) = h.split_once(']').ok_or("an IPv6 address needs its closing ]")?;
            let port = match after.strip_prefix(':') {
                Some(p) => p.parse::<u16>().map_err(|_| format!("port {p:?}"))?,
                None => {
                    if tls {
                        443
                    } else {
                        80
                    }
                }
            };
            (format!("[{h}]"), port)
        } else {
            match hostport.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), p.parse::<u16>().map_err(|_| format!("port {p:?}"))?),
                None => (hostport.to_string(), if tls { 443 } else { 80 }),
            }
        };
        if host.is_empty() || host == "[]" {
            return Err("no host".into());
        }
        Ok(Url { tls, host, port, path })
    }

    /// The path, or `default` when the URL named none.
    pub fn path_or(&self, default: &str) -> String {
        if self.path.is_empty() || self.path == "/" {
            default.to_string()
        } else {
            self.path.clone()
        }
    }

    fn authority(&self) -> String {
        let default = if self.tls { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

pub fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let h = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<_> = (h, port).to_socket_addrs().map_err(|e| format!("{host}:{port}: {e}"))?.collect();
    let mut last = format!("{host}:{port}: no address");
    for a in addrs {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(IO_TIMEOUT));
                let _ = s.set_write_timeout(Some(IO_TIMEOUT));
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    Err(last)
}

/// POST `body` to `path` on `url`'s host; the status code and the response
/// body (as text, still chunk-framed if the server chunked it).
pub fn post(url: &Url, path: &str, tls: &TlsSettings, headers: &[(String, String)], body: &[u8]) -> Result<(u16, String), String> {
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: pvfs-log/1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        url.authority(),
        body.len()
    );
    for (k, v) in headers {
        req.push_str(k);
        req.push_str(": ");
        req.push_str(v);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");
    let tcp = connect(&url.host, url.port)?;
    let raw = if url.tls {
        let cfg = super::tls::client_config(tls)?;
        let conn = rustls::ClientConnection::new(cfg, super::tls::server_name(&url.host)?).map_err(|e| format!("tls: {e}"))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        exchange(&mut s, req.as_bytes(), body)?
    } else {
        let mut s = tcp;
        exchange(&mut s, req.as_bytes(), body)?
    };
    parse_response(&raw)
}

fn exchange<S: Read + Write>(s: &mut S, head: &[u8], body: &[u8]) -> Result<Vec<u8>, String> {
    s.write_all(head).map_err(|e| format!("send: {e}"))?;
    s.write_all(body).map_err(|e| format!("send: {e}"))?;
    s.flush().map_err(|e| format!("send: {e}"))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > MAX_RESPONSE {
                    break;
                }
            }
            // A TLS peer that closes without close_notify: what came is the answer.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !out.is_empty() => break,
            Err(e) => {
                if out.is_empty() {
                    return Err(format!("no answer: {e}"));
                }
                break;
            }
        }
    }
    Ok(out)
}

fn parse_response(raw: &[u8]) -> Result<(u16, String), String> {
    let text = String::from_utf8_lossy(raw);
    let status_line = text.lines().next().ok_or("an empty answer")?;
    let mut parts = status_line.split_whitespace();
    let proto = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/") {
        return Err(format!("not an HTTP answer: {:?}", status_line.chars().take(80).collect::<String>()));
    }
    let code = parts.next().and_then(|c| c.parse::<u16>().ok()).ok_or("no status code")?;
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Ok((code, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = Url::parse("https://splunk.corp:8088/services/collector/event").unwrap();
        assert_eq!((u.tls, u.host.as_str(), u.port, u.path.as_str()), (true, "splunk.corp", 8088, "/services/collector/event"));
        let u = Url::parse("http://192.168.1.83:3100").unwrap();
        assert_eq!((u.tls, u.port, u.path_or("/loki/api/v1/push").as_str()), (false, 3100, "/loki/api/v1/push"));
        let u = Url::parse("https://[::1]/x").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("[::1]", 443));
        assert!(Url::parse("ftp://x").is_err());
        assert!(Url::parse("https://:80").is_err());
        assert!(Url::parse("http://h:99999").is_err());
    }

    #[test]
    fn responses() {
        assert_eq!(parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap(), (204, String::new()));
        let (c, b) = parse_response(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"text\":\"Success\",\"code\":0}").unwrap();
        assert_eq!(c, 200);
        assert!(b.contains("\"code\":0"));
        assert!(parse_response(b"garbage").is_err());
    }
}
