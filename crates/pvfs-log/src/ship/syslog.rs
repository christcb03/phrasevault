//! syslog transports (PVOS D222d decision 4): UDP (one datagram per message,
//! cut at 8 KiB), TCP with RFC 6587 octet counting, and TLS (RFC 5425: the
//! same framing over TLS, the server verified).

use std::io::Write;
use std::net::{ToSocketAddrs, UdpSocket};

use super::config::{SyslogTransport, TlsSettings};

const UDP_MAX: usize = 8192;

fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn split_host_port(address: &str) -> Result<(String, u16), String> {
    let (h, p) = address.rsplit_once(':').ok_or_else(|| format!("{address:?} is not host:port"))?;
    let port = p.parse::<u16>().map_err(|_| format!("{address:?}: port {p:?}"))?;
    Ok((h.trim_start_matches('[').trim_end_matches(']').to_string(), port))
}

pub fn send(address: &str, transport: SyslogTransport, tls: &TlsSettings, msgs: &[String]) -> Result<(), String> {
    let (host, port) = split_host_port(address)?;
    match transport {
        SyslogTransport::Udp => {
            let to = (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| format!("{address}: {e}"))?
                .next()
                .ok_or_else(|| format!("{address}: no address"))?;
            let sock = UdpSocket::bind(if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| format!("udp: {e}"))?;
            for m in msgs {
                sock.send_to(cut(m, UDP_MAX).as_bytes(), to).map_err(|e| format!("udp {address}: {e}"))?;
            }
            Ok(())
        }
        SyslogTransport::Tcp | SyslogTransport::Tls => {
            let mut framed = Vec::new();
            for m in msgs {
                framed.extend_from_slice(format!("{} ", m.len()).as_bytes());
                framed.extend_from_slice(m.as_bytes());
            }
            let tcp = super::http::connect(&host, port)?;
            if transport == SyslogTransport::Tls {
                let cfg = super::tls::client_config(tls)?;
                let conn = rustls::ClientConnection::new(cfg, super::tls::server_name(&host)?).map_err(|e| format!("tls: {e}"))?;
                let mut s = rustls::StreamOwned::new(conn, tcp);
                s.write_all(&framed).map_err(|e| format!("tls {address}: {e}"))?;
                s.flush().map_err(|e| format!("tls {address}: {e}"))?;
                s.conn.send_close_notify();
                let _ = s.conn.complete_io(&mut s.sock);
            } else {
                let mut s = tcp;
                s.write_all(&framed).map_err(|e| format!("tcp {address}: {e}"))?;
                s.flush().map_err(|e| format!("tcp {address}: {e}"))?;
                let _ = s.shutdown(std::net::Shutdown::Write);
            }
            Ok(())
        }
    }
}
