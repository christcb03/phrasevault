//! GELF transports (PVOS D222e decision 2): UDP (one datagram per record,
//! cut to fit), TCP (each document ends with a NUL byte) and HTTP (one POST
//! per record, Graylog's GELF HTTP input).

use std::io::Write;
use std::net::{ToSocketAddrs, UdpSocket};

use super::config::TlsSettings;
use super::http::Url;

pub const UDP_MAX: usize = 8192;

fn host_port(address: &str) -> Result<(String, u16), String> {
    let (h, p) = address.rsplit_once(':').ok_or_else(|| format!("{address:?} is not host:port"))?;
    let port = p.parse::<u16>().map_err(|_| format!("{address:?}: port {p:?}"))?;
    Ok((h.trim_start_matches('[').trim_end_matches(']').to_string(), port))
}

pub fn send_udp(address: &str, docs: &[String]) -> Result<(), String> {
    let (host, port) = host_port(address)?;
    let to = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("{address}: {e}"))?
        .next()
        .ok_or_else(|| format!("{address}: no address"))?;
    let sock = UdpSocket::bind(if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).map_err(|e| format!("udp: {e}"))?;
    for d in docs {
        sock.send_to(d.as_bytes(), to).map_err(|e| format!("gelf udp {address}: {e}"))?;
    }
    Ok(())
}

pub fn send_tcp(address: &str, docs: &[String]) -> Result<(), String> {
    let (host, port) = host_port(address)?;
    let mut s = super::http::connect(&host, port)?;
    let mut buf = Vec::new();
    for d in docs {
        buf.extend_from_slice(d.as_bytes());
        buf.push(0);
    }
    s.write_all(&buf).map_err(|e| format!("gelf tcp {address}: {e}"))?;
    s.flush().map_err(|e| format!("gelf tcp {address}: {e}"))?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    Ok(())
}

pub fn send_http(url: &Url, tls: &TlsSettings, headers: &[(String, String)], docs: &[String]) -> Result<(), String> {
    let path = url.path_or("/gelf");
    for d in docs {
        let (code, text) = super::http::post(url, &path, tls, headers, d.as_bytes())?;
        if !(200..300).contains(&code) {
            return Err(format!("GELF answered {code}: {}", text.chars().take(200).collect::<String>()));
        }
    }
    Ok(())
}
