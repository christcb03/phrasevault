//! TLS for destinations (PVOS D222d decision 8): always verified — by the
//! public roots, or only by a CA file's, or only by one pinned certificate.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

use super::config::TlsSettings;

/// 64 hex characters (colons and spaces ignored) → the 32 bytes.
pub fn parse_pin(pin: &str) -> Option<[u8; 32]> {
    let hex: String = pin.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 64 || pin.chars().any(|c| !(c.is_ascii_hexdigit() || c == ':' || c == ' ')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[derive(Debug)]
struct PinnedSha256 {
    pin: [u8; 32],
}

fn provider() -> rustls::crypto::CryptoProvider {
    rustls::crypto::ring::default_provider()
}

impl ServerCertVerifier for PinnedSha256 {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if got == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("the server's certificate is not the pinned one".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &provider().signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

pub fn client_config(t: &TlsSettings) -> Result<Arc<ClientConfig>, String> {
    let builder = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls: {e}"))?;
    if let Some(pin) = &t.pin_sha256 {
        let pin = parse_pin(pin).ok_or("tls: pin_sha256 is not 64 hex characters")?;
        return Ok(Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedSha256 { pin }))
                .with_no_client_auth(),
        ));
    }
    let mut roots = RootCertStore::empty();
    match &t.ca_file {
        Some(path) => {
            let pem = std::fs::read(path).map_err(|e| format!("tls: ca_file {path}: {e}"))?;
            let mut n = 0;
            for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
                let cert = cert.map_err(|e| format!("tls: ca_file {path}: {e}"))?;
                roots.add(cert).map_err(|e| format!("tls: ca_file {path}: {e}"))?;
                n += 1;
            }
            if n == 0 {
                return Err(format!("tls: ca_file {path} holds no certificate"));
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(Arc::new(builder.with_root_certificates(roots).with_no_client_auth()))
}

pub fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    let h = host.trim_start_matches('[').trim_end_matches(']').to_string();
    ServerName::try_from(h).map_err(|e| format!("tls: server name {host:?}: {e}"))
}
