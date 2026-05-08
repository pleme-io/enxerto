//! TLS for the webhook server itself. K8s API server only sends
//! AdmissionReviews to webhooks over HTTPS, with the cert validated
//! against the `caBundle` configured on the
//! `MutatingWebhookConfiguration`.
//!
//! M2.2 reads the cert + key from filesystem paths (mounted via a
//! cert-manager-issued Secret). M5+ swaps to SPIFFE-issued certs so
//! the webhook eats its own dogfood.

use std::path::Path;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cert pem parse: {0}")]
    CertPem(String),
    #[error("key pem parse: {0}")]
    KeyPem(String),
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
}

pub fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig, TlsError> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertPem(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::CertPem("no certs in pem".into()));
    }

    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::KeyPem(e.to_string()))?
        .ok_or_else(|| TlsError::KeyPem("no private key in pem".into()))?;

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(cfg)
}

#[must_use]
pub fn arc(cfg: ServerConfig) -> Arc<ServerConfig> {
    Arc::new(cfg)
}
