use crate::config::Config;
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::sync::Arc;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

use rcgen::{Certificate, CertificateParams};
use x509_parser::prelude::*;

/// TLS-only bundle (no attestation)
pub struct TlsBundle {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub spki_der: Vec<u8>,
}

/// Minimal self-signed cert/key. No CN/SAN/EKU; trust comes from NSM (SPKI binding).
pub async fn build_tls_keypair(_cfg: &Config) -> Result<TlsBundle> {
    info!("Generating minimal self-signed TLS certificate");

    let params = CertificateParams::default();
    let cert = Certificate::from_params(params).context("rcgen: from_params")?;

    let cert_der = cert.serialize_der().context("rcgen: serialize cert der")?;
    let mut key_der = cert.serialize_private_key_der();
    let spki_der = extract_spki_der(&cert_der).context("extract SPKI from cert")?;

    let out = TlsBundle {
        cert_der,
        key_der: key_der.clone(),
        spki_der,
    };
    key_der.zeroize();
    Ok(out)
}

/// Extract SubjectPublicKeyInfo (SPKI) DER from a certificate DER.
fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = X509Certificate::from_der(cert_der).context("parse x509 der")?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}

/// Public listener TLS: no client auth (vsock-only).
pub fn tls_server_no_client_auth(cert_der: &[u8], key_der: &[u8]) -> Result<Arc<ServerConfig>> {
    info!("Configuring TLS for public listener (no client auth)");

    debug!(
        "Parsing server certificate from DER ({} bytes)",
        cert_der.len()
    );
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    if certs.is_empty() {
        warn!("No certificates found in provided DER data");
        anyhow::bail!("No certificates provided for TLS server");
    }

    debug!("Parsing private key from DER ({} bytes)", key_der.len());
    let mut key_bytes = key_der.to_vec();
    let key = PrivatePkcs8KeyDer::from(key_bytes.clone()).into();
    key_bytes.zeroize();

    debug!("Building rustls ServerConfig...");
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to configure rustls with certificate and key")?;

    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
