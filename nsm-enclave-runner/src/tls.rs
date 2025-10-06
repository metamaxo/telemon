use crate::state::{
    attestation_fields_from_nsm, attestation_response_from_fields, AttestationFields, RaTlsMaterial,
};
use anyhow::{anyhow, Context};
use rand::RngCore;
use rcgen::{Certificate, CertificateParams, CustomExtension, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{debug, info, warn};
use zeroize::Zeroize;

/// Private OID (1.3.6.1.4.1.57264.1.1) carrying the attestation payload in the RA-TLS cert.
const RATLS_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];

pub async fn generate_ratls_material(validity: Duration) -> Result<RaTlsMaterial, RaTlsBuildError> {
    let algorithm = &rcgen::PKCS_ECDSA_P384_SHA384;
    let key_pair = KeyPair::generate(algorithm).map_err(RaTlsBuildError::Keygen)?;
    let spki_der = key_pair.public_key_der();

    let nonce = random_nonce();
    let attn = crate::attest::build_nsm_attestation(&spki_der, &nonce)
        .await
        .map_err(RaTlsBuildError::Nsm)?;
    let attn_fields = attestation_fields_from_nsm(&attn);

    let (cert_der, mut key_der) =
        build_attested_certificate(key_pair, attn_fields.clone(), validity)?;

    let server_config =
        tls_server_no_client_auth(&cert_der, &key_der).map_err(RaTlsBuildError::Tls)?;

    let attestation = attestation_response_from_fields(attn_fields, &cert_der);

    let cert_der_arc: Arc<[u8]> = Arc::from(cert_der);
    let spki_der_arc: Arc<[u8]> = Arc::from(spki_der);

    key_der.zeroize();

    Ok(RaTlsMaterial {
        server_config,
        attestation,
        generated_at: SystemTime::now(),
        cert_der: cert_der_arc,
        spki_der: spki_der_arc,
    })
}

fn build_attested_certificate(
    key_pair: KeyPair,
    attn_fields: AttestationFields,
    validity: Duration,
) -> Result<(Vec<u8>, Vec<u8>), RaTlsBuildError> {
    let mut params = CertificateParams::default();
    params.alg = &rcgen::PKCS_ECDSA_P384_SHA384;
    params.not_before = OffsetDateTime::now_utc() - TimeDuration::minutes(1);
    params.not_after = OffsetDateTime::now_utc()
        + TimeDuration::try_from(validity)
            .map_err(|e| RaTlsBuildError::Cert(anyhow::Error::new(e)))?;
    params.key_pair = Some(key_pair);

    let attn_json = serde_json::to_vec(&attn_fields)
        .map_err(|e| RaTlsBuildError::Cert(anyhow::Error::new(e)))?;
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(RATLS_OID, attn_json));

    let cert = Certificate::from_params(params)
        .map_err(|e| RaTlsBuildError::Cert(anyhow::Error::new(e)))?;
    let cert_der = cert
        .serialize_der()
        .map_err(|e| RaTlsBuildError::Cert(anyhow::Error::new(e)))?;
    let key_der = cert.serialize_private_key_der();

    Ok((cert_der, key_der))
}

#[derive(Debug, Error)]
pub enum RaTlsBuildError {
    #[error("key generation failed: {0}")]
    Keygen(#[from] rcgen::Error),
    #[error("NSM attestation failed: {0}")]
    Nsm(#[source] anyhow::Error),
    #[error("certificate build failed: {0}")]
    Cert(#[source] anyhow::Error),
    #[error("TLS config failed: {0}")]
    Tls(#[source] anyhow::Error),
}

fn random_nonce() -> [u8; 32] {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// Public listener TLS: no client auth (vsock-only).
fn tls_server_no_client_auth(cert_der: &[u8], key_der: &[u8]) -> anyhow::Result<Arc<ServerConfig>> {
    info!("Configuring TLS for public listener (RA-TLS)");

    debug!(
        "Parsing server certificate from DER ({} bytes)",
        cert_der.len()
    );
    let certs = vec![CertificateDer::from(cert_der.to_vec())];
    if certs.is_empty() {
        warn!("No certificates found in provided DER data");
        return Err(anyhow!("No certificates provided for TLS server"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AttestationFields;
    use rcgen::PKCS_ECDSA_P384_SHA384;
    use x509_parser::{der_parser::oid::Oid, prelude::parse_x509_certificate};

    #[test]
    fn build_attested_certificate_embeds_attestation_extension() {
        let key_pair = KeyPair::generate(&PKCS_ECDSA_P384_SHA384).expect("generate key");
        let fields = AttestationFields {
            quote_b64: "cXVvdGU=".to_string(),
            nonce_b64: "bm9uY2U=".to_string(),
            spki_der_b64: "c3BraQ==".to_string(),
            policy: "aws-nitro-nsm".to_string(),
            runner_version: "test-runner".to_string(),
            cabundle_der_b64: None,
            pcrs_hex: None,
            measurement_hex: None,
            module_id: Some("module-123".to_string()),
            digest: Some("SHA384".to_string()),
            timestamp_ms: Some(1_700_000_000),
            user_data_b64: None,
            attestation_cert_der_b64: Some("Y2VydA==".to_string()),
        };

        let (cert_der, key_der) =
            build_attested_certificate(key_pair, fields.clone(), Duration::from_secs(600))
                .expect("build cert");

        assert!(!cert_der.is_empty());
        assert!(!key_der.is_empty());

        let (_, cert) = parse_x509_certificate(&cert_der).expect("parse x509");
        let ratls_oid = Oid::from(&RATLS_OID[..]).expect("valid RA-TLS OID");
        let extension = cert
            .tbs_certificate
            .extensions()
            .iter()
            .find(|ext| ext.oid == ratls_oid)
            .expect("ratls extension present");

        let expected = serde_json::to_vec(&fields).expect("serialize fields");
        assert_eq!(extension.value, expected);
    }
}
