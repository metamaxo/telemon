use super::config::VerifierConfig;
use super::cose::verify_quote;
use super::errors::AttnError;
use super::pcr::verify_pcr_policy;
use super::types::{AttestationEnvelope, VerifiedAttestation};
use super::util::{constant_time_eq, decode_b64, now_millis};
use crate::attestation::certs::{load_pinned_roots, verify_chain, ChainSummary, RootStore};
use x509_parser::prelude::*;

/// Attestation verifier with cached trust anchors.
pub struct Verifier {
    cfg: VerifierConfig,
    roots: RootStore,
    fingerprint_subject: std::collections::HashMap<String, String>,
}

impl Verifier {
    /// Constructs a verifier and pre-loads root certificates according to `cfg`.
    pub fn new(cfg: VerifierConfig) -> anyhow::Result<Self> {
        let root_store = load_pinned_roots(&cfg.root_pem_paths, &cfg.allowed_root_fingerprints)?;
        let fingerprint_subject = root_store
            .metadata
            .iter()
            .map(|meta| (meta.fingerprint.clone(), meta.subject_display.clone()))
            .collect();
        Ok(Self {
            cfg,
            roots: root_store,
            fingerprint_subject,
        })
    }

    /// Verifies an attestation JSON document produced by the enclave runner.
    pub fn verify_json(
        &self,
        json: &str,
        expected_nonce_b64: &str,
    ) -> Result<VerifiedAttestation, AttnError> {
        let env: AttestationEnvelope =
            serde_json::from_str(json).map_err(|e| AttnError::Decode(format!("json: {e}")))?;
        self.verify_envelope(&env, expected_nonce_b64)
    }

    /// Verifies a parsed attestation envelope against the expected nonce.
    pub fn verify_envelope(
        &self,
        env: &AttestationEnvelope,
        expected_nonce_b64: &str,
    ) -> Result<VerifiedAttestation, AttnError> {
        let block = &env.attestation;

        if block.nonce_b64 != expected_nonce_b64 {
            return Err(AttnError::NonceMismatch);
        }

        let now_ms = now_millis();
        let drift = now_ms.abs_diff(block.timestamp_ms);
        if drift > self.cfg.freshness.as_millis() as u64 {
            return Err(AttnError::StaleTimestamp);
        }

        let leaf_der = decode_b64("attestation_cert_der_b64", &block.attestation_cert_der_b64)?;
        let leaf_cert = parse_x509_certificate(&leaf_der)
            .map_err(|e| AttnError::ChainBuild(format!("parse attestation leaf: {e}")))?
            .1;
        let leaf_public_key = leaf_cert
            .tbs_certificate
            .subject_pki
            .subject_public_key
            .data
            .to_vec();

        let parsed_quote = verify_quote(&block.quote_b64, &leaf_public_key)?;

        let expected_nonce = decode_b64("expected nonce", expected_nonce_b64)?;
        let attestation_nonce = decode_b64("attestation nonce", &block.nonce_b64)?;
        if attestation_nonce != expected_nonce {
            return Err(AttnError::NonceMismatch);
        }
        if parsed_quote.nonce != expected_nonce {
            return Err(AttnError::NonceMismatch);
        }

        let attested_spki = decode_b64("spki_der_b64", &block.spki_der_b64)?;
        if parsed_quote.public_key != attested_spki {
            return Err(AttnError::CoseInvalid(
                "attestation payload public_key mismatch".into(),
            ));
        }

        if let Some(user_data_b64) = &block.user_data_b64 {
            let user_data = decode_b64("user_data_b64", user_data_b64)?;
            let payload_ud = parsed_quote
                .user_data
                .as_ref()
                .ok_or_else(|| AttnError::CoseInvalid("user_data missing in payload".into()))?;
            if &user_data != payload_ud {
                return Err(AttnError::CoseInvalid(
                    "user_data mismatch between payload and response".into(),
                ));
            }
        }

        if parsed_quote.module_id != block.module_id {
            return Err(AttnError::CoseInvalid(
                "module_id mismatch between payload and response".into(),
            ));
        }
        if parsed_quote.timestamp_ms != block.timestamp_ms {
            return Err(AttnError::CoseInvalid(
                "timestamp mismatch between payload and response".into(),
            ));
        }

        let intermediates = decode_cabundle(&block.cabundle_der_b64)?;
        let ChainSummary {
            leaf_fingerprint,
            root_fingerprint,
            root_subject,
        } = verify_chain(&leaf_der, &intermediates, &self.roots)?;

        verify_pcr_policy(&self.cfg, block, &parsed_quote).map_err(|e| AttnError::PcrPolicy(e))?;

        let mut spki_bound = true;
        if self.cfg.bind_tls_spki {
            spki_bound = match (&env.cert_der_b64, &block.spki_der_b64) {
                (Some(tls_cert_b64), spki_b64) => {
                    let tls_der = decode_b64("cert_der_b64", tls_cert_b64)?;
                    let tls_spki = extract_spki(&tls_der)
                        .map_err(|e| AttnError::Internal(format!("extract TLS SPKI: {e}")))?;
                    let att_spki = decode_b64("spki_der_b64", spki_b64)?;
                    constant_time_eq(&tls_spki, &att_spki)
                }
                _ => false,
            };
            if !spki_bound {
                return Err(AttnError::SpkiBinding);
            }
        }

        let used_root_subject = self
            .fingerprint_subject
            .get(&root_fingerprint)
            .cloned()
            .unwrap_or(root_subject);

        Ok(VerifiedAttestation {
            module_id: block.module_id.clone(),
            timestamp_ms: block.timestamp_ms,
            leaf_fingerprint_sha256: leaf_fingerprint,
            root_fingerprint_sha256: root_fingerprint,
            used_root_subject,
            pcrs_ok: true,
            spki_bound,
        })
    }
}

/// Decodes base64-encoded intermediates from the attestation response, keeping non-self-signed nodes.
fn decode_cabundle(entries: &[String]) -> Result<Vec<Vec<u8>>, AttnError> {
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let der = decode_b64("cabundle entry", entry)?;
        if !is_self_signed(&der)? {
            out.push(der);
        }
    }
    Ok(out)
}

fn is_self_signed(der: &[u8]) -> Result<bool, AttnError> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| AttnError::Decode(format!("cabundle parse: {e}")))?;
    Ok(cert.tbs_certificate.subject == cert.tbs_certificate.issuer)
}

fn extract_spki(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert_der).map_err(|e| format!("x509 parse: {e}"))?;
    Ok(cert.tbs_certificate.subject_pki.raw.to_vec())
}
