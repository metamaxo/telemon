use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine as _;
use rustls::ServerConfig;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, serde::Serialize)]
/// JSON response envelope sent back to verifiers.
pub struct AttestationResponse {
    /// Fields coming from the fresh NSM attestation (built per verifier nonce).
    pub attestation: AttestationFields,
    /// The server's TLS leaf certificate (DER, base64) to pin after validation.
    pub cert_der_b64: String,
}

#[derive(Clone, serde::Serialize)]
/// Detailed attestation fields returned by `/attestation`.
pub struct AttestationFields {
    /// Raw NSM COSE_Sign1 attestation (base64).
    pub quote_b64: String,
    /// Echo of the verifier-supplied nonce (base64).
    pub nonce_b64: String,
    /// SPKI (DER) the enclave included in the attestation (base64).
    pub spki_der_b64: String,
    /// Static policy tag for clarity (e.g., "aws-nitro-nsm").
    pub policy: String,
    /// Runner version string.
    pub runner_version: String,
    /// CABundle returned by NSM (base64 DER, leaf excluded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cabundle_der_b64: Option<Vec<String>>,
    /// Hex-encoded PCR values keyed by PCR index.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pcrs_hex: Option<BTreeMap<String, String>>,
    /// Convenience alias for PCR0 (measurement) if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurement_hex: Option<String>,
    /// Module identifier emitted by NSM.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_id: Option<String>,
    /// Digest algorithm used by NSM for PCR bank.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Timestamp of the attestation document (ms since Unix epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
    /// Optional user data (base64) bound into the attestation document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_data_b64: Option<String>,
    /// Attestation signing certificate DER emitted by NSM (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_cert_der_b64: Option<String>,
}

/// RA-TLS materials shared between the listener and HTTP handlers.
#[derive(Clone)]
pub struct RaTlsMaterial {
    pub server_config: Arc<ServerConfig>,
    pub attestation: AttestationResponse,
    #[allow(dead_code)]
    pub generated_at: std::time::SystemTime,
    pub cert_der: Arc<[u8]>,
    pub spki_der: Arc<[u8]>,
}

/// Build `AttestationFields` from the result emitted by NSM.
pub fn attestation_fields_from_nsm(out: &crate::attest::NsmAttestationOut) -> AttestationFields {
    let doc = &out.doc;

    let cabundle_der_b64 = if doc.cabundle.is_empty() {
        None
    } else {
        Some(doc.cabundle.iter().map(|c| b64.encode(c)).collect())
    };

    let mut pcrs_hex = BTreeMap::new();
    for (idx, value) in &doc.pcrs {
        pcrs_hex.insert(idx.to_string(), hex::encode(value));
    }
    let measurement_hex = pcrs_hex.get("0").cloned();

    let user_data_b64 = doc.user_data.as_ref().map(|ud| b64.encode(ud));

    AttestationFields {
        quote_b64: b64.encode(&out.quote),
        nonce_b64: b64.encode(&doc.nonce),
        spki_der_b64: b64.encode(&doc.public_key),
        policy: out.policy.clone(),
        runner_version: out.runner_version.clone(),
        cabundle_der_b64,
        pcrs_hex: if pcrs_hex.is_empty() {
            None
        } else {
            Some(pcrs_hex)
        },
        measurement_hex,
        module_id: Some(doc.module_id.clone()),
        digest: Some(doc.digest.clone()),
        timestamp_ms: Some(doc.timestamp_ms),
        user_data_b64,
        attestation_cert_der_b64: Some(b64.encode(&doc.certificate)),
    }
}

/// Combine previously computed attestation fields with the presented TLS certificate.
pub fn attestation_response_from_fields(
    fields: AttestationFields,
    cert_der: &[u8],
) -> AttestationResponse {
    let cert_der_b64 = b64.encode(cert_der);
    AttestationResponse {
        attestation: fields,
        cert_der_b64,
    }
}

/// Convenience helper that generates the full attestation response for a TLS session.
pub fn attestation_response_from_nsm(
    out: &crate::attest::NsmAttestationOut,
    cert_der: &[u8],
) -> AttestationResponse {
    let fields = attestation_fields_from_nsm(out);
    attestation_response_from_fields(fields, cert_der)
}
