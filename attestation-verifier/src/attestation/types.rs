use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug)]
/// Summary returned to callers after successful verification.
pub struct VerifiedAttestation {
    pub module_id: String,
    pub timestamp_ms: u64,
    pub leaf_fingerprint_sha256: String,
    pub root_fingerprint_sha256: String,
    pub used_root_subject: String,
    pub pcrs_ok: bool,
    pub spki_bound: bool,
}

#[derive(Debug, Deserialize)]
/// Shape of the JSON envelope produced by the enclave runner.
pub struct AttestationEnvelope {
    pub attestation: AttestationBlock,
    /// Runner HTTPS leaf cert (DER, base64) – used only for SPKI binding (optional).
    #[serde(default)]
    pub cert_der_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
/// Inner attestation block that mirrors the NSM payload and helper metadata.
pub struct AttestationBlock {
    /// Raw NSM AttestationDocument, base64 (COSE_Sign1 over CBOR payload)
    pub quote_b64: String,
    /// Nonce you sent (base64)
    pub nonce_b64: String,
    /// Enclave TLS SPKI (DER, base64)
    pub spki_der_b64: String,
    pub policy: Option<String>,
    pub runner_version: Option<String>,
    /// 0..N intermediates/root (DER, base64)
    #[serde(default)]
    pub cabundle_der_b64: Vec<String>,
    /// Attestation signing cert (leaf, DER, base64)
    pub attestation_cert_der_b64: String,
    /// PCR map (index -> hex)
    #[serde(default)]
    pub pcrs_hex: HashMap<String, String>,
    /// Shortcut for PCR0 (hex)
    #[serde(default)]
    pub measurement_hex: Option<String>,
    pub module_id: String,
    pub digest: String, // expect "SHA384"
    pub timestamp_ms: u64,
    #[serde(default)]
    pub user_data_b64: Option<String>,
}
