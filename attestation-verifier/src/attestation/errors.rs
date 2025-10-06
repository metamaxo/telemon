use thiserror::Error;

#[derive(Debug, Error)]
/// High-level error taxonomy consumers can match on when verification fails.
pub enum AttnError {
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("stale timestamp")]
    StaleTimestamp,
    #[error("attestation COSE/CBOR invalid or signature failed: {0}")]
    CoseInvalid(String),
    #[error("certificate chain build failed: {0}")]
    ChainBuild(String),
    #[error("root not in allowlist")]
    RootUntrusted,
    #[error("PCR policy failed: {0}")]
    PcrPolicy(String),
    #[error("SPKI binding failed")]
    SpkiBinding,
    #[error("RA-TLS peer certificate mismatch")]
    PeerCertificateMismatch,
    #[error("decode error: {0}")]
    Decode(String),
    #[error("internal: {0}")]
    Internal(String),
}
