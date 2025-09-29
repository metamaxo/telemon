use crate::config::Config;
use sha2::{Digest, Sha256, Sha384};
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

/// Install a `tracing` subscriber using either `RUNNER_LOG_LEVEL` or `RUST_LOG`.
pub fn setup_logging(cfg: &Config) {
    let default = cfg.log_level.as_deref().unwrap_or("info");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    debug!("logging initialized with log level: {:?}", &cfg.log_level);
}

/// Log a concise, non-sensitive summary of the attestation materials.
pub fn log_attestation_summary(
    quote: &[u8],    // NSM COSE_Sign1 bytes
    nonce: &[u8],    // verifier-provided nonce
    spki_der: &[u8], // TLS SPKI bound in the NSM doc
    cert_der: &[u8], // TLS leaf presented by the server
    policy: &str,    // e.g. "aws-nitro-nsm"
    runner_version: &str,
) {
    let quote_len = quote.len();
    let quote_first = quote.first().copied().unwrap_or(0);

    let quote_sha256 = Sha256::digest(quote);
    let quote_sha384 = Sha384::digest(quote);
    let spki_sha256 = Sha256::digest(spki_der);
    let cert_sha256 = Sha256::digest(cert_der);

    info!(
        target: "attestation",
        policy,
        runner_version,
        quote_len,
        quote_first_byte = format_args!("0x{:02x}", quote_first),
        quote_sha256 = %hex::encode(quote_sha256),
        quote_sha384 = %hex::encode(quote_sha384),
        nonce_len = nonce.len(),
        spki_der_len = spki_der.len(),
        spki_sha256 = %hex::encode(spki_sha256),
        cert_der_len = cert_der.len(),
        cert_sha256 = %hex::encode(cert_sha256),
        "attestation summary"
    );
}
