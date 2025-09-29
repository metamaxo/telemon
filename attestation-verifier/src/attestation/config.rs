use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::Duration,
};

#[derive(Debug, Clone)]
/// Parameters that drive signature verification, trust anchors, and policy checks.
pub struct VerifierConfig {
    /// One or more PEM files containing AWS Nitro Enclaves root(s) you trust.
    pub root_pem_paths: Vec<PathBuf>,
    /// Optional SHA-256 fingerprints you accept for roots (uppercase hex with colons).
    pub allowed_root_fingerprints: HashSet<String>,
    /// Freshness window for attestation timestamp (e.g., 5 minutes).
    pub freshness: Duration,
    /// Expected PCR values (index -> 48-byte SHA384).
    pub expected_pcrs: HashMap<u8, Vec<u8>>,
    /// Optional expected measurement (PCR0 shortcut).
    pub expected_measurement: Option<Vec<u8>>,
    /// If set, require TLS SPKI to match the attested SPKI.
    pub bind_tls_spki: bool,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            root_pem_paths: Vec::new(),
            allowed_root_fingerprints: HashSet::new(),
            freshness: Duration::from_secs(300),
            expected_pcrs: HashMap::new(),
            expected_measurement: None,
            bind_tls_spki: true,
        }
    }
}
