use crate::attestation::errors::AttnError;
use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use ring::digest::{digest, SHA256};
use std::time::{SystemTime, UNIX_EPOCH};

/// Formats a SHA-256 digest as uppercase colon-separated hex.
pub fn sha256_fingerprint(data: &[u8]) -> String {
    let d = digest(&SHA256, data);
    let mut out = String::with_capacity(d.as_ref().len() * 3);
    for (idx, byte) in d.as_ref().iter().enumerate() {
        if idx > 0 {
            out.push(':');
        }
        out.push_str(&format!("{:02X}", byte));
    }
    out
}

/// Constant-time comparison for equal-length byte slices.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    acc == 0
}

/// Returns the current Unix timestamp in milliseconds.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Case-insensitive hex comparison supporting optional `0x` prefixes.
pub fn eq_hex(a: &str, b: &str) -> bool {
    let na = a.trim_start_matches("0x");
    let nb = b.trim_start_matches("0x");
    na.eq_ignore_ascii_case(nb)
}

/// Base64-decodes `value`, tagging errors with the provided label.
pub fn decode_b64(label: &str, value: &str) -> Result<Vec<u8>, AttnError> {
    b64.decode(value.as_bytes())
        .map_err(|e| AttnError::Decode(format!("{label}: {e}")))
}
