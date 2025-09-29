use crate::attestation::config::VerifierConfig;
use crate::attestation::cose::ParsedCose;
use crate::attestation::types::AttestationBlock;
use crate::attestation::util::{eq_hex, sha256_fingerprint};
use hex::FromHex;
use std::fmt::Write;

/// Ensures measured PCRs match local policy (including optional PCR0 shortcut).
pub fn verify_pcr_policy(
    cfg: &VerifierConfig,
    block: &AttestationBlock,
    parsed: &ParsedCose,
) -> Result<(), String> {
    if parsed.digest != block.digest {
        return Err(format!(
            "digest mismatch between COSE payload ('{}') and response ('{}')",
            parsed.digest, block.digest
        ));
    }
    if parsed.digest.to_ascii_uppercase() != "SHA384" {
        return Err(format!(
            "unexpected digest '{}' (expected SHA384)",
            parsed.digest
        ));
    }

    // Cross-check measurement_hex with PCR0 if both present.
    if let Some(measurement_hex) = &block.measurement_hex {
        if let Some(pcr0_hex) = block.pcrs_hex.get("0") {
            if !eq_hex(measurement_hex, pcr0_hex) {
                return Err("measurement_hex != PCR0".into());
            }
        }
    }

    // Ensure parsed PCR map aligns with JSON snapshot for indexes we care about.
    for (idx_str, hex_value) in &block.pcrs_hex {
        if let Some(parsed_bytes) = parsed.pcrs.get(idx_str) {
            let json_bytes = Vec::from_hex(hex_value)
                .map_err(|e| format!("PCR{idx_str} hex parse error: {e}"))?;
            if parsed_bytes != &json_bytes {
                let mut msg = String::new();
                write!(
                    &mut msg,
                    "PCR{} mismatch between payload ({}) and response ({})",
                    idx_str,
                    sha256_fingerprint(parsed_bytes),
                    sha256_fingerprint(&json_bytes)
                )
                .ok();
                return Err(msg);
            }
        }
    }

    for (&idx, want_bytes) in &cfg.expected_pcrs {
        let key = idx.to_string();
        let Some(hex_value) = block.pcrs_hex.get(&key) else {
            return Err(format!("missing PCR{idx} in response"));
        };
        let actual = Vec::from_hex(hex_value).map_err(|e| format!("PCR{idx} parse error: {e}"))?;
        if &actual != want_bytes {
            return Err(format!("PCR{idx} mismatch"));
        }
    }

    if let Some(expected) = &cfg.expected_measurement {
        let source_hex = block
            .pcrs_hex
            .get("0")
            .or(block.measurement_hex.as_ref())
            .ok_or_else(|| "missing PCR0/measurement".to_string())?;
        let actual =
            Vec::from_hex(source_hex).map_err(|e| format!("measurement parse error: {e}"))?;
        if &actual != expected {
            return Err("PCR0 measurement mismatch".into());
        }
    }

    Ok(())
}
