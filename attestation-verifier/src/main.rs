use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use env_logger::Env;
use nitro_verifier::attestation::{AttnError, Verifier, VerifierConfig};
use rand::RngCore;
use serde_json::Value as JsonValue;
use std::{collections::HashMap, env, fs, path::PathBuf, time::Duration};

type CliResult<T> = Result<T, anyhow::Error>;

const AWS_COMMERCIAL_ROOT_FP: &str = "64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B";

/// CLI entrypoint: loads policy configuration, fetches attestation, and prints a summary.
#[tokio::main]
async fn main() -> CliResult<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .try_init()
        .ok();

    let root_pem = resolve_root_pem_path()?;
    let expected_pcrs = load_expected_pcrs()?;
    let expected_measurement = load_expected_measurement().ok();

    let mut cfg = VerifierConfig::default();
    cfg.root_pem_paths = vec![root_pem];
    cfg.allowed_root_fingerprints = vec![AWS_COMMERCIAL_ROOT_FP.to_string()]
        .into_iter()
        .collect();
    cfg.expected_pcrs = expected_pcrs;
    cfg.expected_measurement = expected_measurement;
    cfg.freshness = Duration::from_secs(300);

    let verifier = Verifier::new(cfg)?;

    let (nonce_b64, attestation_json) = fetch_attestation().await?;

    match verifier.verify_json(&attestation_json, &nonce_b64) {
        Ok(result) => {
            println!("✅ Attestation verified:");
            println!("  module_id      : {}", result.module_id);
            println!("  timestamp_ms   : {}", result.timestamp_ms);
            println!("  leaf SHA256    : {}", result.leaf_fingerprint_sha256);
            println!("  root SHA256    : {}", result.root_fingerprint_sha256);
            println!("  root subject   : {}", result.used_root_subject);
            println!("  PCR policy ok  : {}", result.pcrs_ok);
            println!("  SPKI bound     : {}", result.spki_bound);
            Ok(())
        }
        Err(err) => Err(anyhow::anyhow!(format_attn_error(err))),
    }
}

/// Decide which root certificate PEM to trust based on CLI/env input.
fn resolve_root_pem_path() -> CliResult<PathBuf> {
    if let Ok(path) = env::var("NITRO_ROOT_PEM_PATH") {
        return Ok(PathBuf::from(path));
    }
    if let Some(arg) = env::args().nth(1) {
        return Ok(PathBuf::from(arg));
    }
    Err(anyhow::anyhow!(
        "provide root PEM path as first argument or set NITRO_ROOT_PEM_PATH"
    ))
}

/// Load the expected PCR json snapshot from disk.
fn load_expected_pcrs() -> CliResult<HashMap<u8, Vec<u8>>> {
    let (_, json) = read_json_from_env("NITRO_EXPECTED_PCRS_PATH")?;
    let mut map = HashMap::new();
    if let Some(pcr0) = json.get("pcr0").and_then(JsonValue::as_str) {
        map.insert(0u8, hex_to_bytes(pcr0)?);
    }
    if let Some(pcr1) = json.get("pcr1").and_then(JsonValue::as_str) {
        map.insert(1u8, hex_to_bytes(pcr1)?);
    }
    if let Some(pcr2) = json.get("pcr2").and_then(JsonValue::as_str) {
        map.insert(2u8, hex_to_bytes(pcr2)?);
    }
    Ok(map)
}

/// Convenience helper for fetching the expected measurement (PCR0) if present.
fn load_expected_measurement() -> Result<Vec<u8>, anyhow::Error> {
    let (_, json) = read_json_from_env("NITRO_MEASUREMENTS_PATH")?;
    let measurement = json
        .get("Measurements")
        .and_then(|m| m.get("PCR0"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow::anyhow!("Measurements.PCR0 not found in measurements JSON"))?;
    hex_to_bytes(measurement)
}

/// Read and parse a JSON file whose path is provided via environment variable.
fn read_json_from_env(var: &str) -> CliResult<(PathBuf, JsonValue)> {
    let path = env::var(var)
        .map(PathBuf::from)
        .map_err(|_| anyhow::anyhow!(format!("{var} not set")))?;
    let contents =
        fs::read_to_string(&path).map_err(|e| anyhow::anyhow!(format!("read {:?}: {e}", path)))?;
    let json: JsonValue = serde_json::from_str(&contents)
        .map_err(|e| anyhow::anyhow!(format!("parse JSON from {:?}: {e}", path)))?;
    Ok((path, json))
}

/// Decode a hex string that may optionally be prefixed with `0x`.
fn hex_to_bytes(hex_str: &str) -> CliResult<Vec<u8>> {
    let trimmed = hex_str.trim_start_matches("0x");
    let bytes =
        hex::decode(trimmed).map_err(|e| anyhow::anyhow!(format!("hex decode error: {e}")))?;
    Ok(bytes)
}

/// Generates a nonce, posts it to the local attestation endpoint, and returns both.
async fn fetch_attestation() -> CliResult<(String, String)> {
    let mut nonce = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let nonce_b64 = b64.encode(&nonce);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(15))
        .build()?;

    let response = client
        .post("https://127.0.0.1:8443/attestation")
        .json(&serde_json::json!({ "nonce_b64": nonce_b64 }))
        .send()
        .await?
        .error_for_status()?;

    let body = response.text().await?;
    Ok((nonce_b64, body))
}

/// Human-friendly rendering of `AttnError` variants for CLI output.
fn format_attn_error(err: AttnError) -> String {
    match err {
        AttnError::NonceMismatch => "nonce mismatch".into(),
        AttnError::StaleTimestamp => "stale timestamp".into(),
        AttnError::CoseInvalid(reason) => format!("COSE validation failed: {reason}"),
        AttnError::ChainBuild(reason) => format!("certificate chain failed: {reason}"),
        AttnError::RootUntrusted => "attestation root not trusted".into(),
        AttnError::PcrPolicy(reason) => format!("PCR policy failed: {reason}"),
        AttnError::SpkiBinding => "TLS SPKI binding failed".into(),
        AttnError::Decode(reason) => format!("decode error: {reason}"),
        AttnError::Internal(reason) => format!("internal error: {reason}"),
    }
}
