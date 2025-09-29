use crate::state::{AttestationFields, AttestationResponse, PublicState};
use axum::http::StatusCode;
use axum::{extract::State, Json};
use base64::engine::general_purpose;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use tokio::signal;
use tracing::{debug, warn};

/// Liveness probe endpoint.
pub async fn ready() -> &'static str {
    "ready"
}

#[derive(Serialize)]
/// Static response body for `/health`.
pub struct Health {
    pub status: &'static str,
}

/// Readiness/health-check endpoint used by the parent instance.
pub async fn health(State(_state): State<PublicState>) -> (StatusCode, Json<Health>) {
    (StatusCode::OK, Json(Health { status: "ok" }))
}

#[derive(Deserialize)]
/// Incoming JSON body for `/attestation` requests.
pub struct AttestationRequest {
    /// Verifier-provided nonce (base64). Must be fresh/single-use on verifier side.
    pub nonce_b64: String,
}

/// Attestation-on-demand:
/// Accepts nonce -> calls NSM with { public_key = SPKI, nonce } -> returns COSE + metadata + TLS cert.
pub async fn attestation_handler(
    State(state): State<PublicState>,
    Json(req): Json<AttestationRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let b64 = |bytes: &[u8]| general_purpose::STANDARD.encode(bytes);

    // Decode + sanity-check nonce
    let nonce = match general_purpose::STANDARD.decode(req.nonce_b64.as_bytes()) {
        Ok(n) if !n.is_empty() && n.len() <= 1024 => n,
        Ok(n) => {
            warn!(len = n.len(), "invalid nonce length");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_nonce_length" })),
            );
        }
        Err(e) => {
            warn!(error=?e, "bad nonce base64");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_nonce_base64" })),
            );
        }
    };

    // Call NSM: build fresh COSE_Sign1 attestation bound to our SPKI + the nonce
    match crate::attest::build_nsm_attestation(&state.spki_der, &nonce).await {
        Ok(nsm_out) => {
            debug!(
                quote_len = nsm_out.quote.len(),
                "fresh NSM attestation built"
            );

            // (optional) structured log – comment out if you removed logging helper
            // crate::logging::log_attestation_summary(&nsm_out.quote, &nonce, &state.spki_der, &state.cert_der, &nsm_out.policy, &nsm_out.runner_version);

            let doc = &nsm_out.doc;

            let cabundle_der_b64 = if doc.cabundle.is_empty() {
                None
            } else {
                Some(doc.cabundle.iter().map(|c| b64(c)).collect())
            };

            let mut pcrs_hex = BTreeMap::new();
            for (idx, value) in &doc.pcrs {
                pcrs_hex.insert(idx.to_string(), hex::encode(value));
            }
            let measurement_hex = pcrs_hex.get("0").cloned();

            let user_data_b64 = doc.user_data.as_ref().map(|ud| b64(ud));

            let out = AttestationResponse {
                attestation: AttestationFields {
                    quote_b64: b64(&nsm_out.quote),
                    nonce_b64: b64(&doc.nonce),
                    spki_der_b64: b64(&doc.public_key),
                    policy: nsm_out.policy,
                    runner_version: nsm_out.runner_version,
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
                    attestation_cert_der_b64: Some(b64(&doc.certificate)),
                },
                cert_der_b64: b64(&state.cert_der),
            };

            (
                StatusCode::OK,
                Json(serde_json::to_value(&out).expect("serialize AttestationResponse")),
            )
        }
        Err(e) => {
            warn!(error=?e, "attestation build failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "attestation_failed" })),
            )
        }
    }
}

/// Blocks until Ctrl+C (or SIGTERM on Unix) to trigger graceful shutdown.
pub async fn shutdown_signal() {
    let ctrl_c = async { signal::ctrl_c().await.expect("install Ctrl+C handler") };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("install signal handler");
        sigterm.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = terminate => {}, };
}
