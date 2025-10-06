use crate::state::{attestation_response_from_nsm, RaTlsMaterial};
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::Json;
use base64::engine::general_purpose;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::signal;
use tracing::{debug, warn};

const MAX_NONCE_LEN: usize = 1024;

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
pub async fn health() -> (StatusCode, Json<Health>) {
    (StatusCode::OK, Json(Health { status: "ok" }))
}

#[derive(Deserialize)]
/// Incoming JSON body for `/attestation` requests.
pub struct AttestationRequest {
    /// Verifier-provided nonce (base64). Must be fresh/single-use on verifier side.
    pub nonce_b64: String,
}

fn resolve_snapshot(ext: Option<Extension<Arc<RaTlsMaterial>>>) -> Option<Arc<RaTlsMaterial>> {
    ext.map(|Extension(snapshot)| snapshot)
}

enum NonceError {
    InvalidLength(usize),
    InvalidBase64(base64::DecodeError),
}

impl NonceError {
    fn into_response(self) -> (StatusCode, Json<serde_json::Value>) {
        match self {
            NonceError::InvalidLength(len) => {
                warn!(len, "invalid nonce length");
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid_nonce_length" })),
                )
            }
            NonceError::InvalidBase64(error) => {
                warn!(error=?error, "bad nonce base64");
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "invalid_nonce_base64" })),
                )
            }
        }
    }
}

fn decode_nonce(nonce_b64: &str) -> Result<Vec<u8>, NonceError> {
    let decoded = general_purpose::STANDARD
        .decode(nonce_b64.as_bytes())
        .map_err(NonceError::InvalidBase64)?;
    if decoded.is_empty() || decoded.len() > MAX_NONCE_LEN {
        Err(NonceError::InvalidLength(decoded.len()))
    } else {
        Ok(decoded)
    }
}

/// Attestation-on-demand:
/// Accepts nonce -> calls NSM with { public_key = SPKI, nonce } -> returns COSE + metadata + TLS cert.
pub async fn attestation_handler(
    maybe_snapshot: Option<Extension<Arc<RaTlsMaterial>>>,
    Json(req): Json<AttestationRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Decode + sanity-check nonce
    let nonce = match decode_nonce(&req.nonce_b64) {
        Ok(bytes) => bytes,
        Err(err) => return err.into_response(),
    };

    let Some(snapshot) = resolve_snapshot(maybe_snapshot) else {
        warn!("RA-TLS snapshot missing from request context");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "ratls_context_unavailable" })),
        );
    };

    // Call NSM: build fresh COSE_Sign1 attestation bound to our SPKI + the nonce
    match crate::attest::build_nsm_attestation(&snapshot.spki_der, &nonce).await {
        Ok(nsm_out) => {
            debug!(
                quote_len = nsm_out.quote.len(),
                "fresh NSM attestation built"
            );

            let out = attestation_response_from_nsm(&nsm_out, &snapshot.cert_der);

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

/// Returns the RA-TLS attestation bundle associated with the currently active TLS cert.
pub async fn ratls_staple(
    maybe_snapshot: Option<Extension<Arc<RaTlsMaterial>>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(snapshot) = resolve_snapshot(maybe_snapshot) else {
        warn!("RA-TLS snapshot missing from request context");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "ratls_context_unavailable" })),
        );
    };
    (
        StatusCode::OK,
        Json(serde_json::to_value(&snapshot.attestation).expect("serialize RA-TLS staple")),
    )
}
