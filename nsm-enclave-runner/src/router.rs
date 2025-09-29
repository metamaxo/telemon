use axum::routing::{get, post};
use axum::Router;
use std::time::Duration;
use tower_http::{
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use crate::handlers::*;
use crate::state::PublicState;

/// Constructs the public HTTP router (health + attestation) with middleware.
pub fn build_public_router(state: PublicState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/attestation", post(attestation_handler))
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(TimeoutLayer::new(Duration::from_secs(15)))
}
