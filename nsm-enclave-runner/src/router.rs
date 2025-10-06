use axum::routing::{get, post};
use axum::Router;
use std::time::Duration;
use tower_http::{
    timeout::TimeoutLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
};
use tracing::Level;

use crate::handlers::{attestation_handler, health, ratls_staple, ready};

fn base_router() -> Router {
    Router::new()
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(TimeoutLayer::new(Duration::from_secs(15)))
}

pub fn build_ratls_router() -> Router {
    base_router()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/attestation", post(attestation_handler))
        .route("/.well-known/ratls", get(ratls_staple))
}
