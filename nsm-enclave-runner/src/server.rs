use axum::body::Body as AxumBody;
use axum::extract::Extension;
use axum::Router;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use std::sync::Arc;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_vsock::VsockListener;
use tower::ServiceBuilder;
use tower_http::map_request_body::MapRequestBodyLayer;
use tracing::{info, warn};

use crate::state::RaTlsMaterial;

/// Accepts VSOCK connections, upgrades them to TLS, and serves the provided Axum app using RA-TLS material.
pub async fn serve_ratls_https(
    mut listener: VsockListener,
    app: Router,
    tls_rx: watch::Receiver<Arc<RaTlsMaterial>>,
    shutdown: CancellationToken,
) {
    info!("vsock RA-TLS server listening");
    let tls_rx = tls_rx;

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("shutdown: stop accepting RA-TLS connections");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((io, peer)) => {
                        info!(cid=%peer.cid(), port=%peer.port(), "VSOCK accept (ra-tls)");

                        let snapshot = tls_rx.borrow().clone();
                        let acceptor = TlsAcceptor::from(snapshot.server_config.clone());
                        let app = app.clone();
                        let child_cancel = shutdown.child_token();

                        tokio::spawn(async move {
                            match acceptor.accept(io).await {
                                Ok(tls_io) => {
                                    let io = TokioIo::new(tls_io);
                                    let svc = app
                                        .clone()
                                        .layer(Extension(snapshot.clone()))
                                        .into_service();
                                    let svc = ServiceBuilder::new()
                                        .layer(MapRequestBodyLayer::new(|body: Incoming| {
                                            AxumBody::from_stream(body.into_data_stream())
                                        }))
                                        .service(svc);
                                    let hyper_svc = TowerToHyperService::new(svc);
                                    if let Err(e) = http1::Builder::new().serve_connection(io, hyper_svc).await {
                                        warn!(error = ?e, "http1 connection error");
                                    }
                                }
                                Err(e) => warn!(error=?e, "ra-tls accept failed"),
                            }
                            drop(child_cancel);
                        });
                    }
                    Err(e) => warn!(error=?e, "listener.accept error; continuing"),
                }
            }
        }
    }
    info!("RA-TLS listener loop exited");
}
