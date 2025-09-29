use axum::Router;
use hyper::server::conn::http1;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use rustls::ServerConfig;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tokio_vsock::VsockListener;
use tracing::{info, warn};

/// Accepts VSOCK connections, upgrades them to TLS, and serves the provided Axum app.
pub async fn serve_axum_https_with_listener(
    mut listener: VsockListener,
    app: Router,
    tls_cfg: Arc<ServerConfig>, // <- static TLS only
    shutdown: CancellationToken,
) {
    info!("vsock https server listening");
    let acceptor = TlsAcceptor::from(tls_cfg);

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!("shutdown: stop accepting");
                break;
            }
            res = listener.accept() => {
                match res {
                    Ok((io, peer)) => {
                        // minimal log; remove if noisy
                        info!(cid=%peer.cid(), port=%peer.port(), "VSOCK accept");

                        let svc = app.clone().into_service();
                        let acceptor = acceptor.clone();
                        let child_cancel = shutdown.child_token();

                        tokio::spawn(async move {
                            match acceptor.accept(io).await {
                                Ok(tls_io) => {
                                    let io = TokioIo::new(tls_io);
                                    let hyper_svc = TowerToHyperService::new(svc);
                                    if let Err(e) = http1::Builder::new()
                                        .serve_connection(io, hyper_svc)
                                        .await
                                    {
                                        warn!(error = ?e, "http1 connection error");
                                    }
                                }
                                Err(e) => warn!(error=?e, "tls accept failed"),
                            }
                            drop(child_cancel);
                        });
                    }
                    Err(e) => warn!(error=?e, "listener.accept error; continuing"),
                }
            }
        }
    }
    info!("listener loop exited");
}
