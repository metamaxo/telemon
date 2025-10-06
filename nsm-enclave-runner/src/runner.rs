use anyhow::{anyhow, Context, Result};
use rustls::crypto::{self, CryptoProvider};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use tracing::{error, info};

use crate::config::Config;
use crate::handlers::shutdown_signal;
use crate::router::build_ratls_router;
use crate::server::serve_ratls_https;
use crate::state::RaTlsMaterial;

const RATLS_ROTATION_INTERVAL: Duration = Duration::from_secs(300);

/// Top-level orchestrator for the enclave HTTP server.
pub struct Runner {
    public_listener: VsockListener,
    ratls_tx: watch::Sender<Arc<RaTlsMaterial>>,
    ratls_rx: watch::Receiver<Arc<RaTlsMaterial>>,
    shutdown: CancellationToken,
}

impl Runner {
    /// Bind a VSOCK listener on the provided port, annotating errors with context.
    async fn bind(addr: SocketAddr, description: &str) -> Result<VsockListener> {
        let port = addr.port() as u32;
        let vsock_addr = VsockAddr::new(VMADDR_CID_ANY, port);
        tracing::info!(vsock_port = port, "binding VSOCK {} listener", description);
        VsockListener::bind(vsock_addr)
            .with_context(|| format!("bind {} vsock addr {:?}", description, vsock_addr))
    }

    /// Runs the enclave server until a shutdown signal is received.
    pub async fn run(self) -> Result<()> {
        tracing::debug!("starting runner");

        let Runner {
            public_listener,
            ratls_tx,
            ratls_rx,
            shutdown,
        } = self;

        let rotation_handle = spawn_ratls_rotation(ratls_tx.clone(), shutdown.clone());

        let ratls_app = build_ratls_router();
        let ratls_handle = tokio::spawn(serve_ratls_https(
            public_listener,
            ratls_app,
            ratls_rx.clone(),
            shutdown.clone(),
        ));

        shutdown_signal().await;
        info!("shutdown signal received, exiting");
        shutdown.cancel();

        if let Err(e) = rotation_handle.await {
            error!(error = ?e, "RA-TLS rotation task panicked");
        }
        if let Err(e) = ratls_handle.await {
            error!(error = ?e, "RA-TLS server task panicked");
        }

        Ok(())
    }
}

pub struct RunnerBuilder {
    cfg: Config,
    public_listener: Option<VsockListener>,
    ratls_material: Option<Arc<RaTlsMaterial>>,
    shutdown: CancellationToken,
}

impl RunnerBuilder {
    pub fn from(cfg: Config) -> Self {
        CryptoProvider::install_default(crypto::ring::default_provider())
            .expect("install ring crypto provider");

        Self {
            cfg,
            public_listener: None,
            ratls_material: None,
            shutdown: CancellationToken::new(),
        }
    }

    pub async fn bind_public(mut self) -> Result<Self> {
        let listener = Runner::bind(self.cfg.public_addr, "public").await?;
        self.public_listener = Some(listener);
        Ok(self)
    }

    pub async fn build_ratls_material(mut self) -> Result<Self> {
        let material = crate::tls::generate_ratls_material(RATLS_ROTATION_INTERVAL)
            .await
            .map_err(|e| anyhow!(e))
            .context("initial RA-TLS build")?;
        self.ratls_material = Some(Arc::new(material));
        Ok(self)
    }

    pub async fn build(self) -> Result<Runner> {
        let ratls_material = self
            .ratls_material
            .ok_or_else(|| anyhow!("RA-TLS material missing"))?;

        let (ratls_tx, ratls_rx) = watch::channel(ratls_material);

        let public_listener = self
            .public_listener
            .ok_or_else(|| anyhow!("public listener not bound"))?;

        Ok(Runner {
            public_listener,
            ratls_tx,
            ratls_rx,
            shutdown: self.shutdown,
        })
    }
}

impl Runner {
    pub fn builder(cfg: Config) -> RunnerBuilder {
        RunnerBuilder::from(cfg)
    }
}

fn spawn_ratls_rotation(
    tx: watch::Sender<Arc<RaTlsMaterial>>,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = sleep(RATLS_ROTATION_INTERVAL) => {
                    match crate::tls::generate_ratls_material(RATLS_ROTATION_INTERVAL).await {
                        Ok(material) => {
                            let _ = tx.send(Arc::new(material));
                        }
                        Err(err) => {
                            error!(error=?err, "failed to rotate RA-TLS material");
                        }
                    }
                }
            }
        }
    })
}
