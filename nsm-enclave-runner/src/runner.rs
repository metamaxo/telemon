use anyhow::{Context, Result};
use rustls::crypto::{self, CryptoProvider};
use std::{net::SocketAddr, sync::Arc};
use tokio_util::sync::CancellationToken;
use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};
use tracing::info;

use crate::{
    config::Config,
    handlers::shutdown_signal,
    router::build_public_router,
    server::serve_axum_https_with_listener, // <- now expects Arc<ServerConfig>
    state::PublicState,
    tls::{build_tls_keypair, tls_server_no_client_auth, TlsBundle},
};

/// Top-level orchestrator for the enclave HTTP server.
pub struct Runner {
    cfg: Config,
    pub_state: PublicState,
    public_listener: VsockListener,
    public_tls: Arc<rustls::ServerConfig>,
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

    /// Builds a TLS keypair for the server. NO attestation here.
    async fn get_tls(cfg: &Config) -> Result<TlsBundle> {
        build_tls_keypair(cfg).await.context("TLS init failed")
    }

    /// Constructs the runtime, including TLS material, listeners, and shared state.
    pub async fn new(cfg: Config) -> Result<Self> {
        tracing::debug!("building runner");
        CryptoProvider::install_default(crypto::ring::default_provider())
            .expect("install ring crypto provider");

        // TLS only (no attestation)
        let tls = Self::get_tls(&cfg).await?;
        let public_tls = tls_server_no_client_auth(&tls.cert_der, &tls.key_der)?;

        // VSOCK listener
        let public_listener = Self::bind(cfg.public_addr, "public").await?;

        // minimal public state (cert + spki)
        let pub_state = PublicState {
            cert_der: Arc::<[u8]>::from(tls.cert_der.clone()),
            spki_der: Arc::<[u8]>::from(tls.spki_der.clone()),
            // If you removed the sealed store from state.rs, delete this field.
            // store: Arc::new(enclave_runner::sealed_state::MemStore::default()),
        };

        Ok(Self {
            cfg,
            pub_state,
            public_listener,
            public_tls,
            shutdown: CancellationToken::new(),
        })
    }

    /// Runs the enclave server until a shutdown signal is received.
    pub async fn run(self) -> Result<()> {
        tracing::debug!("starting runner");
        let shutdown = self.shutdown.clone();

        // public router only
        let public_app = build_public_router(self.pub_state.clone());

        // serve public vsock+TLS (static TLS cfg)
        tokio::spawn(serve_axum_https_with_listener(
            self.public_listener,
            public_app,
            self.public_tls.clone(),
            shutdown.clone(),
        ));

        // block until signal
        shutdown_signal().await;
        info!("shutdown signal received, exiting");
        self.shutdown.cancel();
        Ok(())
    }
}
