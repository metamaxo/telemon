use anyhow::Result;

mod attest;
mod config;
mod handlers;
mod logging;
mod router;
mod runner;
mod server;
mod state;
mod tls;

use runner::Runner;

/// Parses configuration, initialises logging, and runs the enclave HTTP server.
#[tokio::main]
async fn main() -> Result<()> {
    let cfg = config::Config::from_env()?;
    logging::setup_logging(&cfg);
    cfg.info();

    let runner = Runner::builder(cfg)
        .bind_public()
        .await?
        .build_ratls_material()
        .await?
        .build()
        .await?;

    runner.run().await
}
