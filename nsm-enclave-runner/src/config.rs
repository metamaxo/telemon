use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Clone, Debug, Deserialize)]
/// Runtime configuration loaded from `RUNNER_*` environment variables.
pub struct Config {
    pub log_level: Option<String>,

    #[serde(default = "def_public_addr")]
    pub public_addr: SocketAddr,
}

impl Config {
    /// Populates the configuration from environment variables, honoring `.env`.
    pub fn from_env() -> anyhow::Result<Self> {
        tracing::debug!("fetching config");
        let _ = dotenvy::dotenv();
        let cfg: Self = envy::prefixed("RUNNER_").from_env()?;
        Ok(cfg)
    }

    /// Emit the effective configuration via tracing.
    pub fn info(&self) {
        tracing::info!(
            public_addr = %self.public_addr,
            "effective config"
        );
        if self.public_addr.ip().is_unspecified() {
            tracing::warn!("binding to 0.0.0.0 — make sure this is intentional");
        }
    }
}

fn def_public_addr() -> SocketAddr {
    // Only the port is used for VSOCK (CID comes from VMADDR_CID_ANY); IP is ignored.
    "127.0.0.1:8443".parse().unwrap()
}
