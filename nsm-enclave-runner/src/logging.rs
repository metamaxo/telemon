use crate::config::Config;
use tracing::debug;
use tracing_subscriber::EnvFilter;

/// Install a `tracing` subscriber using either `RUNNER_LOG_LEVEL` or `RUST_LOG`.
pub fn setup_logging(cfg: &Config) {
    let default = cfg.log_level.as_deref().unwrap_or("info");
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    debug!("logging initialized with log level: {:?}", &cfg.log_level);
}
