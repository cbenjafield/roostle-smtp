use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use roostle_smtp::cache::CachedBackend;
use roostle_smtp::config::Config;
use roostle_smtp::laravel::HttpBackend;
use roostle_smtp::session::{Mode, Shared};
use roostle_smtp::throttle::AuthThrottle;
use roostle_smtp::tls::TlsContext;
use roostle_smtp::server;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // reqwest is built without a bundled provider; rustls needs one process-wide.
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider is already installed"))?;

    let config = Arc::new(Config::from_env().context("invalid configuration")?);
    info!(?config, "starting roostle-smtp");

    let tls = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(Arc::new(TlsContext::load(cert, key)?)),
        _ => None,
    };
    let backend = Arc::new(CachedBackend::new(HttpBackend::new(&config)?));
    let shared = Arc::new(Shared {
        throttle: AuthThrottle::new(config.auth_max_failures, config.auth_window, config.auth_failure_delay),
        config: config.clone(),
        backend,
        tls: tls.clone(),
    });

    let catch = server::bind(&config.catch_bind).await?;
    let submission = server::bind(&config.submission_bind).await?;

    let permits = Arc::new(Semaphore::new(config.max_connections));
    let tracker = TaskTracker::new();
    let shutdown = CancellationToken::new();
    for (listeners, mode) in [(catch, Mode::Catch), (submission, Mode::Submission)] {
        for listener in listeners {
            tokio::spawn(server::serve(
                listener,
                mode,
                shared.clone(),
                permits.clone(),
                tracker.clone(),
                shutdown.clone(),
            ));
        }
    }

    wait_for_shutdown(tls).await?;
    info!("shutting down; waiting for open connections");
    shutdown.cancel();
    tracker.close();
    if tokio::time::timeout(Duration::from_secs(30), tracker.wait()).await.is_err() {
        error!("connections still open after 30s; exiting anyway");
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown(tls: Option<Arc<TlsContext>>) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = term.recv() => return Ok(()),
            _ = hup.recv() => match &tls {
                Some(tls) => match tls.reload() {
                    Ok(()) => info!("TLS certificate reloaded"),
                    Err(e) => error!(error = %e, "TLS certificate reload failed; keeping the old one"),
                },
                None => info!("SIGHUP ignored: TLS is not configured"),
            },
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown(_tls: Option<Arc<TlsContext>>) -> Result<()> {
    tokio::signal::ctrl_c().await?;
    Ok(())
}
