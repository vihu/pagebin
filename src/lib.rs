//! Validated boot, administrator authentication, and static HTML publishing.
#![doc = include_str!("../README.md")]
#![deny(unsafe_code, missing_docs, rustdoc::broken_intra_doc_links)]

mod auth;
mod config;
mod db;
mod error;
mod host;
mod routes;
mod sites;

use std::net::SocketAddr;
use tokio::net::TcpListener;

pub use config::{Config, ConfigBuilder};
pub use db::open_database;
pub use error::{AppError, Result};
pub use routes::router;

/// Initializes storage and authentication before serving the host-isolated app.
///
/// # Errors
/// Returns a safe diagnostic if configuration, logging, storage initialization,
/// binding, or serving fails. Underlying operational errors remain available
/// through [`std::error::Error::source`], not automatic log output.
pub async fn run() -> Result {
    let config = Config::from_env()?;
    tracing_subscriber::fmt()
        .with_env_filter(config.log_filter())
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|source| AppError::logging(source))?;
    if config.view_host().is_none() {
        // Origin-isolation warnings must remain visible even with RUST_LOG=off.
        eprintln!(
            "pagebin: warning: PAGEBIN_VIEW_HOST is unset; single-host mode is for local development only"
        );
    }
    if config.trust_proxy() {
        eprintln!(
            "pagebin: warning: PAGEBIN_TRUST_PROXY is enabled; only trusted proxies may reach the listener"
        );
    }
    let listen = config.listen();
    let port = listen.port();
    let pool = open_database(config.data_dir()).await?;
    let app = match router(config, pool.clone()).await {
        Ok(app) => app,
        Err(error) => {
            pool.close().await;
            return Err(error);
        }
    };
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(error) => {
            pool.close().await;
            return Err(AppError::listener(error));
        }
    };
    tracing::info!("server started on port {port}");
    let result = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|source| AppError::listener(source));
    pool.close().await;
    result
}
