//! Typed failures with safe diagnostics and one HTTP error boundary.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::{error::Error, fmt, panic::Location};

/// An application failure with configuration-safe diagnostics.
#[derive(thiserror::Error)]
#[error("{kind}")]
pub struct AppError {
    kind: ErrorKind,
    location: &'static Location<'static>,
    #[source]
    source: Option<Box<dyn Error + Send + Sync>>,
}

/// Result of a pagebin operation.
pub type Result<T = ()> = std::result::Result<T, AppError>;

#[derive(Debug, thiserror::Error)]
enum ErrorKind {
    #[error("missing or invalid configuration: {0}")]
    Configuration(&'static str),
    #[error("storage initialization failed")]
    Storage,
    #[error("database initialization failed")]
    Database,
    #[error("database migration failed")]
    Migration,
    #[error("listener operation failed")]
    Listener,
    #[error("logging initialization failed")]
    Logging,
    #[error("authentication operation failed")]
    Authentication,
    #[error("publishing operation failed")]
    Publishing,
    #[error("{1}")]
    Request(StatusCode, &'static str),
}

impl AppError {
    /// Records invalid configuration without retaining its value.
    #[track_caller]
    pub(crate) fn configuration(variable: &'static str) -> Self {
        Self::new(ErrorKind::Configuration(variable), None)
    }

    /// Records a filesystem failure without exposing its path in diagnostics.
    #[track_caller]
    pub(crate) fn storage(source: std::io::Error) -> Self {
        Self::new(ErrorKind::Storage, Some(Box::new(source)))
    }

    /// Records a database failure while retaining its typed source.
    #[track_caller]
    pub(crate) fn database(source: sqlx::Error) -> Self {
        Self::new(ErrorKind::Database, Some(Box::new(source)))
    }

    /// Records a migration failure while retaining its typed source.
    #[track_caller]
    pub(crate) fn migration(source: sqlx::migrate::MigrateError) -> Self {
        Self::new(ErrorKind::Migration, Some(Box::new(source)))
    }

    /// Records a listener or shutdown-signal failure.
    #[track_caller]
    pub(crate) fn listener(source: std::io::Error) -> Self {
        Self::new(ErrorKind::Listener, Some(Box::new(source)))
    }

    /// Records failure to install the tracing subscriber.
    #[track_caller]
    pub(crate) fn logging(source: Box<dyn Error + Send + Sync>) -> Self {
        Self::new(ErrorKind::Logging, Some(source))
    }

    /// Records an authentication failure without exposing its source.
    #[track_caller]
    pub(crate) fn authentication(source: impl Error + Send + Sync + 'static) -> Self {
        Self::new(ErrorKind::Authentication, Some(Box::new(source)))
    }

    /// Records a publishing failure without exposing its underlying source.
    #[track_caller]
    pub(crate) fn publishing(source: impl Error + Send + Sync + 'static) -> Self {
        Self::new(ErrorKind::Publishing, Some(Box::new(source)))
    }

    /// Records a request rejection with a fixed, non-sensitive message.
    #[track_caller]
    pub(crate) fn request(status: StatusCode, message: &'static str) -> Self {
        Self::new(ErrorKind::Request(status, message), None)
    }
}

impl AppError {
    #[track_caller]
    fn new(kind: ErrorKind, source: Option<Box<dyn Error + Send + Sync>>) -> Self {
        Self {
            kind,
            location: Location::caller(),
            source,
        }
    }
}

impl fmt::Debug for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Foreign error sources may contain paths, queries, or secret values.
        formatter
            .debug_struct("AppError")
            .field("kind", &self.kind)
            .field("location", &self.location)
            .finish_non_exhaustive()
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        if let ErrorKind::Request(status, message) = &self.kind {
            return (*status, *message).into_response();
        }
        tracing::error!(error = %self, "request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    }
}
