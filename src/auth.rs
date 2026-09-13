//! Shared password authentication, signed-cookie payloads, and bounded state.

mod key;
mod limiter;
mod password;
mod sessions;
mod tokens;
mod viewer_tokens;

use crate::error::{AppError, Result};
use axum_extra::extract::cookie::Key;
use limiter::Limiter;
use sessions::Sessions;
use std::{net::IpAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{sync::Semaphore, task};

pub(crate) use password::Password;

/// Authentication state; plaintext passwords are never retained here.
pub(crate) struct Auth {
    key: Key,
    password: Arc<Password>,
    sessions: Sessions,
    limiter: Arc<Limiter>,
    password_workers: Arc<Semaphore>,
    login_admission: Semaphore,
}

/// Required size of both configured and persisted master signing keys.
pub(crate) const MASTER_KEY_BYTES: usize = 32;
/// Shared browser and server lifetime for admin sessions.
pub(crate) const SESSION_LIFETIME: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// Shared browser and server lifetime for pre-login CSRF challenges.
pub(crate) const CHALLENGE_LIFETIME: Duration = Duration::from_secs(15 * 60);
/// Shared browser and server lifetime for nonrefreshing viewer grants.
pub(crate) const VIEWER_GRANT_LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Shared browser and server lifetime for slug-bound unlock form challenges.
pub(crate) const VIEWER_CHALLENGE_LIFETIME: Duration = CHALLENGE_LIFETIME;
const MAX_ADMITTED_LOGINS: usize = 16;
const MAX_PASSWORD_WORKERS: usize = 2;

impl Auth {
    /// Initializes signing material and hashes the configured admin password.
    ///
    /// # Errors
    /// Returns an error on invalid persisted keys, storage or entropy failure,
    /// or failure to hash the password on the blocking executor.
    pub(crate) async fn new(
        password: String,
        data_dir: PathBuf,
        secret: Option<[u8; MASTER_KEY_BYTES]>,
    ) -> Result<Self> {
        task::spawn_blocking(move || {
            Ok(Self {
                key: key::load(&data_dir, secret)?,
                password: Arc::new(Password::new(password)?),
                sessions: Sessions::new(),
                limiter: Arc::new(Limiter::new()),
                password_workers: Arc::new(Semaphore::new(MAX_PASSWORD_WORKERS)),
                login_admission: Semaphore::new(MAX_ADMITTED_LOGINS),
            })
        })
        .await
        .map_err(AppError::authentication)?
    }

    /// Returns the library-derived signing key for signed cookie extraction.
    pub(crate) fn key(&self) -> Key {
        self.key.clone()
    }

    /// Creates a domain-separated 15-minute pre-login challenge payload.
    ///
    /// The HTTP boundary must sign this payload before sending it as a cookie.
    ///
    /// # Errors
    /// Returns an error if the clock precedes Unix time or OS randomness fails.
    pub(crate) fn challenge(&self) -> Result<String> {
        tokens::challenge()
    }

    /// Extracts the nonce from a strictly encoded pre-login challenge.
    pub(crate) fn challenge_token(payload: &str) -> Option<&str> {
        tokens::challenge_token(payload)
    }

    /// Validates a signature-verified challenge's expiry and submitted nonce.
    pub(crate) fn verify_challenge(&self, payload: Option<&str>, submitted: &str) -> bool {
        tokens::verify_challenge(payload, submitted)
    }

    /// Checks credentials and creates a fresh server-side session on success.
    ///
    /// # Errors
    /// Returns an error if bounded login resources are saturated or hashing,
    /// randomness, or in-memory state access fails.
    pub(crate) async fn login(&self, ip: IpAddr, password: String) -> Result<Option<String>> {
        let accepted = self
            .verify_password(ip, Arc::clone(&self.password), password)
            .await?;
        if accepted {
            self.sessions.create().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Returns a live session's CSRF token without extending expiry.
    ///
    /// # Errors
    /// Returns an error if the session store cannot be locked safely.
    pub(crate) fn csrf(&self, session_id: &str) -> Result<Option<String>> {
        self.sessions.csrf(session_id)
    }

    /// Verifies a live session's form token without revocation or refresh.
    ///
    /// # Errors
    /// Returns an error if the session store cannot be locked safely.
    pub(crate) fn verify_form(&self, session_id: &str, token: &str) -> Result<bool> {
        self.sessions.verify(session_id, token)
    }

    /// Atomically verifies CSRF and revokes a live session.
    ///
    /// # Errors
    /// Returns an error if the session store cannot be locked safely.
    pub(crate) fn logout(&self, session_id: &str, token: &str) -> Result<bool> {
        self.sessions.logout(session_id, token)
    }
}
