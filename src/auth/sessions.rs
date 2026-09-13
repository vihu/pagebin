//! Bounded, expiring admin sessions with atomic CSRF-checked revocation.

use super::{SESSION_LIFETIME, tokens};
use crate::error::{AppError, Result};
use axum::http::StatusCode;
use std::{
    collections::{HashMap, hash_map::Entry},
    io,
    sync::{Mutex, MutexGuard},
    time::Instant,
};

/// A bounded store of live sessions and their independent CSRF credentials.
pub(super) struct Sessions {
    active: Mutex<HashMap<String, Session>>,
}

const MAX_SESSIONS: usize = 1024;

impl Sessions {
    /// Creates an empty store, invalidating every prior process's sessions.
    pub(super) fn new() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a fresh session without displacing existing live sessions.
    ///
    /// # Errors
    /// Returns an error for capacity, entropy, collision, or poisoned locks.
    pub(super) fn create(&self) -> Result<String> {
        self.create_at(Instant::now())
    }

    /// Looks up a live session's CSRF token without refreshing its deadline.
    ///
    /// # Errors
    /// Returns an error if the session-store lock is poisoned.
    pub(super) fn csrf(&self, session_id: &str) -> Result<Option<String>> {
        self.csrf_at(session_id, Instant::now())
    }

    /// Validates a live session's CSRF token without revoking or refreshing it.
    ///
    /// # Errors
    /// Returns an error if the session-store lock is poisoned.
    pub(super) fn verify(&self, session_id: &str, token: &str) -> Result<bool> {
        self.verify_at(session_id, token, Instant::now())
    }

    /// Atomically validates a session-bound CSRF token and revokes its session.
    ///
    /// # Errors
    /// Returns an error if the session-store lock is poisoned.
    pub(super) fn logout(&self, session_id: &str, token: &str) -> Result<bool> {
        self.logout_at(session_id, token, Instant::now())
    }
}

impl Sessions {
    /// Locks the store and removes sessions expired at the supplied time.
    ///
    /// # Errors
    /// Returns an error if the store lock is poisoned.
    fn lock_at(&self, now: Instant) -> Result<MutexGuard<'_, HashMap<String, Session>>> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| AppError::authentication(io::Error::other("session store poisoned")))?;
        active.retain(|_, session| session.expires_at > now);
        Ok(active)
    }

    /// Creates a bounded session with a deterministic expiration origin.
    ///
    /// # Errors
    /// Returns capacity, entropy, collision, or poisoned-lock failures.
    fn create_at(&self, now: Instant) -> Result<String> {
        let session_id = tokens::random_token()?;
        let csrf_token = tokens::random_token()?;
        let mut active = self.lock_at(now)?;
        if active.len() >= MAX_SESSIONS {
            return Err(AppError::request(
                StatusCode::SERVICE_UNAVAILABLE,
                "too many active sessions; sign out another session",
            ));
        }
        match active.entry(session_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(Session {
                    csrf_token,
                    expires_at: now + SESSION_LIFETIME,
                });
                Ok(session_id)
            }
            Entry::Occupied(_) => Err(AppError::authentication(io::Error::other(
                "session identifier collision",
            ))),
        }
    }

    /// Reads a token only when its session is live at the supplied time.
    ///
    /// # Errors
    /// Returns an error if the store lock is poisoned.
    fn csrf_at(&self, session_id: &str, now: Instant) -> Result<Option<String>> {
        Ok(self
            .lock_at(now)?
            .get(session_id)
            .map(|session| session.csrf_token.clone()))
    }

    /// Compares a live session's verification token without changing it.
    ///
    /// # Errors
    /// Returns an error if the store lock is poisoned.
    fn verify_at(&self, session_id: &str, token: &str, now: Instant) -> Result<bool> {
        Ok(self
            .lock_at(now)?
            .get(session_id)
            .is_some_and(|session| tokens::matches(&session.csrf_token, token)))
    }

    /// Removes a live session only after its token matches under the lock.
    ///
    /// # Errors
    /// Returns an error if the store lock is poisoned.
    fn logout_at(&self, session_id: &str, token: &str, now: Instant) -> Result<bool> {
        let mut active = self.lock_at(now)?;
        if !active
            .get(session_id)
            .is_some_and(|session| tokens::matches(&session.csrf_token, token))
        {
            return Ok(false);
        }
        active.remove(session_id);
        Ok(true)
    }
}

/// A server-tracked session whose deadline is never extended by access.
pub(super) struct Session {
    /// Independent random token required to revoke this session.
    pub(super) csrf_token: String,
    /// Monotonic instant at which this session becomes invalid.
    pub(super) expires_at: Instant,
}
