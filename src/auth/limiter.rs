//! Bounded sliding-window failure history with atomic completion decisions.

use crate::error::{AppError, Result};
use axum::http::StatusCode;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

/// Stores only the last five failures for each recently failing address.
pub(super) struct Limiter {
    failures: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

/// The verified outcome of one completed password check.
pub(super) enum LoginOutcome {
    /// The configured password matched the submitted password.
    Accepted,
    /// The submitted password did not match the configured password.
    Rejected,
}

const FAILURE_THRESHOLD: usize = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);
const FAILURE_DELAY: Duration = Duration::from_secs(1);
const MAX_FAILURE_IPS: usize = 4096;

impl Limiter {
    /// Creates an empty failure history.
    pub(super) fn new() -> Self {
        Self {
            failures: Mutex::new(HashMap::new()),
        }
    }

    /// Atomically counts a completed failure and selects its response delay.
    ///
    /// # Errors
    /// Returns an error if history is full or its lock is poisoned.
    pub(super) fn complete(&self, ip: IpAddr, outcome: LoginOutcome) -> Result<Duration> {
        let mut failures = self
            .failures
            .lock()
            .map_err(|_| AppError::authentication(io::Error::other("login limiter poisoned")))?;
        // Sample inside the lock so completion order is also timestamp order.
        let now = Instant::now();
        failures.retain(|_, history| {
            history.retain(|failed_at| now.duration_since(*failed_at) < FAILURE_WINDOW);
            !history.is_empty()
        });
        let delay = match failures.get(&ip) {
            Some(history) if history.len() >= FAILURE_THRESHOLD => FAILURE_DELAY,
            _ => Duration::ZERO,
        };
        if matches!(outcome, LoginOutcome::Rejected) {
            if failures.len() >= MAX_FAILURE_IPS && !failures.contains_key(&ip) {
                // Never evict a live failure window to admit an attacker IP.
                return Err(AppError::request(
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many login attempts; try again later",
                ));
            }
            let history = failures.entry(ip).or_default();
            if history.len() == FAILURE_THRESHOLD {
                history.pop_front();
            }
            history.push_back(now);
        }
        Ok(delay)
    }
}
