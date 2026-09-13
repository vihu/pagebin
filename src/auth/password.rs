//! Argon2id password hashing and verification for blocking worker threads.

use super::{Auth, limiter::LoginOutcome, tokens};
use crate::{
    config::valid_password,
    error::{AppError, Result},
};
use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::Error as PasswordError,
};
use axum::http::StatusCode;
use std::{io, net::IpAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{task, time};

/// A canonical, fixed-cost Argon2id hash and its full random salt generation.
#[derive(Clone)]
pub(crate) struct Password {
    encoded_hash: String,
    salt_id: String,
}

// Argon2's reviewed default profile: Argon2id v19, 19 MiB, two passes, one lane.
const MEMORY_KIB: u32 = 19 * 1024;
const ITERATIONS: u32 = 2;
const LANES: u32 = 1;
const HASH_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const MAX_ENCODED_HASH_CHARS: usize = 128;

impl Password {
    /// Validates a stored PHC hash without performing expensive password work.
    ///
    /// # Errors
    /// Returns a safe authentication error for malformed or unsupported hashes.
    pub(crate) fn from_encoded(encoded_hash: String) -> Result<Self> {
        if encoded_hash.len() > MAX_ENCODED_HASH_CHARS {
            return Err(invalid_hash());
        }
        let hash = PasswordHash::new(&encoded_hash).map_err(AppError::authentication)?;
        let salt = hash.salt.as_ref().ok_or_else(invalid_hash)?;
        let params = format!("m={MEMORY_KIB},t={ITERATIONS},p={LANES}");
        if hash.algorithm.as_str() != "argon2id"
            || hash.version != Some(u32::from(Version::V0x13))
            || hash.params.as_str() != params
            || salt.len() != SALT_BYTES
            || hash
                .hash
                .as_ref()
                .is_none_or(|output| output.len() != HASH_BYTES)
            || hash.to_string() != encoded_hash
        {
            return Err(invalid_hash());
        }
        Ok(Self {
            salt_id: tokens::hex_encode(salt.as_ref()),
            encoded_hash,
        })
    }

    /// Returns the encoded credential only for persistence, never presentation.
    pub(crate) const fn encoded(&self) -> &str {
        self.encoded_hash.as_str()
    }

    /// Returns all 16 salt bytes as 32 lowercase hexadecimal characters.
    pub(crate) const fn salt_id(&self) -> &str {
        self.salt_id.as_str()
    }

    /// Compares validated fixed-length password generations in constant time.
    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        bool::from(self.salt_id.as_bytes().ct_eq(other.salt_id.as_bytes()))
    }
}

impl Password {
    /// Hashes a fresh password on the caller's blocking thread.
    ///
    /// Call only from a blocking thread or synchronous test, not directly on an
    /// async executor. Production site operations must use
    /// [`Auth::hash_password`][super::Auth::hash_password] for shared limits.
    /// That method also validates input; boot is separately blocking.
    ///
    /// # Errors
    /// Returns an error if OS randomness or password hashing fails.
    pub(crate) fn new(password: String) -> Result<Self> {
        let salt = tokens::random_bytes::<SALT_BYTES>()?;
        let hash: PasswordHash = argon2()?
            .hash_password_with_salt(password.as_bytes(), &salt)
            .map_err(AppError::authentication)?;
        Self::from_encoded(hash.to_string())
    }
}

impl Password {
    /// Verifies a password on the caller's bounded blocking worker.
    ///
    /// # Errors
    /// Returns an error for malformed hashes or password hashing failures.
    pub(super) fn verify(&self, password: &str) -> Result<bool> {
        match argon2()?.verify_password(password.as_bytes(), self.encoded_hash.as_str()) {
            Ok(()) => Ok(true),
            Err(PasswordError::PasswordInvalid) => Ok(false),
            Err(source) => Err(AppError::authentication(source)),
        }
    }
}

fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(HASH_BYTES))
        .map_err(AppError::authentication)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn invalid_hash() -> AppError {
    AppError::authentication(io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid stored password profile",
    ))
}

impl Auth {
    /// Hashes a valid site password with a fresh salt on a bounded worker.
    ///
    /// The password is never trimmed or retained after hashing.
    ///
    /// # Errors
    /// Returns 400 for an invalid password, 429 for exhausted shared resources,
    /// or a safe authentication error for entropy or hashing failure.
    pub(crate) async fn hash_password(&self, password: String) -> Result<Password> {
        validate_site_password(&password)?;
        self.password_job(move || Ok((Password::new(password)?, Duration::ZERO)))
            .await
    }

    /// Checks a site's validated password using the shared admin login limits.
    ///
    /// Recheck the site's existence, access, expiry, and password generation
    /// after awaiting this result and before issuing any viewer grant.
    /// A successful check never creates an admin session or clears IP history.
    ///
    /// # Errors
    /// Returns 400 for invalid input, 429 for exhausted shared resources, or a
    /// safe authentication error for hashing or failure-accounting errors.
    pub(crate) async fn verify_site_password(
        &self,
        ip: IpAddr,
        password: Password,
        submitted: String,
    ) -> Result<bool> {
        validate_site_password(&submitted)?;
        self.verify_password(ip, Arc::new(password), submitted)
            .await
    }
}

impl Auth {
    /// Verifies either credential type with shared accounting and delay.
    ///
    /// # Errors
    /// Returns an error for exhausted resources, hashing, or limiter failures.
    pub(super) async fn verify_password(
        &self,
        ip: IpAddr,
        password: Arc<Password>,
        submitted: String,
    ) -> Result<bool> {
        let limiter = Arc::clone(&self.limiter);
        self.password_job(move || {
            let accepted = password.verify(&submitted)?;
            let outcome = if accepted {
                LoginOutcome::Accepted
            } else {
                LoginOutcome::Rejected
            };
            Ok((accepted, limiter.complete(ip, outcome)?))
        })
        .await
    }
}

impl Auth {
    /// Runs owned blocking work before delaying its bounded response.
    ///
    /// # Errors
    /// Rejects exhausted admission or workers, failed work, and task failures.
    async fn password_job<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<(T, Duration)> + Send + 'static,
    ) -> Result<T> {
        let _admission = self.login_admission.try_acquire().map_err(|_| busy())?;
        let permit = Arc::clone(&self.password_workers)
            .try_acquire_owned()
            .map_err(|_| busy())?;
        let (output, delay) = task::spawn_blocking(move || {
            // Cancellation cannot free a working slot or skip failure accounting.
            let _permit = permit;
            job()
        })
        .await
        .map_err(AppError::authentication)??;
        // Delayed responses keep admission, but never a worker or limiter lock.
        if !delay.is_zero() {
            time::sleep(delay).await;
        }
        Ok(output)
    }
}

/// Applies the shared byte and control-character policy without trimming.
///
/// # Errors
/// Rejects invalid plaintext without retaining it in the error.
fn validate_site_password(password: &str) -> Result {
    if !valid_password(password) {
        return Err(AppError::request(
            StatusCode::BAD_REQUEST,
            "Invalid site password.",
        ));
    }
    Ok(())
}

fn busy() -> AppError {
    AppError::request(
        StatusCode::TOO_MANY_REQUESTS,
        "login is busy; try again shortly",
    )
}

#[cfg(test)]
mod tests {
    use super::{MAX_ENCODED_HASH_CHARS, Password};

    const CANONICAL_HASH: &str = concat!(
        "$argon2id$v=19$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    #[test]
    fn auth_password_hash_verifies_only_the_original_password() {
        let password = Password::new("synthetic-password".into()).unwrap();
        assert!(password.verify("synthetic-password").unwrap());
        assert!(!password.verify("incorrect").unwrap());
        let restored = Password::from_encoded(password.encoded().to_owned()).unwrap();
        assert!(password.same_generation(&restored));
    }

    #[test]
    fn auth_password_rejects_malformed_or_unsupported_stored_hashes() {
        assert!(Password::from_encoded(CANONICAL_HASH.to_owned()).is_ok());
        for invalid in [
            String::new(),
            "malformed-hash".to_owned(),
            "a".repeat(MAX_ENCODED_HASH_CHARS + 1),
            CANONICAL_HASH.replace("argon2id", "argon2i"),
            CANONICAL_HASH.replace("m=19456", "m=8"),
            CANONICAL_HASH.replace("AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgc"),
            format!("{CANONICAL_HASH}\n"),
        ] {
            assert!(Password::from_encoded(invalid).is_err());
        }
    }
}
