//! Slug-bound viewer grants and independent unlock-form CSRF challenges.

use super::{Auth, Password, VIEWER_CHALLENGE_LIFETIME, VIEWER_GRANT_LIFETIME, tokens};
use crate::{error::Result, sites::Slug};

const GRANT_DOMAIN: &str = "unlock:v1:";
const CHALLENGE_DOMAIN: &str = "unlock-form:v1:";

impl Auth {
    /// Creates a seven-day viewer payload bound to the verified generation.
    ///
    /// The HTTP caller must sign this payload using `SignedCookieJar` before
    /// sending it; this method neither signs nor authorizes the password.
    /// Do not refresh this grant on asset requests.
    ///
    /// # Errors
    /// Returns an error if the clock or expiry is outside supported Unix time.
    pub(crate) fn viewer_grant(&self, slug: &Slug, password: &Password) -> Result<String> {
        tokens::timed_payload(
            &format!("{GRANT_DOMAIN}{}:", slug.as_str()),
            password.salt_id(),
            VIEWER_GRANT_LIFETIME,
        )
    }

    /// Validates the slug, current salt generation, and fixed grant expiry.
    ///
    /// The HTTP caller must verify the cookie signature using `SignedCookieJar`
    /// before supplying a payload; raw cookie values are never trusted here.
    pub(crate) fn verify_viewer_grant(
        &self,
        payload: Option<&str>,
        slug: &Slug,
        password: &Password,
    ) -> bool {
        tokens::unix_time().is_ok_and(|now| verify_viewer_grant_at(payload, slug, password, now))
    }

    /// Creates an independent 256-bit, 15-minute unlock-form CSRF challenge.
    ///
    /// The HTTP caller must sign this payload using `SignedCookieJar` before
    /// sending it as a host-only cookie scoped to the requested site.
    ///
    /// # Errors
    /// Returns an error if OS randomness or supported Unix time is unavailable.
    pub(crate) fn viewer_challenge(&self, slug: &Slug) -> Result<String> {
        tokens::timed_payload(
            &format!("{CHALLENGE_DOMAIN}{}:", slug.as_str()),
            &tokens::random_token()?,
            VIEWER_CHALLENGE_LIFETIME,
        )
    }

    /// Extracts a nonce only from a canonical challenge for the requested slug.
    pub(crate) fn viewer_challenge_token<'a>(payload: &'a str, slug: &Slug) -> Option<&'a str> {
        parse_viewer_challenge(payload, slug).map(|(token, _)| token)
    }

    /// Validates a signature-verified unlock challenge and its submitted nonce.
    ///
    /// The HTTP caller must first verify the cookie using `SignedCookieJar` and
    /// separately enforce the viewer Origin and complete form-body cap.
    pub(crate) fn verify_viewer_challenge(
        &self,
        payload: Option<&str>,
        slug: &Slug,
        submitted: &str,
    ) -> bool {
        tokens::unix_time()
            .is_ok_and(|now| verify_viewer_challenge_at(payload, slug, submitted, now))
    }
}

fn verify_viewer_grant_at(
    payload: Option<&str>,
    slug: &Slug,
    password: &Password,
    now: u64,
) -> bool {
    let Some((salt_id, expiry)) = payload.and_then(|payload| {
        tokens::parse_timed_payload(
            payload,
            &format!("{GRANT_DOMAIN}{}:", slug.as_str()),
            password.salt_id().len(),
        )
    }) else {
        return false;
    };
    tokens::valid_expiry(expiry, now, VIEWER_GRANT_LIFETIME)
        && tokens::matches_hex(password.salt_id(), salt_id)
}

fn parse_viewer_challenge<'a>(payload: &'a str, slug: &Slug) -> Option<(&'a str, u64)> {
    tokens::parse_timed_payload(
        payload,
        &format!("{CHALLENGE_DOMAIN}{}:", slug.as_str()),
        tokens::TOKEN_CHARS,
    )
}

fn verify_viewer_challenge_at(
    payload: Option<&str>,
    slug: &Slug,
    submitted: &str,
    now: u64,
) -> bool {
    let Some((token, expiry)) = payload.and_then(|payload| parse_viewer_challenge(payload, slug))
    else {
        return false;
    };
    tokens::valid_expiry(expiry, now, VIEWER_CHALLENGE_LIFETIME)
        && tokens::matches(token, submitted)
}

#[cfg(test)]
mod tests {
    use super::{Auth, Password, VIEWER_GRANT_LIFETIME, verify_viewer_grant_at};
    use crate::{auth::MASTER_KEY_BYTES, sites::Slug};

    const NOW: u64 = 1_000_000;
    const CANONICAL_HASH: &str = concat!(
        "$argon2id$v=19$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    );

    #[tokio::test]
    async fn auth_viewer_grant_round_trips_and_rejects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let auth = Auth::new(
            "synthetic-admin-password".into(),
            directory.path().to_path_buf(),
            Some([42; MASTER_KEY_BYTES]),
        )
        .await
        .unwrap();
        let slug = Slug::parse("private-site").unwrap();
        let other = Slug::parse("other-site").unwrap();
        let password = Password::from_encoded(CANONICAL_HASH.to_owned()).unwrap();
        let reset = Password::from_encoded(CANONICAL_HASH.replace("DA0ODw", "DA0ODA")).unwrap();
        let grant = auth.viewer_grant(&slug, &password).unwrap();
        let forged = format!("{grant}0");
        assert!(auth.verify_viewer_grant(Some(&grant), &slug, &password));
        assert!(!auth.verify_viewer_grant(Some(&grant), &other, &password));
        assert!(!auth.verify_viewer_grant(Some(&grant), &slug, &reset));
        assert!(!auth.verify_viewer_grant(Some(&forged), &slug, &password));
        assert!(!auth.verify_viewer_grant(None, &slug, &password));
    }

    #[test]
    fn auth_viewer_grant_rejects_expired_or_overlong_payloads() {
        let slug = Slug::parse("private-site").unwrap();
        let password = Password::from_encoded(CANONICAL_HASH.to_owned()).unwrap();
        let expiry = NOW + VIEWER_GRANT_LIFETIME.as_secs();
        let payload = format!("unlock:v1:private-site:{}:{expiry}", password.salt_id());
        let valid = |now| verify_viewer_grant_at(Some(&payload), &slug, &password, now);
        assert!(valid(NOW) && valid(expiry - 1));
        assert!(!valid(expiry) && !valid(NOW - 1));
    }
}
