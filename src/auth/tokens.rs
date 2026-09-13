//! Random credentials and shared canonical, expiring cookie payload mechanics.

use super::CHALLENGE_LIFETIME;
use crate::error::{AppError, Result};
use rand::{TryRng, rngs::SysRng};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const TOKEN_BYTES: usize = 32;
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
const HEX_CHARS_PER_BYTE: usize = 2;
const BITS_PER_HEX_DIGIT: u8 = 4;
const HEX_DIGIT_MASK: u8 = 0x0f;
/// Canonical hexadecimal width of session and form credentials.
pub(super) const TOKEN_CHARS: usize = TOKEN_BYTES * HEX_CHARS_PER_BYTE;
const MAX_TIMESTAMP_CHARS: usize = 20;
const CHALLENGE_PREFIX: &str = "login:";

/// Fills a fixed-size array from the operating system's entropy source.
///
/// # Errors
/// Returns the typed entropy-source error if randomness is unavailable.
pub(super) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SysRng
        .try_fill_bytes(&mut bytes)
        .map_err(AppError::authentication)?;
    Ok(bytes)
}

/// Creates a 256-bit credential encoded as canonical lowercase hexadecimal.
///
/// # Errors
/// Returns an error if OS randomness fails.
pub(super) fn random_token() -> Result<String> {
    Ok(hex_encode(&random_bytes::<TOKEN_BYTES>()?))
}

/// Encodes bytes as canonical lowercase hexadecimal without truncation.
pub(super) fn hex_encode(bytes: &[u8]) -> String {
    let mut token = String::with_capacity(bytes.len() * HEX_CHARS_PER_BYTE);
    for byte in bytes {
        let high_digit = byte >> BITS_PER_HEX_DIGIT;
        let low_digit = byte & HEX_DIGIT_MASK;
        token.push(char::from(HEX_DIGITS[usize::from(high_digit)]));
        token.push(char::from(HEX_DIGITS[usize::from(low_digit)]));
    }
    token
}

/// Checks exact length and lowercase hexadecimal credential encoding.
pub(super) fn valid_token(token: &str) -> bool {
    valid_hex(token, TOKEN_CHARS)
}

/// Checks an exact-width hexadecimal value before constant-time comparison.
pub(super) fn valid_hex(token: &str, chars: usize) -> bool {
    token.len() == chars
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Compares a valid submitted token in constant time against its stored token.
pub(super) fn matches(expected: &str, submitted: &str) -> bool {
    valid_token(submitted) && matches_hex(expected, submitted)
}

/// Compares a canonical, fixed-width hexadecimal value in constant time.
pub(super) fn matches_hex(expected: &str, submitted: &str) -> bool {
    valid_hex(submitted, expected.len())
        && bool::from(expected.as_bytes().ct_eq(submitted.as_bytes()))
}

/// Creates a domain-separated challenge for the signed pre-login cookie.
///
/// # Errors
/// Returns an error if randomness fails or the clock predates Unix time.
pub(super) fn challenge() -> Result<String> {
    timed_payload(CHALLENGE_PREFIX, &random_token()?, CHALLENGE_LIFETIME)
}

/// Extracts the nonce only from a correctly encoded login challenge payload.
pub(super) fn challenge_token(payload: &str) -> Option<&str> {
    parse_challenge(payload).map(|(token, _)| token)
}

/// Checks the lifespan and nonce of an already signature-verified challenge.
pub(super) fn verify_challenge(payload: Option<&str>, submitted: &str) -> bool {
    unix_time().is_ok_and(|now| verify_challenge_at(payload, submitted, now))
}

/// Creates a fixed-lifetime payload for signing at the HTTP boundary.
///
/// # Errors
/// Returns an error if the clock or expiry is outside supported Unix time.
pub(super) fn timed_payload(prefix: &str, token: &str, lifetime: Duration) -> Result<String> {
    let expiry = unix_time()?
        .checked_add(lifetime.as_secs())
        .ok_or_else(|| AppError::authentication(io::Error::other("cookie expiry overflow")))?;
    Ok(format!("{prefix}{token}:{expiry}"))
}

/// Returns Unix seconds without substituting an invalid clock value.
///
/// # Errors
/// Returns an error if the clock predates Unix time.
pub(super) fn unix_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|now| now.as_secs())
        .map_err(AppError::authentication)
}

/// Parses an exact-domain, fixed-width hexadecimal token and canonical expiry.
pub(super) fn parse_timed_payload<'a>(
    payload: &'a str,
    prefix: &str,
    token_chars: usize,
) -> Option<(&'a str, u64)> {
    if payload.len() > prefix.len() + token_chars + 1 + MAX_TIMESTAMP_CHARS {
        return None;
    }
    let (token, timestamp) = payload.strip_prefix(prefix)?.split_once(':')?;
    if !valid_hex(token, token_chars)
        || timestamp.is_empty()
        || timestamp.len() > MAX_TIMESTAMP_CHARS
        || timestamp.starts_with('0')
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((token, timestamp.parse().ok()?))
}

/// Rejects expired payloads and expiries beyond the original lifetime.
pub(super) fn valid_expiry(expiry: u64, now: u64, lifetime: Duration) -> bool {
    expiry
        .checked_sub(now)
        .is_some_and(|remaining| (1..=lifetime.as_secs()).contains(&remaining))
}

fn parse_challenge(payload: &str) -> Option<(&str, u64)> {
    parse_timed_payload(payload, CHALLENGE_PREFIX, TOKEN_CHARS)
}

fn verify_challenge_at(payload: Option<&str>, submitted: &str, now: u64) -> bool {
    let Some((token, expiry)) = payload.and_then(parse_challenge) else {
        return false;
    };
    valid_expiry(expiry, now, CHALLENGE_LIFETIME) && matches(token, submitted)
}

#[cfg(test)]
mod tests {
    use super::{
        CHALLENGE_LIFETIME, TOKEN_CHARS, challenge, challenge_token, matches, random_token,
        valid_token, verify_challenge, verify_challenge_at,
    };

    #[test]
    fn auth_tokens_are_fresh_fixed_length_and_strictly_encoded() {
        let first = random_token().unwrap();
        let second = random_token().unwrap();
        assert!(valid_token(&first));
        assert!(first != second);
        assert!(matches(&first, &first));
        assert!(!matches(&first, &second));
        for invalid in ["", &"A".repeat(TOKEN_CHARS), &"g".repeat(TOKEN_CHARS)] {
            assert!(!valid_token(invalid));
            assert!(!matches(&first, invalid));
        }
    }

    #[test]
    fn auth_challenge_round_trip_and_missing_or_tampered_token() {
        let payload = challenge().unwrap();
        let token = challenge_token(&payload).unwrap();
        assert!(verify_challenge(Some(&payload), token));
        assert!(!verify_challenge(None, token));
        assert!(!verify_challenge(Some(&payload), &random_token().unwrap()));
    }

    #[test]
    fn auth_challenge_rejects_noncanonical_or_out_of_bounds_expiry() {
        const NOW: u64 = 1_000_000;
        let token = random_token().unwrap();
        let expiry = NOW + CHALLENGE_LIFETIME.as_secs();
        let payload = format!("login:{token}:{expiry}");
        assert!(challenge_token(&format!("{token}:{expiry}")).is_none());
        assert!(challenge_token(&format!("viewer:{token}:{expiry}")).is_none());
        assert!(verify_challenge_at(Some(&payload), &token, NOW));
        assert!(verify_challenge_at(Some(&payload), &token, expiry - 1));
        assert!(!verify_challenge_at(Some(&payload), &token, expiry));
        assert!(!verify_challenge_at(Some(&payload), &token, expiry + 1));
        assert!(!verify_challenge_at(Some(&payload), &token, NOW - 1));
        for timestamp in [
            "",
            "0",
            "01",
            "+1000001",
            "1000001:1",
            "18446744073709551616",
        ] {
            let invalid = format!("login:{token}:{timestamp}");
            assert!(challenge_token(&invalid).is_none());
            assert!(!verify_challenge_at(Some(&invalid), &token, NOW));
        }
        assert!(
            challenge_token(&format!("login:{}:1000001", "a".repeat(TOKEN_CHARS - 1))).is_none()
        );
    }
}
