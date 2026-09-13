//! validate.

use super::InputError;
use crate::{AppError, Result};
use axum::http::StatusCode;
use petname::Petnames;
use rand::{TryRng, rngs::SysRng};
use std::{
    ops::RangeInclusive,
    path::{Component, Path},
};

/// Maximum number of Unicode scalar values in a display title.
pub(super) const MAX_TITLE_CHARACTERS: usize = 200;
/// Maximum UTF-8 byte length of a display title.
pub(super) const MAX_TITLE_BYTES: usize = 800;

/// A validated optional title preserved without trimming.
pub(super) struct Title(String);

impl Title {
    /// Validates the existing character, UTF-8 byte, and line-break limits.
    ///
    /// # Errors
    /// Rejects oversized titles and NUL, carriage return, or newline.
    pub(super) fn parse(value: String) -> std::result::Result<Self, InputError> {
        if value.len() > MAX_TITLE_BYTES
            || value.chars().count() > MAX_TITLE_CHARACTERS
            || value.contains(['\0', '\r', '\n'])
        {
            return Err(InputError::Title);
        }
        Ok(Self(value))
    }

    /// Returns the exact validated title text.
    pub(super) const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Consumes the validated title without copying its contents.
    pub(super) fn into_string(self) -> String {
        self.0
    }
}

const SLUG_LENGTH: RangeInclusive<usize> = 3..=64;
const RESERVED_SLUGS: [&str; 7] = ["api", "static", "login", "logout", "new", "s", "health"];
const SUFFIX_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const SUFFIX_LENGTH: usize = 8;
const MAX_SAMPLE_ATTEMPTS: usize = 64;

/// A canonical, non-reserved site URL component.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Slug(String);

#[derive(Debug, thiserror::Error)]
enum SlugError {
    #[error("empty random sampling domain")]
    EmptyDomain,
    #[error("random sampling attempt limit reached")]
    SamplingExhausted,
}

impl Slug {
    /// Validates a custom or persisted slug without normalizing it.
    ///
    /// # Errors
    /// Returns 400 for invalid length, alphabet, hyphens, or reserved names.
    pub(crate) fn parse(value: &str) -> Result<Self> {
        if !SLUG_LENGTH.contains(&value.len())
            || value.starts_with('-')
            || value.ends_with('-')
            || RESERVED_SLUGS.contains(&value)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(AppError::request(
                StatusCode::BAD_REQUEST,
                "Invalid site slug.",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the validated URL component.
    pub(crate) const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Slug {
    /// Samples medium dictionaries and eight independent suffix bytes.
    ///
    /// # Errors
    /// Returns an operational error on entropy failure or sampling exhaustion.
    pub(super) fn generate() -> Result<Self> {
        generate_with(&mut || SysRng.try_next_u64().map_err(AppError::publishing))
    }
}

/// Builds a readable slug from independent, fallible random samples.
///
/// # Errors
/// Returns entropy, sampling, or final shape-validation failures.
fn generate_with(next: &mut impl FnMut() -> Result<u64>) -> Result<Slug> {
    let words = Petnames::medium();
    let mut value = String::new();
    for dictionary in [&words.adverbs, &words.adjectives, &words.nouns] {
        value.push_str(dictionary[sample_index(dictionary.len(), next)?]);
        value.push('-');
    }
    for _ in 0..SUFFIX_LENGTH {
        value.push(char::from(
            SUFFIX_ALPHABET[sample_index(SUFFIX_ALPHABET.len(), next)?],
        ));
    }
    Slug::parse(&value)
}

/// Samples a uniform index by discarding the incomplete residue cycle.
///
/// # Errors
/// Returns empty-domain, conversion, entropy, or rejection-budget failures.
fn sample_index(length: usize, next: &mut impl FnMut() -> Result<u64>) -> Result<usize> {
    let bound = u64::try_from(length).map_err(AppError::publishing)?;
    if bound == 0 {
        return Err(AppError::publishing(SlugError::EmptyDomain));
    }
    // Discard the incomplete residue cycle: the remaining 2^64 - threshold
    // values contain exactly the same number of representatives of each index.
    let threshold = bound.wrapping_neg() % bound;
    for _ in 0..MAX_SAMPLE_ATTEMPTS {
        let value = next()?;
        if value >= threshold {
            return usize::try_from(value % bound).map_err(AppError::publishing);
        }
    }
    Err(AppError::publishing(SlugError::SamplingExhausted))
}

/// A normal, non-reserved relative filename, one component unless nested.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct Filename(String);

impl Filename {
    /// Validates a filename before it can participate in any filesystem write.
    ///
    /// # Errors
    /// Rejects empty, nested, absolute, traversal, backslash, NUL, and reserved
    /// names, including platform-specific non-normal path components.
    pub(super) fn parse(value: String) -> std::result::Result<Self, InputError> {
        if value.contains('/') || SitePath::parse(&value).is_none() {
            return Err(InputError::Filename);
        }
        Ok(Self(value))
    }

    /// Validates a nested relative path taken from an archive entry.
    ///
    /// # Errors
    /// Rejects everything [`SitePath::parse`] rejects.
    pub(super) fn parse_nested(value: String) -> std::result::Result<Self, InputError> {
        if SitePath::parse(&value).is_none() {
            return Err(InputError::Filename);
        }
        Ok(Self(value))
    }

    /// Returns the exact validated filename.
    pub(super) const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Identifies HTML extensions without changing the filename's case.
    pub(super) fn is_html(&self) -> bool {
        self.0.rsplit_once('.').is_some_and(|(_, extension)| {
            extension.eq_ignore_ascii_case("html") || extension.eq_ignore_ascii_case("htm")
        })
    }
}

/// A nonempty relative path without traversal or reserved path segments.
#[derive(Clone, Copy)]
pub(crate) struct SitePath<'a>(&'a str);

impl<'a> SitePath<'a> {
    /// Validates an already decoded relative path without normalizing segments.
    ///
    /// # Errors
    /// Returns `None` for empty, absolute, traversal, reserved, or non-normal
    /// components and for paths containing backslashes or NUL bytes.
    pub(crate) fn parse(path: &'a str) -> Option<Self> {
        if path.is_empty()
            || path.contains(['\\', '\0'])
            || path
                .split('/')
                .any(|part| matches!(part, "" | "." | ".." | "__unlock"))
            || Path::new(path)
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return None;
        }
        Some(Self(path))
    }

    /// Returns the validated relative path without URL re-decoding.
    pub(crate) const fn as_str(self) -> &'a str {
        self.0
    }
}

/// The seconds behind each fixed `expires_in` duration.
const EXPIRY_OPTIONS: [(&str, i64); 4] = [
    ("1h", 3_600),
    ("1d", 86_400),
    ("7d", 604_800),
    ("30d", 2_592_000),
];

/// A validated expiry choice from the fixed form options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Expiry {
    /// Retain the current expiry; settings only.
    Keep,
    /// Never expire, clearing any current expiry.
    Never,
    /// Expire this many seconds after the save.
    After(i64),
}

impl Expiry {
    /// Parses `keep`, `never`, an empty choice, or one of the fixed durations.
    ///
    /// # Errors
    /// Returns an expiry error for any other value.
    pub(crate) fn parse(value: &str) -> std::result::Result<Self, InputError> {
        match value {
            "keep" => Ok(Self::Keep),
            "" | "never" => Ok(Self::Never),
            _ => EXPIRY_OPTIONS
                .iter()
                .find(|(name, _)| *name == value)
                .map(|(_, seconds)| Self::After(*seconds))
                .ok_or(InputError::Expiry),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Filename, MAX_TITLE_BYTES, MAX_TITLE_CHARACTERS, SLUG_LENGTH, SitePath, Slug, Title,
    };
    use crate::sites::InputError;
    use axum::{http::StatusCode, response::IntoResponse};

    #[test]
    fn settings_title_preserves_empty_whitespace_and_unicode_limits() {
        for title in [
            "".to_owned(),
            " title ".to_owned(),
            "🦀".repeat(MAX_TITLE_CHARACTERS),
        ] {
            assert_eq!(Title::parse(title.clone()).unwrap().as_str(), title);
        }
        assert_eq!("🦀".repeat(MAX_TITLE_CHARACTERS).len(), MAX_TITLE_BYTES);
        for title in [
            "x\0y".to_owned(),
            "x\ny".to_owned(),
            "x\ry".to_owned(),
            "a".repeat(MAX_TITLE_CHARACTERS + 1),
            "🦀".repeat(MAX_TITLE_CHARACTERS + 1),
        ] {
            assert!(matches!(Title::parse(title), Err(InputError::Title)));
        }
    }

    #[test]
    fn slug_parse_accepts_canonical_values_and_rejects_reserved_or_malformed() {
        assert_eq!(Slug::parse("a-0-z").unwrap().as_str(), "a-0-z");
        for invalid in [
            "login",
            "ABC",
            "-abc",
            "a_b",
            "ab",
            &"a".repeat(SLUG_LENGTH.end() + 1),
        ] {
            assert_eq!(
                Slug::parse(invalid).unwrap_err().into_response().status(),
                StatusCode::BAD_REQUEST
            );
        }
    }

    #[test]
    fn slug_generate_produces_valid_readable_slugs() {
        let generated = Slug::generate().unwrap();
        assert_eq!(generated.as_str().split('-').count(), 4);
        assert!(Slug::parse(generated.as_str()).is_ok());
    }

    #[test]
    fn files_filename_accepts_flat_names_and_rejects_unsafe_names() {
        for name in ["index.html", "REPORT.HTM", "空 白.css", ".hidden", "empty"] {
            assert_eq!(Filename::parse(name.to_owned()).unwrap().as_str(), name);
        }
        for name in [
            "",
            ".",
            "..",
            "/index.html",
            "a/b",
            "a//b",
            "a/",
            "../x",
            "a\\b",
            "a\0b",
            "__unlock",
        ] {
            assert!(Filename::parse(name.to_owned()).is_err(), "{name:?}");
        }
    }

    #[test]
    fn files_filename_html_extensions_are_ascii_case_insensitive() {
        for name in ["a.html", "a.HTML", "a.HtM", ".html"] {
            assert!(Filename::parse(name.to_owned()).unwrap().is_html());
        }
        for name in ["a.html.css", "a.xhtml", "html", "a.hＴml", "a.htm "] {
            assert!(!Filename::parse(name.to_owned()).unwrap().is_html());
        }
    }

    #[test]
    fn publish_paths_accept_normal_components_and_reject_boundary_escapes() {
        for path in [
            "index.html",
            "assets/style.css",
            "a b/日本語.html",
            ".well-known/info",
            "%2e.txt",
        ] {
            assert_eq!(SitePath::parse(path).unwrap().as_str(), path);
        }
        for path in [
            "",
            "/etc/passwd",
            "../outside",
            "a/../b",
            "./index.html",
            "a//b",
            "a/",
            "a\\b",
            "a\0b",
            "__unlock",
            "nested/__unlock/file",
        ] {
            assert!(SitePath::parse(path).is_none(), "accepted {path:?}");
        }
    }
}
