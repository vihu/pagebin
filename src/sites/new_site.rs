//! Validated, create-only pasted HTML or flat-file input.

use super::{
    ENTRY_FILENAME, MAX_SITE_FILES, SiteFile, Slug, UploadedFile, archive,
    validate::{Expiry, Filename, Title},
};
use crate::{AppError, auth::Password};
use axum::{body::Bytes, http::StatusCode};
use std::{collections::HashSet, ops::RangeInclusive};

const FILE_COUNT: RangeInclusive<usize> = 1..=MAX_SITE_FILES;
const SETTINGS_ENTRY_MESSAGE: &str = "Enter the exact filename of an existing site file.";

/// Validated files and optional metadata ready for staging.
pub(crate) struct NewSite {
    /// Owned flat files, validated together before any write.
    pub(super) files: Vec<SiteFile>,
    /// The existing file selected for the site's root response.
    pub(super) entry: Filename,
    /// The checked sum of all actual file lengths, representable in SQLite.
    pub(super) size_bytes: i64,
    /// The optional title, preserved without trimming.
    pub(super) title: String,
    /// The requested canonical URL key, or generated-name selection.
    pub(super) slug: Option<Slug>,
    /// The validated credential committed with the initial access mode.
    pub(super) password: Option<Password>,
    /// Seconds after publication at which the site expires, if any.
    pub(super) expires_in: Option<i64>,
}

impl NewSite {
    /// Attaches an already validated credential before any publication occurs.
    #[must_use]
    pub(crate) fn with_password(mut self, password: Option<Password>) -> Self {
        self.password = password;
        self
    }
}

/// Collects exactly one content mode and optional metadata before validation.
pub(crate) struct NewSiteBuilder {
    html: Option<String>,
    files: Option<Vec<UploadedFile>>,
    entry: Option<String>,
    title: String,
    slug: Option<Slug>,
    expires_in: String,
    archive: Option<(Bytes, usize)>,
}

/// Identifies a rejected input field without exposing submitted content.
#[derive(Debug, thiserror::Error)]
pub(crate) enum InputError {
    /// The HTML is empty or contains only whitespace.
    #[error("Enter HTML to publish.")]
    Html,
    /// The title exceeds its bounds or contains forbidden line separators.
    #[error("Use a single-line title of at most 200 characters.")]
    Title,
    /// No content mode or more than one content mode was supplied.
    #[error("Choose pasted HTML, files, or a ZIP archive, not more than one.")]
    Mode,
    /// The archive is unreadable, encrypted, or contains a symlink.
    #[error("The ZIP archive could not be read. Use a plain ZIP without symlinks or encryption.")]
    Archive,
    /// The files mode contains no files or exceeds its bounded count.
    #[error("Choose a file count within {FILE_COUNT:?}.")]
    FileCount,
    /// An uploaded filename is not a normal, non-reserved flat component.
    #[error("Use flat filenames without paths, backslashes, or the reserved name __unlock.")]
    Filename,
    /// Two uploaded parts use the same exact filename.
    #[error("Each uploaded file must have a different filename.")]
    DuplicateFilename,
    /// The actual total byte count cannot be represented safely.
    #[error("The selected files are too large.")]
    Size,
    /// The entry is unsafe, missing, or its automatic selection is ambiguous.
    #[error("Set the entry to an existing filename, or include index.html or one HTML file.")]
    Entry,
    /// Settings require an explicit safe file already in the published site.
    #[error("{SETTINGS_ENTRY_MESSAGE}")]
    SettingsEntry,
    /// Settings were submitted without an explicit access decision.
    #[error("Choose open or password-protected access.")]
    Access,
    /// Keeping a password requires an already protected current site.
    #[error("Enter a new password to enable protection.")]
    Password,
    /// The expiry is not one of the fixed options, or keeps on creation.
    #[error("Choose one of the listed expiry options.")]
    Expiry,
}

impl InputError {
    /// Returns the fixed form-field name associated with this error.
    pub(crate) const fn field(&self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Title => "title",
            Self::Mode
            | Self::FileCount
            | Self::Filename
            | Self::DuplicateFilename
            | Self::Size => "files",
            Self::Entry | Self::SettingsEntry => "entry",
            Self::Access => "visibility",
            Self::Password => "password",
            Self::Expiry => "expires_in",
            Self::Archive => "zip",
        }
    }
}

impl From<InputError> for AppError {
    fn from(error: InputError) -> Self {
        let message = match error {
            InputError::Html => "Enter HTML to publish.",
            InputError::Title => "Use a single-line title of at most 200 characters.",
            InputError::Mode => "Choose pasted HTML, files, or a ZIP archive, not more than one.",
            InputError::Archive => "The ZIP archive could not be read.",
            InputError::FileCount => "Choose a non-empty, bounded set of files.",
            InputError::Filename => "Use flat, non-reserved filenames without paths.",
            InputError::DuplicateFilename => "Each uploaded file must have a different filename.",
            InputError::Size => "The selected files are too large.",
            InputError::Entry => {
                "Set the entry to an existing filename, or include index.html or one HTML file."
            }
            InputError::SettingsEntry => SETTINGS_ENTRY_MESSAGE,
            InputError::Access => "Choose open or password-protected access.",
            InputError::Password => "Enter a new password to enable protection.",
            InputError::Expiry => "Choose one of the listed expiry options.",
        };
        Self::request(StatusCode::BAD_REQUEST, message)
    }
}

impl Default for NewSiteBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NewSiteBuilder {
    /// Starts a request with no content or optional metadata.
    pub(crate) const fn new() -> Self {
        Self {
            html: None,
            files: None,
            entry: None,
            title: String::new(),
            slug: None,
            expires_in: String::new(),
            archive: None,
        }
    }

    /// Selects pasted HTML, preserving the exact submitted text.
    #[must_use]
    pub(crate) fn html(mut self, html: String) -> Self {
        self.html = Some(html);
        self
    }

    /// Selects flat-file upload mode with unchecked multipart transport data.
    #[must_use]
    pub(crate) fn files(mut self, files: Vec<UploadedFile>) -> Self {
        self.files = Some(files);
        self
    }

    /// Selects an exact existing filename, or automatic selection when empty.
    #[must_use]
    pub(crate) fn entry(mut self, entry: Option<String>) -> Self {
        self.entry = entry.filter(|entry| !entry.is_empty());
        self
    }

    /// Sets an optional title without trimming it.
    #[must_use]
    pub(crate) fn title(mut self, title: String) -> Self {
        self.title = title;
        self
    }

    /// Selects a custom slug or a generated readable name.
    #[must_use]
    pub(crate) fn slug(mut self, slug: Option<Slug>) -> Self {
        self.slug = slug;
        self
    }

    /// Selects a ZIP archive whose declared contents may total `cap` bytes.
    #[must_use]
    pub(crate) fn archive(mut self, bytes: Bytes, cap: usize) -> Self {
        self.archive = Some((bytes, cap));
        self
    }

    /// Selects an expiry duration; empty or `never` means no expiry.
    #[must_use]
    pub(crate) fn expires_in(mut self, expires_in: String) -> Self {
        self.expires_in = expires_in;
        self
    }

    /// Validates all input before writes, without copying content bytes.
    ///
    /// # Errors
    /// Rejects mixed/missing modes, blank HTML, invalid titles, unsafe or
    /// duplicate filenames, excessive counts/byte sums, and unresolved entries.
    pub(crate) fn build(self) -> Result<NewSite, InputError> {
        let (uploaded, nested) = match (self.html, self.files, self.archive) {
            (Some(html), None, None) => {
                if html.trim().is_empty() {
                    return Err(InputError::Html);
                }
                let index = UploadedFile {
                    filename: ENTRY_FILENAME.to_owned(),
                    bytes: Bytes::from(html),
                };
                (vec![index], false)
            }
            (None, Some(files), None) => (files, false),
            (None, None, Some((bytes, cap))) => (archive::extract(&bytes, cap)?, true),
            _ => return Err(InputError::Mode),
        };
        let title = Title::parse(self.title)?;
        let expires_in = match Expiry::parse(&self.expires_in)? {
            Expiry::Keep => return Err(InputError::Expiry),
            Expiry::Never => None,
            Expiry::After(seconds) => Some(seconds),
        };
        if !FILE_COUNT.contains(&uploaded.len()) {
            return Err(InputError::FileCount);
        }
        let mut filenames = HashSet::with_capacity(uploaded.len());
        let mut files = Vec::with_capacity(uploaded.len());
        let mut size_bytes = 0_i64;
        for file in uploaded {
            let filename = if nested {
                Filename::parse_nested(file.filename)?
            } else {
                Filename::parse(file.filename)?
            };
            if !filenames.insert(filename.clone()) {
                return Err(InputError::DuplicateFilename);
            }
            let length = i64::try_from(file.bytes.len()).map_err(|_| InputError::Size)?;
            size_bytes = size_bytes.checked_add(length).ok_or(InputError::Size)?;
            files.push(SiteFile {
                filename,
                bytes: file.bytes,
            });
        }
        let entry = select_entry(&files, self.entry)?;
        Ok(NewSite {
            files,
            entry,
            size_bytes,
            title: title.into_string(),
            slug: self.slug,
            password: None,
            expires_in,
        })
    }
}

/// Selects an explicit entry, index, or sole case-insensitive HTML file.
///
/// # Errors
/// Returns an entry error for invalid, absent, or ambiguous selections.
fn select_entry(files: &[SiteFile], explicit: Option<String>) -> Result<Filename, InputError> {
    if let Some(explicit) = explicit {
        let entry = Filename::parse(explicit).map_err(|_| InputError::Entry)?;
        return files
            .iter()
            .any(|file| file.filename == entry)
            .then_some(entry)
            .ok_or(InputError::Entry);
    }
    if let Some(index) = files
        .iter()
        .find(|file| file.filename.as_str() == ENTRY_FILENAME)
    {
        return Ok(index.filename.clone());
    }
    let mut html = files
        .iter()
        .filter(|file| file.filename.is_html() && !file.filename.as_str().contains('/'));
    match (html.next(), html.next()) {
        (Some(file), None) => Ok(file.filename.clone()),
        _ => Err(InputError::Entry),
    }
}
