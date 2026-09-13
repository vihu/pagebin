//! Multipart content reading shared by the native forms and the API.

use crate::{
    AppError, Result,
    config::PASSWORD_BYTES,
    sites::{InputError, MAX_SITE_FILES, NewSite, NewSiteBuilder, Slug, UploadedFile},
};
use axum::{body::Bytes, extract::Multipart, http::StatusCode};
use std::collections::HashSet;

/// Declared archive contents may total this many times the upload limit.
const ARCHIVE_EXPANSION: usize = 4;

/// The content input a form used; it also selects which tab renders.
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) enum Input {
    /// Pasted HTML published as `index.html`.
    #[default]
    Html,
    /// Flat files selected together.
    Files,
    /// One ZIP archive, folders allowed.
    Zip,
}

impl Input {
    /// Returns the query value and template name of this input.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Html => "html",
            Self::Files => "files",
            Self::Zip => "zip",
        }
    }

    /// Selects the input from a page query without inferring an upload's mode.
    ///
    /// # Errors
    /// Rejects unknown or ambiguous query parameters.
    pub(super) fn parse(query: Option<&str>) -> Result<Self> {
        match query {
            None | Some("") | Some("input=html") => Ok(Self::Html),
            Some("input=files") => Ok(Self::Files),
            Some("input=zip") => Ok(Self::Zip),
            _ => Err(super::invalid()),
        }
    }
}

/// Holds untrusted input until shared publication validation succeeds.
#[derive(Default)]
pub(super) struct PublishingForm {
    /// The submitted session-bound verification token.
    pub(super) csrf_token: String,
    /// Submitted HTML, rendered only as escaped editable text on admin pages.
    pub(super) html: String,
    /// The optional unvalidated display title.
    pub(super) title: String,
    /// The optional unvalidated custom slug.
    pub(super) slug: String,
    /// The optional entry filename, never a filesystem path before validation.
    pub(super) entry: String,
    /// The content input used, which also selects the rendered tab.
    pub(super) input: Input,
    /// An explicit access choice; absent legacy creation defaults to open.
    pub(super) visibility: Option<String>,
    /// Transient submitted credential, never passed to presentation models.
    pub(super) password: String,
    /// The unvalidated expiry choice, echoed back into the select.
    pub(super) expires_in: String,
    html_present: bool,
    files: Vec<UploadedFile>,
    zip: Option<Bytes>,
}

impl PublishingForm {
    /// Returns the explicit access choice or the legacy open default.
    pub(super) fn visibility(&self) -> &str {
        self.visibility.as_deref().unwrap_or("open")
    }

    /// Selects an empty native form without inferring an upload's actual mode.
    ///
    /// # Errors
    /// Rejects unknown or ambiguous query parameters.
    pub(super) fn for_query(query: Option<&str>) -> Result<Self> {
        Ok(Self {
            input: Input::parse(query)?,
            ..Self::default()
        })
    }

    /// Reads scalar metadata and binary files from a capped complete body.
    ///
    /// The caller owns upload admission and has read the complete HTTP body.
    /// Recognizes empty native file controls without creating an empty file.
    ///
    /// # Errors
    /// Rejects malformed/unknown/duplicate fields, oversized metadata or file
    /// counts, invalid text, missing input, or an absent verification field.
    pub(super) async fn read(mut multipart: Multipart, encoded_length: usize) -> Result<Self> {
        let mut submitted = Self::default();
        let mut seen = HashSet::new();
        let mut file_parts = 0;
        while let Some(mut field) = multipart
            .next_field()
            .await
            .map_err(super::multipart_error)?
        {
            if field.name() == Some("files[]") {
                file_parts += 1;
                if file_parts > MAX_SITE_FILES {
                    return Err(AppError::request(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "Too many files in one upload. Select a smaller batch and try again.",
                    ));
                }
                let filename = field.file_name().ok_or_else(super::invalid)?.to_owned();
                if filename.len() > super::METADATA_FIELD_BYTES {
                    return Err(super::invalid());
                }
                let bytes = field.bytes().await.map_err(super::multipart_error)?;
                submitted.input = Input::Files;
                if filename.is_empty() && bytes.is_empty() {
                    continue;
                }
                submitted.files.push(UploadedFile { filename, bytes });
                continue;
            }
            if field.name() == Some("zip") {
                if field.file_name().is_none() || !seen.insert("zip") {
                    return Err(super::invalid());
                }
                let bytes = field.bytes().await.map_err(super::multipart_error)?;
                submitted.input = Input::Zip;
                if !bytes.is_empty() {
                    submitted.zip = Some(bytes);
                }
                continue;
            }
            let name = match field.name() {
                Some("html") => "html",
                Some("title") => "title",
                Some("slug") => "slug",
                Some("entry") => "entry",
                Some("visibility") => "visibility",
                Some("password") => "password",
                Some("expires_in") => "expires_in",
                Some("csrf_token") => "csrf_token",
                _ => return Err(super::invalid()),
            };
            if field.file_name().is_some() || !seen.insert(name) {
                return Err(super::invalid());
            }
            let limit = match name {
                "html" => encoded_length,
                "csrf_token" => super::CSRF_FIELD_BYTES,
                "password" => *PASSWORD_BYTES.end(),
                _ => super::METADATA_FIELD_BYTES,
            };
            let mut bytes = Vec::new();
            while let Some(chunk) = field.chunk().await.map_err(super::multipart_error)? {
                if bytes.len().saturating_add(chunk.len()) > limit {
                    return Err(AppError::request(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "form field is too large",
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            let value = String::from_utf8(bytes).map_err(|_| super::invalid())?;
            match name {
                "html" => {
                    submitted.html = value;
                    submitted.html_present = true;
                }
                "title" => submitted.title = value,
                "slug" => submitted.slug = value,
                "entry" => submitted.entry = value,
                "visibility" => submitted.visibility = Some(value),
                "password" => submitted.password = value,
                "expires_in" => submitted.expires_in = value,
                _ => submitted.csrf_token = value,
            }
        }
        if !submitted.html_present && submitted.input == Input::Html {
            return Err(AppError::request(
                StatusCode::BAD_REQUEST,
                "Paste HTML, select files, or choose a ZIP archive to publish.",
            ));
        }
        Ok(submitted)
    }

    /// Moves file buffers into validated input while retaining editable text.
    ///
    /// # Errors
    /// Returns the shared builder's mode, filename, entry, or text rejection.
    pub(super) fn input(
        &mut self,
        slug: Option<Slug>,
        max_upload_bytes: usize,
    ) -> std::result::Result<NewSite, InputError> {
        let mut builder = NewSiteBuilder::default()
            .title(self.title.clone())
            .slug(slug)
            .expires_in(self.expires_in.clone())
            .entry((!self.entry.is_empty()).then(|| self.entry.clone()));
        if self.html_present {
            builder = builder.html(self.html.clone());
        }
        if self.input == Input::Files {
            builder = builder.files(std::mem::take(&mut self.files));
        }
        if let Some(zip) = self.zip.take() {
            builder = builder.archive(zip, max_upload_bytes.saturating_mul(ARCHIVE_EXPANSION));
        }
        builder.build()
    }
}
