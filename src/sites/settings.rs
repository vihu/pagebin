//! Validated metadata and explicit access intent without password hashing.

use super::{
    AccessUpdate, InputError, SiteDetails, Sites, Slug, content,
    validate::{Expiry, Filename, Title},
};
use crate::{AppError, Result, db};
use std::io::ErrorKind;
use tokio::fs;

/// Validated settings requiring an entry check against current storage.
pub(crate) struct Settings {
    /// The checked optional title, preserved without trimming.
    pub(super) title: Title,
    /// The checked flat filename, requiring current filesystem validation.
    pub(super) entry: Filename,
    /// Explicit access intent applied to the latest committed credential.
    pub(super) access: AccessUpdate,
    /// Explicit expiry intent applied to the current row.
    pub(super) expiry: Expiry,
}

/// Collects metadata and requires an explicit credential-preservation decision.
#[derive(Default)]
pub(crate) struct SettingsBuilder {
    title: String,
    entry: String,
    access: Option<AccessUpdate>,
    expires_in: String,
}

impl SettingsBuilder {
    /// Sets the optional title without trimming its content.
    #[must_use]
    pub(crate) fn title(mut self, title: String) -> Self {
        self.title = title;
        self
    }

    /// Selects an exact existing flat filename, without automatic fallback.
    #[must_use]
    pub(crate) fn entry(mut self, entry: String) -> Self {
        self.entry = entry;
        self
    }

    /// Selects opening, retaining the current password, or setting a fresh one.
    #[must_use]
    pub(crate) fn access(mut self, access: AccessUpdate) -> Self {
        self.access = Some(access);
        self
    }

    /// Selects keeping, clearing, or resetting the expiry.
    #[must_use]
    pub(crate) fn expires_in(mut self, expires_in: String) -> Self {
        self.expires_in = expires_in;
        self
    }

    /// Validates text and entry shape before any mutation is admitted.
    ///
    /// # Errors
    /// Rejects invalid titles, unsafe entries, and missing access intent.
    pub(crate) fn build(self) -> std::result::Result<Settings, InputError> {
        Ok(Settings {
            title: Title::parse(self.title)?,
            entry: Filename::parse(self.entry).map_err(|_| InputError::SettingsEntry)?,
            access: self.access.ok_or(InputError::Access)?,
            expiry: Expiry::parse(&self.expires_in)?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
enum UpdateError {
    #[error("site settings update could not be confirmed")]
    Unconfirmed,
}

/// Saves against the current slug while excluding deletion and recreation.
///
/// # Errors
/// Rejects missing current passwords, unsafe entries, or unconfirmed writes.
pub(super) async fn update(
    sites: &Sites,
    slug: &Slug,
    input: Settings,
) -> Result<Option<SiteDetails>> {
    let _mutation = sites.mutation.lock().await;
    let Some(current) = sites.access(slug).await? else {
        // An absent row never authorizes orphan inspection or adoption.
        return Ok(None);
    };
    let password = match &input.access {
        AccessUpdate::Open => None,
        AccessUpdate::Keep => Some(current.password.as_ref().ok_or(InputError::Password)?),
        AccessUpdate::Set(password) => Some(password),
    };
    validate_entry(sites, slug, &input).await?;
    let updated_at = super::unix_now()?;
    let expires_at = match input.expiry {
        Expiry::Keep => current.site.expires_at,
        Expiry::Never => None,
        Expiry::After(seconds) => Some(updated_at.saturating_add(seconds)),
    };
    let changed = db::update_site(
        &sites.pool,
        slug,
        input.title.as_str(),
        input.entry.as_str(),
        password,
        updated_at,
        expires_at,
    )
    .await
    .map_err(AppError::publishing)?;
    if changed != 1 {
        return Err(AppError::publishing(UpdateError::Unconfirmed));
    }
    // A failed post-write read is not a success, even if the save committed.
    sites
        .details(slug)
        .await?
        .map(Some)
        .ok_or_else(|| AppError::publishing(UpdateError::Unconfirmed))
}

/// Validates a safe existing regular entry without opening or rewriting bytes.
///
/// # Errors
/// Rejects unsafe storage, missing/nonregular entries, or metadata failures.
async fn validate_entry(sites: &Sites, slug: &Slug, input: &Settings) -> Result {
    content::validate_storage(&sites.data_root).await?;
    let directory = sites.directory(slug);
    content::validate_directory(&directory).await?;
    match fs::symlink_metadata(directory.join(input.entry.as_str())).await {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(InputError::SettingsEntry.into()),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(InputError::SettingsEntry.into()),
        Err(error) => Err(AppError::publishing(error)),
    }
}
