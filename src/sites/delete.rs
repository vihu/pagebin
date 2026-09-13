//! Confirmed metadata deletion followed by owned content removal.

use super::{Sites, Slug, content};
use crate::{AppError, Result, db};
use std::io::ErrorKind;
use tokio::fs;

/// The acknowledged result of deleting the current row at a confirmed slug.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeleteOutcome {
    /// No row was removed; any filesystem-only orphan was left untouched.
    NotFound,
    /// Metadata is gone and its content directory was removed or absent.
    Deleted,
    /// Metadata is gone but unsafe or failed content cleanup retained data.
    DeletedContentRetained,
}

/// Deletes a row, then its directory, while excluding same-slug recreation.
///
/// # Errors
/// Returns database failures without removing bytes, even on uncertain results.
pub(super) async fn delete(sites: &Sites, slug: &Slug) -> Result<DeleteOutcome> {
    let _mutation = sites.mutation.lock().await;
    if db::find_site(&sites.pool, slug)
        .await
        .map_err(AppError::publishing)?
        .is_none()
    {
        return Ok(DeleteOutcome::NotFound);
    }
    let removed = db::delete_site(&sites.pool, slug.as_str())
        .await
        .map_err(AppError::publishing)?;
    // A missing/ignored row confers no permission to clean up an orphan.
    if removed != 1 {
        return Ok(DeleteOutcome::NotFound);
    }
    if remove_content(sites, slug).await.is_err() {
        tracing::warn!("site metadata deleted; content retained for operator inspection");
        return Ok(DeleteOutcome::DeletedContentRetained);
    }
    Ok(DeleteOutcome::Deleted)
}

/// Removes the site directory without following a symlinked site path.
///
/// # Errors
/// Returns unsafe-storage, changed-type, or removal failures.
async fn remove_content(sites: &Sites, slug: &Slug) -> Result {
    content::validate_storage(&sites.data_root).await?;
    let directory = sites.directory(slug);
    match fs::symlink_metadata(&directory).await {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(AppError::publishing(error)),
        Ok(metadata) => content::check_directory(&metadata)?,
    }
    // remove_dir_all never follows symlinks; everything below is pagebin's.
    fs::remove_dir_all(&directory)
        .await
        .map_err(AppError::publishing)
}
