//! In-place content replacement that keeps the row's identity and access.

use super::{NewSite, Sites, Slug, content::Content};
use crate::{AppError, Result, db};
use tokio::fs;

/// Stages new content, then swaps it in and records it under the mutex.
///
/// # Errors
/// Returns staging, storage, or database failures; the previous content is
/// restored on every failure after the swap.
pub(super) async fn replace(sites: &Sites, slug: &Slug, input: NewSite) -> Result<bool> {
    let mut content = Content::new(&sites.data_root).await?;
    if let Err(error) = content.write(&input.files).await {
        content.cleanup().await?;
        return Err(error);
    }
    let _mutation = sites.mutation.lock().await;
    let result = swap(sites, slug, &input, &mut content).await;
    content.cleanup().await?;
    result
}

/// Swaps directories, then records the new content; `false` means no row.
async fn swap(sites: &Sites, slug: &Slug, input: &NewSite, content: &mut Content) -> Result<bool> {
    if sites.get(slug).await?.is_none() {
        return Ok(false);
    }
    let updated_at = super::unix_now()?;
    let file_count = i64::try_from(input.files.len()).map_err(AppError::publishing)?;
    let directory = sites.directory(slug);
    let parked = content.swap_into(&directory).await?;
    let recorded = db::replace_site(
        &sites.pool,
        slug,
        input.entry.as_str(),
        file_count,
        input.size_bytes,
        updated_at,
    )
    .await;
    match recorded {
        Ok(1) => {
            if let Err(error) = fs::remove_dir_all(&parked).await {
                tracing::warn!(path = %parked.display(), error = %error, "replaced content retained until the next boot");
            }
            Ok(true)
        }
        other => {
            content.swap_back(&directory, &parked).await?;
            other.map(|_| false).map_err(AppError::publishing)
        }
    }
}
