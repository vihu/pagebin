//! Expiry sweeps and boot reconciliation of site rows against directories.

use super::{Sites, Slug, unix_now};
use crate::{AppError, Result, db};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::fs::{self, DirEntry};

const SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Reconciles storage and sweeps once, then keeps sweeping in the background.
///
/// # Errors
/// Returns an error if storage or the database cannot be read at boot.
pub(crate) async fn start(sites: Arc<Sites>) -> Result {
    reconcile(&sites).await?;
    sweep(&sites).await?;
    tokio::spawn(async move {
        let mut ticks = tokio::time::interval(SWEEP_INTERVAL);
        // The immediate first tick is covered by the sweep above.
        ticks.tick().await;
        loop {
            ticks.tick().await;
            if let Err(error) = sweep(&sites).await {
                tracing::error!(error = %error, "expiry sweep failed");
            }
        }
    });
    Ok(())
}

/// Deletes every site whose expiry has passed, one confirmed row at a time.
async fn sweep(sites: &Sites) -> Result {
    let expired = db::expired_slugs(&sites.pool, unix_now()?)
        .await
        .map_err(AppError::publishing)?;
    for slug in expired {
        let result = match Slug::parse(&slug) {
            Ok(slug) => sites.delete(slug).await.map(|_| ()),
            // A row with an unparsable slug can own no directory.
            Err(_) => db::delete_site(&sites.pool, &slug)
                .await
                .map(|_| ())
                .map_err(AppError::publishing),
        };
        match result {
            Ok(()) => tracing::info!(slug, "expired site removed"),
            Err(error) => tracing::error!(slug, error = %error, "expired site removal failed"),
        }
    }
    Ok(())
}

/// Clears staging, then removes content without a row and rows without content.
async fn reconcile(sites: &Sites) -> Result {
    let _mutation = sites.mutation.lock().await;
    let mut staged = fs::read_dir(sites.data_root.join("tmp"))
        .await
        .map_err(AppError::publishing)?;
    while let Some(entry) = staged.next_entry().await.map_err(AppError::publishing)? {
        remove(&entry, "leftover staging removed").await;
    }
    let rows: HashSet<String> = db::slugs(&sites.pool)
        .await
        .map_err(AppError::publishing)?
        .into_iter()
        .collect();
    let mut present = HashSet::new();
    let mut content = fs::read_dir(sites.data_root.join("sites"))
        .await
        .map_err(AppError::publishing)?;
    while let Some(entry) = content.next_entry().await.map_err(AppError::publishing)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if rows.contains(&name) {
            present.insert(name);
        } else {
            remove(&entry, "content without a site row removed").await;
        }
    }
    for slug in rows.difference(&present) {
        tracing::warn!(slug, "site row without content removed");
        db::delete_site(&sites.pool, slug)
            .await
            .map_err(AppError::publishing)?;
    }
    Ok(())
}

/// Removes one entry pagebin owns without following symlinks, logging failures.
async fn remove(entry: &DirEntry, message: &'static str) {
    let path = entry.path();
    let is_dir = entry.file_type().await.is_ok_and(|kind| kind.is_dir());
    let result = if is_dir {
        fs::remove_dir_all(&path).await
    } else {
        fs::remove_file(&path).await
    };
    match result {
        Ok(()) => tracing::warn!(path = %path.display(), "{message}"),
        Err(error) => {
            tracing::error!(path = %path.display(), error = %error, "reconciliation removal failed")
        }
    }
}
