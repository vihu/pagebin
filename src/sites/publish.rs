//! Unique row reservation, exclusive installation, and conservative commit.

use super::{
    MAX_SLUG_ATTEMPTS, NewSite, Site, Sites, Slug,
    content::{Content, Destination},
};
use crate::{AppError, Result, auth::Password, db};
use axum::http::StatusCode;

#[derive(Debug, thiserror::Error)]
enum PublishError {
    #[error("generated slug attempt limit reached")]
    SlugExhausted,
}

/// Completes one admitted job, retaining uncertain commits and crash orphans.
///
/// # Errors
/// Returns validation/conflict errors or a safe typed operational failure.
pub(super) async fn create(
    sites: &Sites,
    input: NewSite,
    generate: impl FnMut() -> Result<Slug>,
) -> Result<Site> {
    let mut content = Content::new(&sites.data_root).await?;
    if let Err(error) = content.write(&input.files).await {
        content.cleanup().await?;
        return Err(error);
    }
    // Staging does not block other mutations. From reservation through owned
    // cleanup, deletion cannot remove a row or reuse any candidate directory.
    let _mutation = sites.mutation.lock().await;
    let result = publish_staged(sites, &input, generate, &mut content).await;
    // Explicit ownership and detached execution keep this async cleanup alive
    // after client cancellation. There is no recursive deletion or Drop I/O.
    content.cleanup().await?;
    result
}

/// Tries bounded, never-overwriting slug reservations for complete staging.
///
/// # Errors
/// Returns staging, clock, entropy, conflict, or publication failures.
async fn publish_staged(
    sites: &Sites,
    input: &NewSite,
    mut generate: impl FnMut() -> Result<Slug>,
    content: &mut Content,
) -> Result<Site> {
    let timestamp = super::unix_now()?;
    let file_count = i64::try_from(input.files.len()).map_err(AppError::publishing)?;
    for _ in 0..MAX_SLUG_ATTEMPTS {
        let slug = match &input.slug {
            Some(slug) => slug.clone(),
            None => generate()?,
        };
        let site = Site {
            slug: slug.as_str().to_owned(),
            title: input.title.clone(),
            visibility: if input.password.is_some() {
                "password"
            } else {
                "open"
            }
            .to_owned(),
            entry: input.entry.as_str().to_owned(),
            file_count,
            size_bytes: input.size_bytes,
            created_at: timestamp,
            updated_at: timestamp,
            expires_at: input
                .expires_in
                .map(|seconds| timestamp.saturating_add(seconds)),
        };
        if try_publish(sites, &slug, &site, input.password.as_ref(), content).await? {
            return Ok(site);
        }
        if input.slug.is_some() {
            return Err(AppError::request(
                StatusCode::CONFLICT,
                "That site slug is already in use.",
            ));
        }
    }
    Err(AppError::publishing(PublishError::SlugExhausted))
}

/// Reserves and installs one candidate before committing its metadata.
///
/// # Errors
/// Returns database, installation, rollback, or uncertain-commit failures.
async fn try_publish(
    sites: &Sites,
    slug: &Slug,
    site: &Site,
    password: Option<&Password>,
    content: &mut Content,
) -> Result<bool> {
    let mut transaction = sites.pool.begin().await.map_err(AppError::publishing)?;
    if let Err(error) = db::insert_site(&mut transaction, site, password).await {
        transaction.rollback().await.map_err(AppError::publishing)?;
        if error
            .as_database_error()
            .is_some_and(|error| error.is_unique_violation())
        {
            return Ok(false);
        }
        return Err(AppError::publishing(error));
    }
    let installation = async {
        if let Destination::Occupied = content.reserve_destination(sites.directory(slug)).await? {
            return Ok(Destination::Occupied);
        }
        content.install().await?;
        Ok(Destination::Created)
    }
    .await;
    match installation {
        Ok(Destination::Occupied) => {
            transaction.rollback().await.map_err(AppError::publishing)?;
            Ok(false)
        }
        Err(error) => {
            transaction.rollback().await.map_err(AppError::publishing)?;
            Err(error)
        }
        Ok(Destination::Created) => {
            // From here on even a failed commit can have an uncertain outcome.
            // Never remove installed bytes or retry this candidate afterward.
            content.preserve_installed();
            transaction.commit().await.map_err(AppError::publishing)?;
            Ok(true)
        }
    }
}
