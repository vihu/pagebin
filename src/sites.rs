//! Shared publication, settings, and deletion with cancellation-owned jobs.

mod archive;
mod content;
mod delete;
mod new_site;
mod publish;
mod replace;
mod settings;
mod sweep;
mod validate;

use crate::{AppError, Result, auth::Password, config::validated_data_dir, db};
use axum::{body::Bytes, http::StatusCode};
use sqlx::{FromRow, Row, SqlitePool, sqlite::SqliteRow};
use std::{
    future::Future,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use validate::Filename;

pub(crate) use delete::DeleteOutcome;
pub(crate) use new_site::{InputError, NewSite, NewSiteBuilder};
pub(crate) use settings::{Settings, SettingsBuilder};
pub(crate) use sweep::start as start_sweeper;
pub(crate) use validate::{SitePath, Slug};

/// Maximum number of flat uploaded files accepted in one site.
pub(crate) const MAX_SITE_FILES: usize = 10_000;
/// Number of displayed administration rows per page, excluding its sentinel.
pub(crate) const SITES_PER_PAGE: usize = 20;
const MAX_SLUG_ATTEMPTS: usize = 8;
const ENTRY_FILENAME: &str = "index.html";

/// Returns the current Unix time in seconds as a SQLite-representable integer.
///
/// # Errors
/// Returns a safe operational error if the system clock is not representable.
pub(crate) fn unix_now() -> Result<i64> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(AppError::publishing)?
            .as_secs(),
    )
    .map_err(AppError::publishing)
}

/// Shared storage and metadata serialization.
#[derive(Clone)]
pub(crate) struct Sites {
    pool: SqlitePool,
    data_root: PathBuf,
    // NOTE: one global mutation lock, single admin. Per-slug locks if multi-user ever lands.
    mutation: Arc<Mutex<()>>,
}

impl Sites {
    /// Uses existing storage without opening a database or altering files.
    ///
    /// The operator must own the root and its ancestors and prevent local path
    /// replacement; this does not guard against adversarial filesystem races.
    ///
    /// # Errors
    /// Returns an error for invalid paths or symlink/non-directory storage.
    pub(crate) fn new(pool: SqlitePool, data_root: PathBuf) -> Result<Self> {
        let data_root = validated_data_dir(&data_root)?;
        for directory in [&data_root, &data_root.join("sites"), &data_root.join("tmp")] {
            content::check_directory(
                &std::fs::symlink_metadata(directory).map_err(AppError::publishing)?,
            )?;
        }
        Ok(Self {
            pool,
            data_root,
            mutation: Arc::new(Mutex::new(())),
        })
    }

    /// Publishes a new site without replacing an existing row or path.
    ///
    /// A detached task owns the input to completion. Dropping the caller
    /// cannot cancel staging, rollback, installation, or commit; process
    /// shutdown may retain invisible orphans. A commit error retains
    /// installed bytes because its outcome can be uncertain.
    ///
    /// # Errors
    /// Returns 409 for custom conflicts or a safe operational error for
    /// storage, database, entropy, or retry exhaustion.
    pub(crate) async fn publish(&self, input: NewSite) -> Result<Site> {
        let sites = self.clone();
        detached(
            "site publication did not complete successfully",
            async move { publish::create(&sites, input, Slug::generate).await },
        )
        .await
    }

    /// Reads committed metadata without trusting its path or access fields.
    ///
    /// # Errors
    /// Returns a safe operational error when the database cannot be read.
    pub(crate) async fn get(&self, slug: &Slug) -> Result<Option<Site>> {
        db::find_site(&self.pool, slug)
            .await
            .map_err(AppError::publishing)
    }

    /// Reads one consistent metadata and credential snapshot for viewer access.
    ///
    /// Open rows ignore unused hashes; invalid protected credentials fail
    /// closed.
    /// Callers must still validate persisted paths and enforce expiry.
    ///
    /// # Errors
    /// Returns safe database or stored-credential validation failures.
    pub(crate) async fn access(&self, slug: &Slug) -> Result<Option<AccessSite>> {
        db::access_site(&self.pool, slug)
            .await
            .map_err(AppError::publishing)
    }

    /// Saves metadata and access for the current slug without changing files.
    ///
    /// A detached job holds the shared mutation lock through its read,
    /// save, and acknowledgement. Keeping a password uses the latest
    /// credential, not an earlier form snapshot. An absent row returns `None`
    /// without inspecting filesystem-only orphans. Uncertain outcomes never
    /// claim success; no database transaction spans password hashing.
    ///
    /// # Errors
    /// Returns 400 for invalid current entry/password choices or a safe
    /// failure for unsafe storage or unconfirmed writes.
    pub(crate) async fn update(&self, slug: Slug, input: Settings) -> Result<Option<SiteDetails>> {
        let sites = self.clone();
        detached("site settings update could not be confirmed", async move {
            settings::update(&sites, &slug, input).await
        })
        .await
    }

    /// Replaces content in place, keeping the slug, title, access, and expiry.
    ///
    /// # Errors
    /// Returns a safe operational error for storage or database failures.
    pub(crate) async fn replace(&self, slug: Slug, input: NewSite) -> Result<bool> {
        let sites = self.clone();
        detached("site content replacement did not complete", async move {
            replace::replace(&sites, &slug, input).await
        })
        .await
    }

    /// Lists every site, newest first, for the API.
    ///
    /// # Errors
    /// Returns a safe operational error when the database cannot be read.
    pub(crate) async fn all(&self) -> Result<Vec<Site>> {
        db::all_sites(&self.pool)
            .await
            .map_err(AppError::publishing)
    }

    /// Reads administration details without applying viewer access filtering.
    ///
    /// # Errors
    /// Returns a safe operational error when the database cannot be read.
    pub(crate) async fn details(&self, slug: &Slug) -> Result<Option<SiteDetails>> {
        db::site_details(&self.pool, slug)
            .await
            .map_err(AppError::publishing)
    }

    /// Reads one-based pages with at most one extra row indicating a next page.
    ///
    /// # Errors
    /// Returns 400 for zero or overflowing pages, or a safe database failure.
    pub(crate) async fn list(&self, page: usize) -> Result<Vec<SiteDetails>> {
        let offset = page
            .checked_sub(1)
            .and_then(|page| page.checked_mul(SITES_PER_PAGE))
            .and_then(|offset| i64::try_from(offset).ok())
            .ok_or_else(|| AppError::request(StatusCode::BAD_REQUEST, "Invalid site-list page."))?;
        db::list_sites(&self.pool, offset)
            .await
            .map_err(AppError::publishing)
    }

    /// Deletes the current site at an explicitly confirmed slug.
    ///
    /// Confirmation targets the current slug, not a historical incarnation.
    /// Detached ownership survives caller cancellation. The row must be
    /// acknowledged deleted before bounded, nonrecursive cleanup. No cleanup
    /// is retried by slug after releasing mutation serialization. A process
    /// exit can retain invisible content; there is no power-loss durability
    /// claim. In-flight responses and public caches can outlive the deletion;
    /// newly gated requests cannot access an absent row.
    ///
    /// # Errors
    /// Returns a safe database error that retains all content if deletion
    /// cannot be confirmed.
    pub(crate) async fn delete(&self, slug: Slug) -> Result<DeleteOutcome> {
        let sites = self.clone();
        detached("site deletion could not be confirmed", async move {
            delete::delete(&sites, &slug).await
        })
        .await
    }

    /// Returns the content directory for an already validated slug.
    pub(crate) fn directory(&self, slug: &Slug) -> PathBuf {
        self.data_root.join("sites").join(slug.as_str())
    }
}

/// A SQLite site row whose path and access fields require serving validation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, sqlx::FromRow)]
pub(crate) struct Site {
    /// The persisted URL key, not yet trusted as a filesystem component.
    pub(crate) slug: String,
    /// The submitted optional display title.
    pub(crate) title: String,
    /// The stored access mode, currently `open` or `password`.
    pub(crate) visibility: String,
    /// The stored entry path, requiring validation before serving.
    pub(crate) entry: String,
    /// The number of published files.
    pub(crate) file_count: i64,
    /// The exact total content byte size.
    pub(crate) size_bytes: i64,
    /// The creation time in Unix seconds.
    pub(crate) created_at: i64,
    /// The last update time in Unix seconds.
    pub(crate) updated_at: i64,
    /// The optional access-expiration time in Unix seconds.
    pub(crate) expires_at: Option<i64>,
}

/// A committed site row with SQLite-formatted UTC labels for administration.
#[derive(Debug, Eq, PartialEq, sqlx::FromRow)]
pub(crate) struct SiteDetails {
    /// Original metadata, including unmodified integer creation/expiry times.
    #[sqlx(flatten)]
    pub(crate) site: Site,
    /// Creation date/time in UTC, or `Unknown` for unrepresentable timestamps.
    pub(crate) created_label: String,
    /// UTC expiry, `Never` when absent, or `Unknown` for invalid timestamps.
    pub(crate) expires_label: String,
}

/// Metadata and its matching credential from the same database row snapshot.
pub(crate) struct AccessSite {
    /// Untrusted persisted metadata, requiring path and expiry checks.
    pub(crate) site: Site,
    /// The validated current credential, present only for protected sites.
    pub(crate) password: Option<Password>,
}

#[derive(Debug, thiserror::Error)]
enum AccessError {
    #[error("stored site access mode is invalid")]
    Visibility,
    #[error("stored site credential is missing")]
    MissingPassword,
}

impl<'row> FromRow<'row, SqliteRow> for AccessSite {
    fn from_row(row: &'row SqliteRow) -> sqlx::Result<Self> {
        let site = Site::from_row(row)?;
        let password = match site.visibility.as_str() {
            // The schema deliberately permits unused hashes on open rows.
            "open" => None,
            "password" => {
                let encoded: Option<String> = row.try_get("password_hash")?;
                let encoded = encoded
                    .ok_or_else(|| sqlx::Error::Decode(Box::new(AccessError::MissingPassword)))?;
                Some(
                    Password::from_encoded(encoded)
                        .map_err(|error| sqlx::Error::Decode(Box::new(error)))?,
                )
            }
            _ => return Err(sqlx::Error::Decode(Box::new(AccessError::Visibility))),
        };
        Ok(Self { site, password })
    }
}

/// The access change to apply to the current row, not an earlier form snapshot.
pub(crate) enum AccessUpdate {
    /// Remove protection and clear any retained credential.
    Open,
    /// Retain the current credential of an already protected site.
    Keep,
    /// Install a freshly salted credential prepared by bounded authentication.
    Set(Password),
}

/// Unchecked multipart transport data requiring builder validation before use.
#[derive(Clone, Debug)]
pub(crate) struct UploadedFile {
    /// The raw multipart filename, not safe for filesystem use.
    pub(crate) filename: String,
    /// Exact arbitrary bytes, including empty assets and non-UTF-8 content.
    pub(crate) bytes: Bytes,
}

/// Validated flat filename and exact content owned by one publication.
#[derive(Debug)]
struct SiteFile {
    /// The validated single filesystem component.
    filename: Filename,
    /// The owned content, retained through staging without copying.
    bytes: Bytes,
}

/// Runs a mutation on a detached task so a client disconnect cannot cancel it.
async fn detached<T: Send + 'static>(
    message: &'static str,
    job: impl Future<Output = Result<T>> + Send + 'static,
) -> Result<T> {
    tokio::spawn(async move {
        let result = job.await;
        if result.is_err() {
            tracing::error!("{message}");
        }
        result
    })
    .await
    .map_err(AppError::publishing)?
}

#[cfg(test)]
mod tests {
    use super::{ENTRY_FILENAME, NewSite, NewSiteBuilder, Sites, Slug};
    use crate::open_database;
    use axum::{http::StatusCode, response::IntoResponse};
    use std::{fs, path::Path};
    use tempfile::TempDir;

    async fn storage() -> (TempDir, Sites) {
        let directory = tempfile::tempdir().unwrap();
        let pool = open_database(directory.path()).await.unwrap();
        let sites = Sites::new(pool, directory.path().to_owned()).unwrap();
        (directory, sites)
    }

    fn input(slug: &str) -> NewSite {
        NewSiteBuilder::new()
            .html("<h1>🦀 unchanged</h1>\n".to_owned())
            .title(" Test title ".to_owned())
            .slug(Some(Slug::parse(slug).unwrap()))
            .build()
            .unwrap()
    }

    fn assert_empty(directory: &Path) {
        assert_eq!(fs::read_dir(directory).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn publish_concurrent_writers_have_only_one_winner() {
        let (directory, sites) = storage().await;
        let (first, second) = tokio::join!(
            sites.publish(input("concurrent-site")),
            sites.publish(input("concurrent-site"))
        );
        let outcomes = [first, second].map(|result| result.is_ok());
        assert!(outcomes.contains(&true) && outcomes.contains(&false));
        assert_eq!(
            fs::read_dir(directory.path().join("sites"))
                .unwrap()
                .count(),
            1
        );
        assert_empty(&directory.path().join("tmp"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publish_symlink_targets_and_replaced_storage_parents_are_never_followed() {
        use std::os::unix::fs::symlink;
        let (directory, sites) = storage().await;
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join(ENTRY_FILENAME), b"outside").unwrap();
        let destination = directory.path().join("sites/symlink-site");
        symlink(outside.path(), &destination).unwrap();
        let error = sites.publish(input("symlink-site")).await.unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::CONFLICT);
        assert!(fs::symlink_metadata(destination).unwrap().is_symlink());
        assert_eq!(
            fs::read(outside.path().join(ENTRY_FILENAME)).unwrap(),
            b"outside"
        );
        assert_empty(&directory.path().join("tmp"));
        for parent in ["tmp", "sites"] {
            let (directory, sites) = storage().await;
            let outside = tempfile::tempdir().unwrap();
            fs::remove_dir(directory.path().join(parent)).unwrap();
            symlink(outside.path(), directory.path().join(parent)).unwrap();
            assert!(Sites::new(sites.pool.clone(), directory.path().to_owned()).is_err());
            assert!(sites.publish(input("blocked-site")).await.is_err());
            assert_empty(outside.path());
        }
        let root_link = directory.path().join("root-link");
        symlink(directory.path(), &root_link).unwrap();
        assert!(Sites::new(sites.pool.clone(), root_link).is_err());
    }
}
