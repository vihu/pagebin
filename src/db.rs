//! Initializes persistent storage and applies the embedded SQLite schema.

use crate::{
    AppError, Result,
    auth::Password,
    config::validated_data_dir,
    sites::{AccessSite, SITES_PER_PAGE, Site, SiteDetails, Slug},
};
use sqlx::{
    ConnectOptions, SqliteConnection, SqlitePool,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};
use std::path::Path;
use tokio::fs;

const DATABASE_FILENAME: &str = "pagebin.db";
const SITES_DIRECTORY: &str = "sites";
const STAGING_DIRECTORY: &str = "tmp";
const MAX_CONNECTIONS: u32 = 4;
static MIGRATOR: Migrator = sqlx::migrate!();

/// Opens the SQLite database and applies any pending embedded migrations.
///
/// # Errors
/// Returns an error if the absolute data path is not UTF-8, storage directories
/// cannot be created, database setup fails, or a migration
/// cannot be applied or verified. Invalid paths fail before any writes.
pub async fn open_database(data_dir: &Path) -> Result<SqlitePool> {
    let data_dir = validated_data_dir(data_dir)?;
    for directory in [
        data_dir.clone(),
        data_dir.join(SITES_DIRECTORY),
        data_dir.join(STAGING_DIRECTORY),
    ] {
        fs::create_dir_all(directory)
            .await
            .map_err(|source| AppError::storage(source))?;
    }

    let options = SqliteConnectOptions::new()
        .filename(data_dir.join(DATABASE_FILENAME))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .disable_statement_logging();
    let pool = SqlitePoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect_with(options)
        .await
        .map_err(|source| AppError::database(source))?;

    if let Err(error) = MIGRATOR
        .run(&pool)
        .await
        .map_err(|source| AppError::migration(source))
    {
        pool.close().await;
        return Err(error);
    }

    Ok(pool)
}

/// Reads a committed site row by its validated URL component.
///
/// # Errors
/// Returns the typed database failure without changing metadata or files.
pub(crate) async fn find_site(pool: &SqlitePool, slug: &Slug) -> sqlx::Result<Option<Site>> {
    sqlx::query_as::<_, Site>(
        "SELECT slug, title, visibility, entry, file_count, size_bytes,
                created_at, updated_at, expires_at FROM sites WHERE slug = ?",
    )
    .bind(slug.as_str())
    .fetch_optional(pool)
    .await
}

/// Reads access metadata and its required credential in one committed snapshot.
///
/// # Errors
/// Returns a database failure or rejects invalid stored access credentials.
pub(crate) async fn access_site(
    pool: &SqlitePool,
    slug: &Slug,
) -> sqlx::Result<Option<AccessSite>> {
    sqlx::query_as::<_, AccessSite>(
        "SELECT slug, title, visibility, password_hash, entry, file_count,
                size_bytes, created_at, updated_at, expires_at
         FROM sites WHERE slug = ?",
    )
    .bind(slug.as_str())
    .fetch_optional(pool)
    .await
}

/// Reserves final access metadata in the uncommitted publication transaction.
///
/// # Errors
/// Returns a unique violation for an occupied slug or another database failure.
pub(crate) async fn insert_site(
    connection: &mut SqliteConnection,
    site: &Site,
    password: Option<&Password>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO sites (slug, title, visibility, password_hash, entry,
                            file_count, size_bytes, created_at, updated_at, expires_at)
         VALUES (?, ?, CASE WHEN ? IS NULL THEN 'open' ELSE 'password' END,
                 ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&site.slug)
    .bind(&site.title)
    .bind(password.map(Password::encoded))
    .bind(password.map(Password::encoded))
    .bind(&site.entry)
    .bind(site.file_count)
    .bind(site.size_bytes)
    .bind(site.created_at)
    .bind(site.updated_at)
    .bind(site.expires_at)
    .execute(connection)
    .await?;
    Ok(())
}

/// Selects the row columns plus UTC display labels, ending with `$suffix`.
macro_rules! details_query {
    ($suffix:literal) => {
        concat!(
            "SELECT slug, title, visibility, entry, file_count, size_bytes,
                    created_at, updated_at, expires_at,
                    COALESCE(strftime('%Y-%m-%d %H:%M UTC', created_at, 'unixepoch'),
                             'Unknown') AS created_label,
                    CASE WHEN expires_at IS NULL THEN 'Never' ELSE
                        COALESCE(strftime('%Y-%m-%d %H:%M UTC', expires_at, 'unixepoch'),
                                 'Unknown') END AS expires_label
             FROM sites ",
            $suffix
        )
    };
}

/// Reads one committed row and UTC display labels without changing its values.
///
/// # Errors
/// Returns a typed database failure if the query or row decoding fails.
pub(crate) async fn site_details(
    pool: &SqlitePool,
    slug: &Slug,
) -> sqlx::Result<Option<SiteDetails>> {
    sqlx::query_as::<_, SiteDetails>(details_query!("WHERE slug = ?"))
        .bind(slug.as_str())
        .fetch_optional(pool)
        .await
}

/// Reads a deterministic bounded page plus one next-page sentinel row.
///
/// # Errors
/// Returns a typed database failure if the query or row decoding fails.
pub(crate) async fn list_sites(pool: &SqlitePool, offset: i64) -> sqlx::Result<Vec<SiteDetails>> {
    sqlx::query_as::<_, SiteDetails>(details_query!(
        "ORDER BY created_at DESC, slug ASC LIMIT ? OFFSET ?"
    ))
    .bind((SITES_PER_PAGE + 1) as i64)
    .bind(offset)
    .fetch_all(pool)
    .await
}

/// Saves metadata and final access atomically without changing file metadata.
///
/// # Errors
/// Returns a database failure whose acknowledgement may be uncertain.
pub(crate) async fn update_site(
    pool: &SqlitePool,
    slug: &Slug,
    title: &str,
    entry: &str,
    password: Option<&Password>,
    updated_at: i64,
    expires_at: Option<i64>,
) -> sqlx::Result<u64> {
    sqlx::query(
        "UPDATE sites SET title = ?, entry = ?,
         visibility = CASE WHEN ? IS NULL THEN 'open' ELSE 'password' END,
         password_hash = ?, updated_at = ?, expires_at = ? WHERE slug = ?",
    )
    .bind(title)
    .bind(entry)
    .bind(password.map(Password::encoded))
    .bind(password.map(Password::encoded))
    .bind(updated_at)
    .bind(expires_at)
    .bind(slug.as_str())
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
}

/// Acknowledges a parameterized row deletion before any content removal.
///
/// # Errors
/// Returns a database failure whose commit outcome is treated as uncertain.
pub(crate) async fn delete_site(pool: &SqlitePool, slug: &str) -> sqlx::Result<u64> {
    sqlx::query("DELETE FROM sites WHERE slug = ?")
        .bind(slug)
        .execute(pool)
        .await
        .map(|result| result.rows_affected())
}

/// Lists every stored slug for boot reconciliation.
pub(crate) async fn slugs(pool: &SqlitePool) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar("SELECT slug FROM sites")
        .fetch_all(pool)
        .await
}

/// Lists slugs whose expiry is at or before the given Unix time.
pub(crate) async fn expired_slugs(pool: &SqlitePool, now: i64) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar("SELECT slug FROM sites WHERE expires_at IS NOT NULL AND expires_at <= ?")
        .bind(now)
        .fetch_all(pool)
        .await
}

/// Records replaced content without touching title, access, or expiry.
pub(crate) async fn replace_site(
    pool: &SqlitePool,
    slug: &Slug,
    entry: &str,
    file_count: i64,
    size_bytes: i64,
    updated_at: i64,
) -> sqlx::Result<u64> {
    sqlx::query(
        "UPDATE sites SET entry = ?, file_count = ?, size_bytes = ?, updated_at = ? WHERE slug = ?",
    )
    .bind(entry)
    .bind(file_count)
    .bind(size_bytes)
    .bind(updated_at)
    .bind(slug.as_str())
    .execute(pool)
    .await
    .map(|result| result.rows_affected())
}

/// Lists every site, newest first, without display labels.
pub(crate) async fn all_sites(pool: &SqlitePool) -> sqlx::Result<Vec<Site>> {
    sqlx::query_as::<_, Site>(
        "SELECT slug, title, visibility, entry, file_count, size_bytes,
                created_at, updated_at, expires_at
         FROM sites ORDER BY created_at DESC, slug ASC",
    )
    .fetch_all(pool)
    .await
}
