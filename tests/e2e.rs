//! Application regressions using real routers, SQLite, and child processes.

#[path = "e2e/api.rs"]
mod api;
#[path = "e2e/auth.rs"]
mod auth;
#[path = "e2e/expiry.rs"]
mod expiry;
#[path = "e2e/files.rs"]
mod files;
#[path = "e2e/management.rs"]
mod management;
#[path = "e2e/password_sites.rs"]
mod password_sites;
#[path = "e2e/publishing.rs"]
mod publishing;
#[path = "e2e/replace.rs"]
mod replace;
#[path = "e2e/zip.rs"]
mod zip;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        HeaderValue, Request, StatusCode,
        header::{CONTENT_TYPE, HOST},
    },
    response::Response,
};
use pagebin::{ConfigBuilder, open_database, router};
use sqlx::SqlitePool;
use std::{
    collections::HashMap, ffi::OsString, fs, net::TcpListener, path::Path, process::Command,
};
use tempfile::TempDir;
use tower::ServiceExt;

const ADMIN_HOST: &str = "pages.local";
const VIEW_HOST: &str = "view.local";
const SYNTHETIC_PASSWORD: &str = "synthetic-test-password";
const HEALTH_BODY_LIMIT: usize = 64;
const TEST_UPLOAD_MB: usize = 1;
const SQLITE_CHECK_CONSTRAINT_CODE: &str = "275";
const INSERT_SITE: &str = "INSERT INTO sites (slug, visibility, password_hash, created_at, updated_at) VALUES (?, ?, ?, 0, 0)";

fn app_settings(data_dir: &Path, view_host: Option<&str>) -> HashMap<&'static str, OsString> {
    let mut values: HashMap<&str, OsString> = HashMap::from([
        ("PAGEBIN_ADMIN_HOST", ADMIN_HOST.into()),
        ("PAGEBIN_ADMIN_PASSWORD", SYNTHETIC_PASSWORD.into()),
        ("PAGEBIN_DATA_DIR", data_dir.as_os_str().to_owned()),
        ("PAGEBIN_SECRET", "11".repeat(32).into()),
        ("PAGEBIN_MAX_UPLOAD_MB", TEST_UPLOAD_MB.to_string().into()),
    ]);
    values.extend(view_host.map(|host| ("PAGEBIN_VIEW_HOST", host.into())));
    values
}

async fn spawn_app(view_host: Option<&str>) -> (Router, SqlitePool, TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let values = app_settings(directory.path(), view_host);
    let config = ConfigBuilder::from_lookup(|name| values.get(name).cloned())
        .build()
        .unwrap();
    let pool = open_database(config.data_dir()).await.unwrap();
    (router(config, pool.clone()).await.unwrap(), pool, directory)
}

async fn response(app: &Router, uri: &str, hosts: &[&str]) -> Response {
    let mut request = Request::builder().uri(uri);
    for host in hosts {
        request = request.header(HOST, *host);
    }
    let request = request.body(Body::empty()).unwrap();
    app.clone().oneshot(request).await.unwrap()
}

fn command(data_dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_pagebin"));
    command
        .env_clear()
        .envs([
            ("PAGEBIN_ADMIN_HOST", ADMIN_HOST),
            ("PAGEBIN_ADMIN_PASSWORD", SYNTHETIC_PASSWORD),
            ("PAGEBIN_VIEW_HOST", VIEW_HOST),
            ("PAGEBIN_PORT", "0"),
            ("RUST_LOG", "off"),
        ])
        .env("PAGEBIN_DATA_DIR", data_dir);
    // Run outside the package so a developer's .env never reaches the binary.
    if let Some(parent) = data_dir.parent().filter(|parent| parent.is_absolute()) {
        command.current_dir(parent);
    }
    command
}

async fn assert_status(app: &Router, uri: &str, hosts: &[&str], expected: StatusCode) {
    let status = response(app, uri, hosts).await.status();
    assert_eq!(status, expected, "{uri} {hosts:?}");
}

#[tokio::test]
async fn health_admin_host_accepts_valid_authorities_and_rejects_forwarded_and_other_hosts() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let health = response(&app, "/health", &[ADMIN_HOST]).await;
    assert_eq!(health.status(), StatusCode::OK);
    assert_eq!(health.headers()[CONTENT_TYPE], "text/plain; charset=utf-8");
    let body = to_bytes(health.into_body(), HEALTH_BODY_LIMIT).await;
    assert_eq!(body.unwrap().as_ref(), b"ok");
    for host in ["PAGES.LOCAL", "pages.local.", "pages.local:65535"] {
        assert_status(&app, "/health", &[host], StatusCode::OK).await;
    }
    for uri in ["/health", "http://pages.local:8080/health"] {
        assert_status(&app, uri, &["pages.local:8080"], StatusCode::OK).await;
    }
    for host in [
        VIEW_HOST,
        "view.local:8080",
        "unknown.local",
        "pages.local.evil",
        "pages.local,view.local",
        "user@pages.local",
        " pages.local",
        "pages.local ",
        "pages.local:",
        "pages.local:abc",
        "pages.local:65536",
        "pages.local:+80",
        "pages.local/",
        "pages..local",
        "pages.local:80:90",
    ] {
        assert_status(&app, "/health", &[host], StatusCode::NOT_FOUND).await;
    }
    assert_status(&app, "/health", &[], StatusCode::NOT_FOUND).await;
    for hosts in [[ADMIN_HOST, ADMIN_HOST], [ADMIN_HOST, VIEW_HOST]] {
        assert_status(&app, "/health", &hosts, StatusCode::NOT_FOUND).await;
    }
    for uri in ["http://view.local/health", "http://pages.local:80/health"] {
        assert_status(&app, uri, &[ADMIN_HOST], StatusCode::NOT_FOUND).await;
    }
    let request = Request::get("/health")
        .header(HOST, HeaderValue::from_bytes(&[0xff]).unwrap())
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = auth::send(&app, request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    for host in [Some(VIEW_HOST), None] {
        let mut request = Request::get("/health")
            .header("x-forwarded-host", ADMIN_HOST)
            .header("forwarded", "host=pages.local;proto=https");
        if let Some(host) = host {
            request = request.header(HOST, host);
        }
        let (status, _, _) = auth::send(&app, request.body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    pool.close().await;
}

#[tokio::test]
async fn health_unknown_paths_and_methods_stay_behind_host_dispatch() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    for host in [ADMIN_HOST, VIEW_HOST, "unknown.local"] {
        for path in ["/new", "/s/example/", "/api/sites", "/health/"] {
            let expected = if host == ADMIN_HOST && path == "/new" {
                StatusCode::SEE_OTHER
            } else {
                StatusCode::NOT_FOUND
            };
            assert_status(&app, path, &[host], expected).await;
        }
    }
    for (host, expected) in [
        (ADMIN_HOST, StatusCode::METHOD_NOT_ALLOWED),
        (VIEW_HOST, StatusCode::NOT_FOUND),
    ] {
        let request = Request::post("/health")
            .header(HOST, host)
            .body(Body::empty())
            .unwrap();
        let (status, _, _) = auth::send(&app, request).await;
        assert_eq!(status, expected);
    }
    pool.close().await;
}

#[tokio::test]
async fn health_single_host_mode_rejects_alternate_hosts_and_normalizes_ipv6() {
    let (app, pool, _directory) = spawn_app(None).await;
    assert_status(&app, "/health", &[ADMIN_HOST], StatusCode::OK).await;
    assert_status(&app, "/health", &[VIEW_HOST], StatusCode::NOT_FOUND).await;
    pool.close().await;
    let directory = tempfile::tempdir().unwrap();
    let mut values = app_settings(directory.path(), None);
    values.insert("PAGEBIN_ADMIN_HOST", "[::1]".into());
    let config = ConfigBuilder::from_lookup(|name| values.get(name).cloned())
        .build()
        .unwrap();
    let pool = open_database(config.data_dir()).await.unwrap();
    let app = router(config, pool.clone()).await.unwrap();
    for host in ["[::1]", "[0:0:0:0:0:0:0:1]:8080"] {
        assert_status(&app, "/health", &[host], StatusCode::OK).await;
    }
    for host in ["[::2]", "[::1]:", "[::1]:65536", "::1", "[::1%eth0]"] {
        assert_status(&app, "/health", &[host], StatusCode::NOT_FOUND).await;
    }
    pool.close().await;
}

#[tokio::test]
async fn database_fresh_boot_uses_wal_and_preserves_data_on_repeat() {
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path().join("nested/data");
    let pool = open_database(&data_dir).await.unwrap();
    assert!(data_dir.join("pagebin.db").is_file());
    let pragma = "PRAGMA journal_mode";
    let mode: String = sqlx::query_scalar(pragma).fetch_one(&pool).await.unwrap();
    assert_eq!(mode, "wal");
    sqlx::query(INSERT_SITE)
        .bind("saved")
        .bind("open")
        .bind(None::<&str>)
        .execute(&pool)
        .await
        .unwrap();
    let staged = data_dir.join("tmp/interrupted-upload");
    let orphan = data_dir.join("sites/orphan/index.html");
    fs::create_dir(data_dir.join("sites/orphan")).unwrap();
    fs::write(&staged, b"staged").unwrap();
    fs::write(&orphan, b"orphan").unwrap();
    pool.close().await;
    let pool = open_database(&data_dir).await.unwrap();
    let rows = "SELECT count(*) FROM sites WHERE slug = 'saved'";
    let count: i64 = sqlx::query_scalar(rows).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    assert_eq!(fs::read(&staged).unwrap(), b"staged");
    assert_eq!(fs::read(&orphan).unwrap(), b"orphan");
    pool.close().await;
}

#[tokio::test]
async fn database_constraints_reject_invalid_inserts_and_updates() {
    let (_app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    for (slug, visibility, hash) in [
        ("open", "open", None),
        ("protected", "password", Some("synthetic-hash")),
        ("open-with-hash", "open", Some("synthetic-hash")),
    ] {
        sqlx::query(INSERT_SITE)
            .bind(slug)
            .bind(visibility)
            .bind(hash)
            .execute(&pool)
            .await
            .unwrap();
    }
    for statement in [
        "INSERT INTO sites (slug, visibility, created_at, updated_at) VALUES ('x', 'password', 0, 0)",
        "INSERT INTO sites (slug, visibility, created_at, updated_at) VALUES ('y', 'unknown', 0, 0)",
        "UPDATE sites SET visibility = 'password' WHERE slug = 'open'",
        "UPDATE sites SET password_hash = NULL WHERE slug = 'protected'",
        "UPDATE sites SET visibility = 'unknown' WHERE slug = 'open'",
    ] {
        let error = sqlx::query(statement).execute(&pool).await.unwrap_err();
        let code = error.as_database_error().unwrap().code();
        assert_eq!(code.as_deref(), Some(SQLITE_CHECK_CONSTRAINT_CODE));
    }
    let sql = "SELECT sql FROM sqlite_master WHERE name = 'sites_expires_at'";
    let index: String = sqlx::query_scalar(sql).fetch_one(&pool).await.unwrap();
    assert!(index.contains("WHERE expires_at IS NOT NULL"));
    pool.close().await;
}

#[tokio::test]
async fn database_filesystem_and_migration_failures_preserve_existing_files() {
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path();
    fs::write(data_dir.join("sites"), b"file").unwrap();
    let error = open_database(data_dir).await.unwrap_err();
    assert_eq!(error.to_string(), "storage initialization failed");
    assert_eq!(fs::read(data_dir.join("sites")).unwrap(), b"file");
    assert!(!data_dir.join("pagebin.db").exists());
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path();
    fs::write(data_dir.join("pagebin.db"), b"junk").unwrap();
    assert!(open_database(data_dir).await.is_err());
    assert_eq!(fs::read(data_dir.join("pagebin.db")).unwrap(), b"junk");
    let directory = tempfile::tempdir().unwrap();
    let pool = open_database(directory.path()).await.unwrap();
    let corrupt = "UPDATE _sqlx_migrations SET checksum = X'00'";
    sqlx::query(corrupt).execute(&pool).await.unwrap();
    pool.close().await;
    let error = open_database(directory.path()).await.unwrap_err();
    assert_eq!(error.to_string(), "database migration failed");
    assert!(directory.path().join("pagebin.db").is_file());
}

#[cfg(unix)]
#[tokio::test]
async fn database_non_utf8_paths_fail_before_creating_storage() {
    use std::os::unix::ffi::OsStringExt;
    let directory = tempfile::tempdir().unwrap();
    let data_dir = directory.path().join(OsString::from_vec(vec![0xff]));
    let error = open_database(&data_dir).await.unwrap_err();
    assert!(error.to_string().contains("PAGEBIN_DATA_DIR"));
    assert!(!data_dir.exists());
}

#[cfg(unix)]
#[test]
fn boot_single_host_warning_survives_disabled_logs_and_file_prefix_cannot_redirect_storage() {
    let directory = tempfile::tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    fs::create_dir(directory.path().join("store")).unwrap();
    let output = command(Path::new("file:store"))
        .current_dir(directory.path())
        .env_remove("PAGEBIN_VIEW_HOST")
        .env(
            "PAGEBIN_PORT",
            occupied.local_addr().unwrap().port().to_string(),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    let warning = "PAGEBIN_VIEW_HOST is unset; single-host mode is for local development only";
    assert!(stderr.contains(warning));
    assert!(stderr.contains("listener operation failed"));
    assert!(!stderr.contains(SYNTHETIC_PASSWORD));
    assert!(directory.path().join("file:store/pagebin.db").is_file());
    assert!(!directory.path().join("store/pagebin.db").exists());
}

#[test]
fn config_startup_errors_exit_without_listening_or_creating_data() {
    let directory = tempfile::tempdir().unwrap();
    for (name, value) in [
        ("PAGEBIN_ADMIN_HOST", None),
        ("PAGEBIN_ADMIN_PASSWORD", None),
        ("PAGEBIN_ADMIN_HOST", Some("https://pages.local")),
        ("PAGEBIN_VIEW_HOST", Some("PAGES.local.")),
        ("PAGEBIN_SECRET", Some("invalid-signing-secret")),
        ("PAGEBIN_TRUST_PROXY", Some("invalid-proxy-choice")),
        ("PAGEBIN_PORT", Some("invalid-port-value")),
        ("RUST_LOG", Some("pagebin=invalid-filter-value")),
    ] {
        let data_dir = directory.path().join(name);
        let mut command = command(&data_dir);
        command.env_remove(name).envs(value.map(|v| (name, v)));
        let output = command.output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains(name));
        assert!(!stderr.contains(SYNTHETIC_PASSWORD));
        assert!(value.is_none_or(|value| !stderr.contains(value)));
        assert!(!data_dir.exists());
    }
}
