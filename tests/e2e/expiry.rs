//! Expiry regressions: form choices, viewer gating, boot sweep, and reconciliation.

use crate::{INSERT_SITE, VIEW_HOST, app_settings, auth, publishing, spawn_app};
use axum::{Router, http::StatusCode};
use pagebin::{ConfigBuilder, router};
use sqlx::SqlitePool;
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const HTML: &[u8] = b"<!doctype html><h1>Expiring</h1>";
const WEEK: i64 = 7 * 24 * 60 * 60;
const CLOCK_SLACK: i64 = 5;

async fn create(app: &Router, jar: &str, token: &str, slug: &str, expires_in: &str) -> StatusCode {
    let fields = [
        ("csrf_token", token.as_bytes()),
        ("slug", slug.as_bytes()),
        ("html", HTML),
        ("expires_in", expires_in.as_bytes()),
    ];
    auth::send(app, auth::post("/sites", jar, &fields)).await.0
}

/// Returns `None` for an absent row, `Some(expiry)` for a present one.
async fn row(pool: &SqlitePool, slug: &str) -> Option<Option<i64>> {
    sqlx::query_scalar("SELECT expires_at FROM sites WHERE slug = ?")
        .bind(slug)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn reboot(directory: &Path, pool: &SqlitePool) -> Router {
    let values = app_settings(directory, Some(VIEW_HOST));
    let config = ConfigBuilder::from_lookup(|key| values.get(key).cloned())
        .build()
        .unwrap();
    router(config, pool.clone()).await.unwrap()
}

#[tokio::test]
async fn expired_site_is_404_before_sweep_and_settings_keep_or_clear_expiry() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let bad = create(&app, &session, &token, "bad-expiry", "2h").await;
    assert_eq!(bad, StatusCode::BAD_REQUEST);
    assert_eq!(row(&pool, "bad-expiry").await, None);
    let ok = create(&app, &session, &token, "expiring", "7d").await;
    assert_eq!(ok, StatusCode::SEE_OTHER);
    let expiry = row(&pool, "expiring").await.unwrap().unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert!((expiry - now.as_secs() as i64 - WEEK).abs() <= CLOCK_SLACK);
    let (status, _, body) = auth::send(&app, publishing::viewer("/s/expiring/")).await;
    assert_eq!((status, body.as_bytes()), (StatusCode::OK, HTML));
    let save = |expires_in: &'static str| {
        let fields = [
            ("csrf_token", token.as_bytes()),
            ("title", b"".as_slice()),
            ("entry", b"index.html"),
            ("visibility", b"open"),
            ("expires_in", expires_in.as_bytes()),
        ];
        auth::post("/sites/expiring", &session, &fields)
    };
    assert_eq!(
        auth::send(&app, save("keep")).await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(row(&pool, "expiring").await, Some(Some(expiry)));
    assert_eq!(
        auth::send(&app, save("soon")).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        auth::send(&app, save("never")).await.0,
        StatusCode::SEE_OTHER
    );
    assert_eq!(row(&pool, "expiring").await, Some(None));
    sqlx::query("UPDATE sites SET expires_at = 1 WHERE slug = 'expiring'")
        .execute(&pool)
        .await
        .unwrap();
    let (status, _, body) = auth::send(&app, publishing::viewer("/s/expiring/")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body.contains("Expiring"));
    pool.close().await;
}

#[tokio::test]
async fn boot_sweeps_expired_sites_and_reconciles_orphans() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    for (slug, expires_in) in [("expired", "1h"), ("kept", "never")] {
        let status = create(&app, &session, &token, slug, expires_in).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{slug}");
    }
    sqlx::query("UPDATE sites SET expires_at = 1 WHERE slug = 'expired'")
        .execute(&pool)
        .await
        .unwrap();
    let sites = directory.path().join("sites");
    fs::create_dir(sites.join("stray")).unwrap();
    fs::write(sites.join("stray/index.html"), b"stray").unwrap();
    fs::write(directory.path().join("tmp/leftover"), b"staging").unwrap();
    sqlx::query(INSERT_SITE)
        .bind("rowless")
        .bind("open")
        .bind(Option::<String>::None)
        .execute(&pool)
        .await
        .unwrap();
    let rebooted = reboot(directory.path(), &pool).await;
    assert_eq!(row(&pool, "expired").await, None);
    assert!(!sites.join("expired").exists());
    assert_eq!(row(&pool, "rowless").await, None);
    assert!(!sites.join("stray").exists());
    assert_eq!(
        fs::read_dir(directory.path().join("tmp")).unwrap().count(),
        0
    );
    assert!(row(&pool, "kept").await.is_some());
    let (status, _, body) = auth::send(&rebooted, publishing::viewer("/s/kept/")).await;
    assert_eq!((status, body.as_bytes()), (StatusCode::OK, HTML));
    let (status, _, _) = auth::send(&rebooted, publishing::viewer("/s/expired/")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    pool.close().await;
}
