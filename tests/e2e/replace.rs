//! Replacement regressions: content swaps in place and failures keep the old content.

use crate::{VIEW_HOST, auth, publishing, spawn_app};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header::LOCATION},
};
use sqlx::{Row, SqlitePool, sqlite::SqliteRow};
use std::fs;

const OLD: &[u8] = b"<!doctype html><h1>Old</h1>";
const NEW: &[u8] = b"<!doctype html><h1>New</h1><link rel=stylesheet href=style.css>";
const CSS: &[u8] = b"h1 { color: rebeccapurple }";

fn replace(
    jar: &str,
    token: &str,
    slug: &str,
    files: &[(&str, &[u8])],
    entry: &str,
) -> Request<Body> {
    let names: Vec<String> = files
        .iter()
        .map(|(name, _)| format!("files[]\"; filename=\"{name}"))
        .collect();
    let mut fields = vec![
        ("csrf_token", token.as_bytes()),
        ("entry", entry.as_bytes()),
    ];
    fields.extend(names.iter().zip(files).map(|(n, (_, b))| (n.as_str(), *b)));
    auth::post(&format!("/sites/{slug}/content"), jar, &fields)
}

async fn row(pool: &SqlitePool, slug: &str) -> SqliteRow {
    sqlx::query("SELECT * FROM sites WHERE slug = ?")
        .bind(slug)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn served(app: &Router, path: &str) -> (StatusCode, String) {
    let (status, _, body) = auth::send(app, publishing::viewer(path)).await;
    (status, body)
}

#[tokio::test]
async fn replace_keeps_slug_and_settings() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let fields = [
        ("csrf_token", token.as_bytes()),
        ("slug", b"kept".as_slice()),
        ("html", OLD),
        ("title", b"Kept title"),
        ("visibility", b"password"),
        ("password", b"synthetic-site-password"),
        ("expires_in", b"7d"),
    ];
    let (status, _, _) = auth::send(&app, auth::post("/sites", &session, &fields)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let before = row(&pool, "kept").await;
    sqlx::query("UPDATE sites SET updated_at = 0")
        .execute(&pool)
        .await
        .unwrap();
    let files = [("new.html", NEW), ("style.css", CSS)];
    let request = replace(&session, &token, "kept", &files, "new.html");
    let (status, headers, _) = auth::send(&app, request).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], "/sites/kept?notice=replaced");
    let after = row(&pool, "kept").await;
    for column in ["slug", "title", "visibility"] {
        let (b, a) = (
            before.get::<String, _>(column),
            after.get::<String, _>(column),
        );
        assert_eq!(b, a, "{column}");
    }
    assert_eq!(
        before.get::<Option<String>, _>("password_hash"),
        after.get::<Option<String>, _>("password_hash")
    );
    assert_eq!(
        before.get::<i64, _>("expires_at"),
        after.get::<i64, _>("expires_at")
    );
    assert_eq!(
        before.get::<i64, _>("created_at"),
        after.get::<i64, _>("created_at")
    );
    assert_eq!(after.get::<String, _>("entry"), "new.html");
    assert_eq!(after.get::<i64, _>("file_count"), 2);
    assert_eq!(
        after.get::<i64, _>("size_bytes"),
        (NEW.len() + CSS.len()) as i64
    );
    assert!(after.get::<i64, _>("updated_at") > 0);
    let site = directory.path().join("sites/kept");
    assert_eq!(fs::read(site.join("new.html")).unwrap(), NEW);
    assert_eq!(fs::read(site.join("style.css")).unwrap(), CSS);
    assert!(!site.join("index.html").exists());
    assert_eq!(
        fs::read_dir(directory.path().join("tmp")).unwrap().count(),
        0
    );
    let (status, _) = served(&app, "/s/kept/").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "password site stays locked");
    let (status, _, _) = auth::send(&app, publishing::create(&session, &token, "open", OLD)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let paste = [("csrf_token", token.as_bytes()), ("html", NEW)];
    let request = auth::post("/sites/open/content", &session, &paste);
    assert_eq!(auth::send(&app, request).await.0, StatusCode::SEE_OTHER);
    let (status, body) = served(&app, "/s/open/").await;
    assert_eq!((status, body.as_bytes()), (StatusCode::OK, NEW));
    let (status, _, body) = auth::send(&app, auth::get("/sites/open", &session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("replace content") && body.contains("/sites/open?input=files"));
    pool.close().await;
}

#[tokio::test]
async fn replace_failure_leaves_old_content() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let (status, _, _) =
        auth::send(&app, publishing::create(&session, &token, "steady", OLD)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let before = row(&pool, "steady").await;
    let unsafe_name = replace(&session, &token, "steady", &[("../evil.html", NEW)], "");
    let ambiguous = replace(
        &session,
        &token,
        "steady",
        &[("a.html", NEW), ("b.html", NEW)],
        "",
    );
    let missing_entry = replace(
        &session,
        &token,
        "steady",
        &[("a.html", NEW)],
        "absent.html",
    );
    for request in [unsafe_name, ambiguous, missing_entry] {
        let (status, _, body) = auth::send(&app, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body.contains("replace content"),
            "error renders on the detail page"
        );
    }
    let absent = replace(&session, &token, "absent", &[("a.html", NEW)], "");
    assert_eq!(auth::send(&app, absent).await.0, StatusCode::NOT_FOUND);
    let no_csrf = auth::post("/sites/steady/content", &session, &[("html", NEW)]);
    assert_eq!(auth::send(&app, no_csrf).await.0, StatusCode::FORBIDDEN);
    let (status, body) = served(&app, "/s/steady/").await;
    assert_eq!((status, body.as_bytes()), (StatusCode::OK, OLD));
    let after = row(&pool, "steady").await;
    assert_eq!(
        before.get::<String, _>("entry"),
        after.get::<String, _>("entry")
    );
    for column in ["file_count", "size_bytes", "updated_at"] {
        assert_eq!(
            before.get::<i64, _>(column),
            after.get::<i64, _>(column),
            "{column}"
        );
    }
    let site = directory.path().join("sites/steady");
    assert_eq!(fs::read_dir(&site).unwrap().count(), 1);
    assert_eq!(
        fs::read_dir(directory.path().join("tmp")).unwrap().count(),
        0
    );
    pool.close().await;
}
