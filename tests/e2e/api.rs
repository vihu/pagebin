//! Bearer-token API regressions against the same router as the native forms.

use crate::{ADMIN_HOST, VIEW_HOST, app_settings, auth, publishing, spawn_app};
use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, HOST, WWW_AUTHENTICATE},
    },
};
use pagebin::{ConfigBuilder, router};
use serde_json::Value;
use sqlx::SqlitePool;
use std::path::Path;

const TOKEN: &str = "synthetic-api-token";
const HTML: &[u8] = b"<!doctype html><h1>Api</h1>";
const REPLACED: &[u8] = b"<h1>Replaced</h1>";
const JSON: &str = "application/json";

async fn api_app(directory: &Path, pool: &SqlitePool) -> Router {
    let mut values = app_settings(directory, Some(VIEW_HOST));
    values.insert("PAGEBIN_API_TOKEN", TOKEN.into());
    let config = ConfigBuilder::from_lookup(|key| values.get(key).cloned())
        .build()
        .unwrap();
    router(config, pool.clone()).await.unwrap()
}

fn bearer(mut request: Request<Body>, token: &str) -> Request<Body> {
    let value = format!("Bearer {token}").parse().unwrap();
    request.headers_mut().insert(AUTHORIZATION, value);
    request
}

fn call(method: Method, path: &str, json: Option<&str>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header(HOST, ADMIN_HOST);
    match json {
        Some(body) => builder
            .header(CONTENT_TYPE, JSON)
            .body(Body::from(body.to_owned()))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

fn form(method: Method, path: &str, fields: &[(&str, &[u8])]) -> Request<Body> {
    let mut request = bearer(auth::post(path, "", fields), TOKEN);
    *request.method_mut() = method;
    request
}

async fn json(app: &Router, request: Request<Body>) -> (StatusCode, Value) {
    let (status, headers, body) = auth::send(app, request).await;
    let kind = headers[CONTENT_TYPE].to_str().unwrap();
    assert!(kind.starts_with(JSON), "{status} {kind}: {body}");
    (status, serde_json::from_str(&body).unwrap())
}

#[tokio::test]
async fn api_is_404_without_token_config_and_401_with_wrong_token() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let request = bearer(call(Method::GET, "/api/sites", None), TOKEN);
    assert_eq!(auth::send(&app, request).await.0, StatusCode::NOT_FOUND);
    let api = api_app(directory.path(), &pool).await;
    let anonymous = call(Method::GET, "/api/sites", None);
    let wrong = bearer(call(Method::GET, "/api/sites", None), "wrong-token");
    let short = bearer(call(Method::GET, "/api/sites", None), &TOKEN[1..]);
    for request in [anonymous, wrong, short] {
        let (status, headers, body) = auth::send(&api, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers[WWW_AUTHENTICATE], "Bearer");
        assert!(body.starts_with("{\"error\""), "{body}");
    }
    let mut viewer_host = bearer(call(Method::GET, "/api/sites", None), TOKEN);
    viewer_host
        .headers_mut()
        .insert(HOST, VIEW_HOST.parse().unwrap());
    assert_eq!(auth::send(&api, viewer_host).await.0, StatusCode::NOT_FOUND);
    let (status, list) = json(&api, bearer(call(Method::GET, "/api/sites", None), TOKEN)).await;
    assert_eq!((status, list), (StatusCode::OK, serde_json::json!([])));
    pool.close().await;
}

#[tokio::test]
async fn api_create_replace_patch_delete_roundtrip() {
    let (_app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let api = api_app(directory.path(), &pool).await;
    let fields = [
        ("html", HTML),
        ("title", b"Release notes".as_slice()),
        ("slug", b"notes"),
        ("expires_in", b"7d"),
    ];
    let (status, site) = json(&api, form(Method::POST, "/api/sites", &fields)).await;
    assert_eq!(status, StatusCode::CREATED, "{site}");
    assert_eq!(site["slug"], "notes");
    assert_eq!(site["title"], "Release notes");
    assert!(site["url"].as_str().unwrap().ends_with("/s/notes/"));
    assert!(site["expires_at"].is_i64());
    let (status, _, body) = auth::send(&api, publishing::viewer("/s/notes/")).await;
    assert_eq!((status, body.as_bytes()), (StatusCode::OK, HTML));
    let (status, error) = json(&api, form(Method::POST, "/api/sites", &fields)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(error["error"].is_string());
    let blank = [("html", b"   ".as_slice())];
    let (status, _) = json(&api, form(Method::POST, "/api/sites", &blank)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let replacement = [("html", REPLACED)];
    let (status, site) = json(&api, form(Method::PUT, "/api/sites/notes", &replacement)).await;
    assert_eq!(status, StatusCode::OK, "{site}");
    assert_eq!(site["size_bytes"], REPLACED.len());
    let (status, _, body) = auth::send(&api, publishing::viewer("/s/notes/")).await;
    assert_eq!((status, body.as_bytes()), (StatusCode::OK, REPLACED));
    let (status, _) = json(&api, form(Method::PUT, "/api/sites/absent", &replacement)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let protect = r#"{"title":"Private notes","visibility":"password","password":"synthetic-site-password","expires_in":"never"}"#;
    let request = bearer(
        call(Method::PATCH, "/api/sites/notes", Some(protect)),
        TOKEN,
    );
    let (status, site) = json(&api, request).await;
    assert_eq!(status, StatusCode::OK, "{site}");
    assert_eq!(site["visibility"], "password");
    assert_eq!(site["title"], "Private notes");
    assert!(site["expires_at"].is_null());
    let (status, _, _) = auth::send(&api, publishing::viewer("/s/notes/")).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "password site is locked");
    let request = bearer(
        call(Method::PATCH, "/api/sites/notes", Some(r#"{"slug":"x"}"#)),
        TOKEN,
    );
    assert_eq!(json(&api, request).await.0, StatusCode::BAD_REQUEST);
    let request = bearer(
        call(Method::PATCH, "/api/sites/notes", Some("not json")),
        TOKEN,
    );
    assert_eq!(json(&api, request).await.0, StatusCode::BAD_REQUEST);
    let retitle = r#"{"title":"Still private"}"#;
    let request = bearer(
        call(Method::PATCH, "/api/sites/notes", Some(retitle)),
        TOKEN,
    );
    let (status, site) = json(&api, request).await;
    assert_eq!(
        (status, &site["visibility"]),
        (StatusCode::OK, &Value::from("password"))
    );
    let request = bearer(call(Method::DELETE, "/api/sites/notes", None), TOKEN);
    assert_eq!(auth::send(&api, request).await.0, StatusCode::NO_CONTENT);
    let request = bearer(call(Method::DELETE, "/api/sites/notes", None), TOKEN);
    assert_eq!(json(&api, request).await.0, StatusCode::NOT_FOUND);
    assert!(!directory.path().join("sites/notes").exists());
    pool.close().await;
}

#[tokio::test]
async fn api_list_matches_ui_list() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let api = api_app(directory.path(), &pool).await;
    let (session, token) = publishing::login(&app).await;
    let request = publishing::create(&session, &token, "from-ui", HTML);
    assert_eq!(auth::send(&app, request).await.0, StatusCode::SEE_OTHER);
    sqlx::query("UPDATE sites SET created_at = created_at - 10")
        .execute(&pool)
        .await
        .unwrap();
    let fields = [("html", HTML), ("slug", b"from-api".as_slice())];
    let (status, _) = json(&api, form(Method::POST, "/api/sites", &fields)).await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, list) = json(&api, bearer(call(Method::GET, "/api/sites", None), TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    let sites = list.as_array().unwrap();
    let slugs: Vec<&str> = sites.iter().map(|s| s["slug"].as_str().unwrap()).collect();
    assert_eq!(slugs, ["from-api", "from-ui"]);
    let keys = [
        "slug",
        "title",
        "visibility",
        "entry",
        "file_count",
        "size_bytes",
        "created_at",
        "updated_at",
        "expires_at",
        "url",
    ];
    for site in sites {
        for key in keys {
            assert!(site.get(key).is_some(), "{key} missing from {site}");
        }
    }
    let (status, _, body) = auth::send(&app, auth::get("/", &session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.find("from-api").unwrap() < body.find("from-ui").unwrap());
    pool.close().await;
}
