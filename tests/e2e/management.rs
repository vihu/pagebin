//! Authenticated list, detail, deletion, and trusted-admin-asset router regressions.

use crate::{VIEW_HOST, auth, publishing, spawn_app};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        Method, Request, StatusCode,
        header::{CACHE_CONTROL, HOST, LOCATION, ORIGIN, SET_COOKIE},
    },
};
use sqlx::SqlitePool;
use std::{fs, path::Path};

const SLUG: &str = "managed-site";
const HTML: &[u8] = b"<!doctype html><h1>Retained publication</h1>";
const CONFIRM: (&str, &[u8]) = ("confirm", b"delete");
const AUTH_BODY_CAP: usize = 256 * 1024;
const PRIVATE_CACHE: &str = "private, no-store";
const OK: StatusCode = StatusCode::OK;
const SEE_OTHER: StatusCode = StatusCode::SEE_OTHER;
const BAD_REQUEST: StatusCode = StatusCode::BAD_REQUEST;
const FORBIDDEN: StatusCode = StatusCode::FORBIDDEN;
const NOT_FOUND: StatusCode = StatusCode::NOT_FOUND;

/// Sends a request and asserts only its status, naming the URI on failure.
async fn expect(app: &Router, request: Request<Body>, status: StatusCode) {
    let uri = request.uri().to_string();
    assert_eq!(auth::send(app, request).await.0, status, "{uri}");
}

async fn publish(app: &Router, jar: &str, token: &str, slug: &str) {
    expect(app, publishing::create(jar, token, slug, HTML), SEE_OTHER).await;
}

fn delete(session: &str, token: &str, slug: &str) -> Request<Body> {
    let fields = [("csrf_token", token.as_bytes()), CONFIRM];
    auth::post(&format!("/sites/{slug}/delete"), session, &fields)
}

async fn rows(pool: &SqlitePool, slug: &str) -> i64 {
    let query = sqlx::query_scalar("SELECT COUNT(*) FROM sites WHERE slug = ?");
    query.bind(slug).fetch_one(pool).await.unwrap()
}

fn stored(data_dir: &Path, slug: &str) -> Option<Vec<u8>> {
    fs::read(data_dir.join("sites").join(slug).join("index.html")).ok()
}

#[tokio::test]
async fn management_empty_list_and_routes_require_admin_host_and_session() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, _) = publishing::login(&app).await;
    let (status, headers, body) = auth::send(&app, auth::get("/", &session)).await;
    assert_eq!(status, OK);
    assert_eq!(headers[CACHE_CONTROL], PRIVATE_CACHE);
    assert!(body.contains("href=\"/new\""));
    let sites = directory.path().join("sites");
    assert_eq!(fs::read_dir(sites).unwrap().count(), 0);
    let paths = "/ /?page=2 /sites/managed-site /sites/managed-site/delete /new?input=files";
    for path in paths.split(' ') {
        let (status, headers, _) = auth::send(&app, auth::get(path, "")).await;
        assert_eq!(status, SEE_OTHER, "{path}");
        assert_eq!(headers[LOCATION], "/login");
        for host in [VIEW_HOST, "unknown.local"] {
            let mut req = auth::get(path, &session);
            req.headers_mut().insert(HOST, host.parse().unwrap());
            let (status, headers, _) = auth::send(&app, req).await;
            assert_eq!(status, NOT_FOUND, "{host} {path}");
            assert!(!headers.contains_key(SET_COOKIE));
        }
    }
    expect(&app, auth::get("/sites/absent-site", &session), NOT_FOUND).await;
    pool.close().await;
}

#[tokio::test]
async fn management_list_and_detail_escape_metadata_and_csp_allows_only_trusted_host_script() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    const TITLE: &str = "Report <script>management_title_attack()</script> & β";
    let fields = [
        ("csrf_token", token.as_bytes()),
        ("slug", SLUG.as_bytes()),
        ("title", TITLE.as_bytes()),
        ("html", HTML),
    ];
    expect(&app, auth::post("/sites", &session, &fields), SEE_OTHER).await;
    let url = format!("https://{VIEW_HOST}/s/{SLUG}/");
    for path in ["/".to_owned(), format!("/sites/{SLUG}")] {
        let (status, headers, body) = auth::send(&app, auth::get(&path, &session)).await;
        assert_eq!(status, OK);
        assert_eq!(headers[CACHE_CONTROL], PRIVATE_CACHE);
        let policy = headers["content-security-policy"].to_str().unwrap();
        assert!(policy.split(';').any(|d| d.trim() == "script-src 'self'"));
        assert!(!policy.contains("'unsafe-inline'") && !policy.contains("'unsafe-eval'"));
        assert!(body.contains("management_title_attack()") && !body.contains(TITLE));
        assert!(!body.contains("<script>management_title_attack()"));
        assert!(body.contains(SLUG) && body.contains(&url));
        assert!(body.contains("src=\"/static/admin.js\""));
    }
    let delete_path = format!("/sites/{SLUG}/delete");
    let script_free = [
        ("/login", ""),
        ("/new", &*session),
        ("/new?input=files", &session),
        (&delete_path, &session),
    ];
    for (path, cookie) in script_free {
        let (status, headers, body) = auth::send(&app, auth::get(path, cookie)).await;
        assert_eq!(status, OK, "{path}");
        let policy = headers["content-security-policy"].to_str().unwrap();
        assert!(policy.contains("default-src 'none'") && !policy.contains("script-src"));
        assert!(!body.contains("<script"));
    }
    let (status, headers, script) = auth::send(&app, auth::get("/static/admin.js", &session)).await;
    assert_eq!(status, OK);
    let mime = headers["content-type"].to_str().unwrap();
    assert!(mime.contains("javascript") && !script.is_empty());
    for host in [VIEW_HOST, "unknown.local"] {
        let mut req = auth::get("/static/admin.js", &session);
        req.headers_mut().insert(HOST, host.parse().unwrap());
        expect(&app, req, NOT_FOUND).await;
    }
    let (_, _, body) = auth::send(&app, publishing::viewer(&format!("/s/{SLUG}/"))).await;
    assert_eq!(body.as_bytes(), HTML);
    pool.close().await;
}

#[tokio::test]
async fn management_pagination_is_newest_first_and_rejects_ambiguous_or_unbounded_parameters() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, _) = publishing::login(&app).await;
    const PAGE_SIZE: usize = 20;
    let insert = "INSERT INTO sites (slug, visibility, file_count, size_bytes, created_at, updated_at) VALUES (?, 'open', 1, 42, ?, ?)";
    for index in 0..=PAGE_SIZE {
        let (slug, stamp) = (format!("listed-{index:02}"), index as i64);
        let query = sqlx::query(insert).bind(slug).bind(stamp).bind(stamp);
        query.execute(&pool).await.unwrap();
    }
    let (status, _, first) = auth::send(&app, auth::get("/", &session)).await;
    assert_eq!(status, OK);
    let (_, _, explicit) = auth::send(&app, auth::get("/?page=1", &session)).await;
    assert_eq!(first, explicit);
    let link = |index: usize| format!("href=\"/sites/listed-{index:02}\"");
    let row = |index: usize| first.find(&link(index)).unwrap();
    let positions: Vec<_> = (1..=PAGE_SIZE).rev().map(row).collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(!first.contains("listed-00") && first.contains("href=\"/?page=2\""));
    let (status, _, second) = auth::send(&app, auth::get("/?page=2", &session)).await;
    assert_eq!(status, OK);
    assert!(second.contains(&link(0)) && !second.contains("href=\"/?page=3\""));
    assert!((1..=PAGE_SIZE).all(|index| !second.contains(&format!("listed-{index:02}"))));
    let rejected = "page=0 page=-1 page= page=abc page=1.5 page=%2B1 page=%201 page=1&page=2 notice=unknown unknown=1 page=1&unknown=1 notice=deleted&notice=retained page=9999999999999999999999999999999999999999";
    for query in rejected.split(' ') {
        let page = auth::get(&format!("/?{query}"), &session);
        expect(&app, page, BAD_REQUEST).await;
    }
    let accepted =
        "page=1 notice=deleted notice=retained page=1&notice=deleted notice=retained&page=1";
    for query in accepted.split(' ') {
        let page = auth::get(&format!("/?{query}"), &session);
        expect(&app, page, OK).await;
    }
    pool.close().await;
}

#[tokio::test]
async fn delete_confirmation_get_and_absent_rows_never_mutate_publication_or_orphans() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    publish(&app, &session, &token, SLUG).await;
    let path = format!("/sites/{SLUG}/delete");
    for _ in 0..2 {
        let (status, _, body) = auth::send(&app, auth::get(&path, &session)).await;
        assert_eq!(status, OK);
        assert!(body.contains(&format!("action=\"{path}\"")) && body.contains("name=\"confirm\""));
        assert_eq!(auth::csrf(&body), token);
    }
    assert_eq!(rows(&pool, SLUG).await, 1);
    assert_eq!(stored(directory.path(), SLUG).as_deref(), Some(HTML));
    expect(&app, publishing::viewer(&format!("/s/{SLUG}/")), OK).await;
    let orphan = directory.path().join("sites").join("orphan-site");
    fs::create_dir(&orphan).unwrap();
    fs::write(orphan.join("index.html"), HTML).unwrap();
    let confirm_page = auth::get("/sites/orphan-site/delete", &session);
    expect(&app, confirm_page, NOT_FOUND).await;
    expect(&app, delete(&session, &token, "orphan-site"), NOT_FOUND).await;
    assert_eq!(fs::read(orphan.join("index.html")).unwrap(), HTML);
    expect(&app, publishing::viewer("/s/orphan-site/"), NOT_FOUND).await;
    pool.close().await;
}

#[tokio::test]
async fn delete_native_post_and_delete_method_remove_only_the_selected_site() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    publish(&app, &session, &token, "unrelated-site").await;
    let targets = [
        (Method::POST, "native-delete"),
        (Method::DELETE, "method-delete"),
    ];
    for (method, slug) in targets {
        let fields = [
            ("csrf_token", token.as_bytes()),
            ("slug", slug.as_bytes()),
            ("files[]\"; filename=\"index.html", HTML),
            ("files[]\"; filename=\"style.css", b"body { color: blue; }"),
        ];
        expect(&app, auth::post("/sites", &session, &fields), SEE_OTHER).await;
        let mut req = delete(&session, &token, slug);
        if method == Method::DELETE {
            *req.uri_mut() = format!("/sites/{slug}").parse().unwrap();
        }
        *req.method_mut() = method;
        let (status, headers, _) = auth::send(&app, req).await;
        assert_eq!(status, SEE_OTHER);
        assert_eq!(headers[LOCATION], "/?notice=deleted");
        assert_eq!(rows(&pool, slug).await, 0);
        assert!(!directory.path().join("sites").join(slug).exists());
        for suffix in ["", "index.html", "style.css"] {
            let request = publishing::viewer(&format!("/s/{slug}/{suffix}"));
            let (status, headers, _) = auth::send(&app, request).await;
            assert_eq!(status, NOT_FOUND);
            publishing::viewer_headers(&headers, PRIVATE_CACHE);
        }
        let detail = auth::get(&format!("/sites/{slug}"), &session);
        expect(&app, detail, NOT_FOUND).await;
        expect(&app, delete(&session, &token, slug), NOT_FOUND).await;
        let (status, _, notice) = auth::send(&app, auth::get("/?notice=deleted", &session)).await;
        assert_eq!(status, OK);
        assert!(!notice.contains(slug));
    }
    let kept = stored(directory.path(), "unrelated-site");
    assert_eq!(kept.as_deref(), Some(HTML));
    assert_eq!(rows(&pool, "unrelated-site").await, 1);
    pool.close().await;
}

#[tokio::test]
async fn delete_database_failure_keeps_committed_metadata_and_bytes() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    publish(&app, &session, &token, SLUG).await;
    let trigger = "CREATE TRIGGER reject_delete BEFORE DELETE ON sites BEGIN SELECT RAISE(ABORT, 'synthetic-private-delete-failure'); END";
    sqlx::query(trigger).execute(&pool).await.unwrap();
    let (status, headers, body) = auth::send(&app, delete(&session, &token, SLUG)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!headers.contains_key(LOCATION));
    assert!(!body.contains("synthetic-private-delete-failure"));
    assert!(!body.contains(directory.path().to_str().unwrap()));
    assert_eq!(rows(&pool, SLUG).await, 1);
    assert_eq!(stored(directory.path(), SLUG).as_deref(), Some(HTML));
    let (status, _, served) = auth::send(&app, publishing::viewer(&format!("/s/{SLUG}/"))).await;
    assert_eq!((status, served.as_bytes()), (OK, HTML));
    pool.close().await;
}

#[cfg(unix)]
#[tokio::test]
async fn delete_symlinked_site_root_preserves_target_and_warns_after_metadata_removal() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    publish(&app, &session, &token, SLUG).await;
    let site = directory.path().join("sites").join(SLUG);
    let target = directory.path().join("synthetic-unowned-target");
    fs::rename(&site, &target).unwrap();
    std::os::unix::fs::symlink(&target, &site).unwrap();
    let (status, headers, _) = auth::send(&app, delete(&session, &token, SLUG)).await;
    assert_eq!(status, SEE_OTHER);
    assert_eq!(headers[LOCATION], "/?notice=retained");
    assert_eq!(rows(&pool, SLUG).await, 0);
    assert_eq!(fs::read(target.join("index.html")).unwrap(), HTML);
    expect(&app, publishing::viewer(&format!("/s/{SLUG}/")), NOT_FOUND).await;
    let (status, _, body) = auth::send(&app, auth::get("/?notice=retained", &session)).await;
    assert_eq!(status, OK);
    assert!(!body.contains(target.to_str().unwrap()) && !body.contains(SLUG));
    pool.close().await;
}

#[tokio::test]
async fn delete_rejects_ambiguous_forms_oversized_bodies_missing_csrf_and_foreign_origins() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    publish(&app, &session, &token, SLUG).await;
    let path = format!("/sites/{SLUG}/delete");
    let csrf = ("csrf_token", token.as_bytes());
    for extra in [
        vec![],
        vec![("confirm", b"".as_slice())],
        vec![("confirm", b"yes".as_slice())],
        vec![("confirm", b"Delete".as_slice())],
        vec![("confirm", b"delete ".as_slice())],
        vec![CONFIRM, CONFIRM],
        vec![CONFIRM, csrf],
        vec![CONFIRM, ("unknown", b"value".as_slice())],
        vec![("confirm\"; filename=\"confirm.txt", b"delete".as_slice())],
    ] {
        let fields = [&[csrf], &extra[..]].concat();
        expect(&app, auth::post(&path, &session, &fields), BAD_REQUEST).await;
    }
    let (parts, body) = delete(&session, &token, SLUG).into_parts();
    let mut encoded = to_bytes(body, AUTH_BODY_CAP).await.unwrap().to_vec();
    encoded.resize(AUTH_BODY_CAP + 1, b'x');
    let streamed = Body::from_stream(Body::from(encoded).into_data_stream());
    let oversized = Request::from_parts(parts, streamed);
    expect(&app, oversized, StatusCode::PAYLOAD_TOO_LARGE).await;
    let fields = [csrf, CONFIRM];
    for cookie in ["", "pb_admin=unsigned"] {
        expect(&app, auth::post(&path, cookie, &fields), FORBIDDEN).await;
    }
    for csrf in ["", "wrong-token"] {
        let wrong = [("csrf_token", csrf.as_bytes()), CONFIRM];
        expect(&app, auth::post(&path, &session, &wrong), FORBIDDEN).await;
    }
    expect(&app, auth::post(&path, &session, &[CONFIRM]), FORBIDDEN).await;
    let foreign = "null https://external.example https://view.local http://pages.local";
    for origin in foreign.split(' ') {
        let mut req = auth::post(&path, &session, &fields);
        req.headers_mut().insert(ORIGIN, origin.parse().unwrap());
        expect(&app, req, FORBIDDEN).await;
    }
    let mut dup = auth::post(&path, &session, &fields);
    dup.headers_mut()
        .append(ORIGIN, "https://pages.local".parse().unwrap());
    expect(&app, dup, FORBIDDEN).await;
    let doubled = format!("{session}; pb_admin=duplicate");
    expect(&app, auth::post(&path, &doubled, &fields), BAD_REQUEST).await;
    for host in [VIEW_HOST, "unknown.local"] {
        let mut req = auth::post(&path, &session, &fields);
        req.headers_mut().insert(HOST, host.parse().unwrap());
        expect(&app, req, NOT_FOUND).await;
    }
    let logout = auth::post("/logout", &session, &[csrf]);
    expect(&app, logout, SEE_OTHER).await;
    expect(&app, auth::post(&path, &session, &fields), FORBIDDEN).await;
    assert_eq!(rows(&pool, SLUG).await, 1);
    assert_eq!(stored(directory.path(), SLUG).as_deref(), Some(HTML));
    expect(&app, publishing::viewer(&format!("/s/{SLUG}/")), OK).await;
    pool.close().await;
}
