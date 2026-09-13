//! End-to-end publication, request boundaries, and viewer isolation.

use super::{ADMIN_HOST, SYNTHETIC_PASSWORD, TEST_UPLOAD_MB, VIEW_HOST, auth, spawn_app};
use axum::Router;
use axum::body::{Body, HttpBody, to_bytes};
use axum::http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, COOKIE, HOST};
use axum::http::header::{LOCATION, ORIGIN, RANGE, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use sqlx::SqlitePool;
use std::{fs, net::SocketAddr, path::Path, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const HTML: &str = "<!doctype html><meta charset=utf-8><title>Published</title><h1>Hello β</h1><script>document.body.dataset.ready='yes'</script>";
const SLUG: &str = "published-page";
const PUBLIC: &str = "public, max-age=60";
const PRIVATE: &str = "private, no-store";
const UPLOAD_BYTES: usize = TEST_UPLOAD_MB * 1024 * 1024;

/// Signs into the real router and obtains its publication token.
pub(super) async fn login(app: &Router) -> (String, String) {
    let (_, headers, body) = auth::send(app, auth::get("/login", "")).await;
    let token = auth::csrf(&body);
    let password = SYNTHETIC_PASSWORD.as_bytes();
    let fields = [("csrf_token", token.as_bytes()), ("password", password)];
    let request = auth::post("/login", &auth::cookies(&headers), &fields);
    let (status, headers, _) = auth::send(app, request).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let session = auth::cookies(&headers);
    let (_, _, body) = auth::send(app, auth::get("/new", &session)).await;
    (session, auth::csrf(&body))
}

/// Builds a paste request using the shared native multipart helper.
pub(super) fn create(session: &str, token: &str, slug: &str, html: &[u8]) -> Request<Body> {
    let (csrf, slug) = (token.as_bytes(), slug.as_bytes());
    let fields = [("csrf_token", csrf), ("html", html), ("slug", slug)];
    auth::post("/sites", session, &fields)
}

/// Builds a request on the separate viewer host.
pub(super) fn viewer(path: &str) -> Request<Body> {
    let request = Request::builder().uri(path).header(HOST, VIEW_HOST);
    request.body(Body::empty()).unwrap()
}

/// Checks common viewer policy without inheriting administrator policy.
pub(super) fn viewer_headers(headers: &HeaderMap, cache: &str) {
    assert_eq!(headers["x-content-type-options"], "nosniff");
    let referrer = "strict-origin-when-cross-origin";
    assert_eq!(headers["referrer-policy"], referrer);
    assert_eq!(headers["x-robots-tag"], "noindex");
    assert_eq!(headers[CACHE_CONTROL], cache);
    assert!(!headers.contains_key(CONTENT_SECURITY_POLICY) && !headers.contains_key(SET_COOKIE));
}

/// Asserts the committed site count and that staging left nothing behind.
pub(super) async fn assert_stored(pool: &SqlitePool, data_dir: &Path, sites: usize) {
    let sql = "SELECT COUNT(*) FROM sites";
    let count: i64 = sqlx::query_scalar(sql).fetch_one(pool).await.unwrap();
    let dirs = ["sites", "tmp"].map(|name| fs::read_dir(data_dir.join(name)).unwrap().count());
    assert_eq!((count as usize, dirs), (sites, [sites, 0]));
}

#[tokio::test]
async fn publishing_paste_receipt_viewer_and_storage_survive_slug_collisions() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = login(&app).await;
    let title = "Report <script>title_attack()</script> β";
    let fields = [
        ("csrf_token", token.as_bytes()),
        ("title", title.as_bytes()),
        ("html", HTML.as_bytes()),
        ("slug", SLUG.as_bytes()),
    ];
    let (status, headers, _) = auth::send(&app, auth::post("/sites", &session, &fields)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], format!("/sites/{SLUG}"));
    let (_, _, body) = auth::send(&app, auth::get(&format!("/sites/{SLUG}"), &session)).await;
    assert!(body.contains("title_attack") && !body.contains("<script>"));
    let (status, headers, body) = auth::send(&app, viewer(&format!("/s/{SLUG}/"))).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, HTML));
    viewer_headers(&headers, PUBLIC);
    let sql = "SELECT title, file_count, size_bytes FROM sites";
    let row: (String, i64, i64) = sqlx::query_as(sql).fetch_one(&pool).await.unwrap();
    assert_eq!(row, (title.into(), 1, HTML.len() as i64));
    let attack = "\n</textarea><script>escaped_collision()</script>";
    let collision = create(&session, &token, SLUG, attack.as_bytes());
    let (status, _, body) = auth::send(&app, collision).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.contains("id=\"slug-error\"") && body.contains("escaped_collision"));
    assert!(!body.contains("<script>") && body.matches("</textarea>").count() == 1);
    let generated = create(&session, &token, "", HTML.as_bytes());
    let (status, headers, _) = auth::send(&app, generated).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let slug = headers[LOCATION].to_str().unwrap().replace("/sites/", "");
    assert!(slug.matches('-').count() == 3 && slug.rsplit_once('-').unwrap().1.len() == 8);
    assert_stored(&pool, directory.path(), 2).await;
    pool.close().await;
}

#[tokio::test]
async fn publishing_single_host_mode_still_requires_the_configured_host() {
    let (app, pool, _directory) = spawn_app(None).await;
    let (session, token) = login(&app).await;
    let (status, _, _) = auth::send(&app, create(&session, &token, SLUG, HTML.as_bytes())).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let page = format!("/s/{SLUG}/");
    let (status, headers, body) = auth::send(&app, auth::get(&page, "")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, HTML));
    viewer_headers(&headers, PUBLIC);
    let (status, headers, _) = auth::send(&app, viewer(&page)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    viewer_headers(&headers, PRIVATE);
    pool.close().await;
}

#[tokio::test]
async fn publishing_auth_cap_includes_delayed_epilogues_before_session_mutation() {
    const AUTH_BODY_CAP: usize = 256 * 1024;
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = login(&app).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = Router::into_make_service_with_connect_info::<SocketAddr>(app.clone());
    let server = tokio::spawn(async move { axum::serve(listener, service).await.unwrap() });
    let logout = auth::post("/logout", &session, &[("csrf_token", token.as_bytes())]);
    let (parts, body) = logout.into_parts();
    let encoded = to_bytes(body, AUTH_BODY_CAP).await.unwrap();
    let mut head = String::from("POST /logout HTTP/1.1\r\nTransfer-Encoding: chunked\r\n");
    for (name, value) in &parts.headers {
        head.push_str(&format!("{name}: {}\r\n", value.to_str().unwrap()));
    }
    let chunk = |b: &[u8]| format!("{:x}\r\n{}\r\n", b.len(), str::from_utf8(b).unwrap());
    let request = head + "Connection: close\r\n\r\n" + &chunk(&encoded);
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket.write_all(request.as_bytes()).await.unwrap();
    let probe = timeout(Duration::from_millis(100), socket.read(&mut [0])).await;
    assert!(probe.is_err(), "responded before the body was complete");
    let epilogue = chunk(&vec![b'x'; AUTH_BODY_CAP + 1]) + "0\r\n\r\n";
    let _ = socket.write_all(epilogue.as_bytes()).await;
    let mut status_line = [0; 12];
    let read = timeout(Duration::from_secs(3), socket.read_exact(&mut status_line)).await;
    assert!(read.unwrap().is_ok() && status_line == *b"HTTP/1.1 413");
    let (status, _, _) = auth::send(&app, auth::get("/new", &session)).await;
    assert_eq!(status, StatusCode::OK);
    server.abort();
    pool.close().await;
}

#[tokio::test]
async fn publishing_rejects_wrong_host_session_origin_csrf_fields_and_body_cap_overflows() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = login(&app).await;
    let html = HTML.as_bytes();
    for path in ["/new", "/sites/example"] {
        super::assert_status(&app, path, &[ADMIN_HOST], StatusCode::SEE_OTHER).await;
        super::assert_status(&app, path, &[VIEW_HOST], StatusCode::NOT_FOUND).await;
    }
    for cookies in ["", "pb_admin=not-signed"] {
        let (status, headers, _) = auth::send(&app, create(cookies, &token, SLUG, html)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!headers.contains_key(SET_COOKIE));
    }
    for csrf in ["", "incorrect", &"a".repeat(64)] {
        let request = create(&session, csrf, SLUG, html);
        assert_eq!(auth::send(&app, request).await.0, StatusCode::FORBIDDEN);
    }
    let origins = "null https://evil.example https://view.local http://pages.local";
    for origin in origins.split(' ') {
        let mut forged = create(&session, &token, SLUG, html);
        forged.headers_mut().insert(ORIGIN, origin.parse().unwrap());
        assert_eq!(auth::send(&app, forged).await.0, StatusCode::FORBIDDEN);
    }
    let mut doubled = create(&session, &token, SLUG, html);
    let admin: HeaderValue = format!("https://{ADMIN_HOST}").parse().unwrap();
    doubled.headers_mut().append(ORIGIN, admin);
    assert_eq!(auth::send(&app, doubled).await.0, StatusCode::FORBIDDEN);
    let extras = "html csrf_token files[] zip visibility password entry expires_in unexpected";
    let mut cases: Vec<Vec<(&str, &[u8])>> =
        vec![vec![("html", b"\xff")], vec![("html", b" \n\t")]];
    cases.push(vec![("html\"; filename=\"index.html", html)]);
    for extra in extras.split(' ') {
        cases.push(vec![("html", html), (extra, b"ignored")]);
    }
    for name in ["title", "slug"] {
        cases.push(vec![("html", html), (name, b"one"), (name, b"two")]);
        cases.push(vec![("html", html), (name, b"\xff")]);
    }
    for slug in ["UPPERCASE", "../outside", "login", "-edge", "edge-", "ab"] {
        cases.push(vec![("html", html), ("slug", slug.as_bytes())]);
    }
    for (index, mut fields) in cases.into_iter().enumerate() {
        fields.insert(0, ("csrf_token", token.as_bytes()));
        let (status, _, body) = auth::send(&app, auth::post("/sites", &session, &fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {index}");
        assert!(!body.contains("<script>"), "case {index}");
    }
    let large = vec![b'x'; UPLOAD_BYTES + 1];
    let mut sized = create(&session, &token, SLUG, &large);
    let size = sized.body().size_hint().exact().unwrap();
    sized.headers_mut().insert(CONTENT_LENGTH, size.into());
    let (status, _, _) = auth::send(&app, sized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (parts, body) = create(&session, &token, SLUG, html).into_parts();
    let mut epilogue = to_bytes(body, UPLOAD_BYTES).await.unwrap().to_vec();
    epilogue.extend_from_slice(&large);
    let (unbounded, body) = create(&session, &token, SLUG, &large).into_parts();
    for (parts, body) in [(unbounded, body), (parts, Body::from(epilogue))] {
        let streamed = Body::from_stream(body.into_data_stream());
        let (status, _, _) = auth::send(&app, Request::from_parts(parts, streamed)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
    assert_stored(&pool, directory.path(), 0).await;
    // Framing fits the cap; a missing Origin is no CSRF exemption when the token is valid.
    let fits = vec![b'x'; UPLOAD_BYTES - 1024];
    let mut request = create(&session, &token, SLUG, &fits);
    request.headers_mut().remove(ORIGIN);
    assert_eq!(auth::send(&app, request).await.0, StatusCode::SEE_OTHER);
    let stored = directory.path().join("sites").join(SLUG).join("index.html");
    assert_eq!(fs::read(stored).unwrap(), fits);
    let logout = auth::post("/logout", &session, &[("csrf_token", token.as_bytes())]);
    assert_eq!(auth::send(&app, logout).await.0, StatusCode::SEE_OTHER);
    let stale = create(&session, &token, "after-logout", html);
    assert_eq!(auth::send(&app, stale).await.0, StatusCode::FORBIDDEN);
    pool.close().await;
}

#[tokio::test]
async fn publishing_serves_files_and_gates_custom_errors_locked_and_expired_sites() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = login(&app).await;
    let (status, _, _) = auth::send(&app, create(&session, &token, SLUG, HTML.as_bytes())).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let root = directory.path().join("sites").join(SLUG);
    const ERROR_PAGE: &str = "<!doctype html><h1>Custom missing page</h1>";
    fs::write(root.join(".txt"), "wrong double decoding").unwrap();
    for (name, suffix, content) in [
        ("style.css", "style.css", "body { color: blue; }"),
        ("%2e.txt", "%252e.txt", "literal percent"),
        ("404.html", "404.html", ERROR_PAGE),
    ] {
        fs::write(root.join(name), content).unwrap();
        let request = viewer(&format!("/s/{SLUG}/{suffix}"));
        let (status, headers, body) = auth::send(&app, request).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, content));
        viewer_headers(&headers, PUBLIC);
    }
    let mut missing = viewer(&format!("/s/{SLUG}/missing.css"));
    let range: HeaderValue = "bytes=0-1".parse().unwrap();
    missing.headers_mut().insert(RANGE, range);
    let future = "Wed, 31 Dec 2099 23:59:59 GMT".parse().unwrap();
    missing.headers_mut().insert("if-modified-since", future);
    let (status, headers, body) = auth::send(&app, missing).await;
    assert_eq!((status, body.as_str()), (StatusCode::NOT_FOUND, ERROR_PAGE));
    assert!(!headers.contains_key("content-range"));
    viewer_headers(&headers, PUBLIC);
    // A malformed stored hash fails closed on every path, even with the admin cookie.
    const FAILED: &str = "internal server error";
    let lock = "UPDATE sites SET visibility = 'password', password_hash = 'marker' WHERE slug = ?";
    let expire = "UPDATE sites SET visibility = 'open', expires_at = 0 WHERE slug = ?";
    let cookie: HeaderValue = session.parse().unwrap();
    for (sql, expected, served) in [
        (lock, StatusCode::INTERNAL_SERVER_ERROR, FAILED),
        (expire, StatusCode::NOT_FOUND, ""),
    ] {
        sqlx::query(sql).bind(SLUG).execute(&pool).await.unwrap();
        for suffix in ["", "/", "/style.css", "/missing.css", "/404.html"] {
            let mut request = viewer(&format!("/s/{SLUG}{suffix}"));
            request.headers_mut().insert(COOKIE, cookie.clone());
            let (status, headers, body) = auth::send(&app, request).await;
            assert_eq!((status, body.as_str()), (expected, served));
            assert!(!headers.contains_key(LOCATION));
            viewer_headers(&headers, PRIVATE);
        }
    }
    pool.close().await;
}

#[tokio::test]
async fn publishing_rejects_traversal_symlinks_malicious_entries_hosts_and_methods() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = login(&app).await;
    let (status, _, _) = auth::send(&app, create(&session, &token, SLUG, HTML.as_bytes())).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let page = format!("/s/{SLUG}/");
    let root = directory.path().join("sites").join(SLUG);
    let outside = directory.path().join("outside");
    fs::create_dir(root.join("nested")).unwrap();
    fs::create_dir(root.join("index-link")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("index.html"), "outside marker").unwrap();
    fs::write(root.join("__unlock"), "reserved marker").unwrap();
    fs::write(root.join("nested/index.html"), "nested marker").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        for link in ["linked.html", "404.html", "index-link/index.html"] {
            symlink(outside.join("index.html"), root.join(link)).unwrap();
        }
        symlink(&outside, root.join("linked-dir")).unwrap();
    }
    let traversals = "../outside/index.html %2e%2e/outside/index.html %252e%252e/outside/index.html
        nested%2findex.html nested%5cindex.html nested//index.html %00index.html __unlock
        %5f%5funlock nested/../../outside/index.html linked.html linked-dir/index.html linked-dir/
        index-link/ missing.html";
    for suffix in traversals.split_whitespace() {
        let (status, _, body) = auth::send(&app, viewer(&format!("/s/{SLUG}/{suffix}"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "served {suffix}");
        assert!(!body.contains("marker"));
    }
    let singles = [ADMIN_HOST, "unknown.local", "view.local:+80"].map(|host| vec![host]);
    let doubles = [vec![], vec![VIEW_HOST; 2], vec![VIEW_HOST, ADMIN_HOST]];
    for hosts in singles.into_iter().chain(doubles) {
        let response = super::response(&app, &page, &hosts).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{hosts:?}");
        viewer_headers(response.headers(), PRIVATE);
    }
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let mut request = viewer(&page);
        *request.method_mut() = method;
        let (status, headers, _) = auth::send(&app, request).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        viewer_headers(&headers, PRIVATE);
    }
    for path in ["/s", "/s/unknown/", "/s/UPPERCASE/", "/s/ab/", "/s/health/"] {
        let (status, headers, _) = auth::send(&app, viewer(path)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        viewer_headers(&headers, PRIVATE);
    }
    let entries = "../outside/index.html /etc/passwd nested\\index.html __unlock linked.html";
    for entry in entries.split(' ') {
        let update = sqlx::query("UPDATE sites SET entry = ? WHERE slug = ?");
        update.bind(entry).bind(SLUG).execute(&pool).await.unwrap();
        let (status, _, body) = auth::send(&app, viewer(&page)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "served entry {entry}");
        assert!(!body.contains("marker"));
    }
    #[cfg(unix)]
    {
        fs::rename(&root, directory.path().join("preserved-site")).unwrap();
        std::os::unix::fs::symlink(&outside, &root).unwrap();
        let (status, _, body) = auth::send(&app, viewer(&format!("/s/{SLUG}/index.html"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(!body.contains("marker"));
    }
    pool.close().await;
}
