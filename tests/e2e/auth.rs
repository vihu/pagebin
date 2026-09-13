//! Authentication regressions against the same initialized router used by boot.

use super::{ADMIN_HOST, SYNTHETIC_PASSWORD, VIEW_HOST, app_settings, spawn_app};
use axum::response::IntoResponse;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{
        HeaderMap, Request, StatusCode,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, LOCATION, ORIGIN,
            REFERER, SET_COOKIE,
        },
    },
};
use axum_extra::extract::cookie::{Cookie, Key, SameSite, SignedCookieJar};
use pagebin::{ConfigBuilder, open_database, router};
use std::net::SocketAddr;
use tower::ServiceExt;

const BOUNDARY: &str = "pagebin-test-boundary";
// Bounds test response collection, not the application's request-body limits.
// The generated component stylesheet alone is larger than 64 KiB.
const RESPONSE_BODY_LIMIT: usize = 256 * 1024;
const PASSWORD: &[u8] = SYNTHETIC_PASSWORD.as_bytes();

/// Executes an in-process request while retaining its status and headers.
pub(super) async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), RESPONSE_BODY_LIMIT)
        .await
        .unwrap();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

/// Builds an administrator GET with a synthetic browser cookie jar.
pub(super) fn get(path: &str, cookies: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header(HOST, ADMIN_HOST)
        .header(COOKIE, cookies)
        .body(Body::empty())
        .unwrap()
}

/// Builds a native multipart POST with a matching administrator Origin.
pub(super) fn post(path: &str, cookies: &str, fields: &[(&str, &[u8])]) -> Request<Body> {
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(
            format!("--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header(HOST, ADMIN_HOST)
        .header(COOKIE, cookies)
        .header(ORIGIN, format!("https://{ADMIN_HOST}"))
        .header(
            CONTENT_TYPE,
            format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "192.0.2.10:1234".parse::<SocketAddr>().unwrap(),
    ));
    request
}

/// Extracts signed cookies issued to a synthetic browser.
pub(super) fn cookies(headers: &HeaderMap) -> String {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .map(|h| h.to_str().unwrap().split(';').next().unwrap())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Extracts the hidden verification field from a rendered form.
pub(super) fn csrf(body: &str) -> String {
    body.split("name=\"csrf_token\"")
        .nth(1)
        .expect("CSRF field exists")
        .split("value=\"")
        .nth(1)
        .expect("CSRF field has a value")
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}

fn cookie_flags(headers: &HeaderMap, name: &str, seconds: i64) {
    let cookie = headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|h| Cookie::parse(h.to_str().unwrap()).ok())
        .find(|c| c.name() == name)
        .expect("expected cookie exists");
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    assert_eq!(cookie.path(), Some("/"));
    assert!(cookie.domain().is_none());
    assert_eq!(cookie.max_age().unwrap().whole_seconds(), seconds);
}

#[tokio::test]
async fn auth_login_logout_rotates_csrf_and_revokes_session_on_logout_and_restart() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (status, headers, _) = send(&app, get("/", "")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], "/login");
    let (status, headers, body) = send(&app, get("/login", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[CACHE_CONTROL], "private, no-store");
    // no-referrer makes native form POSTs send Origin: null in Chromium.
    assert_eq!(headers["referrer-policy"], "same-origin");
    assert!(headers.contains_key(CONTENT_SECURITY_POLICY));
    assert!(body.contains("autocomplete=\"current-password\""));
    assert!(body.contains("User-supplied DaisyUI Ledger themes"));
    cookie_flags(&headers, "__Host-pb_login", 15 * 60);
    let challenge = cookies(&headers);
    let token = csrf(&body);
    let fields = [("csrf_token", token.as_bytes()), ("password", PASSWORD)];
    let (status, headers, _) = send(&app, post("/login", &challenge, &fields)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], "/");
    cookie_flags(&headers, "pb_admin", 30 * 24 * 60 * 60);
    cookie_flags(&headers, "__Host-pb_login", 0);
    let session = cookies(&headers);
    let (status, _, body) = send(&app, get("/", &session)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("href=\"/new\""));
    let session_token = csrf(&body);
    assert!(session_token != token);
    let (status, headers, _) = send(&app, get("/login", &session)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], "/");
    let values = app_settings(directory.path(), Some(VIEW_HOST));
    let config = ConfigBuilder::from_lookup(|name| values.get(name).cloned())
        .build()
        .unwrap();
    let restarted = router(config, pool.clone()).await.unwrap();
    let (status, _, _) = send(&restarted, get("/", &session)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let stale = [("csrf_token", token.as_bytes())];
    let (status, _, _) = send(&app, post("/logout", &session, &stale)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let fields = [("csrf_token", session_token.as_bytes())];
    let (status, headers, _) = send(&app, post("/logout", &session, &fields)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    cookie_flags(&headers, "pb_admin", 0);
    let (status, _, _) = send(&app, get("/", &session)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    pool.close().await;
}

#[tokio::test]
async fn auth_wrong_password_has_accessible_feedback_without_echoing() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (_, headers, body) = send(&app, get("/login", "")).await;
    let cookie = cookies(&headers);
    let token = csrf(&body);
    let wrong = [
        ("csrf_token", token.as_bytes()),
        ("password", b"synthetic-wrong-private-value".as_slice()),
    ];
    let (status, headers, body) = send(&app, post("/login", &cookie, &wrong)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.contains("aria-describedby=\"password-error\""));
    assert!(!body.contains("synthetic-wrong-private-value"));
    assert!(!cookies(&headers).contains("pb_admin="));
    let missing = [("csrf_token", token.as_bytes())];
    let empty = [("csrf_token", token.as_bytes()), ("password", &b""[..])];
    for fields in [&missing[..], &empty[..]] {
        let (status, _, _) = send(&app, post("/login", &cookie, fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    pool.close().await;
}

#[tokio::test]
async fn auth_csrf_rejects_missing_tampered_and_other_browser_tokens_without_cookies() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let invalid = [("csrf_token", &b"invalid"[..])];
    for path in ["/login", "/logout"] {
        let (status, headers, body) = send(&app, post(path, "", &invalid)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(headers[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(headers[CACHE_CONTROL], "private, no-store");
        assert!(!headers.contains_key(SET_COOKIE));
        assert!(body.contains("name=\"viewport\""));
        assert!(body.contains("<h1>Request not verified</h1>"));
        assert!(body.contains("href=\"/login\">Return to sign in</a>"));
    }
    assert_eq!(send(&app, get("/", "")).await.0, StatusCode::SEE_OTHER);
    let (status, first_headers, body) = send(&app, get("/login", "")).await;
    assert_eq!(status, StatusCode::OK);
    let (_, second_headers, _) = send(&app, get("/login", "")).await;
    let token = csrf(&body);
    let first = cookies(&first_headers);
    let second = cookies(&second_headers);
    let valid = [("csrf_token", token.as_bytes()), ("password", PASSWORD)];
    for cookie in ["", second.as_str()] {
        let (status, _, _) = send(&app, post("/login", cookie, &valid)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    let missing = [("password", PASSWORD)];
    let tampered = [("password", PASSWORD), ("csrf_token", &b"invalid"[..])];
    for fields in [&missing[..], &tampered[..]] {
        let (status, _, _) = send(&app, post("/login", &first, fields)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    for origin in ["https://view.local", "https://external.example", "null"] {
        let mut request = post("/login", &first, &valid);
        request
            .headers_mut()
            .insert(ORIGIN, origin.parse().unwrap());
        assert_eq!(send(&app, request).await.0, StatusCode::FORBIDDEN);
    }
    assert_eq!(send(&app, get("/", &first)).await.0, StatusCode::SEE_OTHER);
    pool.close().await;
}

#[tokio::test]
async fn auth_rejects_ambiguous_fields_invalid_utf8_and_oversized_bodies() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (_, headers, body) = send(&app, get("/login", "")).await;
    let cookie = cookies(&headers);
    let token = csrf(&body);
    let csrf_field = ("csrf_token", token.as_bytes());
    for fields in [
        vec![csrf_field, ("password", b"one"), ("password", b"two")],
        vec![csrf_field, csrf_field, ("password", PASSWORD)],
        vec![csrf_field, ("unexpected", b"value")],
        vec![csrf_field, ("password", &[0xff])],
    ] {
        let (status, _, _) = send(&app, post("/login", &cookie, &fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let large = vec![b'x'; 512 * 1024];
    let oversized = [csrf_field, ("password", large.as_slice())];
    let (status, _, _) = send(&app, post("/login", &cookie, &oversized)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let mut file_part = post("/login", &cookie, &[]);
    *file_part.body_mut() = Body::from(format!(
        "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"password\"; filename=\"secret.txt\"\r\n\r\nx\r\n--{BOUNDARY}--\r\n"
    ));
    assert_eq!(send(&app, file_part).await.0, StatusCode::BAD_REQUEST);
    pool.close().await;
}

#[tokio::test]
async fn auth_cookies_reject_unsigned_unknown_duplicate_and_encoded_names() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let key = Key::derive_from(&[0x11; 32]);
    let forged = SignedCookieJar::new(key)
        .add(Cookie::new("pb_admin", "unknown-session"))
        .into_response();
    let forged = cookies(forged.headers());
    for cookie in ["pb_admin=unsigned-value", forged.as_str()] {
        assert_eq!(send(&app, get("/", cookie)).await.0, StatusCode::SEE_OTHER);
    }
    let (_, headers, body) = send(&app, get("/login", "")).await;
    let cookie = cookies(&headers);
    let token = csrf(&body);
    let fields = [("csrf_token", token.as_bytes()), ("password", PASSWORD)];
    let duplicated = format!("{cookie}; {cookie}");
    let encoded = cookie.replacen("__Host-pb_login", "%5F%5FHost-pb_login", 1);
    for cookie in [duplicated, encoded] {
        let (status, _, _) = send(&app, post("/login", &cookie, &fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let tampered = format!("{cookie}x");
    let (status, _, _) = send(&app, post("/login", &tampered, &fields)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    pool.close().await;
}

#[tokio::test]
async fn auth_routes_and_assets_are_admin_host_only() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    for path in ["/", "/login", "/logout", "/static/app.css"] {
        for host in [VIEW_HOST, "unknown.local"] {
            let mut request = get(path, "");
            request.headers_mut().insert(HOST, host.parse().unwrap());
            request
                .headers_mut()
                .insert("x-forwarded-host", ADMIN_HOST.parse().unwrap());
            let (status, headers, _) = send(&app, request).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(!headers.contains_key(SET_COOKIE));
        }
    }
    let (status, headers, body) = send(&app, get("/static/app.css", "")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[CONTENT_TYPE], "text/css; charset=utf-8");
    assert_eq!(body, include_str!("../../static/app.css"));
    pool.close().await;
}

#[tokio::test]
async fn auth_opt_in_proxy_mode_rejects_invalid_headers_and_requires_connection_info() {
    let directory = tempfile::tempdir().unwrap();
    let mut values = app_settings(directory.path(), Some(VIEW_HOST));
    values.insert("PAGEBIN_TRUST_PROXY", "true".into());
    let config = ConfigBuilder::from_lookup(|name| values.get(name).cloned())
        .build()
        .unwrap();
    let pool = open_database(config.data_dir()).await.unwrap();
    let app = router(config, pool.clone()).await.unwrap();
    let (_, headers, body) = send(&app, get("/login", "")).await;
    let cookie = cookies(&headers);
    let token = csrf(&body);
    let fields = [("csrf_token", token.as_bytes()), ("password", PASSWORD)];
    let forwarded = |value: &str| {
        let mut request = post("/login", &cookie, &fields);
        request
            .headers_mut()
            .insert("x-forwarded-for", value.parse().unwrap());
        request
    };
    let (status, _, _) = send(&app, post("/login", &cookie, &fields)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for value in ["unknown", "192.0.2.1,", "192.0.2.1:8080"] {
        let (status, _, _) = send(&app, forwarded(value)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let mut request = forwarded("192.0.2.1, 2001:db8::1");
    request.extensions_mut().remove::<ConnectInfo<SocketAddr>>();
    let (status, _, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (status, _, _) = send(&app, forwarded("192.0.2.1, 2001:db8::1")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    pool.close().await;
}

#[tokio::test]
async fn theme_choice_persists_in_a_cookie_and_rejects_unknown_values() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let mut request = post("/theme", "", &[("theme", b"ledger-light")]);
    request.headers_mut().insert(
        REFERER,
        format!("https://{ADMIN_HOST}/new").parse().unwrap(),
    );
    let (status, headers, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], "/new");
    let jar = cookies(&headers);
    assert!(jar.contains("pb_theme=ledger-light"));
    let (status, _, body) = send(&app, get("/login", &jar)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("data-theme=\"ledger-light\""));
    assert!(body.contains("value=\"ledger\""));
    let (status, headers, _) = send(&app, post("/theme", "", &[("theme", b"ledger")])).await;
    assert_eq!(
        (status, &headers[LOCATION]),
        (StatusCode::SEE_OTHER, &"/".parse().unwrap())
    );
    let (status, _, _) = send(&app, post("/theme", "", &[("theme", b"bogus")])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    pool.close().await;
}
