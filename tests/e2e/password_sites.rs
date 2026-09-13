//! Password-site regressions: protected creation, viewer grants, unlock, and settings.

use crate::{ADMIN_HOST, VIEW_HOST, app_settings, auth, publishing, spawn_app};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        HeaderMap, Request, StatusCode,
        header::{COOKIE, HOST, LOCATION, ORIGIN, SET_COOKIE},
    },
    response::IntoResponse,
};
use axum_extra::extract::cookie::{Cookie, Key, SameSite, SignedCookieJar};
use pagebin::{ConfigBuilder, router};
use sqlx::SqlitePool;

const SLUG: &str = "private-site";
const OTHER: &str = "other-private-site";
const PASSWORD: &str = "synthetic-site-password";
const HTML: &[u8] = b"<!doctype html><h1>Private bytes</h1><script>ready=1</script>";
const PRIVATE: (&str, &[u8]) = ("visibility", b"password");
const SECRET: (&str, &[u8]) = ("password", PASSWORD.as_bytes());
const FORM_BODY_CAP: usize = 256 * 1024;
const KEY: [u8; 32] = [0x11; 32];
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
    let fields = [
        ("csrf_token", token.as_bytes()),
        ("slug", slug.as_bytes()),
        ("html", HTML),
        PRIVATE,
        SECRET,
    ];
    let (status, headers, _) = auth::send(app, auth::post("/sites", jar, &fields)).await;
    assert_eq!(status, SEE_OTHER);
    assert_eq!(headers[LOCATION], format!("/sites/{slug}"));
}

fn viewer(path: &str, jar: &str) -> Request<Body> {
    let mut req = publishing::viewer(path);
    req.headers_mut().insert(COOKIE, jar.parse().unwrap());
    req
}

fn credentials<'a>(csrf: &'a str, password: &'a [u8]) -> [(&'a str, &'a [u8]); 2] {
    [("csrf_token", csrf.as_bytes()), ("password", password)]
}

fn unlock_post(slug: &str, jar: &str, fields: &[(&str, &[u8])]) -> Request<Body> {
    let mut req = auth::post(&format!("/s/{slug}/__unlock"), jar, fields);
    req.headers_mut().insert(HOST, VIEW_HOST.parse().unwrap());
    let origin = format!("https://{VIEW_HOST}");
    req.headers_mut().insert(ORIGIN, origin.parse().unwrap());
    req
}

async fn challenge(app: &Router, slug: &str) -> (String, String) {
    let request = viewer(&format!("/s/{slug}/__unlock"), "");
    let (status, headers, body) = auth::send(app, request).await;
    assert_eq!(status, OK);
    let name = format!("__Secure-pb_unlock_form_{slug}");
    cookie_flags(&headers, &name, slug, 15 * 60);
    (auth::cookies(&headers), auth::csrf(&body))
}

async fn unlock(app: &Router, slug: &str, password: &str) -> String {
    let (jar, csrf) = challenge(app, slug).await;
    let fields = credentials(&csrf, password.as_bytes());
    let (status, headers, _) = auth::send(app, unlock_post(slug, &jar, &fields)).await;
    assert_eq!(status, SEE_OTHER);
    assert_eq!(headers[LOCATION], format!("/s/{slug}/"));
    let name = format!("pb_unlock_{slug}");
    cookie_flags(&headers, &name, slug, 7 * 24 * 60 * 60);
    let (issued, prefix) = (auth::cookies(&headers), format!("{name}="));
    let grant = issued.split("; ").find(|pair| pair.starts_with(&prefix));
    grant.unwrap().to_owned()
}

fn cookie_flags(headers: &HeaderMap, name: &str, slug: &str, seconds: i64) {
    let raw = headers.get_all(SET_COOKIE).iter();
    let mut parsed = raw.filter_map(|h| Cookie::parse(h.to_str().unwrap()).ok());
    let cookie = parsed.find(|c| c.name() == name).unwrap();
    assert!(cookie.http_only() == Some(true) && cookie.secure() == Some(true));
    assert!(cookie.same_site() == Some(SameSite::Lax) && cookie.domain().is_none());
    assert_eq!(cookie.path(), Some(format!("/s/{slug}/").as_str()));
    assert_eq!(cookie.max_age().unwrap().whole_seconds(), seconds);
}

fn save(jar: &str, token: &str, values: [&str; 4]) -> Request<Body> {
    let names = ["title", "entry", "visibility", "password"];
    let mut fields = vec![("csrf_token", token.as_bytes())];
    fields.extend(names.into_iter().zip(values.map(str::as_bytes)));
    auth::post(&format!("/sites/{SLUG}"), jar, &fields)
}

async fn password_hash(pool: &SqlitePool, slug: &str) -> Option<String> {
    let query = sqlx::query_scalar("SELECT password_hash FROM sites WHERE slug = ?");
    query.bind(slug).fetch_one(pool).await.unwrap()
}

async fn assert_locked(app: &Router, slug: &str, suffix: &str, jar: &str) {
    let request = viewer(&format!("/s/{slug}{suffix}"), jar);
    let (status, headers, body) = auth::send(app, request).await;
    assert_eq!(status, SEE_OTHER, "{slug}{suffix}");
    assert_eq!(headers[LOCATION], format!("/s/{slug}/__unlock"));
    publishing::viewer_headers(&headers, "private, no-store");
    assert!(!body.contains("Private bytes"));
}

/// Runs the header-level rejection matrix shared by every native POST.
async fn native_guards(app: &Router, build: impl Fn() -> Request<Body>, jar: &str) {
    let own = build().headers()[ORIGIN].to_str().unwrap().to_owned();
    let admin = own.contains(ADMIN_HOST);
    let cross = if admin { VIEW_HOST } else { ADMIN_HOST };
    let plain = own.replacen("https", "http", 1);
    let other = format!("https://{cross}");
    for origin in ["null", "https://external.example", &plain, &other] {
        let mut req = build();
        req.headers_mut().insert(ORIGIN, origin.parse().unwrap());
        expect(app, req, FORBIDDEN).await;
    }
    let mut dup = build();
    dup.headers_mut().append(ORIGIN, own.parse().unwrap());
    expect(app, dup, FORBIDDEN).await;
    for host in [cross, "unknown.local"] {
        let mut req = build();
        req.headers_mut().insert(HOST, host.parse().unwrap());
        expect(app, req, NOT_FOUND).await;
    }
    let encoded = format!("%{:02X}{}", jar.as_bytes()[0], &jar[1..]);
    for cookie in [format!("{jar}; {jar}"), encoded] {
        let mut req = build();
        req.headers_mut().insert(COOKIE, cookie.parse().unwrap());
        expect(app, req, BAD_REQUEST).await;
    }
    let mut dup = build();
    dup.headers_mut().append(COOKIE, jar.parse().unwrap());
    expect(app, dup, BAD_REQUEST).await;
    let mut missing = build();
    missing.headers_mut().remove(ORIGIN);
    expect(app, missing, SEE_OTHER).await;
}

#[tokio::test]
async fn password_creation_and_unlock_reject_invalid_access_csrf_origin_caps_replay_and_scripts() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let (csrf, slug) = (token.as_bytes(), SLUG.as_bytes());
    let base = [("csrf_token", csrf), ("slug", slug), ("html", HTML)];
    for extra in [
        vec![PRIVATE],
        vec![PRIVATE, ("password", b"")],
        vec![("visibility", b"open".as_slice()), SECRET],
        vec![("visibility", b"unknown".as_slice())],
        vec![PRIVATE, ("password", b"in\nva\0lid")],
        vec![PRIVATE, PRIVATE, SECRET, SECRET],
    ] {
        let fields = [base.as_slice(), &extra[..]].concat();
        let (status, _, body) = auth::send(&app, auth::post("/sites", &session, &fields)).await;
        assert_eq!(status, BAD_REQUEST, "{extra:?}");
        assert!(!body.contains(PASSWORD));
        assert!(!directory.path().join("sites").join(SLUG).exists());
    }
    publish(&app, &session, &token, SLUG).await;
    publish(&app, &session, &token, OTHER).await;
    let root = format!("/s/{SLUG}/");
    let path = format!("{root}__unlock");
    let name = format!("pb_unlock_{SLUG}=");
    for suffix in ["", "/", "/asset.bin", "/absent"] {
        assert_locked(&app, SLUG, suffix, "").await;
    }
    let (status, headers, body) = auth::send(&app, viewer(&path, "")).await;
    assert_eq!(status, OK);
    let policy = headers["content-security-policy"].to_str().unwrap();
    assert!(policy.contains("default-src 'none'") && !policy.contains("script-src"));
    assert!(!body.contains("<script") && !body.contains("Private bytes"));
    let admin_only = "/static/app.css /static/admin.js /login /s/absent-site/__unlock /s/absent-site/__unlock/app.css";
    for route in admin_only.split(' ') {
        expect(&app, viewer(route, ""), NOT_FOUND).await;
    }
    expect(&app, auth::get(&path, &session), NOT_FOUND).await;
    let (jar, csrf) = challenge(&app, SLUG).await;
    let (other_jar, _) = challenge(&app, OTHER).await;
    let wrong = credentials(&csrf, b"synthetic-wrong");
    let (status, headers, body) = auth::send(&app, unlock_post(SLUG, &jar, &wrong)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!body.contains("synthetic-wrong") && !auth::cookies(&headers).contains(&name));
    let fields = credentials(&csrf, PASSWORD.as_bytes());
    for cookie in ["", session.as_str(), other_jar.as_str()] {
        expect(&app, unlock_post(SLUG, cookie, &fields), FORBIDDEN).await;
    }
    let forged = credentials("invalid", PASSWORD.as_bytes());
    for invalid in [&fields[1..], &forged[..]] {
        expect(&app, unlock_post(SLUG, &jar, invalid), FORBIDDEN).await;
    }
    native_guards(&app, || unlock_post(SLUG, &jar, &fields), &jar).await;
    for extra in [fields[0], fields[1], ("unknown", b"value".as_slice())] {
        let dup = [fields.as_slice(), &[extra]].concat();
        expect(&app, unlock_post(SLUG, &jar, &dup), BAD_REQUEST).await;
    }
    for password in [b"".as_slice(), b"invalid\npassword", &[0xff]] {
        let invalid = credentials(&csrf, password);
        expect(&app, unlock_post(SLUG, &jar, &invalid), BAD_REQUEST).await;
    }
    let large = vec![b'x'; FORM_BODY_CAP + 1];
    let settings = save(&session, &token, ["Rejected", "index.html", "open", ""]);
    for request in [settings, unlock_post(SLUG, &jar, &fields)] {
        let (parts, body) = request.into_parts();
        let mut encoded = to_bytes(body, FORM_BODY_CAP).await.unwrap().to_vec();
        encoded.extend_from_slice(&large);
        let streamed = Body::from_stream(Body::from(encoded).into_data_stream());
        let (status, headers, body) = auth::send(&app, Request::from_parts(parts, streamed)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!auth::cookies(&headers).contains(&name) && !body.contains(PASSWORD));
    }
    let big = unlock_post(SLUG, &jar, &credentials(&csrf, &large));
    expect(&app, big, StatusCode::PAYLOAD_TOO_LARGE).await;
    let grant = unlock(&app, SLUG, PASSWORD).await;
    let (status, _, body) = auth::send(&app, viewer(&root, &grant)).await;
    assert_eq!((status, body.as_bytes()), (OK, HTML));
    assert_locked(&app, OTHER, "/", &grant).await;
    assert_locked(&app, OTHER, "/", &grant.replacen(SLUG, OTHER, 1)).await;
    let twice = format!("{grant}; {grant}");
    let conflicting = format!("{grant}; {name}invalid");
    let encoded = grant.replacen("pb_unlock_", "%70b_unlock_", 1);
    for cookie in [twice, conflicting, encoded] {
        let (status, _, body) = auth::send(&app, viewer(&root, &cookie)).await;
        assert!(status == BAD_REQUEST && !body.contains("Private bytes"));
    }
    let mut dup = viewer(&root, &grant);
    dup.headers_mut().append(COOKIE, grant.parse().unwrap());
    expect(&app, dup, BAD_REQUEST).await;
    pool.close().await;
}

#[tokio::test]
async fn viewer_password_grants_reject_forgery_rotation_expiry_corruption_and_recreation() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    publish(&app, &session, &token, SLUG).await;
    let grant = unlock(&app, SLUG, PASSWORD).await;
    let root = format!("/s/{SLUG}/");
    let at = |suffix: &str| viewer(&format!("{root}{suffix}"), &grant);
    let name = format!("pb_unlock_{SLUG}");
    let headers = HeaderMap::from_iter([(COOKIE, grant.parse().unwrap())]);
    let signed = SignedCookieJar::from_headers(&headers, Key::derive_from(&KEY));
    let payload = signed.get(&name).unwrap().value().to_owned();
    let parts: Vec<_> = payload.split(':').collect();
    let (salt, expiry) = (parts[3], parts[4]);
    let flip = if salt.ends_with('0') { '1' } else { '0' };
    let flipped = format!("{}{flip}", &salt[..31]);
    for invalid in [
        payload.replacen("unlock:", "login:", 1),
        payload.replacen(":v1:", ":v2:", 1),
        format!("unlock:v1:{OTHER}:{salt}:{expiry}"),
        format!("unlock:v1:{SLUG}:{}:{expiry}", "a".repeat(31)),
        format!("unlock:v1:{SLUG}:{}:{expiry}", "A".repeat(32)),
        format!("unlock:v1:{SLUG}:{flipped}:{expiry}"),
        format!("unlock:v1:{SLUG}:{salt}:0"),
        format!("unlock:v1:{SLUG}:{salt}:+{expiry}"),
        format!("unlock:v1:{SLUG}:{salt}:999999999999999999999999999999"),
        format!("{payload}:extra"),
    ] {
        let cookie = Cookie::new(name.clone(), invalid);
        let jar = SignedCookieJar::new(Key::derive_from(&KEY)).add(cookie);
        let forged = auth::cookies(jar.into_response().headers());
        assert_locked(&app, SLUG, "/", &forged).await;
    }
    for invalid in [format!("{grant}x"), format!("{name}=unsigned")] {
        assert_locked(&app, SLUG, "/", &invalid).await;
    }
    assert_locked(&app, SLUG, "/", &format!("{name}={payload}")).await;
    let mut values = app_settings(directory.path(), Some(VIEW_HOST));
    values.insert("PAGEBIN_SECRET", "22".repeat(32).into());
    let lookup = |key: &str| values.get(key).cloned();
    let config = ConfigBuilder::from_lookup(lookup).build().unwrap();
    let rotated = router(config, pool.clone()).await.unwrap();
    assert_locked(&rotated, SLUG, "/", &grant).await;
    let original = password_hash(&pool, SLUG).await.unwrap();
    let expire = "UPDATE sites SET expires_at = 1";
    sqlx::query(expire).execute(&pool).await.unwrap();
    for suffix in ["", "asset.bin", "__unlock", "__unlock/app.css"] {
        let (status, _, body) = auth::send(&app, at(suffix)).await;
        assert_eq!(status, NOT_FOUND, "{suffix}");
        assert!(!body.contains("Private bytes"));
    }
    let revive = "UPDATE sites SET expires_at = NULL";
    sqlx::query(revive).execute(&pool).await.unwrap();
    let huge = original.replace("m=19456", "m=4294967295");
    for malformed in ["invalid-stored-credential", huge.as_str()] {
        let corrupt = sqlx::query("UPDATE sites SET password_hash = ?");
        corrupt.bind(malformed).execute(&pool).await.unwrap();
        for cookie in ["", grant.as_str()] {
            let (status, _, body) = auth::send(&app, viewer(&root, cookie)).await;
            assert!(status.is_client_error() || status.is_server_error());
            assert!(!body.contains("Private bytes") && !body.contains(malformed));
        }
    }
    let yes = ("confirm", b"delete".as_slice());
    let confirm = [("csrf_token", token.as_bytes()), yes];
    let delete = auth::post(&format!("/sites/{SLUG}/delete"), &session, &confirm);
    expect(&app, delete, SEE_OTHER).await;
    expect(&app, at("__unlock"), NOT_FOUND).await;
    publish(&app, &session, &token, SLUG).await;
    assert_ne!(password_hash(&pool, SLUG).await.unwrap(), original);
    assert_locked(&app, SLUG, "/", &grant).await;
    pool.close().await;
}

#[tokio::test]
async fn settings_password_requires_session_origin_csrf_rejects_malformed_forms_and_revokes_grants()
{
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    publish(&app, &session, &token, SLUG).await;
    let mut hash = password_hash(&pool, SLUG).await.unwrap();
    let mut grant = unlock(&app, SLUG, PASSWORD).await;
    let keep = ["Changed", "index.html", "password", ""];
    let attempt = |jar: &str, csrf: &str| save(jar, csrf, keep);
    for jar in ["", "pb_admin=unsigned"] {
        expect(&app, attempt(jar, &token), FORBIDDEN).await;
    }
    for csrf in ["", "invalid"] {
        expect(&app, attempt(&session, csrf), FORBIDDEN).await;
    }
    native_guards(&app, || attempt(&session, &token), &session).await;
    let path = format!("/sites/{SLUG}");
    let form = [
        ("csrf_token", token.as_bytes()),
        ("title", b"Changed".as_slice()),
        ("entry", b"index.html".as_slice()),
        PRIVATE,
        ("password", b"".as_slice()),
    ];
    expect(&app, auth::post(&path, &session, &form[..4]), SEE_OTHER).await;
    // A metadata-only save keeps the stored hash and the existing grant.
    assert_eq!(password_hash(&pool, SLUG).await.unwrap(), hash);
    let (status, _, body) = auth::send(&app, viewer(&format!("/s/{SLUG}/"), &grant)).await;
    assert_eq!((status, body.as_bytes()), (OK, HTML));
    for missing in ["title", "entry", "visibility"] {
        let partial: Vec<_> = form.iter().copied().filter(|f| f.0 != missing).collect();
        expect(&app, auth::post(&path, &session, &partial), BAD_REQUEST).await;
    }
    for extra in [
        ("title", b"duplicate".as_slice()),
        ("csrf_token", token.as_bytes()),
        ("unknown", b"value".as_slice()),
        ("slug", b"renamed-site".as_slice()),
        ("expires_at", b"1".as_slice()),
        ("files[]\"; filename=\"index.html", HTML),
    ] {
        let dup = [form.as_slice(), &[extra]].concat();
        expect(&app, auth::post(&path, &session, &dup), BAD_REQUEST).await;
    }
    let as_file = ("title\"; filename=\"title.txt", b"Title".as_slice());
    for title in [("title", &[0xff][..]), as_file] {
        let swap = [&form[..1], &[title], &form[2..]].concat();
        expect(&app, auth::post(&path, &session, &swap), BAD_REQUEST).await;
    }
    const TITLE: &str = "Rejected <script>settings_error_title()</script>";
    let entries =
        "|absent.html|../index.html|/index.html|__unlock|nested/index.html|index.html\\other";
    for entry in entries.split('|') {
        let bad = [TITLE, entry, "password", PASSWORD];
        let (status, _, body) = auth::send(&app, save(&session, &token, bad)).await;
        assert_eq!(status, BAD_REQUEST, "entry {entry}");
        assert!(body.contains("settings_error_title()") && !body.contains(TITLE));
        assert!(!body.contains(PASSWORD) && !body.contains(&hash));
    }
    for pw in [PASSWORD, "synthetic-replacement-password"] {
        let reset = save(&session, &token, ["Reset", "index.html", "password", pw]);
        expect(&app, reset, SEE_OTHER).await;
        let changed = password_hash(&pool, SLUG).await.unwrap();
        assert_ne!(changed, hash);
        assert_locked(&app, SLUG, "/", &grant).await;
        grant = unlock(&app, SLUG, pw).await;
        hash = changed;
    }
    let open = save(&session, &token, ["Open now", "index.html", "open", ""]);
    expect(&app, open, SEE_OTHER).await;
    assert!(password_hash(&pool, SLUG).await.is_none());
    let (status, _, body) = auth::send(&app, viewer(&format!("/s/{SLUG}/"), "")).await;
    assert_eq!((status, body.as_bytes()), (OK, HTML));
    let again = ["Again", "index.html", "password", PASSWORD];
    expect(&app, save(&session, &token, again), SEE_OTHER).await;
    assert_ne!(password_hash(&pool, SLUG).await.unwrap(), hash);
    assert_locked(&app, SLUG, "/", &grant).await;
    assert_locked(&app, SLUG, "/", "").await;
    expect(&app, auth::post("/logout", &session, &form[..1]), SEE_OTHER).await;
    expect(&app, attempt(&session, &token), FORBIDDEN).await;
    pool.close().await;
}
