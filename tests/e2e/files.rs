//! Flat-file publishing regressions using real multipart requests and storage.

use crate::{TEST_UPLOAD_MB, VIEW_HOST, auth, publishing, spawn_app};
use axum::body::{Body, HttpBody, to_bytes};
use axum::http::header::{CONTENT_LENGTH, LOCATION};
use axum::http::{Request, StatusCode};
use std::fs;
use tower::ServiceExt;

const UPLOAD_BYTES: usize = TEST_UPLOAD_MB * 1024 * 1024;
const HTML: &[u8] = b"<!doctype html><link rel=stylesheet href=style.css><img src=asset.bin>";
const CSS: &[u8] = b"body { color: rebeccapurple; }\n";
const BINARY: &[u8] = b"\x00\xff\xfe\x80\r\n\x01asset\x00";
const TITLE: &str = "Binary asset report";
const PUBLIC: &str = "public, max-age=60";

fn upload(
    session: &str,
    token: &str,
    slug: &str,
    files: &[(&str, &[u8])],
    entry: Option<&str>,
) -> Request<Body> {
    let names: Vec<String> = files
        .iter()
        .map(|(n, _)| format!("files[]\"; filename=\"{n}"))
        .collect();
    let (csrf, slug, title) = (token.as_bytes(), slug.as_bytes(), TITLE.as_bytes());
    let mut fields = vec![("csrf_token", csrf), ("slug", slug), ("title", title)];
    for (name, (_, bytes)) in names.iter().zip(files) {
        fields.push((name.as_str(), *bytes));
    }
    fields.extend(entry.map(|entry| ("entry", entry.as_bytes())));
    auth::post("/sites", session, &fields)
}

#[tokio::test]
async fn files_uploads_preserve_bytes_and_metadata_and_conflicts_keep_existing_content() {
    const SLUG: &str = "binary-assets";
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let files = [
        ("index.html", HTML),
        ("style.css", CSS),
        ("asset.bin", BINARY),
    ];
    let (status, headers, _) = auth::send(&app, upload(&session, &token, SLUG, &files, None)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], format!("/sites/{SLUG}"));
    for (path, expected, mime) in [
        ("", HTML, "text/html"),
        ("style.css", CSS, "text/css"),
        ("asset.bin", BINARY, "application/octet-stream"),
    ] {
        let request = publishing::viewer(&format!("/s/{SLUG}/{path}"));
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], mime);
        publishing::viewer_headers(response.headers(), PUBLIC);
        let served = to_bytes(response.into_body(), UPLOAD_BYTES).await.unwrap();
        assert_eq!(served.as_ref(), expected);
    }
    let sql = "SELECT title, entry, file_count, size_bytes FROM sites";
    let row: (String, String, i64, i64) = sqlx::query_as(sql).fetch_one(&pool).await.unwrap();
    let size = (HTML.len() + CSS.len() + BINARY.len()) as i64;
    assert_eq!(row, (TITLE.into(), "index.html".into(), 3, size));
    let replacement = [("index.html", b"must not replace".as_slice())];
    let conflict = upload(&session, &token, SLUG, &replacement, None);
    assert_eq!(auth::send(&app, conflict).await.0, StatusCode::CONFLICT);
    for (name, bytes) in files {
        let stored = directory.path().join("sites").join(SLUG).join(name);
        assert_eq!(fs::read(stored).unwrap(), bytes);
    }
    publishing::assert_stored(&pool, directory.path(), 1).await;
    let orphan = directory.path().join("sites/orphan-files");
    fs::create_dir(&orphan).unwrap();
    fs::write(orphan.join("retained.bin"), BINARY).unwrap();
    let squatted = upload(&session, &token, "orphan-files", &replacement, None);
    assert_eq!(auth::send(&app, squatted).await.0, StatusCode::CONFLICT);
    assert_eq!(fs::read(orphan.join("retained.bin")).unwrap(), BINARY);
    assert!(!orphan.join("index.html").exists());
    let sql = "SELECT COUNT(*) FROM sites";
    let count: i64 = sqlx::query_scalar(sql).fetch_one(&pool).await.unwrap();
    assert_eq!(count, 1);
    pool.close().await;
}

#[tokio::test]
async fn files_entry_selection_prefers_explicit_then_index_then_sole_html() {
    let (app, pool, _directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let both = [("index.html", b"index".as_slice()), ("other.htm", b"other")];
    let upper = [
        ("Report.HTML", b"upper html".as_slice()),
        ("style.css", CSS),
    ];
    let htm = [("Report.HtM", b"upper htm".as_slice())];
    let text = [("readme.txt", b"explicit text".as_slice())];
    for (slug, files, entry, expected) in [
        ("chosen", both.as_slice(), Some("other.htm"), "other.htm"),
        ("index-entry", both.as_slice(), None, "index.html"),
        ("sole-html", upper.as_slice(), None, "Report.HTML"),
        ("sole-htm", htm.as_slice(), None, "Report.HtM"),
        ("text", text.as_slice(), Some("readme.txt"), "readme.txt"),
    ] {
        let (status, _, _) = auth::send(&app, upload(&session, &token, slug, files, entry)).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "{slug}");
        let query = sqlx::query_scalar("SELECT entry FROM sites WHERE slug = ?").bind(slug);
        let stored: String = query.fetch_one(&pool).await.unwrap();
        assert_eq!(stored, expected);
        let page = publishing::viewer(&format!("/s/{slug}/"));
        let (status, headers, body) = auth::send(&app, page).await;
        let content = files.iter().find(|(name, _)| *name == expected).unwrap().1;
        assert_eq!((status, body.as_bytes()), (StatusCode::OK, content));
        publishing::viewer_headers(&headers, PUBLIC);
    }
    pool.close().await;
}

#[tokio::test]
async fn files_reject_missing_mixed_repeated_and_wrong_part_types() {
    const FILE_PART: &str = "files[]\"; filename=\"index.html";
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let mut cases: Vec<Vec<(&str, &[u8])>> = vec![
        vec![],
        vec![("files[]", HTML)],
        vec![("html", HTML), (FILE_PART, HTML)],
        vec![("html", b""), (FILE_PART, HTML)],
        vec![("html\"; filename=\"index.html", HTML)],
        vec![(FILE_PART, HTML), ("unknown", b"value")],
        vec![(FILE_PART, HTML), ("csrf_token", token.as_bytes())],
    ];
    for name in ["entry", "title", "slug"] {
        cases.push(vec![(FILE_PART, HTML), (name, b"one"), (name, b"two")]);
    }
    let shaped =
        ["title", "slug", "entry", "csrf_token"].map(|f| format!("{f}\"; filename=\"value.txt"));
    for file_field in &shaped {
        cases.push(vec![(FILE_PART, HTML), (file_field, b"value")]);
    }
    for (index, mut fields) in cases.into_iter().enumerate() {
        fields.insert(0, ("csrf_token", token.as_bytes()));
        let (status, _, _) = auth::send(&app, auth::post("/sites", &session, &fields)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {index}");
        publishing::assert_stored(&pool, directory.path(), 0).await;
    }
    pool.close().await;
}

#[tokio::test]
async fn files_reject_unsafe_duplicate_names_and_unresolvable_entries() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let names =
        ". .. ../outside.html /absolute.html nested/index.html a\\b.html bad\0name.html __unlock";
    for filename in names.split(' ').chain([""]) {
        let files = [("index.html", HTML), (filename, b"invalid")];
        let request = upload(&session, &token, "invalid-files", &files, None);
        let (status, _, _) = auth::send(&app, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "filename {filename:?}");
        publishing::assert_stored(&pool, directory.path(), 0).await;
    }
    let duplicate = [("index.html", HTML), ("index.html", b"duplicate")];
    let ambiguous = [("one.html", HTML), ("two.HTM", HTML)];
    let css = [("style.css", CSS)];
    for files in [duplicate.as_slice(), ambiguous.as_slice(), css.as_slice()] {
        let request = upload(&session, &token, "bad-files", files, None);
        let (status, _, _) = auth::send(&app, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{files:?}");
        publishing::assert_stored(&pool, directory.path(), 0).await;
    }
    let index = [("index.html", HTML)];
    for entry in "absent.html ../index.html /index.html __unlock".split(' ') {
        let request = upload(&session, &token, "bad-entry", &index, Some(entry));
        let (status, _, _) = auth::send(&app, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "entry {entry}");
        publishing::assert_stored(&pool, directory.path(), 0).await;
    }
    pool.close().await;
}

#[tokio::test]
async fn files_part_count_and_complete_body_caps_cover_streamed_and_epilogue_bytes() {
    const FILE_PART_LIMIT: usize = 10_000;
    const SLUG: &str = "bounded-files";
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    for (count, expected) in [
        (FILE_PART_LIMIT, StatusCode::BAD_REQUEST),
        (FILE_PART_LIMIT + 1, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let mut fields = vec![("files[]\"; filename=\"", b"".as_slice()); count];
        fields.push(("csrf_token", token.as_bytes()));
        let request = auth::post("/sites?input=files", &session, &fields);
        assert!(request.body().size_hint().exact().unwrap() < UPLOAD_BYTES as u64);
        let (status, _, _) = auth::send(&app, request).await;
        assert_eq!(status, expected, "part count {count}");
        publishing::assert_stored(&pool, directory.path(), 0).await;
    }
    let large = vec![b'x'; UPLOAD_BYTES];
    let files = [("index.html", large.as_slice())];
    let mut sized = upload(&session, &token, SLUG, &files, None);
    let size = sized.body().size_hint().exact().unwrap();
    sized.headers_mut().insert(CONTENT_LENGTH, size.into());
    let (status, _, _) = auth::send(&app, sized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (parts, body) = upload(&session, &token, SLUG, &[("index.html", HTML)], None).into_parts();
    let mut epilogue = to_bytes(body, UPLOAD_BYTES).await.unwrap().to_vec();
    epilogue.extend_from_slice(&large);
    let (unbounded, body) = upload(&session, &token, SLUG, &files, None).into_parts();
    for (parts, body) in [(unbounded, body), (parts, Body::from(epilogue))] {
        let streamed = Body::from_stream(body.into_data_stream());
        let (status, _, _) = auth::send(&app, Request::from_parts(parts, streamed)).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }
    publishing::assert_stored(&pool, directory.path(), 0).await;
    // Every multipart delimiter and scalar field counts toward the exact cap.
    let framing = upload(&session, &token, SLUG, &[("index.html", b"")], None);
    let framing = framing.body().size_hint().exact().unwrap() as usize;
    let fits = vec![b'x'; UPLOAD_BYTES - framing];
    let request = upload(&session, &token, SLUG, &[("index.html", &fits)], None);
    let exact = request.body().size_hint().exact();
    assert_eq!(exact, Some(UPLOAD_BYTES as u64));
    assert_eq!(auth::send(&app, request).await.0, StatusCode::SEE_OTHER);
    let stored = directory.path().join("sites").join(SLUG).join("index.html");
    assert_eq!(fs::read(stored).unwrap(), fits);
    let sql = "SELECT size_bytes FROM sites";
    let size: i64 = sqlx::query_scalar(sql).fetch_one(&pool).await.unwrap();
    assert_eq!(size, fits.len() as i64);
    publishing::assert_stored(&pool, directory.path(), 1).await;
    pool.close().await;
}
