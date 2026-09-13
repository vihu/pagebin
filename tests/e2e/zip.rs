//! ZIP publishing regressions: nested archives serve, unsafe entries never land, caps hold.

use crate::{TEST_UPLOAD_MB, VIEW_HOST, auth, publishing, spawn_app};
use axum::{
    body::Body,
    http::{Request, StatusCode, header::LOCATION},
};
use std::{
    fs,
    io::{Cursor, Write},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const INDEX: &[u8] = b"<!doctype html><link rel=stylesheet href=css/style.css><h1>Zipped</h1>";
const CSS: &[u8] = b"h1 { color: rebeccapurple }";
const ASSET: &[u8] = b"asset-bytes";
const UPLOAD_BYTES: usize = TEST_UPLOAD_MB * 1024 * 1024;

fn archive(entries: &[(&str, &[u8])], symlink: Option<(&str, &str)>) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (name, bytes) in entries {
        if name.ends_with('/') {
            writer.add_directory(*name, options).unwrap();
            continue;
        }
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    if let Some((name, target)) = symlink {
        writer.add_symlink(name, target, options).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// Writes a safe placeholder name, then swaps the raw bytes the writer would
/// have normalized away, so the archive really carries `name`.
fn crafted(placeholder: &str, name: &str) -> Vec<u8> {
    assert_eq!(placeholder.len(), name.len());
    let bytes = archive(&[(placeholder, INDEX)], None);
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(placeholder.as_bytes()) {
            out.extend_from_slice(name.as_bytes());
            index += placeholder.len();
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    out
}

fn publish(jar: &str, token: &str, slug: &str, zip: &[u8], entry: &str) -> Request<Body> {
    let fields = [
        ("csrf_token", token.as_bytes()),
        ("slug", slug.as_bytes()),
        ("entry", entry.as_bytes()),
        ("zip\"; filename=\"site.zip", zip),
    ];
    auth::post("/sites", jar, &fields)
}

#[tokio::test]
async fn zip_with_nested_dirs_and_top_level_dir_stripped_serves_relative_assets() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let entries = [
        ("site/", b"".as_slice()),
        ("site/index.html", INDEX),
        ("site/css/", b""),
        ("site/css/style.css", CSS),
        ("site/img/a.bin", ASSET),
    ];
    let zip = archive(&entries, None);
    let request = publish(&session, &token, "zipped", &zip, "");
    let (status, headers, _) = auth::send(&app, request).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers[LOCATION], "/sites/zipped");
    for (path, bytes) in [
        ("/s/zipped/", INDEX),
        ("/s/zipped/css/style.css", CSS),
        ("/s/zipped/img/a.bin", ASSET),
    ] {
        let (status, _, body) = auth::send(&app, publishing::viewer(path)).await;
        assert_eq!((status, body.as_bytes()), (StatusCode::OK, bytes), "{path}");
    }
    let (count, entry): (i64, String) =
        sqlx::query_as("SELECT file_count, entry FROM sites WHERE slug = 'zipped'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!((count, entry.as_str()), (3, "index.html"));
    let second = archive(
        &[("index.html", b"<h1>Second</h1>"), ("a/b/c.txt", b"deep")],
        None,
    );
    let fields = [
        ("csrf_token", token.as_bytes()),
        ("zip\"; filename=\"v2.zip", second.as_slice()),
    ];
    let request = auth::post("/sites/zipped/content", &session, &fields);
    assert_eq!(auth::send(&app, request).await.0, StatusCode::SEE_OTHER);
    let (status, _, body) = auth::send(&app, publishing::viewer("/s/zipped/a/b/c.txt")).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "deep"));
    assert!(!directory.path().join("sites/zipped/css").exists());
    assert_eq!(
        fs::read_dir(directory.path().join("tmp")).unwrap().count(),
        0
    );
    let confirm = [
        ("csrf_token", token.as_bytes()),
        ("confirm", b"delete".as_slice()),
    ];
    let request = auth::post("/sites/zipped/delete", &session, &confirm);
    assert_eq!(auth::send(&app, request).await.0, StatusCode::SEE_OTHER);
    assert!(!directory.path().join("sites/zipped").exists());
    pool.close().await;
}

#[tokio::test]
async fn zip_slip_symlink_and_reserved_paths_are_rejected_and_leave_no_files() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let unsafe_archives = [
        crafted("xx/evil.html", "../evil.html"),
        crafted("zabs.html", "/abs.html"),
        crafted("dir_evil.html", "dir\\evil.html"),
        archive(&[("__unlock/index.html", INDEX)], None),
        archive(&[("index.html", INDEX)], Some(("link.html", "/etc/passwd"))),
        archive(&[("a/x.txt", b"no entry")], None),
        b"not a zip".to_vec(),
    ];
    for (index, zip) in unsafe_archives.iter().enumerate() {
        let request = publish(&session, &token, "unsafe", zip, "");
        let (status, _, body) = auth::send(&app, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "case {index}: {body}");
    }
    let plain = archive(&[("index.html", INDEX)], None);
    let both = [
        ("csrf_token", token.as_bytes()),
        ("html", INDEX),
        ("zip\"; filename=\"s.zip", plain.as_slice()),
    ];
    let (status, _, _) = auth::send(&app, auth::post("/sites", &session, &both)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "html and zip together");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sites")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    assert_eq!(
        fs::read_dir(directory.path().join("sites"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        fs::read_dir(directory.path().join("tmp")).unwrap().count(),
        0
    );
    pool.close().await;
}

#[tokio::test]
async fn zip_entry_count_and_size_caps_are_enforced() {
    let (app, pool, directory) = spawn_app(Some(VIEW_HOST)).await;
    let (session, token) = publishing::login(&app).await;
    let zeros = vec![0_u8; UPLOAD_BYTES * 4 + 1];
    let oversized = archive(&[("index.html", INDEX), ("big.bin", &zeros)], None);
    assert!(
        oversized.len() < UPLOAD_BYTES,
        "fixture must fit the upload cap"
    );
    let request = publish(&session, &token, "capped", &oversized, "");
    assert_eq!(auth::send(&app, request).await.0, StatusCode::BAD_REQUEST);
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let stored = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for index in 0..=10_000 {
        writer.start_file(format!("f{index}"), stored).unwrap();
    }
    let crowded = writer.finish().unwrap().into_inner();
    assert!(
        crowded.len() < UPLOAD_BYTES,
        "fixture must fit the upload cap"
    );
    let request = publish(&session, &token, "crowded", &crowded, "");
    assert_eq!(auth::send(&app, request).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        fs::read_dir(directory.path().join("sites"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        fs::read_dir(directory.path().join("tmp")).unwrap().count(),
        0
    );
    pool.close().await;
}
