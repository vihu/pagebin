//! Metadata-gated static serving isolated from administrator cookies and CSP.

use super::{ClientIpSource, unlock};
use crate::{
    AppError, Result,
    auth::{Auth, Password},
    sites::{Site, SitePath, Sites, Slug},
};
use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{Path, Request, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode, Uri,
        header::{
            CACHE_CONTROL, CONTENT_SECURITY_POLICY, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH,
            IF_RANGE, IF_UNMODIFIED_SINCE, LOCATION, RANGE, REFERRER_POLICY,
            X_CONTENT_TYPE_OPTIONS,
        },
        request::Parts,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use std::{
    collections::HashMap, fs::Metadata, io::ErrorKind, path::Path as FsPath, sync::Arc,
    time::Duration,
};
use tokio::fs;
use tower_http::services::{ServeDir, ServeFile};

const INDEX_FILE: &str = "index.html";
const NOT_FOUND_FILE: &str = "404.html";
const OPEN_CACHE: &str = "public, max-age=60";
const CLOSED_CACHE: &str = "private, no-store";
const UNLOCK_POLICY: &str = "default-src 'none'; style-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const SITE_PARENT_COUNT: usize = 2;

/// Builds viewer routes without administrator middleware.
pub(super) fn router(sites: Arc<Sites>, auth: Arc<Auth>, ip_source: ClientIpSource) -> Router {
    let state = ViewerState {
        sites,
        auth,
        ip_source,
    };
    Router::new()
        .route("/s/{slug}", get(serve))
        .route("/s/{slug}/", get(serve))
        .route("/s/{slug}/{*path}", get(serve))
        .with_state(state.clone())
        .merge(unlock::router(state))
}

/// Identifies only the viewer namespace, not administrator `/sites` routes.
pub(super) fn is_site_path(path: &str) -> bool {
    path == "/s" || path.starts_with("/s/")
}

/// Checks access and expiry before any site response reads content.
///
/// # Errors
/// Returns a safe operational error if the system clock is not representable.
pub(super) fn available(site: &Site) -> Result<bool> {
    let now = crate::sites::unix_now()?;
    Ok(matches!(site.visibility.as_str(), "open" | "password")
        && site.expires_at.is_none_or(|expiry| expiry > now))
}

/// Adds viewer policy to every namespace outcome, including outer rejections.
pub(super) async fn finish_response(request: Request, next: Next) -> Response {
    let viewer = is_site_path(request.uri().path());
    let head = request.method() == Method::HEAD;
    let mut response = next.run(request).await;
    if viewer {
        let trusted_ui = response.extensions().get::<ViewerUi>().is_some();
        let headers = response.headers_mut();
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(
            REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        headers.insert("x-robots-tag", HeaderValue::from_static("noindex"));
        headers
            .entry(CACHE_CONTROL)
            .or_insert(HeaderValue::from_static(CLOSED_CACHE));
        if trusted_ui {
            headers.insert(
                CONTENT_SECURITY_POLICY,
                HeaderValue::from_static(UNLOCK_POLICY),
            );
        } else {
            headers.remove(CONTENT_SECURITY_POLICY);
        }
        if head {
            *response.body_mut() = Body::empty();
        }
    }
    response
}

/// Serves only committed, eligible site metadata.
///
/// # Errors
/// Returns safe database, clock, or filesystem failures.
async fn serve(
    State(state): State<ViewerState>,
    Path(parameters): Path<HashMap<String, String>>,
    request: Request,
) -> Result<Response> {
    let Some(slug) = parameters
        .get("slug")
        .and_then(|slug| Slug::parse(slug).ok())
    else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(access) = state.sites.access(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !available(&access.site)? {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let protected = access.password.is_some();
    if let Some(password) = &access.password
        && !authorized(request.headers(), &state.auth, &slug, password)?
    {
        return Ok(unlock::redirect(&slug));
    }
    let root = state.sites.directory(&slug);
    let mut response = serve_open(&root, &access.site, parameters.get("path"), request).await?;
    if !protected && !response.status().is_server_error() {
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static(OPEN_CACHE));
    }
    Ok(response)
}

/// Validates a site-relative path before delegating file transfer.
///
/// # Errors
/// Returns safe filesystem or response-construction failures.
async fn serve_open(
    root: &FsPath,
    site: &Site,
    captured: Option<&String>,
    request: Request,
) -> Result<Response> {
    let (mut parts, _) = request.into_parts();
    if captured.is_none() {
        if safe_metadata(root, None).await?.is_none() {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        if !parts.uri.path().ends_with('/') {
            return redirect(&parts.uri);
        }
        return entry(root, &site.entry, parts).await;
    }
    let decoded = captured.map(String::as_str).unwrap_or_default();
    let decoded = decoded.strip_suffix('/').unwrap_or(decoded);
    let raw = parts
        .uri
        .path()
        .strip_prefix("/s/")
        .and_then(|path| path.split_once('/'))
        .map_or("", |(_, path)| path);
    let lower = raw.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let Some(relative) = SitePath::parse(decoded) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(metadata) = safe_metadata(root, Some(relative)).await? else {
        return not_found(root, parts).await;
    };
    if metadata.is_dir() {
        if !parts.uri.path().ends_with('/') {
            return redirect(&parts.uri);
        }
        let index = format!("{}/{INDEX_FILE}", relative.as_str());
        let Some(index) = SitePath::parse(&index) else {
            return Ok(StatusCode::NOT_FOUND.into_response());
        };
        if !safe_metadata(root, Some(index))
            .await?
            .is_some_and(|file| file.is_file())
        {
            return not_found(root, parts).await;
        }
    }
    // Pass the original encoded suffix: Axum and ServeDir each decode once.
    // Passing Axum's decoded capture would decode percent-containing names twice.
    let suffix = match parts.uri.query() {
        Some(query) => format!("/{raw}?{query}"),
        None => format!("/{raw}"),
    };
    let original = parts.clone();
    parts.uri = suffix.parse().map_err(AppError::publishing)?;
    let mut service = ServeDir::new(root).redirect_to_trailing_slash(false);
    match service
        .try_call(Request::from_parts(parts, Body::empty()))
        .await
    {
        Ok(response) if response.status() != StatusCode::NOT_FOUND => Ok(response.map(Body::new)),
        Ok(_) => not_found(root, original).await,
        Err(error) if missing(error.kind()) => not_found(root, original).await,
        Err(error) => Err(AppError::publishing(error)),
    }
}

/// Serves a validated entry without changing its URL-relative asset base.
///
/// # Errors
/// Returns safe file-access failures.
async fn entry(root: &FsPath, entry: &str, parts: Parts) -> Result<Response> {
    let Some(path) = SitePath::parse(entry) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !safe_metadata(root, Some(path))
        .await?
        .is_some_and(|file| file.is_file())
    {
        return not_found(root, parts).await;
    }
    let mut service = ServeFile::new(root.join(path.as_str()));
    match service
        .try_call(Request::from_parts(parts.clone(), Body::empty()))
        .await
    {
        Ok(response) if response.status() != StatusCode::NOT_FOUND => Ok(response.map(Body::new)),
        Ok(_) => not_found(root, parts).await,
        Err(error) if missing(error.kind()) => not_found(root, parts).await,
        Err(error) => Err(AppError::publishing(error)),
    }
}

/// Uses only a safe regular custom error file with a 404 status.
///
/// # Errors
/// Returns safe file-access failures.
async fn not_found(root: &FsPath, mut parts: Parts) -> Result<Response> {
    let path =
        SitePath::parse(NOT_FOUND_FILE).expect("fixed error filename is a safe relative path");
    if !safe_metadata(root, Some(path))
        .await?
        .is_some_and(|file| file.is_file())
    {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    // Conditions/ranges for a missing asset must not suppress or slice its 404.
    for header in [
        RANGE,
        IF_RANGE,
        IF_MATCH,
        IF_NONE_MATCH,
        IF_MODIFIED_SINCE,
        IF_UNMODIFIED_SINCE,
    ] {
        parts.headers.remove(header);
    }
    let mut service = ServeFile::new(root.join(NOT_FOUND_FILE));
    match service
        .try_call(Request::from_parts(parts, Body::empty()))
        .await
    {
        Ok(response) => {
            let mut response = response.map(Body::new);
            *response.status_mut() = StatusCode::NOT_FOUND;
            Ok(response)
        }
        Err(error) if missing(error.kind()) => Ok(StatusCode::NOT_FOUND.into_response()),
        Err(error) => Err(AppError::publishing(error)),
    }
}

/// Adds a directory slash while preserving the request query.
///
/// # Errors
/// Returns an error if the local Location header cannot be encoded.
fn redirect(uri: &Uri) -> Result<Response> {
    let location = match uri.query() {
        Some(query) => format!("{}/?{query}", uri.path()),
        None => format!("{}/", uri.path()),
    };
    let mut response = StatusCode::MOVED_PERMANENTLY.into_response();
    response
        .headers_mut()
        .insert(LOCATION, location.parse().map_err(AppError::publishing)?);
    Ok(response)
}

/// Checks storage parents and every relative component without symlinks.
///
/// # Errors
/// Returns filesystem failures other than unavailable-path outcomes.
async fn safe_metadata(root: &FsPath, relative: Option<SitePath<'_>>) -> Result<Option<Metadata>> {
    // Only this process publishes files beneath operator-owned storage. Reject
    // existing symlinks; this is not a claim of hostile local-writer race safety.
    for parent in root.ancestors().skip(1).take(SITE_PARENT_COUNT) {
        if !metadata(parent).await?.is_some_and(|entry| entry.is_dir()) {
            return Ok(None);
        }
    }
    let Some(mut current) = metadata(root).await?.filter(Metadata::is_dir) else {
        return Ok(None);
    };
    let mut path = root.to_path_buf();
    if let Some(relative) = relative {
        for component in relative.as_str().split('/') {
            if !current.is_dir() {
                return Ok(None);
            }
            path.push(component);
            let Some(next) = metadata(&path).await? else {
                return Ok(None);
            };
            current = next;
        }
    }
    Ok(Some(current))
}

/// Reads final-component metadata without following symlinks.
///
/// # Errors
/// Returns filesystem failures other than unavailable-path outcomes.
async fn metadata(path: &FsPath) -> Result<Option<Metadata>> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.is_file() || metadata.is_dir() => Ok(Some(metadata)),
        Ok(_) => Ok(None),
        Err(error) if missing(error.kind()) => Ok(None),
        Err(error) => Err(AppError::publishing(error)),
    }
}

const fn missing(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::PermissionDenied
    )
}

/// Boot-initialized services for access-gated content and native unlock.
#[derive(Clone)]
pub(super) struct ViewerState {
    /// The same committed metadata store used by publishing and settings.
    pub(super) sites: Arc<Sites>,
    /// Shared signing, bounded password workers, and failure accounting.
    pub(super) auth: Arc<Auth>,
    /// The explicitly configured socket or trusted-proxy address policy.
    pub(super) ip_source: ClientIpSource,
}

/// Marks trusted UI without imposing application CSP on uploaded HTML.
#[derive(Clone, Copy)]
pub(super) struct ViewerUi;

impl ViewerUi {
    /// Attaches trusted provenance only to an application-rendered response.
    pub(super) fn mark(mut response: Response) -> Response {
        response.extensions_mut().insert(Self);
        response
    }
}

/// Returns the site-specific grant name, never an administrator credential.
pub(super) fn grant_name(slug: &Slug) -> String {
    format!("pb_unlock_{}", slug.as_str())
}

/// Returns the site-specific Secure-prefixed anti-CSRF challenge name.
pub(super) fn challenge_name(slug: &Slug) -> String {
    format!("__Secure-pb_unlock_form_{}", slug.as_str())
}

/// Extracts signature-verified viewer cookies without accepting aliases.
///
/// # Errors
/// Rejects ambiguous target names or malformed headers without granting access.
pub(super) fn read(headers: &HeaderMap, auth: &Auth, slug: &Slug) -> Result<SignedCookieJar> {
    super::signed(
        headers,
        auth.key(),
        &[&grant_name(slug), &challenge_name(slug)],
    )
}

/// Checks the signed grant against the password generation in this snapshot.
///
/// # Errors
/// Returns a safe cookie-header rejection, never access on malformed input.
pub(super) fn authorized(
    headers: &HeaderMap,
    auth: &Auth,
    slug: &Slug,
    password: &Password,
) -> Result<bool> {
    let jar = read(headers, auth, slug)?;
    let grant = jar.get(&grant_name(slug));
    Ok(auth.verify_viewer_grant(grant.as_ref().map(Cookie::value), slug, password))
}

/// Builds one host-only viewer cookie at its fixed site path.
///
/// # Panics
/// The caller must supply a lifetime representable by the cookie library.
pub(super) fn cookie(
    name: String,
    value: String,
    slug: &Slug,
    lifetime: Duration,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .path(format!("/s/{}/", slug.as_str()))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(
            lifetime
                .try_into()
                .expect("fixed viewer lifetimes fit cookie duration"),
        )
        .build()
}

/// Renders a fixed recovery link without changing authentication state.
#[derive(Template)]
#[template(path = "forbidden.html")]
pub(super) struct ForbiddenPage {
    /// The stored admin theme choice for this browser.
    pub(super) theme: &'static str,
}
