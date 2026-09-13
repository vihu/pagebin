//! Fail-closed host dispatch between administrator and uploaded-site origins.

mod admin;
mod api;
mod management;
mod publishing;
mod settings;
mod unlock;
mod upload;
mod view;

use crate::{
    AppError, Config, Result,
    auth::Auth,
    config::PASSWORD_BYTES,
    host::Host,
    sites::{self, Sites},
};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{FromRequest, Multipart, Request, State, multipart::MultipartError},
    http::{
        HeaderMap, StatusCode, Uri,
        header::{COOKIE, HOST, ORIGIN},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_extra::extract::cookie::{Cookie, Key, SignedCookieJar};
use publishing::PublishingState;
use sqlx::SqlitePool;
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Builds host-isolated administration and serving around initialized storage.
///
/// Consumes configuration so its plaintext password cannot enter shared state.
/// The pool must come from `open_database` for the configured data directory.
/// Request ports are validated but do not affect hostname dispatch; forwarded
/// hosts are ignored.
/// The listener must supply socket connection information for login throttling.
///
/// # Errors
/// Fails if storage, signing-key setup, or password hashing fails.
pub async fn router(config: Config, pool: SqlitePool) -> Result<Router> {
    let admin_host = config.admin_host().to_owned();
    let view_host = config.view_host().map(str::to_owned);
    let public_url = config.public_url().to_owned();
    let max_upload_bytes = config.max_upload_bytes();
    let sites = Arc::new(Sites::new(pool, config.data_dir().to_path_buf())?);
    sites::start_sweeper(Arc::clone(&sites)).await?;
    let ip_source = if config.trust_proxy() {
        ClientIpSource::Forwarded
    } else {
        ClientIpSource::Socket
    };
    let api_token = config.api_token().map(str::to_owned);
    let (password, data_dir, secret) = config.into_auth_settings();
    let auth = Arc::new(Auth::new(password, data_dir, secret).await?);
    let state = PublishingState::new(
        Arc::clone(&auth),
        Arc::clone(&sites),
        public_url,
        max_upload_bytes,
    );
    let publishing = publishing::router(state.clone()).merge(management::router(state.clone()));
    Ok(Router::new()
        .route("/health", get(|| async { "ok" }))
        .merge(admin::router(Arc::clone(&auth), ip_source, publishing))
        .merge(view::router(sites, auth, ip_source))
        .merge(api::router(state, api_token))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .layer(middleware::from_fn_with_state(
            (admin_host, view_host),
            require_host,
        ))
        .layer(middleware::from_fn(view::finish_response)))
}

async fn require_host(
    State((admin_host, view_host)): State<(String, Option<String>)>,
    request: Request,
    next: Next,
) -> Response {
    let mut hosts = request.headers().get_all(HOST).iter();
    let Some(value) = hosts.next().and_then(|value| value.to_str().ok()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if hosts.next().is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(host) = Host::from_authority(value) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let site_path = view::is_site_path(request.uri().path());
    let authorized = if host.as_str() == admin_host {
        view_host.is_none() || !site_path
    } else {
        site_path && view_host.as_deref() == Some(host.as_str())
    };
    if !authorized {
        return StatusCode::NOT_FOUND.into_response();
    }
    // Absolute-form requests must not carry a second, conflicting authority.
    if request
        .uri()
        .authority()
        .is_some_and(|authority| !authority.as_str().eq_ignore_ascii_case(value))
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

/// Selects the explicit source of client addresses for login throttling.
#[derive(Clone, Copy)]
enum ClientIpSource {
    /// Uses the connection's socket address without trusting forwarded headers.
    Socket,
    /// Requires a verified final hop supplied by an exclusively trusted proxy.
    Forwarded,
}

const FORWARDED_FOR: &str = "x-forwarded-for";

impl ClientIpSource {
    /// Resolves an address, rejecting malformed or ambiguous trusted headers.
    ///
    /// # Errors
    /// Returns a safe request error for missing or invalid forwarded addresses.
    fn resolve(self, headers: &HeaderMap, peer: SocketAddr) -> Result<IpAddr> {
        if matches!(self, Self::Socket) {
            return Ok(peer.ip().to_canonical());
        }
        let invalid =
            || AppError::request(StatusCode::BAD_REQUEST, "invalid forwarded client address");
        let mut headers = headers.get_all(FORWARDED_FOR).iter();
        let value = headers.next().ok_or_else(invalid)?;
        if headers.next().is_some() {
            return Err(invalid());
        }
        let value = value.to_str().map_err(|_| invalid())?;
        let mut client = None;
        for hop in value.split(',') {
            client = Some(hop.trim().parse::<IpAddr>().map_err(|_| invalid())?);
        }
        client.map(|ip| ip.to_canonical()).ok_or_else(invalid)
    }
}

/// Extracts signed cookies after rejecting ambiguous protected cookie names.
///
/// Unrelated cookies cannot satisfy the caller's explicitly named credentials.
/// Percent decoding must not manufacture a browser-enforced cookie prefix.
///
/// # Errors
/// Returns a safe form error for malformed headers, aliases, or duplicates.
fn signed(headers: &HeaderMap, key: Key, names: &[&str]) -> Result<SignedCookieJar> {
    let mut seen = HashSet::new();
    for header in headers.get_all(COOKIE) {
        let raw = header.to_str().map_err(|_| invalid())?;
        for part in raw.split(';') {
            let Ok(decoded) = Cookie::parse_encoded(part) else {
                continue;
            };
            let Some(name) = names.iter().find(|name| **name == decoded.name()) else {
                continue;
            };
            let literal = Cookie::parse(part).map_err(|_| invalid())?;
            if literal.name() != *name || !seen.insert(*name) {
                return Err(invalid());
            }
        }
    }
    Ok(SignedCookieJar::from_headers(headers, key))
}

/// Maximum encoded body size for native authentication and settings forms.
const FORM_BODY_BYTES: usize = 256 * 1024;
/// Maximum size of either administrator form's verification token.
const CSRF_FIELD_BYTES: usize = 128;
/// Transport bound for ordinary nonsecret metadata fields.
const METADATA_FIELD_BYTES: usize = 1024;
const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;

/// Reads bounded scalar password/CSRF fields without ambiguous duplicates.
///
/// # Errors
/// Returns a safe request error for malformed, repeated, or oversized fields.
async fn read(request: Request) -> Result<HashMap<&'static str, String>> {
    read_fields(
        request,
        &[
            ("password", *PASSWORD_BYTES.end()),
            ("csrf_token", CSRF_FIELD_BYTES),
        ],
    )
    .await
}

/// Reads an explicit scalar field whitelist from the complete capped body.
///
/// # Errors
/// Rejects unknown, duplicate, file, oversized, or non-UTF-8 fields.
async fn read_fields(
    request: Request,
    allowed: &[(&'static str, usize)],
) -> Result<HashMap<&'static str, String>> {
    let (mut multipart, _) = buffered_multipart(request).await?;
    let mut fields = HashMap::new();
    while let Some(mut field) = multipart.next_field().await.map_err(multipart_error)? {
        let &(name, limit) = allowed
            .iter()
            .find(|(name, _)| Some(*name) == field.name())
            .ok_or_else(invalid)?;
        if field.file_name().is_some() || fields.contains_key(name) {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = field.chunk().await.map_err(multipart_error)? {
            if bytes.len().saturating_add(chunk.len()) > limit {
                return Err(AppError::request(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "form field is too large",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        fields.insert(name, String::from_utf8(bytes).map_err(|_| invalid())?);
    }
    Ok(fields)
}

/// Checks the complete encoded body before parsing its multipart fields.
///
/// The caller must install its route's `DefaultBodyLimit` before extraction.
/// Reading through EOF counts epilogues even when the parser would stop early.
///
/// # Errors
/// Returns safe request errors for malformed or oversized complete bodies.
async fn buffered_multipart(request: Request) -> Result<(Multipart, usize)> {
    let (parts, body) = request.into_parts();
    let encoded = Bytes::from_request(Request::from_parts(parts.clone(), body), &())
        .await
        .map_err(|error| {
            let message = if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                "the upload exceeds the configured size limit"
            } else {
                "invalid form submission"
            };
            AppError::request(error.status(), message)
        })?;
    let length = encoded.len();
    let multipart = Multipart::from_request(Request::from_parts(parts, Body::from(encoded)), &())
        .await
        .map_err(|error| AppError::request(error.status(), "invalid form submission"))?;
    Ok((multipart, length))
}

/// Rejects supplied foreign origins in addition to mandatory CSRF checks.
///
/// TLS termination need not be inferred from forwarded headers: non-loopback
/// browser origins must use HTTPS. Localhost HTTP is allowed for browsers with
/// a native Secure-cookie exception. Absent Origin still needs a valid token.
///
/// # Errors
/// Returns a fixed rejection for foreign or ambiguous origins.
fn check_origin(headers: &HeaderMap) -> Result<()> {
    let mut values = headers.get_all(ORIGIN).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(forbidden());
    }
    let raw = value.to_str().map_err(|_| forbidden())?;
    let origin: Uri = raw.parse().map_err(|_| forbidden())?;
    let scheme = origin.scheme_str().ok_or_else(forbidden)?;
    let authority = origin.authority().ok_or_else(forbidden)?;
    if raw != format!("{scheme}://{authority}") {
        return Err(forbidden());
    }
    let host = Host::from_authority(authority.as_str()).ok_or_else(forbidden)?;
    let port = match scheme {
        "https" => HTTPS_PORT,
        "http" if host.is_loopback() => HTTP_PORT,
        _ => return Err(forbidden()),
    };
    let request_host = headers
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(forbidden)?;
    let expected = Host::from_authority(request_host).ok_or_else(forbidden)?;
    let request_authority: axum::http::uri::Authority =
        request_host.parse().map_err(|_| forbidden())?;
    if host != expected
        || authority.port_u16().unwrap_or(port) != request_authority.port_u16().unwrap_or(port)
    {
        return Err(forbidden());
    }
    Ok(())
}

/// Returns a fixed form-shape error without retaining submitted data.
fn invalid() -> AppError {
    AppError::request(StatusCode::BAD_REQUEST, "invalid form submission")
}

/// Returns a fixed CSRF error without revealing tokens or cookie contents.
fn forbidden() -> AppError {
    AppError::request(
        StatusCode::FORBIDDEN,
        "request could not be verified; reopen the sign-in page",
    )
}

/// Preserves multipart rejection status without exposing submitted content.
fn multipart_error(error: MultipartError) -> AppError {
    AppError::request(error.status(), "invalid form submission")
}
