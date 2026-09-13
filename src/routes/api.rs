//! Bearer-token JSON API on the admin host, sharing the native form readers.

use super::{publishing::PublishingState, settings, upload::PublishingForm};
use crate::{
    AppError, Result,
    auth::Password,
    sites::{AccessUpdate, DeleteOutcome, InputError, SettingsBuilder, Site, Slug},
};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{
        HeaderValue, StatusCode,
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, WWW_AUTHENTICATE,
            X_CONTENT_TYPE_OPTIONS,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

const ERROR_BODY_BYTES: usize = 64 * 1024;

/// Builds the token-gated API; every route is absent without a configured token.
pub(super) fn router(state: PublishingState, token: Option<String>) -> Router {
    Router::new()
        .route("/api/sites", get(list).post(create))
        .route(
            "/api/sites/{slug}",
            put(replace).patch(update).delete(delete),
        )
        .layer(DefaultBodyLimit::max(state.max_upload_bytes))
        .layer(middleware::from_fn_with_state(token, require_token))
        .layer(middleware::from_fn(json_errors))
        .with_state(state)
}

/// A site as the API reports it, with its share URL.
#[derive(Serialize)]
struct SiteJson {
    #[serde(flatten)]
    site: Site,
    url: String,
}

/// Partial settings; absent keys keep the current values.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Patch {
    title: Option<String>,
    entry: Option<String>,
    visibility: Option<String>,
    password: Option<String>,
    expires_in: Option<String>,
}

async fn list(State(state): State<PublishingState>) -> Result<Response> {
    let sites = state
        .sites
        .all()
        .await?
        .into_iter()
        .map(|site| present(site, &state.public_url))
        .collect::<Result<Vec<_>>>()?;
    respond(StatusCode::OK, &sites)
}

async fn create(State(state): State<PublishingState>, request: Request) -> Result<Response> {
    let mut form = read_form(request).await?;
    let slug = (!form.slug.is_empty())
        .then(|| Slug::parse(&form.slug))
        .transpose()?;
    let input = form.input(slug, state.max_upload_bytes)?;
    let password = password(&state, &mut form).await?;
    let site = state.sites.publish(input.with_password(password)).await?;
    respond(StatusCode::CREATED, &present(site, &state.public_url)?)
}

async fn replace(
    State(state): State<PublishingState>,
    Path(raw_slug): Path<String>,
    request: Request,
) -> Result<Response> {
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let mut form = read_form(request).await?;
    let input = form.input(None, state.max_upload_bytes)?;
    if !state.sites.replace(slug.clone(), input).await? {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    found(&state, &slug).await
}

async fn update(
    State(state): State<PublishingState>,
    Path(raw_slug): Path<String>,
    request: Request,
) -> Result<Response> {
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let bytes = to_bytes(request.into_body(), super::FORM_BODY_BYTES)
        .await
        .map_err(|_| AppError::request(StatusCode::PAYLOAD_TOO_LARGE, "JSON body is too large"))?;
    let patch: Patch = serde_json::from_slice(&bytes).map_err(|_| {
        AppError::request(
            StatusCode::BAD_REQUEST,
            "Send a JSON object with only title, entry, visibility, password, or expires_in.",
        )
    })?;
    let Some(current) = state.sites.get(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let visibility = patch.visibility.unwrap_or(current.visibility);
    let password = patch.password.unwrap_or_default();
    let access = settings::prepare(&state.auth, &visibility, password).await?;
    let input = SettingsBuilder::default()
        .title(patch.title.unwrap_or(current.title))
        .entry(patch.entry.unwrap_or(current.entry))
        .access(access)
        .expires_in(patch.expires_in.unwrap_or_else(|| "keep".to_owned()))
        .build()?;
    match state.sites.update(slug, input).await? {
        Some(details) => respond(StatusCode::OK, &present(details.site, &state.public_url)?),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

async fn delete(
    State(state): State<PublishingState>,
    Path(raw_slug): Path<String>,
) -> Result<Response> {
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    Ok(match state.sites.delete(slug).await? {
        DeleteOutcome::NotFound => StatusCode::NOT_FOUND,
        DeleteOutcome::Deleted | DeleteOutcome::DeletedContentRetained => StatusCode::NO_CONTENT,
    }
    .into_response())
}

/// Rejects every request without the exact configured bearer token.
async fn require_token(
    State(token): State<Option<String>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(token) = token else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let presented = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if presented.is_some_and(|presented| bool::from(presented.as_bytes().ct_eq(token.as_bytes()))) {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(WWW_AUTHENTICATE, "Bearer")],
        "missing or invalid bearer token",
    )
        .into_response()
}

/// Renders plain-text failures as JSON and marks every response uncacheable.
async fn json_errors(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if response.status().is_client_error() || response.status().is_server_error() {
        let (mut parts, body) = response.into_parts();
        let message = match to_bytes(body, ERROR_BODY_BYTES).await {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(_) => parts.status.to_string(),
        };
        parts.headers.remove(CONTENT_LENGTH);
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = serde_json::json!({ "error": message }).to_string();
        response = Response::from_parts(parts, Body::from(body));
    }
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    response
}

async fn read_form(request: Request) -> Result<PublishingForm> {
    let (multipart, encoded_length) = super::buffered_multipart(request).await?;
    PublishingForm::read(multipart, encoded_length).await
}

/// Prepares the final credential for a new site; keeping is impossible here.
async fn password(state: &PublishingState, form: &mut PublishingForm) -> Result<Option<Password>> {
    let password = std::mem::take(&mut form.password);
    match settings::prepare(&state.auth, form.visibility(), password).await? {
        AccessUpdate::Open => Ok(None),
        AccessUpdate::Set(password) => Ok(Some(password)),
        AccessUpdate::Keep => Err(InputError::Password.into()),
    }
}

async fn found(state: &PublishingState, slug: &Slug) -> Result<Response> {
    match state.sites.get(slug).await? {
        Some(site) => respond(StatusCode::OK, &present(site, &state.public_url)?),
        None => Ok(StatusCode::NOT_FOUND.into_response()),
    }
}

fn present(site: Site, public_url: &str) -> Result<SiteJson> {
    let slug = Slug::parse(&site.slug).map_err(AppError::publishing)?;
    Ok(SiteJson {
        url: format!("{public_url}/s/{}/", slug.as_str()),
        site,
    })
}

fn respond(status: StatusCode, value: &impl Serialize) -> Result<Response> {
    let body = serde_json::to_string(value).map_err(AppError::publishing)?;
    Ok((status, [(CONTENT_TYPE, "application/json")], body).into_response())
}
