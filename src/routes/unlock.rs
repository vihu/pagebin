//! Native viewer unlock with independent CSRF and generation-bound grants.

use super::{
    admin, settings,
    view::{self, ViewerState, ViewerUi},
};
use crate::{
    AppError, Result,
    auth::{Auth, Password, VIEWER_CHALLENGE_LIFETIME, VIEWER_GRANT_LIFETIME},
    config::valid_password,
    sites::Slug,
};
use askama::Template;
use axum::{
    Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use axum_extra::extract::cookie::{Cookie, SignedCookieJar};
use std::{net::SocketAddr, time::Duration};

/// Builds only the reserved unlock UI and trusted stylesheet endpoints.
pub(super) fn router(state: ViewerState) -> Router {
    Router::new()
        .route("/s/{slug}/__unlock", get(page).post(submit))
        .route("/s/{slug}/__unlock/app.css", get(stylesheet))
        .route("/s/{slug}/__unlock/fonts/{name}", get(font))
        .route("/s/{slug}/__unlock/favicon.png", get(favicon))
        .layer(DefaultBodyLimit::max(super::FORM_BODY_BYTES))
        .with_state(state)
}

/// Returns a local unlock location without a client-controlled target.
pub(super) fn redirect(slug: &Slug) -> Response {
    Redirect::to(&format!("/s/{}/__unlock", slug.as_str())).into_response()
}

/// Opens a native challenge only for a known, unexpired protected site.
///
/// # Errors
/// Returns safe storage, clock, cookie, or rendering failures.
async fn page(
    State(state): State<ViewerState>,
    Path(raw_slug): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(access) = state.sites.access(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !view::available(&access.site)? {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let Some(password) = access.password else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let jar = view::read(&headers, &state.auth, &slug)?;
    let grant = jar.get(&view::grant_name(&slug));
    if state
        .auth
        .verify_viewer_grant(grant.as_ref().map(Cookie::value), &slug, &password)
    {
        return Ok(Redirect::to(&format!("/s/{}/", slug.as_str())).into_response());
    }
    show(&state.auth, jar, &slug, StatusCode::OK, None, None)
}

/// Serves embedded styles without consulting the uploaded site directory.
///
/// # Errors
/// Serves the embedded stylesheet only for a live password site.
async fn stylesheet(
    State(state): State<ViewerState>,
    Path(raw_slug): Path<String>,
) -> Result<Response> {
    let stylesheet = (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../../static/app.css"),
    );
    asset(&state, &raw_slug, stylesheet.into_response()).await
}

/// Serves one embedded font only for a live password site.
async fn font(
    State(state): State<ViewerState>,
    Path((raw_slug, name)): Path<(String, String)>,
) -> Result<Response> {
    asset(&state, &raw_slug, admin::font_response(&name)).await
}

/// Serves the embedded favicon only for a live password site.
async fn favicon(
    State(state): State<ViewerState>,
    Path(raw_slug): Path<String>,
) -> Result<Response> {
    asset(&state, &raw_slug, admin::favicon_response()).await
}

/// Gates a trusted asset behind the same checks as the unlock page.
async fn asset(state: &ViewerState, raw_slug: &str, response: Response) -> Result<Response> {
    let Ok(slug) = Slug::parse(raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(access) = state.sites.access(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !view::available(&access.site)? || access.password.is_none() {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    Ok(ViewerUi::mark(response))
}

/// Verifies the complete native form before checking a bounded password job.
///
/// # Errors
/// Returns safe database, clock, cookie, or rendering failures.
async fn submit(
    State(state): State<ViewerState>,
    Path(raw_slug): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response> {
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(access) = state.sites.access(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !view::available(&access.site)? {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    let Some(password) = access.password else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if super::check_origin(request.headers()).is_err() {
        return show(
            &state.auth,
            SignedCookieJar::new(state.auth.key()),
            &slug,
            StatusCode::FORBIDDEN,
            Some("Request could not be verified. Reopen the unlock form."),
            None,
        );
    }
    let jar = view::read(request.headers(), &state.auth, &slug)?;
    let ip = state.ip_source.resolve(request.headers(), peer)?;
    let mut fields = match super::read(request).await {
        Ok(fields) => fields,
        Err(error) => return failure(&state.auth, jar, &slug, error),
    };
    let csrf = fields.remove("csrf_token").unwrap_or_default();
    let challenge = jar.get(&view::challenge_name(&slug));
    if !state
        .auth
        .verify_viewer_challenge(challenge.as_ref().map(Cookie::value), &slug, &csrf)
    {
        return show(
            &state.auth,
            jar,
            &slug,
            StatusCode::FORBIDDEN,
            Some("Request could not be verified. Reopen the unlock form."),
            None,
        );
    }
    let submitted = fields.remove("password").unwrap_or_default();
    if !valid_password(&submitted) {
        return show(
            &state.auth,
            jar,
            &slug,
            StatusCode::BAD_REQUEST,
            Some("Enter a valid site password."),
            Some("password"),
        );
    }
    let accepted = match state
        .auth
        .verify_site_password(ip, password.clone(), submitted)
        .await
    {
        Ok(accepted) => accepted,
        Err(error) => return failure(&state.auth, jar, &slug, error),
    };
    if !accepted {
        return show(
            &state.auth,
            jar,
            &slug,
            StatusCode::UNAUTHORIZED,
            Some("Incorrect password. Try again."),
            Some("password"),
        );
    }
    complete(&state, slug, password, jar).await
}

/// Rechecks current access after verification before issuing its exact grant.
///
/// # Errors
/// Returns safe storage, clock, cookie-generation, or rendering failures.
async fn complete(
    state: &ViewerState,
    slug: Slug,
    password: Password,
    jar: SignedCookieJar,
) -> Result<Response> {
    // The grant can refer only to the generation actually verified above.
    let Some(current) = state.sites.access(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    if !view::available(&current.site)? {
        return Ok(StatusCode::NOT_FOUND.into_response());
    }
    if !current
        .password
        .as_ref()
        .is_some_and(|current| password.same_generation(current))
    {
        return show(
            &state.auth,
            jar,
            &slug,
            StatusCode::CONFLICT,
            Some("Site access changed. Reopen the unlock form before retrying."),
            None,
        );
    }
    let payload = state.auth.viewer_grant(&slug, &password)?;
    let jar = jar
        .remove(view::cookie(
            view::challenge_name(&slug),
            String::new(),
            &slug,
            Duration::ZERO,
        ))
        .add(view::cookie(
            view::grant_name(&slug),
            payload,
            &slug,
            VIEWER_GRANT_LIFETIME,
        ));
    Ok((jar, Redirect::to(&format!("/s/{}/", slug.as_str()))).into_response())
}

/// Renders a fresh or reusable slug-bound challenge without password retention.
///
/// # Errors
/// Returns safe entropy, clock, or template failures.
fn show(
    auth: &Auth,
    jar: SignedCookieJar,
    slug: &Slug,
    status: StatusCode,
    message: Option<&str>,
    invalid_field: Option<&str>,
) -> Result<Response> {
    let name = view::challenge_name(slug);
    let existing = jar.get(&name).filter(|cookie| {
        Auth::viewer_challenge_token(cookie.value(), slug)
            .is_some_and(|token| auth.verify_viewer_challenge(Some(cookie.value()), slug, token))
    });
    let (jar, payload) = if let Some(existing) = existing {
        (jar, existing.value().to_owned())
    } else {
        let payload = auth.viewer_challenge(slug)?;
        let jar = jar.add(view::cookie(
            name,
            payload.clone(),
            slug,
            VIEWER_CHALLENGE_LIFETIME,
        ));
        (jar, payload)
    };
    let token = Auth::viewer_challenge_token(&payload, slug)
        .expect("issued or verified viewer challenge has a token");
    let body = UnlockPage {
        slug: slug.as_str(),
        csrf_token: token,
        error_message: message,
        invalid_password: invalid_field == Some("password"),
        theme: admin::DARK_THEME,
    }
    .render()
    .map_err(AppError::authentication)?;
    Ok(ViewerUi::mark((status, jar, Html(body)).into_response()))
}

/// Presents safe request recovery without retaining a submitted password.
///
/// # Errors
/// Returns safe challenge generation or rendering failures.
fn failure(auth: &Auth, jar: SignedCookieJar, slug: &Slug, error: AppError) -> Result<Response> {
    let (status, message) = settings::feedback(error);
    let message = if status.is_server_error() {
        "Unlock could not be completed. Reopen the form and try again."
    } else if status == StatusCode::PAYLOAD_TOO_LARGE {
        "The unlock request or password is too large. Reopen the form and use a shorter password."
    } else {
        &message
    };
    show(auth, jar, slug, status, Some(message), None)
}

/// Renders trusted viewer authentication without private site metadata.
#[derive(Template)]
#[template(path = "unlock.html")]
pub(super) struct UnlockPage<'a> {
    /// The stored admin theme choice for this browser.
    pub(super) theme: &'static str,
    /// The validated requested slug used for the form and trusted stylesheet.
    pub(super) slug: &'a str,
    /// The independent, slug-bound unlock challenge token.
    pub(super) csrf_token: &'a str,
    /// Safe feedback explaining the problem and how to continue.
    pub(super) error_message: Option<&'a str>,
    /// Whether existing feedback belongs to the empty password field.
    pub(super) invalid_password: bool,
}
