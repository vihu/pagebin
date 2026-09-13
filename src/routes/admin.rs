//! Server-rendered admin authentication behind the shared host boundary.

use super::{ClientIpSource, view::ForbiddenPage};
use crate::{
    AppError, Result,
    auth::{Auth, CHALLENGE_LIFETIME, SESSION_LIFETIME},
    config::valid_password,
};
use askama::Template;
use axum::{
    Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode, Uri,
        header::{
            CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERER,
            REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
        },
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite, SignedCookieJar};
use std::{net::SocketAddr, sync::Arc, time::Duration};

const ADMIN_COOKIE: &str = "pb_admin";
const LOGIN_COOKIE: &str = "__Host-pb_login";
const THEME_COOKIE: &str = "pb_theme";
const THEME_LIFETIME: Duration = Duration::from_secs(365 * 24 * 60 * 60);
const THEME_FIELD_BYTES: usize = 16;
/// The default dark daisyUI theme name.
pub(super) const DARK_THEME: &str = "ledger";
const LIGHT_THEME: &str = "ledger-light";
const STYLESHEET: &str = include_str!("../../static/app.css");
const ADMIN_POLICY: &str = "default-src 'none'; style-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
const FONT_CACHE: &str = "public, max-age=31536000, immutable";
type AdminState = (Arc<Auth>, ClientIpSource);

/// Builds administrator routes with one shared response security policy.
pub(super) fn router(auth: Arc<Auth>, ip_source: ClientIpSource, publishing: Router) -> Router {
    Router::new()
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/theme", post(set_theme))
        .route(
            "/static/app.css",
            get(|| async { ([(CONTENT_TYPE, "text/css; charset=utf-8")], STYLESHEET) }),
        )
        .route("/static/admin.js", get(|| async { AdminScript::asset() }))
        .route(
            "/static/fonts/{name}",
            get(|Path(name): Path<String>| async move { font_response(&name) }),
        )
        .layer(DefaultBodyLimit::max(super::FORM_BODY_BYTES))
        .with_state((auth, ip_source))
        .merge(publishing)
        .layer(middleware::from_fn(finish_response))
}

async fn login_page(State((auth, _)): State<AdminState>, headers: HeaderMap) -> Result<Response> {
    let jar = cookies(&headers, &auth)?;
    if let Some(session) = jar.get(ADMIN_COOKIE)
        && auth.csrf(session.value())?.is_some()
    {
        return Ok(Redirect::to("/").into_response());
    }
    show_login(&auth, jar, StatusCode::OK, None, theme(&headers))
}

/// Checks the complete form and verification token before authenticating.
///
/// # Errors
/// Returns form, client-address, password, or template failures.
async fn login(
    State((auth, ip_source)): State<AdminState>,
    headers: HeaderMap,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
) -> Result<Response> {
    super::check_origin(&headers)?;
    let jar = cookies(&headers, &auth)?;
    let ip = ip_source.resolve(&headers, peer)?;
    let mut fields = super::read(request).await?;
    let csrf_token = fields.remove("csrf_token").ok_or_else(super::forbidden)?;
    let challenge = jar.get(LOGIN_COOKIE);
    if !auth.verify_challenge(challenge.as_ref().map(Cookie::value), &csrf_token) {
        return Err(super::forbidden());
    }
    let Some(password) = fields.remove("password").filter(|p| valid_password(p)) else {
        return show_login(
            &auth,
            jar,
            StatusCode::BAD_REQUEST,
            Some("Enter a valid admin password."),
            theme(&headers),
        );
    };
    let Some(session) = auth.login(ip, password).await? else {
        return show_login(
            &auth,
            jar,
            StatusCode::UNAUTHORIZED,
            Some("Incorrect password. Try again."),
            theme(&headers),
        );
    };
    Ok((
        jar.remove(cookie(LOGIN_COOKIE, String::new(), Duration::ZERO))
            .add(cookie(ADMIN_COOKIE, session, SESSION_LIFETIME)),
        Redirect::to("/"),
    )
        .into_response())
}

/// Revokes a session only after checking its complete form and token.
///
/// # Errors
/// Returns request or session-store failures without revoking unverified input.
async fn logout(
    State((auth, _)): State<AdminState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Response> {
    super::check_origin(&headers)?;
    let jar = cookies(&headers, &auth)?;
    let mut fields = super::read(request).await?;
    let csrf_token = fields.remove("csrf_token").ok_or_else(super::forbidden)?;
    if !fields.is_empty() {
        return Err(super::invalid());
    }
    let session = jar.get(ADMIN_COOKIE).ok_or_else(super::forbidden)?;
    if !auth.logout(session.value(), &csrf_token)? {
        return Err(super::forbidden());
    }
    Ok((
        jar.remove(cookie(ADMIN_COOKIE, String::new(), Duration::ZERO)),
        Redirect::to("/login"),
    )
        .into_response())
}

fn show_login(
    auth: &Auth,
    jar: SignedCookieJar,
    status: StatusCode,
    error_message: Option<&str>,
    theme: &'static str,
) -> Result<Response> {
    let existing = jar.get(LOGIN_COOKIE).filter(|cookie| {
        Auth::challenge_token(cookie.value())
            .is_some_and(|token| auth.verify_challenge(Some(cookie.value()), token))
    });
    let (jar, challenge) = if let Some(existing) = existing {
        (jar, existing.value().to_owned())
    } else {
        let challenge = auth.challenge()?;
        (
            jar.add(cookie(LOGIN_COOKIE, challenge.clone(), CHALLENGE_LIFETIME)),
            challenge,
        )
    };
    let csrf_token =
        Auth::challenge_token(&challenge).expect("issued or verified challenge has a token");
    let page = LoginPage {
        csrf_token,
        error_message,
        theme,
    }
    .render()
    .map_err(|source| AppError::authentication(source))?;
    Ok((status, jar, Html(page)).into_response())
}

fn cookie(name: &'static str, value: String, lifetime: Duration) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(
            lifetime
                .try_into()
                .expect("fixed lifetimes fit the cookie duration"),
        )
        .build()
}

/// Stores the chosen theme in a plain cookie and returns to the sending page.
///
/// # Errors
/// Returns origin or form validation failures.
async fn set_theme(headers: HeaderMap, request: Request) -> Result<Response> {
    super::check_origin(&headers)?;
    let mut fields = super::read_fields(request, &[("theme", THEME_FIELD_BYTES)]).await?;
    let choice = fields.remove("theme").ok_or_else(super::invalid)?;
    if ![DARK_THEME, LIGHT_THEME].contains(&choice.as_str()) {
        return Err(super::invalid());
    }
    let back = headers
        .get(REFERER)
        .and_then(|value| value.to_str().ok()?.parse::<Uri>().ok())
        .and_then(|uri| uri.path_and_query().map(|path| path.as_str().to_owned()))
        .filter(|path| path.starts_with('/') && !path.starts_with("//"))
        .unwrap_or_else(|| "/".to_owned());
    let jar = CookieJar::new().add(cookie(THEME_COOKIE, choice, THEME_LIFETIME));
    Ok((jar, Redirect::to(&back)).into_response())
}

/// Reads the stored theme choice, defaulting to dark.
pub(super) fn theme(headers: &HeaderMap) -> &'static str {
    match CookieJar::from_headers(headers)
        .get(THEME_COOKIE)
        .map(Cookie::value)
    {
        Some(LIGHT_THEME) => LIGHT_THEME,
        _ => DARK_THEME,
    }
}

/// Resolves a signature-verified live session and its independent form token.
///
/// # Errors
/// Returns an error for ambiguous cookies or an unavailable session store.
pub(super) fn session(headers: &HeaderMap, auth: &Auth) -> Result<Option<(String, String)>> {
    let jar = cookies(headers, auth)?;
    let Some(cookie) = jar.get(ADMIN_COOKIE) else {
        return Ok(None);
    };
    Ok(auth
        .csrf(cookie.value())?
        .map(|csrf| (cookie.value().to_owned(), csrf)))
}

fn cookies(headers: &HeaderMap, auth: &Auth) -> Result<SignedCookieJar> {
    super::signed(headers, auth.key(), &[ADMIN_COOKIE, LOGIN_COOKIE])
}

async fn finish_response(request: Request, next: Next) -> Response {
    let theme = theme(request.headers());
    let mut response = next.run(request).await;
    if response.status() == StatusCode::FORBIDDEN {
        // Present the rejection without changing status, cookies, or session state.
        match (ForbiddenPage { theme }).render() {
            Ok(page) => {
                *response.body_mut() = Body::from(page);
                response.headers_mut().remove(CONTENT_LENGTH);
                response.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("text/html; charset=utf-8"),
                );
            }
            Err(source) => {
                tracing::error!(error = %AppError::authentication(source), "recovery page rendering failed")
            }
        }
    }
    let policy =
        if response.status().is_success() && response.extensions().get::<AdminScript>().is_some() {
            HeaderValue::from_str(&format!("{ADMIN_POLICY}; script-src 'self'"))
                .expect("the fixed admin policy contains only valid header characters")
        } else {
            HeaderValue::from_static(ADMIN_POLICY)
        };
    let headers = response.headers_mut();
    headers
        .entry(CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("private, no-store"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    // no-referrer serializes native form POST origins as null in browsers.
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    headers.insert(CONTENT_SECURITY_POLICY, policy);
    response
}

/// Serves one embedded Atkinson Hyperlegible face, or 404 for any other name.
pub(super) fn font_response(name: &str) -> Response {
    let bytes: &'static [u8] = match name {
        "AtkinsonHyperlegibleNext-Regular.woff2" => {
            include_bytes!("../../static/fonts/AtkinsonHyperlegibleNext-Regular.woff2")
        }
        "AtkinsonHyperlegibleNext-SemiBold.woff2" => {
            include_bytes!("../../static/fonts/AtkinsonHyperlegibleNext-SemiBold.woff2")
        }
        "AtkinsonHyperlegibleNext-Bold.woff2" => {
            include_bytes!("../../static/fonts/AtkinsonHyperlegibleNext-Bold.woff2")
        }
        "AtkinsonHyperlegibleMono-Regular.woff2" => {
            include_bytes!("../../static/fonts/AtkinsonHyperlegibleMono-Regular.woff2")
        }
        "AtkinsonHyperlegibleMono-Medium.woff2" => {
            include_bytes!("../../static/fonts/AtkinsonHyperlegibleMono-Medium.woff2")
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [(CONTENT_TYPE, "font/woff2"), (CACHE_CONTROL, FONT_CACHE)],
        bytes,
    )
        .into_response()
}

/// Renders a login form without retaining or echoing its submitted password.
#[derive(Template)]
#[template(path = "login.html")]
pub(super) struct LoginPage<'a> {
    /// The stored admin theme choice for this browser.
    pub(super) theme: &'static str,
    /// The current browser-bound pre-login CSRF token.
    pub(super) csrf_token: &'a str,
    /// Fixed, non-sensitive feedback for a failed submission.
    pub(super) error_message: Option<&'a str>,
}

/// Marks only rendered pages that include the trusted admin script.
#[derive(Clone, Copy)]
pub(super) struct AdminScript;

impl AdminScript {
    /// Serves the embedded script without filesystem or outbound access.
    pub(super) const fn asset() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
        (
            [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
            include_str!("../../static/admin.js"),
        )
    }

    /// Enables the script permission for a rendered admin response.
    pub(super) fn allow(mut response: Response) -> Response {
        response.extensions_mut().insert(Self);
        response
    }
}
