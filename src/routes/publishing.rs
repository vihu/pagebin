//! Authenticated native creation with final access chosen before publication.

use super::{
    admin, management, settings,
    upload::{Input, PublishingForm},
};
use crate::{
    AppError, Result,
    auth::Auth,
    sites::{AccessUpdate, InputError, MAX_SITE_FILES, Sites, Slug},
};
use askama::Template;
use axum::{
    Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use std::sync::Arc;

const BYTES_PER_MIB: usize = 1024 * 1024;

/// Builds only the publishing routes; the caller applies admin response policy.
pub(super) fn router(state: PublishingState) -> Router {
    Router::new()
        .route("/new", get(new_site))
        .route("/sites", post(create))
        .route("/sites/{slug}/content", post(replace))
        .layer(DefaultBodyLimit::max(state.max_upload_bytes))
        .with_state(state)
}

/// Renders a blank form for a live administrator session.
///
/// # Errors
/// Returns cookie/session validation or template failures.
async fn new_site(
    State(state): State<PublishingState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response> {
    let Some((_, csrf_token)) = admin::session(&headers, &state.auth)? else {
        return Ok(Redirect::to("/login").into_response());
    };
    show_form(
        StatusCode::OK,
        &csrf_token,
        &PublishingForm::for_query(uri.query())?,
        None,
        None,
        admin::theme(&headers),
    )
}

/// Publishes one verified-origin upload for a live administrator session.
///
/// # Errors
/// Returns request validation, session, publication, or template failures.
async fn create(State(state): State<PublishingState>, request: Request) -> Result<Response> {
    super::check_origin(request.headers())?;
    let theme = admin::theme(request.headers());
    let Some((session_id, csrf_token)) = admin::session(request.headers(), &state.auth)? else {
        return Err(super::forbidden());
    };
    let blank = PublishingForm::for_query(request.uri().query())?;
    let (multipart, encoded_length) = match super::buffered_multipart(request).await {
        Ok(buffered) => buffered,
        Err(error) => {
            let message = error.to_string();
            let status = error.into_response().status();
            let message = if status == StatusCode::PAYLOAD_TOO_LARGE {
                let limit = state.max_upload_bytes / BYTES_PER_MIB;
                if blank.input != Input::Html {
                    format!(
                        "The request limit is {limit} MiB, including multipart overhead. Choose fewer or smaller files and select them again. The oversized form was not kept."
                    )
                } else {
                    format!(
                        "The request limit is {limit} MiB, including multipart overhead. Reduce the HTML and paste it again. The oversized form was not kept."
                    )
                }
            } else {
                message
            };
            return show_form(status, &csrf_token, &blank, Some(&message), None, theme);
        }
    };
    let mut submitted = match PublishingForm::read(multipart, encoded_length).await {
        Ok(submitted) => submitted,
        Err(error) => return reject(error, &csrf_token, &blank, None, theme),
    };
    if !state.auth.verify_form(&session_id, &submitted.csrf_token)? {
        return Err(super::forbidden());
    }
    let slug = if submitted.slug.is_empty() {
        None
    } else {
        match Slug::parse(&submitted.slug) {
            Ok(slug) => Some(slug),
            Err(error) => return reject(error, &csrf_token, &submitted, Some("slug"), theme),
        }
    };
    let input = match submitted.input(slug, state.max_upload_bytes) {
        Ok(input) => input,
        Err(error) => {
            return show_form(
                StatusCode::BAD_REQUEST,
                &csrf_token,
                &submitted,
                Some(&error.to_string()),
                Some(error.field()),
                theme,
            );
        }
    };
    let password = std::mem::take(&mut submitted.password);
    let access = match settings::prepare(&state.auth, submitted.visibility(), password).await {
        Ok(access) => access,
        Err(error) => {
            let (status, message) = settings::feedback(error);
            return show_form(
                status,
                &csrf_token,
                &submitted,
                Some(if status.is_server_error() {
                    "Password protection could not be prepared. Try again."
                } else {
                    &message
                }),
                Some(settings::field(submitted.visibility())),
                theme,
            );
        }
    };
    let password = match access {
        AccessUpdate::Open => None,
        AccessUpdate::Set(password) => Some(password),
        AccessUpdate::Keep => {
            return reject(
                InputError::Password.into(),
                &csrf_token,
                &submitted,
                Some("password"),
                theme,
            );
        }
    };
    // A queued password operation must not authorize a newly revoked session.
    if !state.auth.verify_form(&session_id, &submitted.csrf_token)? {
        return Err(super::forbidden());
    }
    match state.sites.publish(input.with_password(password)).await {
        Ok(site) => Ok(Redirect::to(&format!("/sites/{}", site.slug)).into_response()),
        Err(error) => reject(error, &csrf_token, &submitted, Some("slug"), theme),
    }
}

/// Renders escaped submitted values and safe correction feedback.
///
/// # Errors
/// Returns a safe template-rendering failure.
fn show_form(
    status: StatusCode,
    csrf_token: &str,
    submitted: &PublishingForm,
    error_message: Option<&str>,
    invalid_field: Option<&str>,
    theme: &'static str,
) -> Result<Response> {
    let body = NewPage {
        csrf_token,
        html: &submitted.html,
        title: &submitted.title,
        slug: &submitted.slug,
        entry: &submitted.entry,
        input: submitted.input.as_str(),
        visibility: submitted.visibility(),
        expires_in: &submitted.expires_in,
        error_message,
        invalid_field,
        theme,
    }
    .render()
    .map_err(AppError::publishing)?;
    Ok((status, Html(body)).into_response())
}

/// Presents correctable failures without exposing operational details.
///
/// # Errors
/// Returns a safe template-rendering failure.
fn reject(
    error: AppError,
    csrf_token: &str,
    submitted: &PublishingForm,
    invalid_field: Option<&str>,
    theme: &'static str,
) -> Result<Response> {
    let message = error.to_string();
    let response = error.into_response();
    let status = response.status();
    if status == StatusCode::FORBIDDEN {
        return Ok(response);
    }
    if status.is_server_error() {
        return show_form(
            status,
            csrf_token,
            submitted,
            Some("Publication could not be confirmed. Your existing sites were not changed."),
            None,
            theme,
        );
    }
    show_form(
        status,
        csrf_token,
        submitted,
        Some(&message),
        invalid_field,
        theme,
    )
}

/// Boot-validated services and settings used by the publishing handlers.
#[derive(Clone)]
pub(super) struct PublishingState {
    /// The same authentication instance used by login and logout.
    pub(super) auth: Arc<Auth>,
    /// The shared site store using the boot-initialized database pool.
    pub(super) sites: Arc<Sites>,
    /// The validated public origin without a trailing slash.
    pub(super) public_url: String,
    /// Maximum encoded multipart bytes, including multipart framing.
    pub(super) max_upload_bytes: usize,
}

impl PublishingState {
    /// Combines shared services with settings validated by the config builder.
    pub(super) fn new(
        auth: Arc<Auth>,
        sites: Arc<Sites>,
        public_url: String,
        max_upload_bytes: usize,
    ) -> Self {
        Self {
            auth,
            sites,
            public_url,
            max_upload_bytes,
        }
    }
}

/// Renders one native publishing mode with optional correctable feedback.
#[derive(Template)]
#[template(path = "new.html")]
pub(super) struct NewPage<'a> {
    /// The stored admin theme choice for this browser.
    pub(super) theme: &'static str,
    /// A CSRF token bound to the current authenticated session.
    pub(super) csrf_token: &'a str,
    /// Bounded submitted HTML, escaped inside the native textarea.
    pub(super) html: &'a str,
    /// The bounded submitted title, or an empty string for no title.
    pub(super) title: &'a str,
    /// The bounded submitted custom slug, or an empty string to generate one.
    pub(super) slug: &'a str,
    /// The bounded entry filename, or an empty string for automatic selection.
    pub(super) entry: &'a str,
    /// The submitted access mode; unsupported values select neither choice.
    pub(super) visibility: &'a str,
    /// The submitted expiry choice; unsupported values select `never`.
    pub(super) expires_in: &'a str,
    /// The content tab to render: `html`, `files`, or `zip`.
    pub(super) input: &'a str,
    /// Safe feedback explaining the problem and how to continue.
    pub(super) error_message: Option<&'a str>,
    /// The invalid field, including `visibility` and `password`.
    pub(super) invalid_field: Option<&'a str>,
}

impl NewPage<'_> {
    /// Shows the same file-count limit enforced by parsing and storage.
    const fn max_site_files(&self) -> usize {
        MAX_SITE_FILES
    }

    /// Shows general feedback when its field is absent from this mode.
    fn general_error(&self) -> bool {
        match self.invalid_field {
            Some("title" | "slug" | "visibility" | "password" | "expires_in") => false,
            Some("html") => self.input != "html",
            Some("files") => self.input != "files",
            Some("zip") => self.input != "zip",
            Some("entry") => self.input == "html",
            _ => true,
        }
    }
}

/// Replaces content in place, keeping the slug, title, access, and expiry.
///
/// # Errors
/// Returns origin, session, upload, or replacement failures.
async fn replace(
    State(state): State<PublishingState>,
    Path(raw_slug): Path<String>,
    request: Request,
) -> Result<Response> {
    super::check_origin(request.headers())?;
    let theme = admin::theme(request.headers());
    let Some((session_id, csrf_token)) = admin::session(request.headers(), &state.auth)? else {
        return Err(super::forbidden());
    };
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(record) = state.sites.details(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let site = management::present(record, &state.public_url)?;
    let tab = Input::parse(request.uri().query())?.as_str();
    let fail = |error: AppError, field: &str| {
        let (status, message) = settings::feedback(error);
        if status == StatusCode::FORBIDDEN {
            return Err(super::forbidden());
        }
        let message = if status.is_server_error() {
            "Replacement could not be confirmed. The existing content was kept."
        } else {
            &message
        };
        let blank = settings::SettingsForm::from_site(&site);
        let feedback = settings::Feedback::Error {
            message,
            field: Some(field),
        };
        settings::show(status, &csrf_token, &site, &blank, feedback, tab, theme)
    };
    let (multipart, encoded_length) = match super::buffered_multipart(request).await {
        Ok(buffered) => buffered,
        Err(error) => return fail(error, "replace"),
    };
    let mut submitted = match PublishingForm::read(multipart, encoded_length).await {
        Ok(submitted) => submitted,
        Err(error) => return fail(error, "replace"),
    };
    if !state.auth.verify_form(&session_id, &submitted.csrf_token)? {
        return Err(super::forbidden());
    }
    let input = match submitted.input(None, state.max_upload_bytes) {
        Ok(input) => input,
        Err(error) => {
            let field = format!("replace-{}", error.field());
            return fail(error.into(), &field);
        }
    };
    match state.sites.replace(slug, input).await {
        Ok(true) => {
            Ok(Redirect::to(&format!("/sites/{}?notice=replaced", site.slug)).into_response())
        }
        Ok(false) => Ok(StatusCode::NOT_FOUND.into_response()),
        Err(error) => fail(error, "replace"),
    }
}
