//! Verified metadata updates and truthful native detail recovery.

use super::{
    admin::{self, AdminScript},
    management::{self, AdminSite},
    publishing::PublishingState,
};
use crate::{
    AppError, Result,
    auth::Auth,
    config::PASSWORD_BYTES,
    sites::{AccessUpdate, InputError, MAX_SITE_FILES, SettingsBuilder, Slug},
};
use askama::Template;
use axum::{
    extract::{Path, Request, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};

/// Applies a complete, live-session-verified settings form to the current slug.
///
/// # Errors
/// Returns safe session, database, or rendering failures without hash exposure.
pub(super) async fn update(
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
    let mut submitted = match SettingsForm::read(request).await {
        Ok(submitted) => submitted,
        Err(error) => {
            return reject(
                error,
                &csrf_token,
                &site,
                &SettingsForm::from_site(&site),
                theme,
            );
        }
    };
    if !state.auth.verify_form(&session_id, &submitted.csrf_token)? {
        return Err(super::forbidden());
    }
    let password = std::mem::take(&mut submitted.password);
    let access = match prepare(&state.auth, &submitted.visibility, password).await {
        Ok(access) => access,
        Err(error) => {
            let (status, message) = feedback(error);
            return show(
                status,
                &csrf_token,
                &site,
                &submitted,
                Feedback::Error {
                    message: if status.is_server_error() {
                        "Password protection could not be prepared. Try again."
                    } else {
                        &message
                    },
                    field: Some(field(&submitted.visibility)),
                },
                "html",
                theme,
            );
        }
    };
    let input = match SettingsBuilder::default()
        .title(submitted.title.clone())
        .entry(submitted.entry.clone())
        .expires_in(submitted.expires_in.clone())
        .access(access)
        .build()
    {
        Ok(input) => input,
        Err(error) => {
            return show(
                StatusCode::BAD_REQUEST,
                &csrf_token,
                &site,
                &submitted,
                Feedback::Error {
                    message: &error.to_string(),
                    field: Some(error.field()),
                },
                "html",
                theme,
            );
        }
    };
    if !state.auth.verify_form(&session_id, &submitted.csrf_token)? {
        return Err(super::forbidden());
    }
    match state.sites.update(slug, input).await {
        Ok(Some(_)) => {
            Ok(Redirect::to(&format!("/sites/{}?notice=saved", site.slug)).into_response())
        }
        Ok(None) => Ok(StatusCode::NOT_FOUND.into_response()),
        Err(error) => reject(error, &csrf_token, &site, &submitted, theme),
    }
}

/// Feedback rendered on the detail page: an outcome notice or a rejection.
#[derive(Clone, Copy)]
pub(super) enum Feedback<'a> {
    /// Nothing to report.
    None,
    /// A fixed, safe parent-supplied outcome message.
    Notice(&'a str),
    /// Safe rejection text and the field it belongs to, if any.
    Error {
        /// Safe rejection text.
        message: &'a str,
        /// The rejected field, or `None` for general feedback.
        field: Option<&'a str>,
    },
}

/// Renders persisted metadata separately from uncommitted editable values.
///
/// # Errors
/// Returns a safe rendering failure.
pub(super) fn show(
    status: StatusCode,
    csrf_token: &str,
    site: &AdminSite,
    submitted: &SettingsForm,
    feedback: Feedback<'_>,
    input: &'static str,
    theme: &'static str,
) -> Result<Response> {
    let body = SitePage {
        csrf_token,
        title: &site.title,
        url: &site.url,
        slug: &site.slug,
        file_count: site.file_count,
        size_bytes: site.size_bytes,
        visibility: &site.visibility,
        entry: &site.entry,
        created: &site.created,
        expires: &site.expires,
        settings_title: &submitted.title,
        settings_entry: &submitted.entry,
        settings_visibility: &submitted.visibility,
        settings_expires_in: &submitted.expires_in,
        settings_error_message: match feedback {
            Feedback::Error { message, .. } => Some(message),
            _ => None,
        },
        settings_invalid_field: match feedback {
            Feedback::Error { field, .. } => field,
            _ => None,
        },
        notice: match feedback {
            Feedback::Notice(notice) => Some(notice),
            _ => None,
        },
        replace_input: input,
        theme,
    }
    .render()
    .map_err(AppError::publishing)?;
    Ok(AdminScript::allow((status, Html(body)).into_response()))
}

/// Keeps HTTP status and nonsecret text while acknowledging uncertain outcomes.
///
/// # Errors
/// Returns a safe rendering failure.
fn reject(
    error: AppError,
    csrf_token: &str,
    site: &AdminSite,
    submitted: &SettingsForm,
    theme: &'static str,
) -> Result<Response> {
    let (status, message) = feedback(error);
    if status == StatusCode::FORBIDDEN {
        return Err(super::forbidden());
    }
    let message = if status.is_server_error() {
        "Settings could not be confirmed. Reopen this site's details before retrying."
    } else {
        &message
    };
    show(
        status,
        csrf_token,
        site,
        submitted,
        Feedback::Error {
            message,
            field: None,
        },
        "html",
        theme,
    )
}

/// Untrusted metadata and transient password input awaiting validation.
pub(super) struct SettingsForm {
    /// The untrusted session-bound verification token.
    pub(super) csrf_token: String,
    /// The proposed display title, never the persisted detail heading.
    pub(super) title: String,
    /// The proposed existing flat entry filename.
    pub(super) entry: String,
    /// The explicit untrusted access choice.
    pub(super) visibility: String,
    /// Transient plaintext, never passed into presentation data.
    pub(super) password: String,
    /// The untrusted expiry choice; `keep` retains the current expiry.
    pub(super) expires_in: String,
}

impl SettingsForm {
    /// Initializes editable fields from current metadata without a password.
    pub(super) fn from_site(site: &AdminSite) -> Self {
        Self {
            csrf_token: String::new(),
            title: site.title.clone(),
            entry: site.entry.clone(),
            visibility: site.visibility.clone(),
            password: String::new(),
            expires_in: if site.expires == "Never" {
                "never"
            } else {
                "keep"
            }
            .to_owned(),
        }
    }

    /// Reads exactly the settings fields through the complete-body boundary.
    ///
    /// # Errors
    /// Rejects invalid fields, ambiguous forms, missing metadata or CSRF,
    /// excessive input, and malformed encodings without changing settings.
    pub(super) async fn read(request: Request) -> Result<Self> {
        let mut fields = super::read_fields(
            request,
            &[
                ("csrf_token", super::CSRF_FIELD_BYTES),
                ("title", super::METADATA_FIELD_BYTES),
                ("entry", super::METADATA_FIELD_BYTES),
                ("visibility", super::METADATA_FIELD_BYTES),
                ("password", *PASSWORD_BYTES.end()),
                ("expires_in", super::METADATA_FIELD_BYTES),
            ],
        )
        .await?;
        Ok(Self {
            csrf_token: fields.remove("csrf_token").ok_or_else(super::forbidden)?,
            title: fields.remove("title").ok_or_else(super::invalid)?,
            entry: fields.remove("entry").ok_or_else(super::invalid)?,
            visibility: fields.remove("visibility").ok_or_else(super::invalid)?,
            password: fields.remove("password").unwrap_or_default(),
            expires_in: fields
                .remove("expires_in")
                .unwrap_or_else(|| "keep".to_owned()),
        })
    }
}

/// Prepares explicit access intent without deciding against a stale site row.
///
/// Creation must reject `Keep`; settings resolve it under the mutation lock.
/// The caller must authenticate and verify the complete form before hashing.
///
/// # Errors
/// Rejects invalid access or passwords, and exhausted or failed workers.
pub(super) async fn prepare(
    auth: &Auth,
    visibility: &str,
    password: String,
) -> Result<AccessUpdate> {
    match (visibility, password.is_empty()) {
        ("open", true) => Ok(AccessUpdate::Open),
        ("open", false) => Err(AppError::request(
            StatusCode::BAD_REQUEST,
            "Choose Password access to set a password, or clear the password field.",
        )),
        ("password", true) => Ok(AccessUpdate::Keep),
        ("password", false) => auth.hash_password(password).await.map(AccessUpdate::Set),
        _ => Err(InputError::Access.into()),
    }
}

/// Identifies the only access field that can explain credential preparation.
pub(super) fn field(visibility: &str) -> &'static str {
    if matches!(visibility, "open" | "password") {
        "password"
    } else {
        "visibility"
    }
}

/// Preserves a safe rejection status with operation-appropriate recovery text.
pub(super) fn feedback(error: AppError) -> (StatusCode, String) {
    let message = error.to_string();
    let status = error.into_response().status();
    let message = if status == StatusCode::TOO_MANY_REQUESTS {
        "Password processing is busy. Try again shortly.".to_owned()
    } else {
        message
    };
    (status, message)
}

/// Renders protected site details with the actual viewer link and metadata.
#[derive(Template)]
#[template(path = "site.html")]
pub(super) struct SitePage<'a> {
    /// The stored admin theme choice for this browser.
    pub(super) theme: &'static str,
    /// A CSRF token bound to the current authenticated session.
    pub(super) csrf_token: &'a str,
    /// The stored optional title, represented by an empty string when absent.
    pub(super) title: &'a str,
    /// The share URL built from validated configuration and the persisted slug.
    pub(super) url: &'a str,
    /// The validated persisted slug identifying this site.
    pub(super) slug: &'a str,
    /// The human-readable stored access mode.
    pub(super) visibility: &'a str,
    /// The stored entry filename.
    pub(super) entry: &'a str,
    /// The creation time formatted as a UTC display label.
    pub(super) created: &'a str,
    /// The expiry formatted as a UTC display label, or the no-expiry label.
    pub(super) expires: &'a str,
    /// The stored number of published files.
    pub(super) file_count: i64,
    /// The stored total size of the published files in bytes.
    pub(super) size_bytes: i64,
    /// The bounded pending title, kept separate from the stored identity.
    pub(super) settings_title: &'a str,
    /// The bounded pending entry filename.
    pub(super) settings_entry: &'a str,
    /// The pending access mode; unsupported values select neither choice.
    pub(super) settings_visibility: &'a str,
    /// The editable expiry choice, `keep` when an expiry exists.
    pub(super) settings_expires_in: &'a str,
    /// The content tab the replace section renders: `html`, `files`, or `zip`.
    pub(super) replace_input: &'static str,
    /// Safe settings feedback explaining the problem and how to continue.
    pub(super) settings_error_message: Option<&'a str>,
    /// The invalid settings field, or an unrecognized general error name.
    pub(super) settings_invalid_field: Option<&'a str>,
    /// A fixed, safe parent-supplied outcome message.
    pub(super) notice: Option<&'a str>,
}

impl SitePage<'_> {
    /// Keeps unrecognized settings errors visible above the settings fields.
    fn general_settings_error(&self) -> bool {
        !matches!(
            self.settings_invalid_field,
            Some("title" | "entry" | "visibility" | "password" | "expires_in")
        ) && !self
            .settings_invalid_field
            .is_some_and(|field| field.starts_with("replace"))
    }

    /// Shows a replacement error above its inputs when no input owns it.
    fn general_replace_error(&self) -> bool {
        self.settings_invalid_field == Some("replace")
    }

    /// Routes a replacement error to the input inside the replace section.
    fn replace_invalid_field(&self) -> Option<&str> {
        self.settings_invalid_field
            .and_then(|field| field.strip_prefix("replace-"))
    }

    /// Passes feedback to the replace inputs only when it belongs to them.
    fn replace_error_message(&self) -> Option<&str> {
        self.settings_error_message.filter(|_| {
            self.settings_invalid_field
                .is_some_and(|field| field.starts_with("replace"))
        })
    }

    /// Links the replace tabs back to this page.
    fn replace_base(&self) -> String {
        format!("/sites/{}", self.slug)
    }

    /// Shows the same file-count limit enforced by parsing and storage.
    const fn max_site_files(&self) -> usize {
        MAX_SITE_FILES
    }
}
