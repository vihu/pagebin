//! Authenticated discovery, detail, and deliberate metadata-first deletion.

use super::{
    admin::{self, AdminScript},
    publishing::PublishingState,
    settings::{self, Feedback, SettingsForm},
};
use crate::{
    AppError, Result,
    sites::{DeleteOutcome, SITES_PER_PAGE, SiteDetails, Slug},
};
use askama::Template;
use axum::{
    Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};

/// Builds management routes with the smaller authentication-form body cap.
pub(super) fn router(state: PublishingState) -> Router {
    Router::new()
        .route("/", get(index))
        .route(
            "/sites/{slug}",
            get(detail).post(settings::update).delete(delete_site),
        )
        .route("/sites/{slug}/delete", get(confirmation).post(delete_site))
        .layer(DefaultBodyLimit::max(super::FORM_BODY_BYTES))
        .with_state(state)
}

/// Renders a bounded page of actual metadata, never a public listing.
///
/// # Errors
/// Returns session, query, database, or template failures.
async fn index(
    State(state): State<PublishingState>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response> {
    let Some((_, csrf_token)) = admin::session(&headers, &state.auth)? else {
        return Ok(Redirect::to("/login").into_response());
    };
    let query = ListQuery::parse(uri.query())?;
    let mut records = state.sites.list(query.page).await?;
    let next = if records.len() > SITES_PER_PAGE {
        let page = query.page.checked_add(1).ok_or_else(super::invalid)?;
        Some(format!("/?page={page}"))
    } else {
        None
    };
    records.truncate(SITES_PER_PAGE);
    let sites = records
        .into_iter()
        .map(|record| present(record, &state.public_url))
        .collect::<Result<Vec<_>>>()?;
    let previous = (query.page > 1).then(|| format!("/?page={}", query.page - 1));
    let body = IndexPage {
        csrf_token: &csrf_token,
        sites: &sites,
        previous_url: previous.as_deref(),
        next_url: next.as_deref(),
        notice: query.notice,
        theme: admin::theme(&headers),
    }
    .render()
    .map_err(AppError::publishing)?;
    Ok(AdminScript::allow(Html(body).into_response()))
}

/// Shows actual metadata and a configured share link to the administrator.
///
/// # Errors
/// Returns session, database, or template failures.
async fn detail(
    State(state): State<PublishingState>,
    Path(raw_slug): Path<String>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response> {
    let Some((_, csrf_token)) = admin::session(&headers, &state.auth)? else {
        return Ok(Redirect::to("/login").into_response());
    };
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(record) = state.sites.details(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let site = present(record, &state.public_url)?;
    let (notice, input) = match uri.query() {
        None | Some("") => (None, "html"),
        Some("notice=saved") => (Some("Settings saved."), "html"),
        Some("notice=replaced") => (Some("Content replaced."), "html"),
        Some("input=files") => (None, "files"),
        Some("input=zip") => (None, "zip"),
        _ => return Err(super::invalid()),
    };
    settings::show(
        StatusCode::OK,
        &csrf_token,
        &site,
        &SettingsForm::from_site(&site),
        notice.map_or(Feedback::None, Feedback::Notice),
        input,
        admin::theme(&headers),
    )
}

/// Displays confirmation without mutating metadata or content.
///
/// # Errors
/// Returns session, database, or template failures.
async fn confirmation(
    State(state): State<PublishingState>,
    Path(raw_slug): Path<String>,
    headers: HeaderMap,
) -> Result<Response> {
    let Some((_, csrf_token)) = admin::session(&headers, &state.auth)? else {
        return Ok(Redirect::to("/login").into_response());
    };
    let Ok(slug) = Slug::parse(&raw_slug) else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let Some(site) = state.sites.get(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    show_confirmation(
        StatusCode::OK,
        &csrf_token,
        slug.as_str(),
        &site.title,
        None,
        admin::theme(&headers),
    )
}

/// Deletes only after complete-body, live-session, and explicit confirmation.
///
/// # Errors
/// Returns origin/session, metadata, or rendering failures. Rejected requests
/// never authorize content cleanup.
async fn delete_site(
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
    let Some(site) = state.sites.get(&slug).await? else {
        return Ok(StatusCode::NOT_FOUND.into_response());
    };
    let submitted = match DeleteForm::read(request).await {
        Ok(submitted) => submitted,
        Err(error) => {
            let message = error.to_string();
            let response = error.into_response();
            if response.status() == StatusCode::FORBIDDEN {
                return Ok(response);
            }
            return show_confirmation(
                response.status(),
                &csrf_token,
                slug.as_str(),
                &site.title,
                Some(&message),
                theme,
            );
        }
    };
    if !state.auth.verify_form(&session_id, &submitted.csrf_token)? {
        return Err(super::forbidden());
    }
    match state.sites.delete(slug).await {
        Ok(DeleteOutcome::Deleted) => Ok(Redirect::to("/?notice=deleted").into_response()),
        Ok(DeleteOutcome::DeletedContentRetained) => {
            Ok(Redirect::to("/?notice=retained").into_response())
        }
        Ok(DeleteOutcome::NotFound) => Ok(StatusCode::NOT_FOUND.into_response()),
        Err(error) => {
            let status = error.into_response().status();
            show_confirmation(
                status,
                &csrf_token,
                &site.slug,
                &site.title,
                Some("Deletion could not be confirmed. Check your site list before retrying."),
                theme,
            )
        }
    }
}

/// Projects persisted values without inventing statistics or external URLs.
///
/// # Errors
/// Rejects invalid persisted slugs before constructing navigation URLs.
pub(super) fn present(record: SiteDetails, public_url: &str) -> Result<AdminSite> {
    let site = record.site;
    let slug = Slug::parse(&site.slug).map_err(AppError::publishing)?;
    Ok(AdminSite {
        url: format!("{public_url}/s/{}/", slug.as_str()),
        title: site.title,
        slug: site.slug,
        visibility: site.visibility,
        entry: site.entry,
        file_count: site.file_count,
        size_bytes: site.size_bytes,
        created: record.created_label,
        expires: record.expires_label,
    })
}

/// Renders escaped confirmation context and an optional safe rejection.
///
/// # Errors
/// Returns a safe template-rendering failure.
fn show_confirmation(
    status: StatusCode,
    csrf_token: &str,
    slug: &str,
    title: &str,
    error_message: Option<&str>,
    theme: &'static str,
) -> Result<Response> {
    let body = DeletePage {
        csrf_token,
        slug,
        title,
        error_message,
        theme,
    }
    .render()
    .map_err(AppError::publishing)?;
    Ok((status, Html(body)).into_response())
}

/// Renders an explicit native confirmation without mutating the site.
#[derive(Template)]
#[template(path = "delete.html")]
pub(super) struct DeletePage<'a> {
    /// The stored admin theme choice for this browser.
    pub(super) theme: &'static str,
    /// A CSRF token bound to the current authenticated session.
    pub(super) csrf_token: &'a str,
    /// The validated persisted slug used for confirmation and cancellation.
    pub(super) slug: &'a str,
    /// The stored optional title, empty when absent.
    pub(super) title: &'a str,
    /// Safe feedback explaining why the deletion could not be completed.
    pub(super) error_message: Option<&'a str>,
}

/// A syntactically confirmed form awaiting live-session token verification.
pub(super) struct DeleteForm {
    /// The bounded, untrusted session-bound verification token.
    pub(super) csrf_token: String,
}

impl DeleteForm {
    /// Requires exactly one token and one explicit deletion confirmation.
    ///
    /// # Errors
    /// Rejects oversized/malformed bodies, duplicate/unknown/file fields,
    /// invalid text, missing tokens, and missing or incorrect confirmation.
    pub(super) async fn read(request: Request) -> Result<Self> {
        let mut fields = super::read_fields(
            request,
            &[
                ("csrf_token", super::CSRF_FIELD_BYTES),
                ("confirm", super::CSRF_FIELD_BYTES),
            ],
        )
        .await?;
        let csrf_token = fields.remove("csrf_token").ok_or_else(super::forbidden)?;
        if fields.remove("confirm").as_deref() != Some("delete") {
            return Err(AppError::request(
                StatusCode::BAD_REQUEST,
                "Select the confirmation checkbox before deleting this site.",
            ));
        }
        Ok(Self { csrf_token })
    }
}

/// Renders a bounded site list with native pagination and session-bound logout.
#[derive(Template)]
#[template(path = "index.html")]
pub(super) struct IndexPage<'a> {
    /// The stored admin theme choice for this browser.
    pub(super) theme: &'static str,
    /// A CSRF token bound to the current authenticated session.
    pub(super) csrf_token: &'a str,
    /// The bounded page of persisted site metadata.
    pub(super) sites: &'a [AdminSite],
    /// A validated local URL for the previous page, when available.
    pub(super) previous_url: Option<&'a str>,
    /// A validated local URL for the next page, when available.
    pub(super) next_url: Option<&'a str>,
    /// A fixed application notice, rather than reflected query text.
    pub(super) notice: Option<&'a str>,
}

const BYTES_PER_UNIT: f64 = 1024.0;
const SIZE_UNITS: [&str; 6] = ["K", "M", "G", "T", "P", "E"];
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const DISPLAY_DAY: std::ops::RangeInclusive<u8> = 1..=31;
const YEAR_DIGITS: usize = 4;

/// Presents persisted site metadata without exposing uploaded content.
pub(super) struct AdminSite {
    /// The stored optional title, empty when absent.
    pub(super) title: String,
    /// The validated persisted slug used for local management links.
    pub(super) slug: String,
    /// The viewer URL built from validated configuration and the stored slug.
    pub(super) url: String,
    /// The human-readable stored access mode.
    pub(super) visibility: String,
    /// The stored entry filename.
    pub(super) entry: String,
    /// The creation time formatted as a UTC display label.
    pub(super) created: String,
    /// The expiry formatted as a UTC display label, or the no-expiry label.
    pub(super) expires: String,
    /// The stored number of published files.
    pub(super) file_count: i64,
    /// The stored total size of published files in bytes.
    pub(super) size_bytes: i64,
}

impl AdminSite {
    /// Formats a rounded binary-unit size; the full byte count stays available.
    pub(super) fn compact_size(&self) -> String {
        compact_size(self.size_bytes)
    }

    /// Formats the date in a SQL-generated UTC label without losing its source.
    pub(super) fn created_date(&self) -> String {
        created_date(&self.created)
    }
}

fn compact_size(bytes: i64) -> String {
    let mut value = bytes as f64;
    if value < BYTES_PER_UNIT {
        return bytes.to_string();
    }
    let mut suffix = "";
    for unit in SIZE_UNITS {
        if value < BYTES_PER_UNIT {
            break;
        }
        value /= BYTES_PER_UNIT;
        suffix = unit;
    }
    let rounded = format!("{value:.1}");
    format!("{}{suffix}", rounded.strip_suffix(".0").unwrap_or(&rounded))
}

fn created_date(label: &str) -> String {
    let date = label.split(' ').next().unwrap_or(label);
    let mut parts = date.split('-');
    let (Some(year), Some(month), Some(day), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return label.to_owned();
    };
    let month = month
        .parse::<usize>()
        .ok()
        .and_then(|month| month.checked_sub(1))
        .and_then(|index| MONTHS.get(index));
    match (month, day.parse::<u8>()) {
        (Some(month), Ok(day))
            if year.len() == YEAR_DIGITS
                && year.bytes().all(|byte| byte.is_ascii_digit())
                && DISPLAY_DAY.contains(&day) =>
        {
            format!("{day} {month} {year}")
        }
        _ => label.to_owned(),
    }
}

/// Validated pagination with optional application-owned status copy.
pub(super) struct ListQuery {
    /// The one-based page; the storage layer checks offset representability.
    pub(super) page: usize,
    /// Fixed status text, never reflected query input.
    pub(super) notice: Option<&'static str>,
}

impl ListQuery {
    /// Parses only a single page and a single recognized deletion notice.
    ///
    /// # Errors
    /// Rejects unknown/repeated fields, empty or invalid numbers, and zero.
    pub(super) fn parse(query: Option<&str>) -> Result<Self> {
        let mut page = None;
        let mut notice = None;
        if let Some(query) = query.filter(|query| !query.is_empty()) {
            for field in query.split('&') {
                let (name, value) = field.split_once('=').ok_or_else(super::invalid)?;
                match name {
                    "page" if page.is_none() => {
                        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                            return Err(super::invalid());
                        }
                        let number = value.parse::<usize>().map_err(|_| super::invalid())?;
                        if number == 0 {
                            return Err(super::invalid());
                        }
                        page = Some(number);
                    }
                    "notice" if notice.is_none() => {
                        notice = Some(match value {
                            "deleted" => {
                                "Site deleted. New requests to its share link return not found. Previously cached responses may remain for up to 60 seconds."
                            }
                            "retained" => {
                                "Site removed from sharing, but some files could not be safely removed. Residual files remain in storage and may block reuse of this slug. Check server diagnostics before manual cleanup."
                            }
                            _ => return Err(super::invalid()),
                        });
                    }
                    _ => return Err(super::invalid()),
                }
            }
        }
        Ok(Self {
            page: page.unwrap_or(1),
            notice,
        })
    }
}
