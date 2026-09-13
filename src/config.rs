//! Validated boot settings consumed before constructing shared request state.

use crate::{AppError, Result, auth::MASTER_KEY_BYTES, host::Host};
use axum::http::{Uri, uri::Scheme};
use std::{
    collections::HashMap,
    env,
    ffi::OsString,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ops::RangeInclusive,
    path::{Path, PathBuf},
};
use tracing_subscriber::EnvFilter;

/// Validated boot configuration whose secrets are consumed by router setup.
pub struct Config {
    admin_host: Host,
    admin_password: String,
    api_token: Option<String>,
    view_host: Option<Host>,
    public_url: String,
    max_upload_bytes: usize,
    data_dir: PathBuf,
    listen: SocketAddr,
    log_filter: EnvFilter,
    signing_secret: Option<[u8; MASTER_KEY_BYTES]>,
    trust_proxy: bool,
}

/// Reads raw settings through a lookup and validates them in `build`.
///
/// It stores no values, so a password never sits in an unvalidated struct.
pub struct ConfigBuilder<F>(F);

/// Accepted UTF-8 password byte lengths for configuration and browser forms.
pub(crate) const PASSWORD_BYTES: RangeInclusive<usize> = 1..=128 * 1024;
const HEX_DIGITS_PER_BYTE: usize = 2;
const SECRET_HEX_LENGTH: usize = MASTER_KEY_BYTES * HEX_DIGITS_PER_BYTE;
const BYTES_PER_MIB: u64 = 1024 * 1024;
const SECRET: &str = "PAGEBIN_SECRET";
const TRUST_PROXY: &str = "PAGEBIN_TRUST_PROXY";
const ADMIN_HOST: &str = "PAGEBIN_ADMIN_HOST";
const ADMIN_PASSWORD: &str = "PAGEBIN_ADMIN_PASSWORD";
const API_TOKEN: &str = "PAGEBIN_API_TOKEN";
const VIEW_HOST: &str = "PAGEBIN_VIEW_HOST";
const PUBLIC_URL: &str = "PAGEBIN_PUBLIC_URL";
const MAX_UPLOAD_MB: &str = "PAGEBIN_MAX_UPLOAD_MB";
const DEFAULT_MAX_UPLOAD_MB: &str = "50";
const DATA_DIR: &str = "PAGEBIN_DATA_DIR";
const PORT: &str = "PAGEBIN_PORT";
const LOG_FILTER: &str = "RUST_LOG";
const DEFAULT_DATA_DIR: &str = "data";
const DEFAULT_PORT: &str = "5050";
const DOTENV: &str = ".env";
const DEFAULT_LOG_FILTER: &str = "pagebin=info,tower_http=info";

impl Config {
    /// Loads settings from the environment, then `.env` in the working directory.
    ///
    /// A real environment variable always wins over the file.
    ///
    /// # Errors
    /// Returns an error naming a missing or invalid variable without its value.
    pub fn from_env() -> Result<Self> {
        let file = dotenv_file();
        ConfigBuilder::from_lookup(|name| env::var_os(name).or_else(|| file.get(name).cloned()))
            .build()
    }

    /// Returns the canonical admin hostname without a port.
    pub const fn admin_host(&self) -> &str {
        self.admin_host.as_str()
    }

    /// Returns the canonical viewer hostname when origin separation is enabled.
    pub fn view_host(&self) -> Option<&str> {
        self.view_host.as_ref().map(Host::as_str)
    }

    /// Returns the validated public base URL without a trailing slash.
    pub fn public_url(&self) -> &str {
        &self.public_url
    }

    /// Returns the encoded upload cap in bytes, including multipart overhead.
    pub const fn max_upload_bytes(&self) -> usize {
        self.max_upload_bytes
    }

    /// Returns the absolute UTF-8 path for database and site storage.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the listen address: every interface on `PAGEBIN_PORT`.
    pub const fn listen(&self) -> SocketAddr {
        self.listen
    }
}

impl Config {
    /// Returns the validated tracing filter without reloading the environment.
    pub(crate) fn log_filter(&self) -> EnvFilter {
        self.log_filter.clone()
    }

    /// Returns whether the operator explicitly enabled forwarded-IP trust.
    pub(crate) const fn trust_proxy(&self) -> bool {
        self.trust_proxy
    }

    /// Returns the configured API bearer token, absent when the API is disabled.
    pub(crate) fn api_token(&self) -> Option<&str> {
        self.api_token.as_deref()
    }

    /// Consumes boot settings for authentication initialization.
    pub(crate) fn into_auth_settings(self) -> (String, PathBuf, Option<[u8; MASTER_KEY_BYTES]>) {
        (self.admin_password, self.data_dir, self.signing_secret)
    }
}

impl<F: FnMut(&str) -> Option<OsString>> ConfigBuilder<F> {
    /// Wraps a lookup such as `std::env::var_os` or a test map, reading nothing yet.
    pub fn from_lookup(lookup: F) -> Self {
        Self(lookup)
    }

    /// Validates every setting, naming the first missing or invalid variable.
    ///
    /// # Errors
    /// Hosts must be DNS names, IPv4, or bracketed IPv6 without ports, and the
    /// viewer host must differ from the admin host. The public URL must be a
    /// root HTTP(S) URL on the effective viewer host, HTTP on loopback only.
    /// The upload limit is a positive whole MiB count that fits body buffers
    /// and SQLite. The data root must resolve to an absolute UTF-8 path.
    pub fn build(mut self) -> Result<Config> {
        let admin_host = self.required(ADMIN_HOST)?;
        let admin_host =
            Host::parse(&admin_host).ok_or_else(|| AppError::configuration(ADMIN_HOST))?;
        let admin_password = self.required(ADMIN_PASSWORD)?;
        if !valid_password(&admin_password) {
            return Err(AppError::configuration(ADMIN_PASSWORD));
        }
        let api_token = self.optional(API_TOKEN)?;
        if api_token
            .as_deref()
            .is_some_and(|token| !valid_password(token))
        {
            return Err(AppError::configuration(API_TOKEN));
        }
        let view_host = self
            .optional(VIEW_HOST)?
            .map(|value| Host::parse(&value).ok_or_else(|| AppError::configuration(VIEW_HOST)))
            .transpose()?;
        if view_host.as_ref() == Some(&admin_host) {
            return Err(AppError::configuration(VIEW_HOST));
        }
        let viewer_host = view_host.as_ref().unwrap_or(&admin_host);
        let public_url = self
            .optional(PUBLIC_URL)?
            .unwrap_or_else(|| format!("https://{}", viewer_host.as_str()));
        let public_url = parse_public_url(&public_url, viewer_host)
            .ok_or_else(|| AppError::configuration(PUBLIC_URL))?;
        let max_upload_mb = self.or_default(MAX_UPLOAD_MB, DEFAULT_MAX_UPLOAD_MB)?;
        let max_upload_bytes = parse_upload_limit(&max_upload_mb)
            .ok_or_else(|| AppError::configuration(MAX_UPLOAD_MB))?;
        let data_dir = self.or_default(DATA_DIR, DEFAULT_DATA_DIR)?;
        let data_dir = validated_data_dir(Path::new(&data_dir))?;
        let port = self
            .or_default(PORT, DEFAULT_PORT)?
            .parse::<u16>()
            .map_err(|_| AppError::configuration(PORT))?;
        let listen = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let log_filter = EnvFilter::builder()
            .with_regex(false)
            .parse(self.or_default(LOG_FILTER, DEFAULT_LOG_FILTER)?)
            .map_err(|_| AppError::configuration(LOG_FILTER))?;
        let signing_secret = self
            .optional(SECRET)?
            .map(|value| parse_secret(&value))
            .transpose()?;
        let trust_proxy = self
            .optional(TRUST_PROXY)?
            .map(|value| {
                value
                    .parse::<bool>()
                    .map_err(|_| AppError::configuration(TRUST_PROXY))
            })
            .transpose()?
            .unwrap_or(false);
        Ok(Config {
            admin_host,
            admin_password,
            api_token,
            view_host,
            public_url,
            max_upload_bytes,
            data_dir,
            listen,
            log_filter,
            signing_secret,
            trust_proxy,
        })
    }

    /// Reads a set variable as nonempty UTF-8 text; an unset one is `None`.
    fn optional(&mut self, name: &'static str) -> Result<Option<String>> {
        match (self.0)(name) {
            None => Ok(None),
            Some(value) => value
                .into_string()
                .ok()
                .filter(|value| !value.is_empty())
                .map(Some)
                .ok_or_else(|| AppError::configuration(name)),
        }
    }

    fn required(&mut self, name: &'static str) -> Result<String> {
        self.optional(name)?
            .ok_or_else(|| AppError::configuration(name))
    }

    fn or_default(&mut self, name: &'static str, default: &str) -> Result<String> {
        Ok(self.optional(name)?.unwrap_or_else(|| default.to_owned()))
    }
}

/// Reads `KEY=VALUE` lines from `.env` in the working directory, if present.
///
/// Blank lines, `#` comments, and an `export ` prefix are skipped. Values are
/// taken verbatim, so quotes stay part of the value.
fn dotenv_file() -> HashMap<String, OsString> {
    let text = fs::read_to_string(DOTENV).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = line.strip_prefix("export ").unwrap_or(line);
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_owned(), OsString::from(value.trim())))
        })
        .collect()
}

/// Checks the shared configuration and browser-form password contract.
pub(crate) fn valid_password(password: &str) -> bool {
    PASSWORD_BYTES.contains(&password.len()) && !password.contains(['\0', '\r', '\n'])
}

/// Validates data paths before writes and prevents SQLite URI interpretation.
///
/// # Errors
/// Returns a configuration error for empty, NUL-containing, non-UTF-8, or
/// unresolvable paths. Relative paths are resolved without creating storage.
pub(crate) fn validated_data_dir(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(AppError::configuration(DATA_DIR));
    }
    let path = std::path::absolute(path).map_err(|_| AppError::configuration(DATA_DIR))?;
    if path.to_str().is_none() {
        return Err(AppError::configuration(DATA_DIR));
    }
    Ok(path)
}

fn parse_secret(value: &str) -> Result<[u8; MASTER_KEY_BYTES]> {
    if value.len() != SECRET_HEX_LENGTH || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::configuration(SECRET));
    }
    let mut secret = [0; MASTER_KEY_BYTES];
    for (index, byte) in secret.iter_mut().enumerate() {
        let start = index * HEX_DIGITS_PER_BYTE;
        *byte = u8::from_str_radix(&value[start..start + HEX_DIGITS_PER_BYTE], 16)
            .map_err(|_| AppError::configuration(SECRET))?;
    }
    Ok(secret)
}

/// Parses positive ASCII-decimal MiB into a byte count that fits buffers and SQLite.
fn parse_upload_limit(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let bytes = value.parse::<u64>().ok()?.checked_mul(BYTES_PER_MIB)?;
    if bytes == 0 {
        return None;
    }
    // SQLite INTEGER is signed 64-bit; Rust allocations cannot exceed isize.
    let sqlite_bytes = i64::try_from(bytes).ok()?;
    usize::try_from(isize::try_from(sqlite_bytes).ok()?).ok()
}

/// Validates a root HTTP(S) URL on the viewer host, canonicalizing scheme and host.
fn parse_public_url(value: &str, viewer_host: &Host) -> Option<String> {
    // Uri parsing can discard fragments; reject them before parsing.
    if value.contains('#') {
        return None;
    }
    let uri = value.parse::<Uri>().ok()?;
    let scheme = uri.scheme()?;
    if scheme != &Scheme::HTTP && scheme != &Scheme::HTTPS {
        return None;
    }
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return None;
    }
    let authority = uri.authority()?;
    // Share links need a service port, not an ephemeral listen port.
    if authority.port_u16() == Some(0) {
        return None;
    }
    let host = Host::from_authority(authority.as_str())?;
    if &host != viewer_host || (scheme == &Scheme::HTTP && !host.is_loopback()) {
        return None;
    }
    let mut base = format!("{scheme}://{}", host.as_str());
    if let Some(port) = authority.port() {
        base.push(':');
        base.push_str(port.as_str());
    }
    Some(base)
}

#[cfg(test)]
mod tests {
    use super::{
        BYTES_PER_MIB, Config, ConfigBuilder, Result, parse_public_url, parse_upload_limit,
    };
    use crate::host::Host;
    use std::{collections::HashMap, ffi::OsString};

    fn settings() -> HashMap<&'static str, OsString> {
        HashMap::from([
            ("PAGEBIN_ADMIN_HOST", "pages.local".into()),
            ("PAGEBIN_ADMIN_PASSWORD", "synthetic-password".into()),
        ])
    }

    fn build(settings: &HashMap<&str, OsString>) -> Result<Config> {
        ConfigBuilder::from_lookup(|key| settings.get(key).cloned()).build()
    }

    #[test]
    fn config_full_environment_builds_and_defaults_apply() {
        let mut settings = settings();
        let config = build(&settings).unwrap();
        assert_eq!(config.listen().to_string(), "0.0.0.0:5050");
        settings.extend([
            ("PAGEBIN_VIEW_HOST", "VIEW.localhost.".into()),
            ("PAGEBIN_PUBLIC_URL", "http://VIEW.localhost:8080/".into()),
            ("PAGEBIN_PORT", "0".into()),
            ("RUST_LOG", "pagebin=debug".into()),
            ("PAGEBIN_SECRET", "ab".repeat(32).into()),
            ("PAGEBIN_TRUST_PROXY", "true".into()),
        ]);
        let config = build(&settings).unwrap();
        assert_eq!(config.admin_host(), "pages.local");
        assert_eq!(config.view_host(), Some("view.localhost"));
        assert_eq!(config.public_url(), "http://view.localhost:8080");
        assert_eq!(config.listen().to_string(), "0.0.0.0:0");
        assert_eq!(config.log_filter().to_string(), "pagebin=debug");
        assert!(config.trust_proxy());
        let (password, _, secret) = config.into_auth_settings();
        assert_eq!(password, "synthetic-password");
        assert_eq!(secret, Some([0xab; 32]));
    }

    #[test]
    fn config_missing_or_invalid_values_name_only_the_variable() {
        for (name, value) in [("PAGEBIN_ADMIN_HOST", None), ("PAGEBIN_PORT", Some("http"))] {
            let mut settings = settings();
            settings.remove(name);
            settings.extend(value.map(|value| (name, value.into())));
            let error = build(&settings).err().unwrap();
            assert!(error.to_string().contains(name));
            assert!(!format!("{error:?}").contains("synthetic-password"));
        }
    }

    #[test]
    fn config_upload_limit_accepts_whole_mebibytes_and_rejects_zero_or_overflow() {
        assert_eq!(parse_upload_limit("50"), Some(50 * 1024 * 1024));
        let max_mib = u64::try_from(isize::MAX).unwrap() / BYTES_PER_MIB;
        assert!(parse_upload_limit(&max_mib.to_string()).is_some());
        assert!(parse_upload_limit(&(max_mib + 1).to_string()).is_none());
        for input in ["", "0", "-1", "1.5", "50MiB", "18446744073709551616"] {
            assert!(parse_upload_limit(input).is_none(), "accepted {input:?}");
        }
    }

    #[test]
    fn config_public_url_canonicalizes_root_urls_on_the_viewer_host() {
        let host = Host::parse("view.example").unwrap();
        let url = parse_public_url("HTTPS://VIEW.EXAMPLE.:8443/", &host);
        assert_eq!(url.as_deref(), Some("https://view.example:8443"));
        let local = Host::parse("localhost").unwrap();
        let url = parse_public_url("http://LOCALHOST:8080", &local);
        assert_eq!(url.as_deref(), Some("http://localhost:8080"));
    }

    #[test]
    fn config_public_url_rejects_paths_schemes_and_foreign_hosts() {
        let host = Host::parse("view.example").unwrap();
        for input in [
            "https://view.example/path",
            "https://view.example/?query",
            "https://view.example#fragment",
            "ftp://view.example/",
            "http://view.example",
            "https://foreign.example",
            "https://user@view.example",
            "https://view.example:0",
        ] {
            assert!(parse_public_url(input, &host).is_none());
        }
    }
}
