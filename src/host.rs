//! Canonical hostnames shared by configuration and request validation.

use axum::http::uri::Authority;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::RangeInclusive,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Host(String);

const HOST_LENGTH: RangeInclusive<usize> = 1..=253;
const LABEL_LENGTH: RangeInclusive<usize> = 1..=63;

impl Host {
    /// Parses a hostname or bracketed IPv6 address without a port.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        if let Some(address) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            return address
                .parse::<Ipv6Addr>()
                .ok()
                .map(|address| Self(format!("[{address}]")));
        }
        let value = value.strip_suffix('.').unwrap_or(value);
        if !HOST_LENGTH.contains(&value.len()) || !value.is_ascii() {
            return None;
        }
        if let Ok(address) = value.parse::<Ipv4Addr>() {
            return Some(Self(address.to_string()));
        }
        let valid = value.split('.').all(|label| {
            LABEL_LENGTH.contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
        valid.then(|| Self(value.to_ascii_lowercase()))
    }

    /// Parses a request authority, validating its optional numeric port.
    pub(crate) fn from_authority(value: &str) -> Option<Self> {
        if value.contains('@') {
            return None;
        }
        let authority = value.parse::<Authority>().ok()?;
        let host = authority.host();
        let suffix = value.strip_prefix(host)?;
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':')?;
            if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            port.parse::<u16>().ok()?;
        }
        Self::parse(host)
    }

    /// Identifies the loopback names and addresses allowed for local HTTP.
    pub(crate) fn is_loopback(&self) -> bool {
        let host = self.as_str();
        host == "localhost"
            || host.ends_with(".localhost")
            || host
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    }

    /// Returns the normalized hostname without a port.
    #[inline]
    pub(crate) const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::Host;

    #[test]
    fn host_parse_normalizes_names_and_bracketed_ipv6_and_rejects_ports() {
        for (input, normalized) in [
            ("Pages.Example.COM.", "pages.example.com"),
            ("127.0.0.1", "127.0.0.1"),
            ("[0:0:0:0:0:0:0:1]", "[::1]"),
        ] {
            assert_eq!(Host::parse(input).unwrap().as_str(), normalized);
        }
        for input in ["", "a..b", "a_b", "a:8080", "::1", "[::1]:8080"] {
            assert!(Host::parse(input).is_none(), "accepted {input:?}");
        }
    }

    #[test]
    fn host_authority_accepts_optional_ports_and_rejects_forwarded_shapes() {
        for input in ["pages.local", "pages.local:8080", "[::1]:8080"] {
            assert!(Host::from_authority(input).is_some(), "rejected {input:?}");
        }
        for input in [
            "pages.local:",
            "pages.local:abc",
            "pages.local:65536",
            "user@pages.local",
            "pages.local:80:90",
            "pages.local,view.local",
            " pages.local",
            "pages.local/",
        ] {
            assert!(Host::from_authority(input).is_none(), "accepted {input:?}");
        }
    }
}
