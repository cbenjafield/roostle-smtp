use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};

pub const DEFAULT_MAX_MESSAGE_KILOBYTES: usize = 5_120;

#[derive(Clone)]
pub struct Config {
    pub base_url: String,
    pub service_token: String,
    pub catch_domain: String,
    pub hostname: String,
    pub max_message_bytes: usize,
    pub catch_bind: Vec<SocketAddr>,
    pub submission_bind: Vec<SocketAddr>,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub allow_insecure_auth: bool,
    pub max_connections: usize,
    pub validation_timeout: Duration,
    pub delivery_timeout: Duration,
    pub idle_timeout: Duration,
    pub auth_max_failures: u32,
    pub auth_window: Duration,
    pub auth_failure_delay: Duration,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("base_url", &self.base_url)
            .field("service_token", &"<redacted>")
            .field("catch_domain", &self.catch_domain)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("catch_bind", &self.catch_bind)
            .field("submission_bind", &self.submission_bind)
            .finish_non_exhaustive()
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let get = |key: &str| get(key).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        let required = |key: &str| get(key).with_context(|| format!("{key} is required"));

        let base_url = required("ROOSTLE_BASE_URL")?.trim_end_matches('/').to_owned();
        if !is_acceptable_base_url(&base_url) {
            bail!("ROOSTLE_BASE_URL must be an https:// URL (http:// is only allowed for localhost)");
        }

        let kilobytes = match get("ROOSTLE_MAX_MESSAGE_KILOBYTES") {
            Some(v) => v.parse::<usize>().context("ROOSTLE_MAX_MESSAGE_KILOBYTES must be an integer")?,
            None => DEFAULT_MAX_MESSAGE_KILOBYTES,
        };

        let catch_bind = binds(get("ROOSTLE_CATCH_BIND").as_deref().unwrap_or("0.0.0.0:25"))?;
        let submission_bind = binds(get("ROOSTLE_SUBMISSION_BIND").as_deref().unwrap_or("0.0.0.0:587"))?;

        let config = Config {
            base_url,
            service_token: required("ROOSTLE_SMTP_SERVICE_TOKEN")?,
            catch_domain: get("ROOSTLE_CATCH_DOMAIN").unwrap_or_else(|| "catch.roostle.co.uk".into()),
            hostname: get("ROOSTLE_SMTP_HOSTNAME").unwrap_or_else(|| "smtp.roostle.co.uk".into()),
            max_message_bytes: kilobytes * 1024,
            catch_bind,
            submission_bind,
            tls_cert: get("ROOSTLE_TLS_CERT"),
            tls_key: get("ROOSTLE_TLS_KEY"),
            allow_insecure_auth: get("ROOSTLE_ALLOW_INSECURE_AUTH").is_some_and(|v| v == "true" || v == "1"),
            max_connections: parse_or(&get, "ROOSTLE_MAX_CONNECTIONS", 500)?,
            validation_timeout: Duration::from_secs(5),
            delivery_timeout: Duration::from_secs(60),
            idle_timeout: Duration::from_secs(300),
            auth_max_failures: parse_or(&get, "ROOSTLE_AUTH_MAX_FAILURES", 5)?,
            auth_window: Duration::from_secs(parse_or(&get, "ROOSTLE_AUTH_WINDOW_SECONDS", 900)?),
            auth_failure_delay: Duration::from_secs(1),
        };

        if config.tls_cert.is_some() != config.tls_key.is_some() {
            bail!("ROOSTLE_TLS_CERT and ROOSTLE_TLS_KEY must be set together");
        }
        if !config.submission_bind.is_empty() && config.tls_cert.is_none() && !config.allow_insecure_auth {
            bail!(
                "the submission listener requires TLS: set ROOSTLE_TLS_CERT and ROOSTLE_TLS_KEY \
                 (or ROOSTLE_ALLOW_INSECURE_AUTH=true for local development only)"
            );
        }
        Ok(config)
    }
}

fn parse_or<T: std::str::FromStr>(get: &impl Fn(&str) -> Option<String>, key: &str, default: T) -> Result<T> {
    match get(key) {
        Some(v) => v.parse().map_err(|_| anyhow::anyhow!("{key} is not a valid number")),
        None => Ok(default),
    }
}

/// Comma-separated socket addresses; an empty value disables the listener.
fn binds(value: &str) -> Result<Vec<SocketAddr>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().with_context(|| format!("invalid bind address {s:?}")))
        .collect()
}

fn is_acceptable_base_url(url: &str) -> bool {
    if url.starts_with("https://") {
        return true;
    }
    url.strip_prefix("http://").is_some_and(|rest| {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        host == "localhost" || host == "127.0.0.1" || host == "[::1]"
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let pairs: Vec<_> = pairs.to_vec();
        move |k| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn defaults_and_validation() {
        let base = [
            ("ROOSTLE_BASE_URL", "https://roostle.co.uk/"),
            ("ROOSTLE_SMTP_SERVICE_TOKEN", "secret"),
            ("ROOSTLE_ALLOW_INSECURE_AUTH", "true"),
        ];
        let c = Config::from_lookup(lookup(&base)).unwrap();
        assert_eq!(c.base_url, "https://roostle.co.uk");
        assert_eq!(c.max_message_bytes, 5_242_880);
        assert!(!format!("{c:?}").contains("secret"));

        // Submission without TLS or the dev override is refused.
        assert!(Config::from_lookup(lookup(&base[..2])).is_err());
        // Plain http is refused except for localhost.
        let http = [("ROOSTLE_BASE_URL", "http://example.com"), base[1], base[2]];
        assert!(Config::from_lookup(lookup(&http)).is_err());
        let local = [("ROOSTLE_BASE_URL", "http://localhost:8000"), base[1], base[2]];
        assert!(Config::from_lookup(lookup(&local)).is_ok());
    }
}
