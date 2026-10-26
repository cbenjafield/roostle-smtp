//! HTTP client for Laravel's `/api/internal/smtp` endpoints.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::multipart::{Form, Part};
use reqwest::{Body, Client, RequestBuilder, StatusCode};
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use tracing::{error, warn};

use crate::backend::{Backend, DeliveryError, LookupError};
use crate::config::Config;
use crate::message::{EmailAddress, ParsedMessage};

pub struct HttpBackend {
    client: Client,
    base: String,
    token: String,
    validation_timeout: Duration,
    delivery_timeout: Duration,
}

impl HttpBackend {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::builder()
                .connect_timeout(config.validation_timeout)
                .user_agent(concat!("roostle-smtp/", env!("CARGO_PKG_VERSION")))
                .build()?,
            base: format!("{}/api/internal/smtp", config.base_url),
            token: config.service_token.clone(),
            validation_timeout: config.validation_timeout,
            delivery_timeout: config.delivery_timeout,
        })
    }

    fn post(&self, path: &str, timeout: Duration) -> RequestBuilder {
        self.client
            .post(format!("{}/{path}", self.base))
            .bearer_auth(&self.token)
            .header("Accept", "application/json")
            .timeout(timeout)
    }

    /// A 401 always means a bad service token (alert, 451); a 404 means the
    /// recipient or login is unknown.
    async fn validate(&self, path: &str, body: Value) -> Result<i64, LookupError> {
        let response = self
            .post(path, self.validation_timeout)
            .json(&body)
            .send()
            .await
            .map_err(|e| transport_failure(path, e))?;
        match response.status() {
            StatusCode::OK => {
                let json: Value = response.json().await.map_err(|e| {
                    warn!(path, error = %e, "unreadable validation response");
                    LookupError::Unavailable { misconfigured: false }
                })?;
                json.get("inbox_id").and_then(Value::as_i64).ok_or_else(|| {
                    error!(path, "validation response had no inbox_id");
                    LookupError::Unavailable { misconfigured: false }
                })
            }
            StatusCode::UNAUTHORIZED => {
                alert_bad_token(path);
                Err(LookupError::Unavailable { misconfigured: true })
            }
            StatusCode::NOT_FOUND => Err(LookupError::Unknown),
            StatusCode::UNPROCESSABLE_ENTITY => Err(LookupError::Invalid),
            status => {
                warn!(path, %status, "unexpected validation status");
                Err(LookupError::Unavailable { misconfigured: false })
            }
        }
    }
}

fn transport_failure(path: &str, e: reqwest::Error) -> LookupError {
    let timed_out = e.is_timeout();
    warn!(path, timed_out, error = %e.without_url(), "request to Laravel failed");
    LookupError::Unavailable { misconfigured: false }
}

fn alert_bad_token(path: &str) {
    error!(
        alert = true,
        path, "ALERT: Laravel rejected the service token (401); check ROOSTLE_SMTP_SERVICE_TOKEN"
    );
}

#[async_trait]
impl Backend for HttpBackend {
    async fn validate_recipient(&self, address: &str) -> Result<i64, LookupError> {
        self.validate("recipients/validate", json!({ "address": address })).await
    }

    async fn validate_credentials(&self, username: &str, password: &str) -> Result<i64, LookupError> {
        self.validate("credentials/validate", json!({ "username": username, "password": password })).await
    }

    async fn deliver(&self, inbox_id: i64, message: &ParsedMessage) -> Result<(), DeliveryError> {
        let path = "messages";
        let response = self
            .post(path, self.delivery_timeout)
            .multipart(build_form(inbox_id, message))
            .send()
            .await
            .map_err(|e| {
                warn!(path, timeout = e.is_timeout(), error = %e.without_url(), "delivery request failed");
                DeliveryError::Unavailable { misconfigured: false }
            })?;
        match response.status() {
            StatusCode::CREATED => Ok(()),
            StatusCode::UNAUTHORIZED => {
                alert_bad_token(path);
                Err(DeliveryError::Unavailable { misconfigured: true })
            }
            StatusCode::UNPROCESSABLE_ENTITY => {
                let body = response.bytes().await.unwrap_or_default();
                if is_size_error(&body) { Err(DeliveryError::TooLarge) } else {
                    warn!(inbox_id, "Laravel rejected message (422)");
                    Err(DeliveryError::Rejected)
                }
            }
            status => {
                warn!(path, %status, "unexpected delivery status");
                Err(DeliveryError::Unavailable { misconfigured: false })
            }
        }
    }
}

/// A 422 is a size rejection when the errors name `raw` or `attachments.*`.
fn is_size_error(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("errors").and_then(Value::as_object).cloned())
        .is_some_and(|errors| errors.keys().any(|k| k == "raw" || k.starts_with("attachments")))
}

pub fn build_form(inbox_id: i64, m: &ParsedMessage) -> Form {
    let mut form = Form::new().text("inbox_id", inbox_id.to_string());
    let text = |form: Form, name: &str, value: &Option<String>| match value {
        Some(v) => form.text(name.to_owned(), v.clone()),
        None => form,
    };
    form = text(form, "message_id", &m.message_id);
    form = form.text("from_address", m.from_address.clone());
    form = text(form, "from_name", &m.from_name);
    form = address_fields(form, "to", &m.to);
    form = address_fields(form, "cc", &m.cc);
    form = text(form, "subject", &m.subject);
    form = text(form, "text_body", &m.text_body);
    form = text(form, "html_body", &m.html_body);
    for (i, (name, value)) in m.headers.iter().enumerate() {
        form = form
            .text(format!("headers[{i}][name]"), name.clone())
            .text(format!("headers[{i}][value]"), value.clone());
    }
    if let Ok(at) = m.received_at.format(&Rfc3339) {
        form = form.text("received_at", at);
    }
    form = form.part("raw", file_part(&m.raw, "message.eml", "message/rfc822"));
    for a in &m.attachments {
        form = form.part("attachments[]", file_part(&a.data, &a.filename, &a.content_type));
    }
    form
}

fn address_fields(mut form: Form, field: &str, list: &[EmailAddress]) -> Form {
    for (i, a) in list.iter().enumerate() {
        form = form.text(format!("{field}[{i}][address]"), a.address.clone());
        if let Some(name) = &a.name {
            form = form.text(format!("{field}[{i}][name]"), name.clone());
        }
    }
    form
}

fn file_part(data: &bytes::Bytes, filename: &str, content_type: &str) -> Part {
    // A known length keeps the request non-chunked, which PHP-FPM prefers.
    let part = Part::stream_with_length(Body::from(data.clone()), data.len() as u64)
        .file_name(filename.to_owned());
    // An unparseable content type falls back to reqwest's default for the part.
    match part.mime_str(content_type) {
        Ok(part) => part,
        Err(_) => Part::stream_with_length(Body::from(data.clone()), data.len() as u64)
            .file_name(filename.to_owned())
            .mime_str("application/octet-stream")
            .expect("static mime type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_errors_are_detected_by_field_name() {
        assert!(is_size_error(br#"{"message":"x","errors":{"raw":["too big"]}}"#));
        assert!(is_size_error(br#"{"errors":{"attachments.0":["too big"]}}"#));
        assert!(!is_size_error(br#"{"errors":{"inbox_id":["unknown"]}}"#));
        assert!(!is_size_error(b""));
    }
}
