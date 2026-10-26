use async_trait::async_trait;

use crate::message::ParsedMessage;

/// Outcome of asking Laravel about a recipient or a set of credentials.
#[derive(Debug, PartialEq, Eq)]
pub enum LookupError {
    /// Laravel said the recipient or credentials (404) are not valid.
    Unknown,
    /// Laravel rejected the request itself (422).
    Invalid,
    /// Timeout, network error, 5xx, or a bad service token (`misconfigured`).
    Unavailable { misconfigured: bool },
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeliveryError {
    /// 422 caused by `raw` or `attachments.*`.
    TooLarge,
    /// Any other 422.
    Rejected,
    Unavailable { misconfigured: bool },
}

/// Everything the SMTP side needs from Laravel. Implemented over HTTP in
/// `laravel` and wrapped by `cache::CachedBackend`.
#[async_trait]
pub trait Backend: Send + Sync {
    async fn validate_recipient(&self, address: &str) -> Result<i64, LookupError>;
    async fn validate_credentials(&self, username: &str, password: &str) -> Result<i64, LookupError>;
    async fn deliver(&self, inbox_id: i64, message: &ParsedMessage) -> Result<(), DeliveryError>;
}
