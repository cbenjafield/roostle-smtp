//! Short-lived in-memory caching in front of a `Backend`, per the contract:
//! positive recipient results ~45s, 404s a few seconds, positive credential
//! results ~45s keyed by a hash (never the plaintext), failures never cached.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::backend::{Backend, DeliveryError, LookupError};
use crate::message::ParsedMessage;

const POSITIVE_TTL: Duration = Duration::from_secs(45);
const NEGATIVE_TTL: Duration = Duration::from_secs(3);
const MAX_ENTRIES: usize = 10_000;

pub struct TtlCache<K, V> {
    entries: Mutex<HashMap<K, (V, Instant)>>,
}

impl<K, V> Default for TtlCache<K, V> {
    fn default() -> Self {
        Self { entries: Mutex::new(HashMap::new()) }
    }
}

impl<K: Hash + Eq, V: Clone> TtlCache<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let mut entries = self.entries.lock().unwrap();
        match entries.get(key) {
            Some((value, expires)) if *expires > Instant::now() => Some(value.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_ENTRIES {
            let now = Instant::now();
            entries.retain(|_, (_, expires)| *expires > now);
            if entries.len() >= MAX_ENTRIES {
                entries.clear();
            }
        }
        entries.insert(key, (value, Instant::now() + ttl));
    }
}

pub struct CachedBackend<B> {
    inner: B,
    /// `None` records an unknown address (short TTL).
    recipients: TtlCache<String, Option<i64>>,
    credentials: TtlCache<Vec<u8>, i64>,
}

impl<B: Backend> CachedBackend<B> {
    pub fn new(inner: B) -> Self {
        Self { inner, recipients: TtlCache::new(), credentials: TtlCache::new() }
    }
}

fn credential_key(username: &str, password: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update([0]);
    hasher.update(password.as_bytes());
    hasher.finalize().to_vec()
}

#[async_trait]
impl<B: Backend> Backend for CachedBackend<B> {
    async fn validate_recipient(&self, address: &str) -> Result<i64, LookupError> {
        let key = address.to_lowercase();
        match self.recipients.get(&key) {
            Some(Some(id)) => return Ok(id),
            Some(None) => return Err(LookupError::Unknown),
            None => {}
        }
        match self.inner.validate_recipient(address).await {
            Ok(id) => {
                self.recipients.insert(key, Some(id), POSITIVE_TTL);
                Ok(id)
            }
            Err(LookupError::Unknown) => {
                self.recipients.insert(key, None, NEGATIVE_TTL);
                Err(LookupError::Unknown)
            }
            Err(e) => Err(e),
        }
    }

    async fn validate_credentials(&self, username: &str, password: &str) -> Result<i64, LookupError> {
        let key = credential_key(username, password);
        if let Some(id) = self.credentials.get(&key) {
            return Ok(id);
        }
        let id = self.inner.validate_credentials(username, password).await?;
        self.credentials.insert(key, id, POSITIVE_TTL);
        Ok(id)
    }

    async fn deliver(&self, inbox_id: i64, message: &ParsedMessage) -> Result<(), DeliveryError> {
        self.inner.deliver(inbox_id, message).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counting {
        recipient_calls: AtomicUsize,
        credential_calls: AtomicUsize,
    }

    #[async_trait]
    impl Backend for Counting {
        async fn validate_recipient(&self, address: &str) -> Result<i64, LookupError> {
            self.recipient_calls.fetch_add(1, Ordering::SeqCst);
            if address.starts_with("known") { Ok(7) } else { Err(LookupError::Unknown) }
        }
        async fn validate_credentials(&self, _: &str, password: &str) -> Result<i64, LookupError> {
            self.credential_calls.fetch_add(1, Ordering::SeqCst);
            if password == "good" { Ok(9) } else { Err(LookupError::Unknown) }
        }
        async fn deliver(&self, _: i64, _: &ParsedMessage) -> Result<(), DeliveryError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn caches_positive_recipients_case_insensitively() {
        let b = CachedBackend::new(Counting::default());
        assert_eq!(b.validate_recipient("known@x").await, Ok(7));
        assert_eq!(b.validate_recipient("KNOWN@x").await, Ok(7));
        assert_eq!(b.inner.recipient_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_recipients_cached_briefly_and_credential_failures_not_at_all() {
        let b = CachedBackend::new(Counting::default());
        assert!(b.validate_recipient("nope@x").await.is_err());
        assert!(b.validate_recipient("nope@x").await.is_err());
        assert_eq!(b.inner.recipient_calls.load(Ordering::SeqCst), 1);

        assert!(b.validate_credentials("u", "bad").await.is_err());
        assert!(b.validate_credentials("u", "bad").await.is_err());
        assert_eq!(b.inner.credential_calls.load(Ordering::SeqCst), 2);
        assert_eq!(b.validate_credentials("u", "good").await, Ok(9));
        assert_eq!(b.validate_credentials("u", "good").await, Ok(9));
        assert_eq!(b.inner.credential_calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn expired_entries_are_dropped() {
        let c: TtlCache<&str, i32> = TtlCache::new();
        c.insert("a", 1, Duration::ZERO);
        assert_eq!(c.get(&"a"), None);
    }
}
