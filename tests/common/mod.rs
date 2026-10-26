#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use roostle_smtp::backend::{Backend, DeliveryError, LookupError};
use roostle_smtp::config::Config;
use roostle_smtp::message::ParsedMessage;
use roostle_smtp::server;
use roostle_smtp::session::{Mode, Shared};
use roostle_smtp::throttle::AuthThrottle;
use roostle_smtp::tls::TlsContext;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub struct Delivered {
    pub inbox_id: i64,
    pub message: ParsedMessage,
}

#[derive(Clone, Copy)]
pub enum Fail {
    Unavailable,
    TooLarge,
    Rejected,
}

#[derive(Default)]
pub struct MockBackend {
    pub recipients: HashMap<String, i64>,
    pub fail_delivery: Mutex<Option<Fail>>,
    pub recipient_unavailable: Mutex<bool>,
    pub delivered: Mutex<Vec<Delivered>>,
    pub credential_calls: Mutex<u32>,
}

impl MockBackend {
    pub fn new() -> Self {
        let mut recipients = HashMap::new();
        recipients.insert("known1@catch.test".into(), 1);
        recipients.insert("known2@catch.test".into(), 1);
        recipients.insert("other@catch.test".into(), 2);
        Self { recipients, ..Default::default() }
    }
}

#[async_trait]
impl Backend for MockBackend {
    async fn validate_recipient(&self, address: &str) -> Result<i64, LookupError> {
        if *self.recipient_unavailable.lock().unwrap() {
            return Err(LookupError::Unavailable { misconfigured: false });
        }
        self.recipients.get(&address.to_lowercase()).copied().ok_or(LookupError::Unknown)
    }

    async fn validate_credentials(&self, username: &str, password: &str) -> Result<i64, LookupError> {
        *self.credential_calls.lock().unwrap() += 1;
        if username == "rstuser" && password == "secret" { Ok(5) } else { Err(LookupError::Unknown) }
    }

    async fn deliver(&self, inbox_id: i64, message: &ParsedMessage) -> Result<(), DeliveryError> {
        match *self.fail_delivery.lock().unwrap() {
            Some(Fail::Unavailable) => return Err(DeliveryError::Unavailable { misconfigured: false }),
            Some(Fail::TooLarge) => return Err(DeliveryError::TooLarge),
            Some(Fail::Rejected) => return Err(DeliveryError::Rejected),
            None => {}
        }
        self.delivered.lock().unwrap().push(Delivered { inbox_id, message: message.clone() });
        Ok(())
    }
}

pub struct Options {
    pub max_message_bytes: usize,
    pub allow_insecure_auth: bool,
    pub auth_max_failures: u32,
    pub tls: Option<Arc<TlsContext>>,
}

impl Default for Options {
    fn default() -> Self {
        Self { max_message_bytes: 1_000_000, allow_insecure_auth: false, auth_max_failures: 5, tls: None }
    }
}

pub struct TestServer {
    pub addr: std::net::SocketAddr,
    pub backend: Arc<MockBackend>,
    _shutdown: CancellationToken,
}

pub fn test_config(opts: &Options) -> Config {
    Config::from_lookup(|k| {
        match k {
            "ROOSTLE_BASE_URL" => Some("http://localhost".to_owned()),
            "ROOSTLE_SMTP_SERVICE_TOKEN" => Some("test-token".to_owned()),
            "ROOSTLE_ALLOW_INSECURE_AUTH" => Some("true".to_owned()),
            _ => None,
        }
    })
    .map(|mut c| {
        c.max_message_bytes = opts.max_message_bytes;
        c.allow_insecure_auth = opts.allow_insecure_auth;
        c.auth_max_failures = opts.auth_max_failures;
        c.auth_failure_delay = Duration::ZERO;
        c.idle_timeout = Duration::from_secs(5);
        c.hostname = "smtp.test".into();
        c
    })
    .unwrap()
}

pub async fn start(mode: Mode, opts: Options) -> TestServer {
    let config = Arc::new(test_config(&opts));
    let backend = Arc::new(MockBackend::new());
    let shared = Arc::new(Shared {
        throttle: AuthThrottle::new(config.auth_max_failures, Duration::from_secs(60), Duration::ZERO),
        config,
        backend: backend.clone(),
        tls: opts.tls,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    tokio::spawn(server::serve(
        listener,
        mode,
        shared,
        Arc::new(Semaphore::new(50)),
        TaskTracker::new(),
        shutdown.clone(),
    ));
    TestServer { addr, backend, _shutdown: shutdown }
}

/// Minimal line-oriented SMTP client.
pub struct Client<S> {
    pub stream: BufReader<S>,
}

impl Client<tokio::net::TcpStream> {
    pub async fn connect(addr: std::net::SocketAddr) -> Self {
        Client { stream: BufReader::new(tokio::net::TcpStream::connect(addr).await.unwrap()) }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Client<S> {
    /// Reads one (possibly multi-line) reply; returns the full text.
    pub async fn reply(&mut self) -> String {
        let mut all = String::new();
        loop {
            let mut line = String::new();
            let n = tokio::time::timeout(Duration::from_secs(5), self.stream.read_line(&mut line))
                .await
                .expect("reply timed out")
                .unwrap();
            assert!(n > 0, "connection closed; got so far: {all:?}");
            all.push_str(&line);
            if line.as_bytes().get(3) != Some(&b'-') {
                return all;
            }
        }
    }

    pub async fn send_raw(&mut self, data: &[u8]) {
        self.stream.write_all(data).await.unwrap();
        self.stream.flush().await.unwrap();
    }

    pub async fn cmd(&mut self, line: &str) -> String {
        self.send_raw(format!("{line}\r\n").as_bytes()).await;
        self.reply().await
    }

    pub async fn data(&mut self, body: &str) -> String {
        assert!(self.cmd("DATA").await.starts_with("354"));
        self.send_raw(format!("{body}\r\n.\r\n").as_bytes()).await;
        self.reply().await
    }
}

pub fn plain(user: &str, pass: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(format!("\0{user}\0{pass}"))
}
