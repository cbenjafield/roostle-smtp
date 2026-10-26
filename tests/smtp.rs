mod common;

use std::sync::Arc;

use common::*;
use roostle_smtp::session::Mode;
use roostle_smtp::tls::TlsContext;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, crypto::ring};

const MSG: &str = "From: Sender <s@example.com>\r\nTo: known1@catch.test\r\nSubject: Hi\r\n\r\nbody";

async fn catch() -> (TestServer, Client<tokio::net::TcpStream>) {
    catch_with(Options::default()).await
}

async fn catch_with(opts: Options) -> (TestServer, Client<tokio::net::TcpStream>) {
    let server = start(Mode::Catch, opts).await;
    let mut c = Client::connect(server.addr).await;
    assert!(c.reply().await.starts_with("220 smtp.test"));
    assert!(c.cmd("EHLO client.test").await.starts_with("250"));
    (server, c)
}

#[tokio::test]
async fn catch_accepts_known_and_rejects_unknown_recipients() {
    let (_s, mut c) = catch().await;
    assert!(c.cmd("MAIL FROM:<s@example.com>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<KNOWN1@catch.test>").await.starts_with("250"));
    assert!(c.cmd("RCPT TO:<nobody@catch.test>").await.starts_with("550 5.1.1"));
    assert!(c.cmd("RCPT TO:<known1@elsewhere.test>").await.starts_with("550"));
}

#[tokio::test]
async fn catch_never_advertises_auth_and_rejects_it() {
    let server = start(Mode::Catch, Options { allow_insecure_auth: true, ..Default::default() }).await;
    let mut c = Client::connect(server.addr).await;
    c.reply().await;
    let ehlo = c.cmd("EHLO x").await;
    assert!(!ehlo.contains("AUTH"));
    assert!(ehlo.contains("SIZE 1000000"));
    assert!(c.cmd("AUTH PLAIN").await.starts_with("503"));
}

#[tokio::test]
async fn two_recipients_for_one_inbox_deliver_once() {
    let (s, mut c) = catch().await;
    c.cmd("MAIL FROM:<s@example.com>").await;
    c.cmd("RCPT TO:<known1@catch.test>").await;
    c.cmd("RCPT TO:<known2@catch.test>").await;
    assert!(c.data(MSG).await.starts_with("250"));
    let delivered = s.backend.delivered.lock().unwrap();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].inbox_id, 1);
    assert_eq!(delivered[0].message.subject.as_deref(), Some("Hi"));
    assert_eq!(delivered[0].message.text_body.as_deref(), Some("body\r\n"));
}

#[tokio::test]
async fn recipients_for_two_inboxes_deliver_twice() {
    let (s, mut c) = catch().await;
    c.cmd("MAIL FROM:<s@example.com>").await;
    c.cmd("RCPT TO:<known1@catch.test>").await;
    c.cmd("RCPT TO:<other@catch.test>").await;
    assert!(c.data(MSG).await.starts_with("250"));
    let ids: Vec<_> = s.backend.delivered.lock().unwrap().iter().map(|d| d.inbox_id).collect();
    assert_eq!(ids, [1, 2]);
}

#[tokio::test]
async fn delivery_failures_map_to_the_right_replies_and_never_250() {
    for (fail, expected) in [(Fail::Unavailable, "451 4.3.0"), (Fail::TooLarge, "552 5.3.4"), (Fail::Rejected, "554 5.6.0")] {
        let (s, mut c) = catch().await;
        *s.backend.fail_delivery.lock().unwrap() = Some(fail);
        c.cmd("MAIL FROM:<s@example.com>").await;
        c.cmd("RCPT TO:<known1@catch.test>").await;
        let reply = c.data(MSG).await;
        assert!(reply.starts_with(expected), "{reply}");
        assert!(s.backend.delivered.lock().unwrap().is_empty());
        // The session is still usable for another attempt.
        assert!(c.cmd("NOOP").await.starts_with("250"));
    }
}

#[tokio::test]
async fn recipient_validation_outage_is_a_temporary_error() {
    let (s, mut c) = catch().await;
    *s.backend.recipient_unavailable.lock().unwrap() = true;
    c.cmd("MAIL FROM:<s@example.com>").await;
    assert!(c.cmd("RCPT TO:<known1@catch.test>").await.starts_with("451 4.3.0"));
}

#[tokio::test]
async fn oversize_messages_get_552_at_mail_and_at_data() {
    let (s, mut c) = catch_with(Options { max_message_bytes: 1000, ..Default::default() }).await;
    assert!(c.cmd("MAIL FROM:<s@example.com> SIZE=5000").await.starts_with("552 5.3.4"));
    assert!(c.cmd("MAIL FROM:<s@example.com> SIZE=100").await.starts_with("250"));
    c.cmd("RCPT TO:<known1@catch.test>").await;
    let big = format!("Subject: big\r\n\r\n{}", vec!["x".repeat(60); 50].join("\r\n"));
    assert!(c.data(&big).await.starts_with("552 5.3.4"));
    assert!(s.backend.delivered.lock().unwrap().is_empty());
    // The connection survives and a small message still goes through.
    c.cmd("MAIL FROM:<s@example.com>").await;
    c.cmd("RCPT TO:<known1@catch.test>").await;
    assert!(c.data(MSG).await.starts_with("250"));
}

#[tokio::test]
async fn dot_stuffing_and_bare_lf_are_handled() {
    let (s, mut c) = catch().await;
    c.cmd("MAIL FROM:<s@example.com>").await;
    c.cmd("RCPT TO:<known1@catch.test>").await;
    c.cmd("DATA").await;
    c.send_raw(b"Subject: dots\n\n..leading dot\r\n.\r\n").await;
    assert!(c.reply().await.starts_with("250"));
    let delivered = s.backend.delivered.lock().unwrap();
    assert_eq!(&delivered[0].message.raw[..], b"Subject: dots\r\n\r\n.leading dot\r\n");
}

#[tokio::test]
async fn sequence_errors() {
    let (_s, mut c) = catch().await;
    assert!(c.cmd("RCPT TO:<known1@catch.test>").await.starts_with("503"));
    assert!(c.cmd("DATA").await.starts_with("503"));
    c.cmd("MAIL FROM:<s@example.com>").await;
    assert!(c.cmd("DATA").await.starts_with("503"), "DATA without a valid recipient");
    assert!(c.cmd("BOGUS").await.starts_with("500"));
    assert!(c.cmd("RSET").await.starts_with("250"));
    assert!(c.cmd("QUIT").await.starts_with("221"));
}

// ---------------------------------------------------------------- submission

#[tokio::test]
async fn submission_refuses_auth_and_mail_before_tls() {
    let server = start(Mode::Submission, Options::default()).await;
    let mut c = Client::connect(server.addr).await;
    c.reply().await;
    let ehlo = c.cmd("EHLO x").await;
    assert!(!ehlo.contains("AUTH"), "{ehlo}");
    let auth = format!("AUTH PLAIN {}", plain("rstuser", "secret"));
    assert!(c.cmd(&auth).await.starts_with("530 5.7.0"));
    assert!(c.cmd("MAIL FROM:<a@b.test>").await.starts_with("530"));
    assert_eq!(*server.backend.credential_calls.lock().unwrap(), 0);
}

async fn submission() -> (TestServer, Client<tokio::net::TcpStream>) {
    let server = start(Mode::Submission, Options { allow_insecure_auth: true, ..Default::default() }).await;
    let mut c = Client::connect(server.addr).await;
    c.reply().await;
    assert!(c.cmd("EHLO x").await.contains("AUTH PLAIN LOGIN"));
    (server, c)
}

#[tokio::test]
async fn submission_rejects_bad_credentials_and_accepts_any_recipient_after_auth() {
    let (s, mut c) = submission().await;
    assert!(c.cmd("MAIL FROM:<a@b.test>").await.starts_with("530"));
    let bad = format!("AUTH PLAIN {}", plain("rstuser", "wrong"));
    assert!(c.cmd(&bad).await.starts_with("535 5.7.8"));
    let good = format!("AUTH PLAIN {}", plain("rstuser", "secret"));
    assert!(c.cmd(&good).await.starts_with("235"));

    c.cmd("MAIL FROM:<a@b.test>").await;
    for rcpt in ["x@anywhere.test", "y@elsewhere.test", "known1@catch.test"] {
        assert!(c.cmd(&format!("RCPT TO:<{rcpt}>")).await.starts_with("250"));
    }
    assert!(c.data(MSG).await.starts_with("250"));
    let delivered = s.backend.delivered.lock().unwrap();
    assert_eq!(delivered.len(), 1, "one copy regardless of recipient count");
    assert_eq!(delivered[0].inbox_id, 5);
}

#[tokio::test]
async fn auth_login_two_step_and_cancel() {
    use base64::Engine;
    let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
    let (_s, mut c) = submission().await;
    assert!(c.cmd("AUTH LOGIN").await.starts_with("334 VXNlcm5hbWU6"));
    assert!(c.cmd(&b64("rstuser")).await.starts_with("334 UGFzc3dvcmQ6"));
    assert!(c.cmd(&b64("secret")).await.starts_with("235"));

    let (_s, mut c) = submission().await;
    assert!(c.cmd("AUTH PLAIN").await.starts_with("334"));
    assert!(c.cmd("*").await.starts_with("501"));
    assert!(c.cmd("AUTH PLAIN !!!notbase64").await.starts_with("501"));
}

#[tokio::test]
async fn repeated_failed_auth_from_one_ip_is_throttled_across_connections() {
    let server = start(Mode::Submission, Options { allow_insecure_auth: true, auth_max_failures: 2, ..Default::default() }).await;
    let bad = format!("AUTH PLAIN {}", plain("rstuser", "wrong"));

    let mut c = Client::connect(server.addr).await;
    c.reply().await;
    c.cmd("EHLO x").await;
    assert!(c.cmd(&bad).await.starts_with("535"));
    assert!(c.cmd(&bad).await.starts_with("535"));
    // Even the correct password is refused once the IP has used its failures.
    let good = format!("AUTH PLAIN {}", plain("rstuser", "secret"));
    assert!(c.cmd(&good).await.starts_with("421 4.7.0"));

    let mut c2 = Client::connect(server.addr).await;
    c2.reply().await;
    c2.cmd("EHLO x").await;
    assert!(c2.cmd(&good).await.starts_with("421 4.7.0"));
    assert_eq!(*server.backend.credential_calls.lock().unwrap(), 2);
}

#[tokio::test]
async fn starttls_then_auth_and_deliver() {
    let _ = ring::default_provider().install_default();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let tls = Arc::new(TlsContext::from_pem(cert.cert.pem().as_bytes(), cert.signing_key.serialize_pem().as_bytes()).unwrap());
    let server = start(Mode::Submission, Options { tls: Some(tls), ..Default::default() }).await;

    let mut c = Client::connect(server.addr).await;
    c.reply().await;
    let ehlo = c.cmd("EHLO x").await;
    assert!(ehlo.contains("STARTTLS") && !ehlo.contains("AUTH"), "{ehlo}");
    assert!(c.cmd("STARTTLS").await.starts_with("220"));

    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = c.stream.into_inner();
    let stream = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    let mut c = Client { stream: tokio::io::BufReader::new(stream) };

    // Pre-TLS state is forgotten: EHLO is required again.
    assert!(c.cmd("MAIL FROM:<a@b.test>").await.starts_with("503"));
    let ehlo = c.cmd("EHLO x").await;
    assert!(ehlo.contains("AUTH PLAIN LOGIN") && !ehlo.contains("STARTTLS"), "{ehlo}");
    assert!(c.cmd(&format!("AUTH PLAIN {}", plain("rstuser", "secret"))).await.starts_with("235"));
    c.cmd("MAIL FROM:<a@b.test>").await;
    c.cmd("RCPT TO:<z@anywhere.test>").await;
    assert!(c.data(MSG).await.starts_with("250"));
    assert_eq!(server.backend.delivered.lock().unwrap()[0].inbox_id, 5);
}
