use roostle_smtp::backend::{Backend, DeliveryError, LookupError};
use roostle_smtp::config::Config;
use roostle_smtp::laravel::HttpBackend;
use roostle_smtp::message;
use serde_json::json;
use time::OffsetDateTime;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn backend(server: &MockServer) -> HttpBackend {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let uri = server.uri();
    let config = Config::from_lookup(|k| match k {
        "ROOSTLE_BASE_URL" => Some(uri.clone()),
        "ROOSTLE_SMTP_SERVICE_TOKEN" => Some("tok".into()),
        "ROOSTLE_ALLOW_INSECURE_AUTH" => Some("true".into()),
        _ => None,
    })
    .unwrap();
    HttpBackend::new(&config).unwrap()
}

#[tokio::test]
async fn recipient_validation_maps_statuses() {
    let server = MockServer::start().await;
    let b = backend(&server);

    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/recipients/validate"))
        .and(header("authorization", "Bearer tok"))
        .and(header("accept", "application/json"))
        .and(body_json(json!({ "address": "ok@catch.test" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "inbox_id": 42 })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/recipients/validate"))
        .and(body_json(json!({ "address": "nope@catch.test" })))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/recipients/validate"))
        .and(body_json(json!({ "address": "bad-token@catch.test" })))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/recipients/validate"))
        .and(body_json(json!({ "address": "boom@catch.test" })))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    assert_eq!(b.validate_recipient("ok@catch.test").await, Ok(42));
    assert_eq!(b.validate_recipient("nope@catch.test").await, Err(LookupError::Unknown));
    assert_eq!(b.validate_recipient("bad-token@catch.test").await, Err(LookupError::Unavailable { misconfigured: true }));
    assert_eq!(b.validate_recipient("boom@catch.test").await, Err(LookupError::Unavailable { misconfigured: false }));
}

#[tokio::test]
async fn credential_validation_maps_statuses() {
    let server = MockServer::start().await;
    let b = backend(&server);
    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/credentials/validate"))
        .and(body_json(json!({ "username": "u", "password": "p" })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "inbox_id": 7 })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/credentials/validate"))
        .and(body_json(json!({ "username": "u", "password": "wrong" })))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/credentials/validate"))
        .and(body_json(json!({ "username": "u", "password": "bad-token" })))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    assert_eq!(b.validate_credentials("u", "p").await, Ok(7));
    assert_eq!(b.validate_credentials("u", "wrong").await, Err(LookupError::Unknown));
    assert_eq!(
        b.validate_credentials("u", "bad-token").await,
        Err(LookupError::Unavailable { misconfigured: true })
    );
}

fn sample() -> message::ParsedMessage {
    let raw = "From: Ann <ann@example.com>\r\nTo: a@x.test\r\nSubject: Hello\r\nMessage-ID: <m1@example.com>\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nplain body\r\n--B\r\nContent-Type: application/pdf; name=inv.pdf\r\nContent-Disposition: attachment; filename=inv.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n--B--\r\n";
    message::parse(raw.as_bytes().to_vec(), "env@example.com", OffsetDateTime::UNIX_EPOCH)
}

#[tokio::test]
async fn delivery_sends_the_contracted_multipart_fields() {
    let server = MockServer::start().await;
    let b = backend(&server);
    Mock::given(method("POST"))
        .and(path("/api/internal/smtp/messages"))
        .and(header("authorization", "Bearer tok"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": 123 })))
        .mount(&server)
        .await;

    assert_eq!(b.deliver(42, &sample()).await, Ok(()));

    let requests = server.received_requests().await.unwrap();
    let ct = requests[0].headers.get("content-type").unwrap().to_str().unwrap().to_owned();
    assert!(ct.starts_with("multipart/form-data; boundary="));
    let body = String::from_utf8_lossy(&requests[0].body).into_owned();
    for expected in [
        "name=\"inbox_id\"\r\n\r\n42",
        "name=\"message_id\"\r\n\r\n<m1@example.com>",
        "name=\"from_address\"\r\n\r\nann@example.com",
        "name=\"from_name\"\r\n\r\nAnn",
        "name=\"to[0][address]\"\r\n\r\na@x.test",
        "name=\"subject\"\r\n\r\nHello",
        "name=\"text_body\"",
        "name=\"headers[0][name]\"\r\n\r\nFrom",
        "name=\"received_at\"\r\n\r\n1970-01-01T00:00:00Z",
        "name=\"raw\"; filename=\"message.eml\"",
        "name=\"attachments[]\"; filename=\"inv.pdf\"",
        "Content-Type: application/pdf",
    ] {
        assert!(body.contains(expected), "missing {expected:?} in:\n{body}");
    }
    assert!(!body.contains("name=\"html_body\""), "absent optional fields are omitted");
}

#[tokio::test]
async fn delivery_maps_statuses() {
    let server = MockServer::start().await;
    let b = backend(&server);
    let m = sample();

    let cases: Vec<(ResponseTemplate, DeliveryError)> = vec![
        (
            ResponseTemplate::new(422).set_body_json(json!({ "message": "x", "errors": { "raw": ["too large"] } })),
            DeliveryError::TooLarge,
        ),
        (
            ResponseTemplate::new(422).set_body_json(json!({ "message": "x", "errors": { "attachments.0": ["too large"] } })),
            DeliveryError::TooLarge,
        ),
        (
            ResponseTemplate::new(422).set_body_json(json!({ "message": "x", "errors": { "inbox_id": ["gone"] } })),
            DeliveryError::Rejected,
        ),
        (ResponseTemplate::new(422), DeliveryError::Rejected),
        (ResponseTemplate::new(401), DeliveryError::Unavailable { misconfigured: true }),
        (ResponseTemplate::new(503), DeliveryError::Unavailable { misconfigured: false }),
        (ResponseTemplate::new(413), DeliveryError::Unavailable { misconfigured: false }),
    ];
    for (response, expected) in cases {
        server.reset().await;
        Mock::given(method("POST")).and(path("/api/internal/smtp/messages")).respond_with(response).mount(&server).await;
        assert_eq!(b.deliver(1, &m).await, Err(expected));
    }
}

#[tokio::test]
async fn delivery_timeout_is_temporary_and_not_retried() {
    let server = MockServer::start().await;
    let uri = server.uri();
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut config = Config::from_lookup(|k| match k {
        "ROOSTLE_BASE_URL" => Some(uri.clone()),
        "ROOSTLE_SMTP_SERVICE_TOKEN" => Some("tok".into()),
        "ROOSTLE_ALLOW_INSECURE_AUTH" => Some("true".into()),
        _ => None,
    })
    .unwrap();
    config.delivery_timeout = std::time::Duration::from_millis(100);
    let b = HttpBackend::new(&config).unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_delay(std::time::Duration::from_millis(500)))
        .mount(&server)
        .await;
    assert_eq!(b.deliver(1, &sample()).await, Err(DeliveryError::Unavailable { misconfigured: false }));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
