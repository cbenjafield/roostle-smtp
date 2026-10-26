//! Turns a raw RFC 5322 message into the fields Laravel's delivery endpoint takes.

use bytes::Bytes;
use mail_parser::{HeaderValue, Message, MessageParser, MimeHeaders};
use time::OffsetDateTime;

const MAX_MESSAGE_ID: usize = 998;
const MAX_ADDRESS: usize = 320;
const MAX_NAME: usize = 255;
const MAX_SUBJECT: usize = 998;
const UNKNOWN_SENDER: &str = "unknown@unknown.invalid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAddress {
    pub address: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub data: Bytes,
}

#[derive(Debug, Clone)]
pub struct ParsedMessage {
    pub message_id: Option<String>,
    pub from_address: String,
    pub from_name: Option<String>,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub subject: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub headers: Vec<(String, String)>,
    pub received_at: OffsetDateTime,
    pub raw: Bytes,
    pub attachments: Vec<Attachment>,
}

/// Parse `raw`. Never fails: an unparseable message is still delivered with
/// its `raw` bytes and the envelope sender, so nothing accepted is lost.
pub fn parse(raw: Vec<u8>, envelope_from: &str, received_at: OffsetDateTime) -> ParsedMessage {
    let raw = Bytes::from(raw);
    let fallback_from = if envelope_from.is_empty() { UNKNOWN_SENDER } else { envelope_from };

    let Some(msg) = MessageParser::default().parse(&raw[..]) else {
        return ParsedMessage {
            message_id: None,
            from_address: clip(fallback_from, MAX_ADDRESS),
            from_name: None,
            to: vec![],
            cc: vec![],
            subject: None,
            text_body: None,
            html_body: None,
            headers: vec![],
            received_at,
            raw,
            attachments: vec![],
        };
    };

    let from = msg
        .from()
        .and_then(|a| a.iter().find(|a| a.address().is_some_and(|s| !s.is_empty())));

    ParsedMessage {
        message_id: msg
            .header_raw("Message-ID")
            .map(|v| clip(&unfold(v), MAX_MESSAGE_ID))
            .filter(|v| !v.is_empty()),
        from_address: clip(from.and_then(|a| a.address()).unwrap_or(fallback_from), MAX_ADDRESS),
        from_name: from.and_then(|a| a.name()).filter(|n| !n.is_empty()).map(|n| clip(n, MAX_NAME)),
        to: addresses(msg.to()),
        cc: addresses(msg.cc()),
        subject: msg.subject().map(|s| clip(s, MAX_SUBJECT)),
        text_body: text_body(&msg),
        html_body: html_body(&msg),
        headers: headers(&msg, &raw),
        received_at,
        attachments: attachments(&msg),
        raw,
    }
}

fn addresses(addr: Option<&mail_parser::Address<'_>>) -> Vec<EmailAddress> {
    addr.map(|a| {
        a.iter()
            .filter_map(|a| {
                let address = a.address().filter(|s| !s.is_empty())?;
                Some(EmailAddress {
                    address: clip(address, MAX_ADDRESS),
                    name: a.name().filter(|n| !n.is_empty()).map(|n| clip(n, MAX_NAME)),
                })
            })
            .collect()
    })
    .unwrap_or_default()
}

/// The first genuine `text/plain` body part. `Message::body_text` would also
/// synthesise text from HTML, which isn't what the contract asks for.
fn text_body(msg: &Message<'_>) -> Option<String> {
    msg.text_bodies()
        .find(|p| {
            p.is_text()
                && !p.is_text_html()
                && p.content_type()
                    .and_then(|c| c.subtype())
                    .is_none_or(|s| s.eq_ignore_ascii_case("plain"))
        })
        .and_then(|p| p.text_contents())
        .map(str::to_owned)
}

fn html_body(msg: &Message<'_>) -> Option<String> {
    msg.html_bodies()
        .find(|p| p.is_text_html())
        .and_then(|p| p.text_contents())
        .map(str::to_owned)
}

fn headers(msg: &Message<'_>, raw: &[u8]) -> Vec<(String, String)> {
    msg.headers()
        .iter()
        .map(|h| {
            let value = match h.value() {
                HeaderValue::Text(t) => t.to_string(),
                HeaderValue::TextList(l) => l.join(", "),
                HeaderValue::DateTime(d) => d.to_rfc822(),
                HeaderValue::Address(a) => a
                    .iter()
                    .filter_map(|a| {
                        let address = a.address()?;
                        Some(match a.name() {
                            Some(n) => format!("{n} <{address}>"),
                            None => address.to_owned(),
                        })
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
                _ => raw
                    .get(h.offset_start() as usize..h.offset_end() as usize)
                    .map(|b| unfold(&String::from_utf8_lossy(b)))
                    .unwrap_or_default(),
            };
            (h.name().to_owned(), value)
        })
        .collect()
}

fn attachments(msg: &Message<'_>) -> Vec<Attachment> {
    msg.attachments()
        .enumerate()
        .map(|(i, part)| {
            let filename = part
                .attachment_name()
                .map(sanitize_filename)
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| {
                    if part.is_message() {
                        format!("attachment-{}.eml", i + 1)
                    } else {
                        format!("attachment-{}", i + 1)
                    }
                });
            let content_type = part
                .content_type()
                .map(|c| match c.subtype() {
                    Some(sub) => format!("{}/{}", c.ctype(), sub),
                    None => c.ctype().to_owned(),
                })
                .unwrap_or_else(|| "application/octet-stream".into());
            Attachment { filename, content_type, data: Bytes::copy_from_slice(part.contents()) }
        })
        .collect()
}

/// Drop any path and control characters, so the name is safe to place in a
/// multipart `Content-Disposition` and in Laravel's storage.
fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    clip(base.chars().filter(|c| !c.is_control()).collect::<String>().trim(), MAX_NAME)
}

/// Collapse header folding (CRLF + whitespace) and trim.
fn unfold(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, line) in value.lines().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(if i == 0 { line.trim_end() } else { line.trim() });
    }
    out.trim().to_owned()
}

fn clip(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => s[..idx].to_owned(),
        None => s.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(raw: &str, env: &str) -> ParsedMessage {
        parse(raw.replace('\n', "\r\n").into_bytes(), env, OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn simple_message_without_subject() {
        let m = p("From: Ann <ann@example.com>\nTo: a@x.test, \"B\" <b@x.test>\nCc: c@x.test\nMessage-ID: <1@example.com>\n\nhello\n", "env@x.test");
        assert_eq!(m.from_address, "ann@example.com");
        assert_eq!(m.from_name.as_deref(), Some("Ann"));
        assert_eq!(m.to.len(), 2);
        assert_eq!(m.to[1].name.as_deref(), Some("B"));
        assert_eq!(m.cc[0].address, "c@x.test");
        assert_eq!(m.subject, None);
        assert_eq!(m.message_id.as_deref(), Some("<1@example.com>"));
        assert_eq!(m.text_body.as_deref().map(str::trim), Some("hello"));
        assert!(m.html_body.is_none());
        assert_eq!(m.headers.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), ["From", "To", "Cc", "Message-ID"]);
    }

    #[test]
    fn multipart_alternative_with_attachment() {
        let m = p(
            "From: a@x.test\nSubject: =?UTF-8?B?SMOpbGxv?=\nX-Mailer: Example\nContent-Type: multipart/mixed; boundary=\"M\"\n\n--M\nContent-Type: multipart/alternative; boundary=\"A\"\n\n--A\nContent-Type: text/plain\n\nplain\n--A\nContent-Type: text/html\n\n<p>rich</p>\n--A--\n--M\nContent-Type: application/pdf; name=\"../inv.pdf\"\nContent-Disposition: attachment; filename=\"../inv.pdf\"\nContent-Transfer-Encoding: base64\n\nSGVsbG8=\n--M--\n",
            "",
        );
        assert_eq!(m.subject.as_deref(), Some("Héllo"));
        assert_eq!(m.text_body.as_deref().map(str::trim), Some("plain"));
        assert_eq!(m.html_body.as_deref().map(str::trim), Some("<p>rich</p>"));
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].filename, "inv.pdf");
        assert_eq!(m.attachments[0].content_type, "application/pdf");
        assert_eq!(&m.attachments[0].data[..], b"Hello");
        assert!(m.headers.contains(&("X-Mailer".into(), "Example".into())));
    }

    #[test]
    fn html_only_has_no_text_body() {
        let m = p("From: a@x.test\nContent-Type: text/html\n\n<b>hi</b>\n", "");
        assert!(m.text_body.is_none());
        assert!(m.html_body.is_some());
    }

    #[test]
    fn non_utf8_charset_is_decoded() {
        let mut raw = b"From: a@x.test\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncaf".to_vec();
        raw.push(0xE9);
        raw.extend_from_slice(b"\r\n");
        let m = parse(raw, "", OffsetDateTime::UNIX_EPOCH);
        assert_eq!(m.text_body.as_deref().map(str::trim), Some("café"));
    }

    #[test]
    fn missing_from_falls_back_to_envelope() {
        let m = p("Subject: x\n\nbody\n", "bounce@x.test");
        assert_eq!(m.from_address, "bounce@x.test");
        let m = p("Subject: x\n\nbody\n", "");
        assert_eq!(m.from_address, UNKNOWN_SENDER);
    }

    #[test]
    fn folded_headers_are_unfolded() {
        assert_eq!(unfold("a\r\n  b\r\n"), "a b");
    }
}
