//! One SMTP connection. The same state machine serves both listeners; `Mode`
//! switches between the catch rules (validate each recipient, no auth) and the
//! submission rules (TLS + AUTH, accept any recipient, deliver to one inbox).

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use crate::backend::{Backend, DeliveryError, LookupError};
use crate::config::Config;
use crate::message;
use crate::throttle::AuthThrottle;
use crate::tls::TlsContext;

const MAX_COMMAND_LINE: usize = 4096;
const MAX_RECIPIENTS: usize = 100;
const MAX_BAD_COMMANDS: u32 = 20;
const MAX_AUTH_FAILURES_PER_CONNECTION: u32 = 3;
const MAX_USERNAME: usize = 64;
const MAX_PASSWORD: usize = 255;
/// A DATA line with no newline is flushed to the message once it reaches this.
const PARTIAL_LINE_FLUSH: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Catch,
    Submission,
}

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

pub struct Shared {
    pub config: Arc<Config>,
    pub backend: Arc<dyn Backend>,
    pub throttle: AuthThrottle,
    pub tls: Option<Arc<TlsContext>>,
}

pub async fn handle(shared: Arc<Shared>, mode: Mode, io: Box<dyn Io>, peer: IpAddr) {
    let mut session = Session::new(shared, mode, peer);
    if let Err(e) = session.run(io).await {
        debug!(%peer, error = %e, "connection ended");
    }
}

// ---------------------------------------------------------------- connection

enum Line {
    Text(String),
    TooLong,
    Eof,
}

enum Data {
    Complete(Vec<u8>),
    TooLarge,
}

struct Conn {
    io: Box<dyn Io>,
    buf: Vec<u8>,
    pos: usize,
    idle: Duration,
}

impl Conn {
    fn new(io: Box<dyn Io>, idle: Duration) -> Self {
        Self { io, buf: Vec::new(), pos: 0, idle }
    }

    async fn reply(&mut self, code: u16, text: &str) -> io::Result<()> {
        self.io.write_all(format!("{code} {text}\r\n").as_bytes()).await?;
        self.io.flush().await
    }

    async fn reply_multi(&mut self, code: u16, lines: &[String]) -> io::Result<()> {
        let mut out = String::new();
        for (i, line) in lines.iter().enumerate() {
            let sep = if i + 1 == lines.len() { ' ' } else { '-' };
            out.push_str(&format!("{code}{sep}{line}\r\n"));
        }
        self.io.write_all(out.as_bytes()).await?;
        self.io.flush().await
    }

    async fn fill(&mut self) -> io::Result<()> {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.reserve(8192);
        match timeout(self.idle, self.io.read_buf(&mut self.buf)).await {
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
            Ok(Err(e)) => Err(e),
            Ok(Ok(0)) => Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(Ok(_)) => Ok(()),
        }
    }

    async fn read_line(&mut self) -> io::Result<Line> {
        loop {
            if let Some(nl) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let mut line = &self.buf[self.pos..self.pos + nl];
                if line.last() == Some(&b'\r') {
                    line = &line[..line.len() - 1];
                }
                let text = String::from_utf8_lossy(line).into_owned();
                self.pos += nl + 1;
                return Ok(Line::Text(text));
            }
            if self.buf.len() - self.pos > MAX_COMMAND_LINE {
                return Ok(Line::TooLong);
            }
            match self.fill().await {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Line::Eof),
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads a dot-terminated message body, undoing dot-stuffing and
    /// normalising line endings to CRLF. Anything past `max` is counted and
    /// dropped so the client still gets a reply once it has finished sending.
    async fn read_data(&mut self, max: usize) -> io::Result<Data> {
        let mut out = Vec::new();
        let mut total = 0usize;
        let mut overflow = false;
        let mut at_line_start = true;
        loop {
            while let Some(nl) = self.buf[self.pos..].iter().position(|&b| b == b'\n') {
                let mut line = &self.buf[self.pos..self.pos + nl];
                if line.last() == Some(&b'\r') {
                    line = &line[..line.len() - 1];
                }
                if at_line_start && line == b"." {
                    self.pos += nl + 1;
                    return Ok(if overflow { Data::TooLarge } else { Data::Complete(out) });
                }
                let content = if at_line_start && line.first() == Some(&b'.') { &line[1..] } else { line };
                total += content.len() + 2;
                if !overflow {
                    if total > max {
                        overflow = true;
                        out = Vec::new();
                    } else {
                        out.extend_from_slice(content);
                        out.extend_from_slice(b"\r\n");
                    }
                }
                self.pos += nl + 1;
                at_line_start = true;
            }
            // No newline in the buffered remainder. Flush absurdly long lines
            // rather than buffering them, holding back a trailing CR that may
            // be half of a CRLF.
            let pending = self.buf.len() - self.pos;
            if pending > PARTIAL_LINE_FLUSH {
                let mut chunk = &self.buf[self.pos..];
                if chunk.last() == Some(&b'\r') {
                    chunk = &chunk[..chunk.len() - 1];
                }
                if at_line_start && chunk.first() == Some(&b'.') {
                    chunk = &chunk[1..];
                    self.pos += 1;
                }
                total += chunk.len();
                if !overflow {
                    if total > max {
                        overflow = true;
                        out = Vec::new();
                    } else {
                        out.extend_from_slice(chunk);
                    }
                }
                self.pos += chunk.len();
                at_line_start = false;
            }
            self.fill().await?;
        }
    }

    /// Wraps the stream in TLS. Refuses if the client pipelined data behind
    /// STARTTLS, which would otherwise be processed as if it were encrypted.
    async fn upgrade(self, tls: &TlsContext) -> io::Result<Conn> {
        if self.pos != self.buf.len() {
            return Err(io::Error::other("data pipelined after STARTTLS"));
        }
        let stream = tls.acceptor().accept(self.io).await?;
        Ok(Conn::new(Box::new(stream), self.idle))
    }
}

// ------------------------------------------------------------------- session

struct Recipient {
    inbox_id: i64,
}

struct Session {
    shared: Arc<Shared>,
    mode: Mode,
    peer: IpAddr,
    helo: bool,
    tls_active: bool,
    auth_inbox: Option<i64>,
    mail_from: Option<String>,
    recipients: Vec<Recipient>,
    recipient_count: usize,
    auth_failures: u32,
}

enum Flow {
    Continue,
    Quit,
}

impl Session {
    fn new(shared: Arc<Shared>, mode: Mode, peer: IpAddr) -> Self {
        Self {
            shared,
            mode,
            peer,
            helo: false,
            tls_active: false,
            auth_inbox: None,
            mail_from: None,
            recipients: Vec::new(),
            recipient_count: 0,
            auth_failures: 0,
        }
    }

    fn reset_transaction(&mut self) {
        self.mail_from = None;
        self.recipients.clear();
        self.recipient_count = 0;
    }

    fn can_auth(&self) -> bool {
        self.mode == Mode::Submission && (self.tls_active || self.shared.config.allow_insecure_auth)
    }

    async fn run(&mut self, io: Box<dyn Io>) -> io::Result<()> {
        let config = self.shared.config.clone();
        let mut conn = Conn::new(io, config.idle_timeout);
        conn.reply(220, &format!("{} ESMTP Roostle", config.hostname)).await?;
        let mut bad_commands = 0u32;

        loop {
            let line = match conn.read_line().await {
                Ok(Line::Text(l)) => l,
                Ok(Line::Eof) => return Ok(()),
                Ok(Line::TooLong) => {
                    conn.reply(500, "5.5.2 Line too long").await?;
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                    let _ = conn.reply(421, "4.4.2 Timeout, closing connection").await;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let line = line.trim();
            let (verb, arg) = line.split_once(' ').map_or((line, ""), |(v, a)| (v, a.trim()));

            let flow = match verb.to_ascii_uppercase().as_str() {
                "EHLO" | "HELO" => self.cmd_hello(&mut conn, verb, arg).await?,
                "STARTTLS" => {
                    let Some(tls) = self.starttls_available(&mut conn).await? else { continue };
                    conn.reply(220, "2.0.0 Ready to start TLS").await?;
                    conn = match conn.upgrade(&tls).await {
                        Ok(c) => c,
                        Err(e) => {
                            debug!(peer = %self.peer, error = %e, "TLS handshake failed");
                            return Ok(());
                        }
                    };
                    // RFC 3207: forget everything learned before TLS.
                    self.tls_active = true;
                    self.helo = false;
                    self.auth_inbox = None;
                    self.reset_transaction();
                    Flow::Continue
                }
                "AUTH" => self.cmd_auth(&mut conn, arg).await?,
                "MAIL" => self.cmd_mail(&mut conn, arg).await?,
                "RCPT" => self.cmd_rcpt(&mut conn, arg).await?,
                "DATA" => self.cmd_data(&mut conn).await?,
                "RSET" => {
                    self.reset_transaction();
                    conn.reply(250, "2.0.0 OK").await?;
                    Flow::Continue
                }
                "NOOP" => {
                    conn.reply(250, "2.0.0 OK").await?;
                    Flow::Continue
                }
                "QUIT" => {
                    conn.reply(221, "2.0.0 Bye").await?;
                    Flow::Quit
                }
                "VRFY" => {
                    conn.reply(252, "2.5.2 Cannot VRFY user").await?;
                    Flow::Continue
                }
                "HELP" => {
                    conn.reply(214, "2.0.0 See https://roostle.co.uk").await?;
                    Flow::Continue
                }
                _ => {
                    bad_commands += 1;
                    conn.reply(500, "5.5.1 Command not recognized").await?;
                    if bad_commands >= MAX_BAD_COMMANDS {
                        let _ = conn.reply(421, "4.7.0 Too many errors").await;
                        return Ok(());
                    }
                    Flow::Continue
                }
            };
            if let Flow::Quit = flow {
                return Ok(());
            }
        }
    }

    async fn cmd_hello(&mut self, conn: &mut Conn, verb: &str, arg: &str) -> io::Result<Flow> {
        if arg.is_empty() {
            conn.reply(501, "5.5.4 Domain required").await?;
            return Ok(Flow::Continue);
        }
        self.helo = true;
        self.reset_transaction();
        let host = self.shared.config.hostname.clone();
        if verb.eq_ignore_ascii_case("HELO") {
            conn.reply(250, &host).await?;
            return Ok(Flow::Continue);
        }
        let mut lines = vec![
            format!("{host} at your service"),
            format!("SIZE {}", self.shared.config.max_message_bytes),
            "8BITMIME".into(),
            "ENHANCEDSTATUSCODES".into(),
        ];
        if self.shared.tls.is_some() && !self.tls_active {
            lines.push("STARTTLS".into());
        }
        if self.can_auth() {
            lines.push("AUTH PLAIN LOGIN".into());
        }
        conn.reply_multi(250, &lines).await?;
        Ok(Flow::Continue)
    }

    async fn starttls_available(&mut self, conn: &mut Conn) -> io::Result<Option<Arc<TlsContext>>> {
        if self.tls_active {
            conn.reply(503, "5.5.1 TLS already active").await?;
            return Ok(None);
        }
        match self.shared.tls.clone() {
            Some(tls) => Ok(Some(tls)),
            None => {
                conn.reply(502, "5.5.1 STARTTLS not available").await?;
                Ok(None)
            }
        }
    }

    // ---- AUTH

    async fn cmd_auth(&mut self, conn: &mut Conn, arg: &str) -> io::Result<Flow> {
        if self.mode != Mode::Submission {
            conn.reply(503, "5.5.1 Authentication not available on this port").await?;
            return Ok(Flow::Continue);
        }
        if !self.can_auth() {
            conn.reply(530, "5.7.0 Must issue a STARTTLS command first").await?;
            return Ok(Flow::Continue);
        }
        if !self.helo {
            conn.reply(503, "5.5.1 EHLO first").await?;
            return Ok(Flow::Continue);
        }
        if self.auth_inbox.is_some() {
            conn.reply(503, "5.5.1 Already authenticated").await?;
            return Ok(Flow::Continue);
        }
        if self.mail_from.is_some() {
            conn.reply(503, "5.5.1 AUTH not permitted during a mail transaction").await?;
            return Ok(Flow::Continue);
        }
        if self.shared.throttle.is_blocked(self.peer) {
            warn!(peer = %self.peer, "AUTH refused: too many failed attempts");
            let _ = conn.reply(421, "4.7.0 Too many failed authentication attempts").await;
            return Ok(Flow::Quit);
        }

        let (mechanism, initial) = arg.split_once(' ').map_or((arg, None), |(m, i)| (m, Some(i.trim())));
        let credentials = match mechanism.to_ascii_uppercase().as_str() {
            "PLAIN" => self.read_plain(conn, initial).await?,
            "LOGIN" => self.read_login(conn, initial).await?,
            _ => {
                conn.reply(504, "5.5.4 Unrecognized authentication mechanism").await?;
                return Ok(Flow::Continue);
            }
        };
        let Some((username, password)) = credentials else { return Ok(Flow::Continue) };

        let result = if username.chars().count() > MAX_USERNAME || password.chars().count() > MAX_PASSWORD {
            // Laravel would answer 422; it can't be a valid login either way.
            Err(LookupError::Unknown)
        } else {
            self.shared.backend.validate_credentials(&username, &password).await
        };

        match result {
            Ok(inbox_id) => {
                self.auth_inbox = Some(inbox_id);
                info!(peer = %self.peer, inbox_id, "submission authenticated");
                conn.reply(235, "2.7.0 Authentication successful").await?;
            }
            Err(LookupError::Unknown | LookupError::Invalid) => {
                let delay = self.shared.throttle.record_failure(self.peer);
                self.auth_failures += 1;
                warn!(peer = %self.peer, "submission authentication failed");
                sleep(delay).await;
                conn.reply(535, "5.7.8 Authentication credentials invalid").await?;
                if self.auth_failures >= MAX_AUTH_FAILURES_PER_CONNECTION {
                    let _ = conn.reply(421, "4.7.0 Too many failed authentication attempts").await;
                    return Ok(Flow::Quit);
                }
            }
            Err(LookupError::Unavailable { .. }) => {
                conn.reply(454, "4.7.0 Temporary authentication failure").await?;
            }
        }
        Ok(Flow::Continue)
    }

    /// Reads one client response during an AUTH exchange. `None` means the
    /// client cancelled or sent invalid base64 and a reply was already sent.
    async fn auth_response(&mut self, conn: &mut Conn, challenge: &str) -> io::Result<Option<Vec<u8>>> {
        conn.reply(334, challenge).await?;
        match conn.read_line().await? {
            Line::Text(t) => self.decode_auth(conn, t.trim()).await,
            Line::TooLong => {
                conn.reply(501, "5.5.2 Response too long").await?;
                Ok(None)
            }
            Line::Eof => Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }

    async fn decode_auth(&mut self, conn: &mut Conn, text: &str) -> io::Result<Option<Vec<u8>>> {
        if text == "*" {
            conn.reply(501, "5.0.0 Authentication cancelled").await?;
            return Ok(None);
        }
        // "=" is the SASL spelling of an empty initial response.
        let text = if text == "=" { "" } else { text };
        match B64.decode(text) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(_) => {
                conn.reply(501, "5.5.2 Invalid base64").await?;
                Ok(None)
            }
        }
    }

    async fn read_plain(&mut self, conn: &mut Conn, initial: Option<&str>) -> io::Result<Option<(String, String)>> {
        let decoded = match initial {
            Some(i) => self.decode_auth(conn, i).await?,
            None => self.auth_response(conn, "").await?,
        };
        let Some(bytes) = decoded else { return Ok(None) };
        // authzid NUL authcid NUL passwd
        let mut parts = bytes.splitn(3, |&b| b == 0);
        let (_authzid, user, pass) = (parts.next(), parts.next(), parts.next());
        match (user, pass) {
            (Some(u), Some(p)) => Ok(Some((String::from_utf8_lossy(u).into_owned(), String::from_utf8_lossy(p).into_owned()))),
            _ => {
                conn.reply(501, "5.5.2 Malformed PLAIN response").await?;
                Ok(None)
            }
        }
    }

    async fn read_login(&mut self, conn: &mut Conn, initial: Option<&str>) -> io::Result<Option<(String, String)>> {
        let user = match initial {
            Some(i) => self.decode_auth(conn, i).await?,
            None => self.auth_response(conn, "VXNlcm5hbWU6").await?, // "Username:"
        };
        let Some(user) = user else { return Ok(None) };
        let Some(pass) = self.auth_response(conn, "UGFzc3dvcmQ6").await? else { return Ok(None) }; // "Password:"
        Ok(Some((String::from_utf8_lossy(&user).into_owned(), String::from_utf8_lossy(&pass).into_owned())))
    }

    // ---- envelope

    async fn cmd_mail(&mut self, conn: &mut Conn, arg: &str) -> io::Result<Flow> {
        if !self.helo {
            conn.reply(503, "5.5.1 EHLO first").await?;
        } else if self.mode == Mode::Submission && self.auth_inbox.is_none() {
            conn.reply(530, "5.7.0 Authentication required").await?;
        } else if self.mail_from.is_some() {
            conn.reply(503, "5.5.1 Sender already specified").await?;
        } else if let Some((address, params)) = parse_path(arg, "FROM:") {
            let declared = params
                .split_whitespace()
                .find_map(|p| p.get(..5).filter(|k| k.eq_ignore_ascii_case("SIZE=")).map(|_| &p[5..]))
                .and_then(|v| v.parse::<usize>().ok());
            if declared.is_some_and(|n| n > self.shared.config.max_message_bytes) {
                conn.reply(552, "5.3.4 Message size exceeds fixed maximum message size").await?;
            } else {
                self.mail_from = Some(address);
                conn.reply(250, "2.1.0 OK").await?;
            }
        } else {
            conn.reply(501, "5.5.4 Syntax: MAIL FROM:<address>").await?;
        }
        Ok(Flow::Continue)
    }

    async fn cmd_rcpt(&mut self, conn: &mut Conn, arg: &str) -> io::Result<Flow> {
        if self.mail_from.is_none() {
            conn.reply(503, "5.5.1 MAIL first").await?;
            return Ok(Flow::Continue);
        }
        let Some((address, _)) = parse_path(arg, "TO:").filter(|(a, _)| !a.is_empty()) else {
            conn.reply(501, "5.5.4 Syntax: RCPT TO:<address>").await?;
            return Ok(Flow::Continue);
        };
        if self.recipient_count >= MAX_RECIPIENTS {
            conn.reply(452, "4.5.3 Too many recipients").await?;
            return Ok(Flow::Continue);
        }

        if self.mode == Mode::Submission {
            // Mailtrap-style: everything sent is captured, so any recipient is fine.
            self.recipient_count += 1;
            conn.reply(250, "2.1.5 OK").await?;
            return Ok(Flow::Continue);
        }

        match self.shared.backend.validate_recipient(&address).await {
            Ok(inbox_id) => {
                self.recipient_count += 1;
                self.recipients.push(Recipient { inbox_id });
                conn.reply(250, "2.1.5 OK").await?;
            }
            Err(LookupError::Unknown) => conn.reply(550, "5.1.1 No such mailbox").await?,
            Err(LookupError::Invalid) => conn.reply(550, "5.1.3 Invalid recipient address").await?,
            Err(LookupError::Unavailable { .. }) => conn.reply(451, "4.3.0 Temporary error").await?,
        }
        Ok(Flow::Continue)
    }

    async fn cmd_data(&mut self, conn: &mut Conn) -> io::Result<Flow> {
        let have_recipients = match self.mode {
            Mode::Catch => !self.recipients.is_empty(),
            Mode::Submission => self.recipient_count > 0,
        };
        if self.mail_from.is_none() || !have_recipients {
            conn.reply(503, "5.5.1 Need MAIL and RCPT first").await?;
            return Ok(Flow::Continue);
        }
        conn.reply(354, "End data with <CR><LF>.<CR><LF>").await?;

        let raw = match conn.read_data(self.shared.config.max_message_bytes).await {
            Ok(Data::Complete(raw)) => raw,
            Ok(Data::TooLarge) => {
                self.reset_transaction();
                conn.reply(552, "5.3.4 Message too large").await?;
                return Ok(Flow::Continue);
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                let _ = conn.reply(421, "4.4.2 Timeout, closing connection").await;
                return Ok(Flow::Quit);
            }
            Err(e) => return Err(e),
        };

        let received_at = OffsetDateTime::now_utc();
        let envelope_from = self.mail_from.clone().unwrap_or_default();
        let parsed = match tokio::task::spawn_blocking(move || message::parse(raw, &envelope_from, received_at)).await {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "message parser panicked");
                self.reset_transaction();
                conn.reply(451, "4.3.0 Temporary error").await?;
                return Ok(Flow::Continue);
            }
        };

        // One copy per distinct inbox (catch), or to the authenticated inbox (submission).
        let mut targets: Vec<i64> = match self.mode {
            Mode::Submission => self.auth_inbox.into_iter().collect(),
            Mode::Catch => self.recipients.iter().map(|r| r.inbox_id).collect(),
        };
        let mut seen = std::collections::HashSet::new();
        targets.retain(|id| seen.insert(*id));

        let mut outcome = Ok(());
        for inbox_id in targets {
            match self.shared.backend.deliver(inbox_id, &parsed).await {
                Ok(()) => info!(peer = %self.peer, inbox_id, bytes = parsed.raw.len(), "message stored"),
                Err(e) => {
                    outcome = Err(e);
                    break;
                }
            }
        }

        self.reset_transaction();
        match outcome {
            Ok(()) => conn.reply(250, "2.0.0 OK").await?,
            Err(DeliveryError::TooLarge) => conn.reply(552, "5.3.4 Message too large").await?,
            Err(DeliveryError::Rejected) => conn.reply(554, "5.6.0 Message rejected").await?,
            Err(DeliveryError::Unavailable { .. }) => conn.reply(451, "4.3.0 Temporary error").await?,
        }
        Ok(Flow::Continue)
    }
}

/// Parses `FROM:<addr> params` / `TO:<addr> params` (keyword includes the
/// colon). Returns the address without brackets and the remaining parameters.
fn parse_path<'a>(arg: &'a str, keyword: &str) -> Option<(String, &'a str)> {
    let head = arg.get(..keyword.len())?;
    if !head.eq_ignore_ascii_case(keyword) {
        return None;
    }
    let rest = arg[keyword.len()..].trim_start().strip_prefix('<')?;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut end = None;
    for (i, c) in rest.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '>' if !in_quotes => {
                end = Some(i);
                break;
            }
            _ => {}
        }
    }
    let end = end?;
    let mut address = &rest[..end];
    // Strip an obsolete source route: <@a,@b:user@host>
    if address.starts_with('@') {
        address = address.split_once(':')?.1;
    }
    (address.len() <= 320).then(|| (address.to_owned(), rest[end + 1..].trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_parsing() {
        assert_eq!(parse_path("FROM:<a@b.test> SIZE=10", "FROM:"), Some(("a@b.test".into(), "SIZE=10")));
        assert_eq!(parse_path("from: <a@b.test>", "FROM:"), Some(("a@b.test".into(), "")));
        assert_eq!(parse_path("FROM:<>", "FROM:"), Some((String::new(), "")));
        assert_eq!(parse_path("TO:<@r.test:u@b.test>", "TO:"), Some(("u@b.test".into(), "")));
        assert_eq!(parse_path("TO:<\"a>b\"@x.test>", "TO:"), Some(("\"a>b\"@x.test".into(), "")));
        assert_eq!(parse_path("FROM:a@b.test", "FROM:"), None);
        assert_eq!(parse_path("TO:<a@b.test>", "FROM:"), None);
        assert_eq!(parse_path("FROM:<a@b.test", "FROM:"), None);
    }
}
