# roostle-smtp

Standalone SMTP service for Roostle, implementing [SMTP_SERVICE_CONTRACT.md](SMTP_SERVICE_CONTRACT.md).
It holds no database: every recipient, credential and stored message goes through Laravel's
`/api/internal/smtp` API. Mail is only ever stored, never relayed.

- **Catch listener** (default `:25`): no auth; each `RCPT TO` is validated against Laravel; one delivery per distinct inbox.
- **Submission listener** (default `:587`, optionally `:2525`): STARTTLS then `AUTH PLAIN`/`LOGIN`; any recipient accepted; one delivery to the authenticated inbox.

## Run

```sh
cp .env.example .env   # fill in ROOSTLE_BASE_URL and ROOSTLE_SMTP_SERVICE_TOKEN
set -a; . ./.env; set +a
cargo run --release
```

Local development without privileged ports or certificates:

```sh
ROOSTLE_BASE_URL=http://localhost:8000 ROOSTLE_SMTP_SERVICE_TOKEN=... \
ROOSTLE_CATCH_BIND=127.0.0.1:2525 ROOSTLE_SUBMISSION_BIND=127.0.0.1:2587 \
ROOSTLE_ALLOW_INSECURE_AUTH=true cargo run
```

`SIGHUP` reloads the TLS certificate and key; `SIGTERM`/Ctrl-C stops accepting and drains open connections (30s).

## Behaviour worth knowing

- Failed `AUTH`s are throttled per client IP (5 per 15 minutes by default, with a growing delay); beyond that the IP gets `421` until the window expires. A connection is dropped after 3 failures.
- A Laravel `401` (bad service token) replies `451` to the sender and logs an `ERROR` carrying `alert = true`. Alert on it.
- Deliveries are never retried inside a session (Laravel doesn't deduplicate); failures reply `451` and the sending server retries.
- If a message has no parseable `From`, the envelope sender is used (or `unknown@unknown.invalid` for a null sender), since Laravel requires `from_address`.
- Inbound STARTTLS is also offered on the catch port when a certificate is configured.

## Test

```sh
cargo test
```
