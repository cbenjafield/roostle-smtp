# Roostle SMTP service: API contract

This describes what the standalone SMTP service (Rust, separate repo) must do, and the Laravel HTTP API it calls. Laravel is the single source of truth for inboxes, credentials and stored mail. The SMTP service holds no database and keeps no durable state.

## Responsibilities

The service runs two listeners:

| Listener | Port | Auth | Purpose |
| --- | --- | --- | --- |
| Catch | 25 | none | Accepts mail for `{token}@catch.roostle.co.uk` |
| Submission | 587 (and/or 2525) | required, STARTTLS | Accepts mail from users who configured their app with an inbox's SMTP credentials |

Rules for both:

- **Never relay.** Mail is only ever stored, never forwarded to another server.
- Parse each accepted message (the `mail-parser` crate is recommended) and POST it to Laravel.
- Advertise `SIZE` as the max message size (default 5,242,880 bytes, see Limits) and reject larger messages with `552`.
- Submission: require TLS before offering `AUTH` (PLAIN and LOGIN are enough).

### Catch listener (port 25)

1. At each `RCPT TO`, call **Validate recipient**. If it returns 200, accept; if 404, reply `550`; on timeout, network error or 5xx, reply `451`.
2. Collect the `inbox_id` for each accepted recipient. After `DATA`, deliver one copy per **distinct** `inbox_id` (several recipients may point at the same inbox: deliver once).
3. Reply `250` only after every delivery has returned 201. If any delivery fails with a retryable error, reply `451` for the whole transaction.

### Submission listener (port 587)

1. On `AUTH`, call **Validate credentials**. 200 means authenticated (remember the `inbox_id` for the session); 404 means reply `535`; 401 (bad service token) means reply `454` and raise an alert; any other failure means `454` (temporary).
2. After authentication, accept **any** recipient address. Do not validate recipients, because this inbox behaves like Mailtrap: everything sent is captured.
3. After `DATA`, deliver one copy to the authenticated `inbox_id` regardless of the recipient count.

## Laravel API

Base URL: the Laravel app's `APP_URL` (HTTPS only), for example `https://roostle.co.uk`.

All endpoints are under `/api/internal/smtp`.

Every request must send:

```
Authorization: Bearer <ROOSTLE_SMTP_SERVICE_TOKEN>
Accept: application/json
```

A missing or wrong token returns `401`. The token is generated on the Laravel side with `php artisan roostle:smtp-token`. Treat it as a secret and never log it.

### POST `/api/internal/smtp/recipients/validate`

Request (JSON):

```json
{ "address": "k3x9q2m7vbn4ah8t@catch.roostle.co.uk" }
```

| Status | Meaning | Body |
| --- | --- | --- |
| 200 | Valid catch address | `{ "inbox_id": 42 }` |
| 404 | Unknown token or wrong domain | none relied upon |
| 422 | Missing or invalid `address` | `{ "message": "...", "errors": { ... } }` |
| 401 | Bad service token (a configuration error) | none relied upon |

Matching is case-insensitive.

### POST `/api/internal/smtp/credentials/validate`

Request (JSON):

```json
{ "username": "rstk3x9q2m7vbn4ah8t", "password": "<32 chars>" }
```

Limits: `username` is at most 64 characters and `password` at most 255.

| Status | Meaning | Body |
| --- | --- | --- |
| 200 | Credentials valid | `{ "inbox_id": 42 }` |
| 404 | Wrong username or password | none relied upon |
| 401 | Bad service token (a configuration error) | none relied upon |
| 422 | Missing fields | validation errors |

Laravel does **not** rate-limit this endpoint. The SMTP service must limit failed `AUTH` attempts per client IP and apply a delay or disconnect after repeated failures.

### POST `/api/internal/smtp/messages`

Deliver one message to one inbox. Send `multipart/form-data`.

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `inbox_id` | integer | yes | From a validate call |
| `message_id` | string | no | `Message-ID` header, at most 998 characters |
| `from_address` | string | yes | From header address, at most 320 characters |
| `from_name` | string | no | Display name, at most 255 characters |
| `to[N][address]`, `to[N][name]` | string | no | Addresses from the `To` header (`name` optional) |
| `cc[N][address]`, `cc[N][name]` | string | no | Addresses from the `Cc` header |
| `subject` | string | no | Decoded, at most 998 characters |
| `text_body` | string | no | Decoded `text/plain` part |
| `html_body` | string | no | Decoded `text/html` part |
| `headers[N][name]`, `headers[N][value]` | string | no | Every header, in original order, decoded to UTF-8 |
| `received_at` | ISO 8601 | no | When the SMTP service accepted the message. Defaults to now if omitted |
| `raw` | file | **yes** | The complete original RFC 5322 message, sent as `message.eml` |
| `attachments[]` | file | no | One part per attachment, with its filename and `Content-Type` set on the part |

Notes on the fields:

- `to` and `cc` come from the message **headers**, not the SMTP envelope. A Bcc recipient or a mailing-list delivery will therefore not appear in `to`, even though it was the envelope recipient. This is acceptable for now.
- Use the part's own filename as the attachment name. Laravel stores whatever filename and content type you send, and serves downloads as `application/octet-stream`.
- There is no inline-image (`Content-ID`) handling yet. Inline images arrive as ordinary attachments.
- `raw` and each attachment must be at most `ROOSTLE_MAX_MESSAGE_KILOBYTES` (default 5,120 KB, i.e. 5,242,880 bytes). Roostle is a testing tool, so messages are expected to be small.

| Status | Meaning | Body |
| --- | --- | --- |
| 201 | Stored | `{ "id": 123 }` |
| 422 | Rejected: invalid fields, unknown `inbox_id` (deleted mid-session), or file too large | `{ "message": "...", "errors": { "raw": ["..."] } }` |
| 401 | Bad service token (a configuration error) | none relied upon |
| 5xx / timeout / network error | Laravel problem | none relied upon |

## Mapping HTTP results to SMTP replies

| Result from Laravel | SMTP reply |
| --- | --- |
| 200 / 201 | `250 OK` |
| 404 on recipient validation | `550 5.1.1 No such mailbox` |
| 404 on credential validation | `535 5.7.8 Authentication failed` |
| 422 caused by size (`raw` or `attachments.*`) | `552 5.3.4 Message too large` |
| Other 422 | `554 5.6.0 Message rejected` (permanent, do not retry) |
| 401 from Laravel (bad service token) | `451 4.3.0 Temporary error` **and raise an alert**: this is a misconfiguration, not the sender's fault |
| Timeout, connection error, 5xx | `451 4.3.0 Temporary error`. The sending server will retry |

Never expose Laravel's response bodies or the service token to SMTP clients.

## Caching

- Cache successful recipient validations in memory for 30 to 60 seconds, keyed by lowercased address. This keeps bursts of mail to one inbox cheap.
- Cache **positive** credential results only if keyed by a hash of username plus password, with a TTL of at most 60 seconds. Never cache the plaintext password.
- Do not cache 404 results for more than a few seconds. A new inbox must work almost immediately.
- Note that a deleted inbox or regenerated password can remain valid for up to the cache TTL.

## Timeouts and retries

- Validation calls: 5 second timeout, no automatic retry inside a session (reply `451` and let the client retry).
- Delivery: 30 second timeout or more (large attachments).
- **No idempotency.** Laravel does not deduplicate on `message_id`. If a delivery request times out *after* Laravel committed it, a retry creates a duplicate. Only retry a delivery when the connection failed or Laravel returned 5xx. A timeout should return `451` and accept a possible duplicate.

## Laravel and PHP limits to be aware of

- A delivery request contains the `raw` message **and** each attachment again. A 5 MB message whose attachments total about 3.7 MB decoded is about 8.7 MB of upload.
- `upload_max_filesize` and `post_max_size` in `php.ini` (and the reverse proxy's body limit, for example nginx `client_max_body_size`) must be set high enough for this, roughly 2x the maximum message size. The 5 MB default fits PHP limits of 10M (the Herd default) but not PHP's stock `upload_max_filesize` of 2M, so raise that on the server. Otherwise deliveries fail with 413 or an empty 422.
- If you raise the message limit, change `ROOSTLE_MAX_MESSAGE_KILOBYTES` in Laravel and the advertised `SIZE` in the SMTP service together.

## Configuration the SMTP service needs

| Setting | Example |
| --- | --- |
| Laravel base URL | `https://roostle.co.uk` |
| Service token | value of `ROOSTLE_SMTP_SERVICE_TOKEN` |
| Catch domain | `catch.roostle.co.uk` (used for logging only, since Laravel validates the address) |
| Max message size | `5242880` bytes |
| TLS certificate and key | for STARTTLS on the submission port |

DNS: the `MX` record for `catch.roostle.co.uk` must point at the host running the SMTP service, with inbound port 25 open.

Laravel's matching settings are `ROOSTLE_CATCH_DOMAIN`, `ROOSTLE_SMTP_HOST`, `ROOSTLE_SMTP_PORT` and `ROOSTLE_SMTP_SERVICE_TOKEN`. The host and port are what users see in the inbox UI.

## Example delivery request

```bash
curl -X POST https://roostle.co.uk/api/internal/smtp/messages \
  -H "Authorization: Bearer $ROOSTLE_SMTP_SERVICE_TOKEN" \
  -H "Accept: application/json" \
  -F inbox_id=42 \
  -F message_id='<abc@example.com>' \
  -F from_address=sender@example.com \
  -F from_name='Sender' \
  -F 'to[0][address]=k3x9q2m7vbn4ah8t@catch.roostle.co.uk' \
  -F subject='Hello' \
  -F text_body='Plain text' \
  -F html_body='<p>Rich text</p>' \
  -F 'headers[0][name]=X-Mailer' -F 'headers[0][value]=Example' \
  -F received_at=2026-10-26T18:00:00Z \
  -F raw=@message.eml \
  -F 'attachments[]=@invoice.pdf;type=application/pdf'
```

Expected response: `201 {"id":123}`.

## Test checklist for the SMTP service

- Catch address that exists is accepted; unknown token and wrong domain are rejected with `550`.
- Two recipients for the same inbox produce one delivery.
- Recipients for two different inboxes produce two deliveries.
- Submission rejects `AUTH` before STARTTLS, rejects wrong credentials with `535`, and accepts any recipient once authenticated.
- A message over the size limit is rejected with `552` at the `SIZE`/`DATA` stage.
- Laravel returning 5xx or timing out produces `451`, never `250`.
- Attachments, a multipart/alternative message, a non-UTF-8 charset and a message with no subject are parsed and delivered correctly.
- Repeated failed `AUTH` from one IP is throttled.
