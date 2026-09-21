# inletbox

A private, self-hosted **file drop box**. An administrator creates a case, generates an
upload link and hands it to a client. The client uploads files from the browser or with
`curl`, sees only the list of files sent through **their own** link and **cannot download
anything**. The administrator collects the files.

This is not a network drive and not a sharing tool: no previews, no public downloads,
no self-registration.

- **Stack:** Node.js 26+ (TypeScript, Express 5), SQLite (built-in `node:sqlite`), local
  disk or S3/MinIO storage, resumable uploads via the **tus** protocol (`@tus/server` +
  `tus-js-client`). No native modules.
- **Deployment:** one container + one volume; optional MinIO profile for S3 testing.
- **Admin 2FA:** TOTP (RFC 6238) with recovery codes, optionally enforced for every admin.
- **UI languages:** English and Polish. Polish is used when it is the browser's primary
  language (`Accept-Language`), English in every other case; a footer switcher (EN | PL)
  stores an explicit choice in a cookie. API error messages follow the same language.
- **Light and dark theme:** follows the operating system / browser preference
  (`prefers-color-scheme`). No toggle, no script, no cookie — nothing to configure.

What changed between releases is in [CHANGELOG.md](CHANGELOG.md); each version's section
there is also the body of its [GitHub Release](https://github.com/pan-dolina/inletbox/releases).

---

## Table of contents

1. [Quick start](#1-quick-start)
2. [Permission model](#2-permission-model)
3. [Configuration](#3-configuration)
4. [Uploading from the terminal (curl)](#4-uploading-from-the-terminal-curl)
5. [Resumable uploads](#5-resumable-uploads)
6. [Limits and reservations](#6-limits-and-reservations)
7. [Storage](#7-storage)
8. [Reverse proxy](#8-reverse-proxy)
9. [Security](#9-security)
10. [Architecture and data model](#10-architecture-and-data-model)
11. [Tests and security scanning](#11-tests-and-security-scanning)
12. [Limitations and next steps](#12-limitations-and-next-steps)

---

## 1. Quick start

### Docker Compose (recommended)

```bash
cp .env.example .env
# set PUBLIC_URL to the address clients will use (https://drop.example.com)
docker compose up -d --build
docker compose exec app node dist/cli.js create-admin admin      # password prompted interactively, min. 12 characters
```

After the first login enable two-factor authentication in the panel (**Security**) or enforce it for every administrator with `ADMIN_REQUIRE_TOTP=true`.

Panel: `PUBLIC_URL/admin`. Data (the SQLite database and, with the local backend, the
files) lives on the `inletbox-data` volume mounted at `/data`.

There is no default password. The first administrator is created only through the CLI on
the server (the password can also be piped: `echo "$PASS" | node dist/cli.js create-admin admin --password-stdin`).
`reset-password <user>` changes a password and ends that admin's sessions;
`disable-totp <user>` removes the second factor when an admin has lost both the
authenticator app and the recovery codes (it also ends all their sessions).

### Local development

```bash
npm install
cp .env.example .env            # for http://localhost set COOKIE_SECURE=false
npm run cli -- create-admin admin
npm run dev                     # http://localhost:3000/admin
```

### MinIO test profile

```bash
docker compose --profile minio up -d           # MinIO + creation of the private "inletbox" bucket
# in .env: STORAGE_BACKEND=s3  S3_ENDPOINT=http://minio:9000  S3_BUCKET=inletbox
#          S3_ACCESS_KEY_ID=minioadmin  S3_SECRET_ACCESS_KEY=minioadmin  S3_FORCE_PATH_STYLE=true
docker compose up -d --build app
```

---

## 2. Permission model

| Who | Can | Cannot |
|---|---|---|
| **Administrator** (cookie session, optional TOTP) | create/edit/close cases; generate and revoke links, set their expiry and limits; inspect metadata; download and delete files; read the audit log | — |
| **Link holder** (token) | upload files (browser, curl, tus); see the list and status of files uploaded through **that** link | download or preview any file, including their own; delete or overwrite completed files; see files of other links; reach the admin panel |

**One case = many links. Each link = one recipient and one visibility scope.**
The application cannot tell apart people who use the same link: whoever knows the link has
exactly the same access (uploading + listing their own files). If two people must be kept
separate, they get two links. The panel states this next to the links.

The no-download rule is enforced by the backend and the storage layout, not by the UI:

- there is no endpoint that returns file contents for a link token (`GET /api/files/:id`,
  `GET /api/files/:id/download`, `DELETE /api/files/:id` answer `403` and are covered by tests);
- the tus endpoint refuses `GET` (`405`), so it cannot act as a read endpoint;
- files live outside any statically served directory (`DATA_DIR/files`) and the S3 bucket
  is private; the application never issues presigned URLs;
- the storage key is a random identifier (`f_…`), never a client-supplied name;
- downloading requires an admin session and streams through the application as
  `Content-Disposition: attachment`, `application/octet-stream`, `nosniff`, `CSP: sandbox`.

Once a tus upload completes, its bookkeeping object ("sidecar") is removed from storage, so
a finished file can no longer be addressed via `HEAD`/`PATCH`/`DELETE` (`410`).

---

## 3. Configuration

Everything is configured through environment variables (`.env.example` lists them all;
it contains no secrets). Sizes: `1048576`, `500MB`, `2GB`, `512KiB` (binary units).

| Variable | Default | Description |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:3000` | Public address of the instance; used to build links and curl commands and as the CSRF origin. |
| `HOST`, `PORT` | `0.0.0.0`, `3000` | Listen address. |
| `TRUST_PROXY` | `false` | Number of reverse-proxy hops (usually `1`) or a list of proxy addresses/CIDRs; client IPs are then read from `X-Forwarded-For` for rate limiting and the audit log. `true` is refused because it would let clients forge their IP. |
| `DATA_DIR` | `./data` | SQLite database (`inletbox.sqlite`) and files (`files/`). |
| `STORAGE_BACKEND` | `local` | `local` or `s3`. |
| `LOCAL_STORAGE_DIR` | `$DATA_DIR/files` | Directory for file objects (outside any public directory; must not contain the database). |
| `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_FORCE_PATH_STYLE`, `S3_PART_SIZE` | — | S3 backend; `S3_FORCE_PATH_STYLE=true` for MinIO; part size ≥ 5MB. |
| `MAX_FILE_SIZE` | `10GB` | Global per-file limit; per-link limits can only lower it. |
| `UPLOAD_CHUNK_SIZE` | `32MB` | Size of one browser PATCH request; must fit the reverse proxy body limit. |
| `INCOMPLETE_UPLOAD_TTL_HOURS` | `24` | Unfinished uploads older than this are removed and their reservation released. |
| `CLEANUP_INTERVAL_MINUTES` | `30` | How often the in-process cleanup runs (`0` disables it; `node dist/cli.js cleanup` runs it manually). |
| `SESSION_TTL_HOURS` | `12` | Admin session lifetime. |
| `ADMIN_REQUIRE_TOTP` | `false` | Enforce TOTP: an admin without a second factor only sees the security page until they enrol. |
| `COOKIE_SECURE` | auto (`https` → `true`) | `false` only for plain-HTTP local development. |
| `LOGIN_RATE_LIMIT_PER_15MIN` | `10` | Failed logins (password or TOTP step) per IP. |
| `TOKEN_FAILURE_RATE_LIMIT_PER_15MIN` | `30` | Unknown/unauthenticated token attempts per IP (brute force). |
| `PUBLIC_RATE_LIMIT_PER_MINUTE` | `600` | General API request limit per IP (tus chunks included). |
| `BRAND_NAME`, `BRAND_LOGO_PATH`, `BRAND_COLOR_*`, `BRAND_FOOTER_TEXT` | — | Branding, see below. |
| `LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error`. |

Per-link limits (file size, number of files, total bytes) and the expiry date are set in
the panel when a link is generated.

### Branding

The look can be adapted to an organisation without code changes (`BRAND_*` variables, see
`.env.example`): name (`BRAND_NAME`, also used as the issuer in authenticator apps), logo
(`BRAND_LOGO_PATH`: PNG/SVG/JPEG/WebP, served at `/brand/logo` in place of the name in the
top bar and as the favicon), colours (`BRAND_COLOR_PRIMARY` for buttons/links,
`BRAND_COLOR_TOPBAR` for the header background, `BRAND_COLOR_ACCENT` for highlights; hex
`#rrggbb` **in quotes**, because an unquoted `#` starts a comment in `.env` files) and the
footer text. Colours are emitted as a generated stylesheet at `/brand/theme.css`, so the CSP
stays free of `unsafe-inline`. Keep the logo file outside the repository (the `branding/`
directory is git-ignored) and mount it into the container, e.g.
`volumes: ["./branding:/branding:ro"]` + `BRAND_LOGO_PATH=/branding/logo.png`.

The interface follows the viewer's `prefers-color-scheme`: page background, cards, inputs,
code blocks and badges switch to a dark palette automatically. The three `BRAND_COLOR_*`
values are **not** touched by the dark theme — an instance keeps its own primary, top-bar
and accent colour in both modes, so pick values that are legible on a light *and* a dark
card. A QR code keeps its white quiet zone in both themes, because scanners need it.

---

## 4. Uploading from the terminal (curl)

The link page has a "Upload from the terminal" section with ready-made commands (real
instance address, token, copy buttons). The API returns JSON and proper HTTP status codes;
`--fail-with-body` makes curl exit non-zero (22) on errors while still printing the body.

```bash
# one file: curl -T appends the file name to a URL ending in "/"
curl --fail-with-body -H 'Authorization: Bearer <TOKEN>' \
  -T '/path/to/file.pdf' 'https://drop.example.com/api/upload/'

# several files (paths with spaces are safe)
for f in '/path/report.pdf' '/path/photo 1.jpg'; do
  curl --fail-with-body -H 'Authorization: Bearer <TOKEN>' -T "$f" 'https://drop.example.com/api/upload/'; echo
done

# token in an environment variable (recommended; the leading space keeps it out of history with HISTCONTROL=ignorespace)
 export INLETBOX_TOKEN='<TOKEN>'
curl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" -T '/path/to/file.pdf' 'https://drop.example.com/api/upload/'

# list your own files
curl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" 'https://drop.example.com/api/files'
```

Response `201`:

```json
{"id":"f_3kq9…","name":"file.pdf","size":1234567,"sha256":"…","status":"complete"}
```

Errors: `401 missing_token`, `404 invalid_token`, `403 link_expired | link_revoked | case_closed`,
`413 file_too_large | too_many_files | quota_exceeded`, `429 rate_limited`.

The endpoint takes a raw body (`PUT`/`POST /api/upload/<name>`, alternatively an
`X-File-Name` header), with `Content-Length` or `Transfer-Encoding: chunked`, and supports
`Expect: 100-continue`. The token is accepted only in the `Authorization` header, never in
the query string, so it does not end up in logs.

**Note:** a command containing the token stays in the shell history (`~/.bash_history`,
`~/.zsh_history`). Treat the link like a password.

---

## 5. Resumable uploads

### Comparison

| Approach | Pros | Cons |
|---|---|---|
| **tus** (`@tus/server`, `tus-js-client`) | mature open protocol; stores for local disk and S3 in the same library; browser client with fingerprinting and retries; clear `HEAD`/`PATCH`/offset semantics | one more protocol to understand; a CLI client needs a script (several curl calls) |
| custom chunks + offsets | full control, no dependency | reinventing tus: locking, expiry, sidecars, edge cases, no ready-made client |
| S3 multipart upload | native to S3, parallel parts | a **backend** mechanism: by itself it defines no client↔application protocol (upload identity, offsets, authorising a resume) and does not work with local disk |

**Decision:** tus, working from the first version with both backends. On S3 tus uses
multipart upload underneath (`@tus/s3-store`); on disk it writes to a file at an offset.

### How it works

- The browser uses `tus-js-client` (served locally, no CDN) with `UPLOAD_CHUNK_SIZE`
  chunks, automatic retries on network/5xx errors and the upload URL remembered in
  `localStorage` (fingerprint: name + size + mtime + endpoint). After a dropped connection
  the upload continues on its own. **After a page reload the same file has to be picked
  again** (a browser cannot reopen a file from disk by itself); the upload then resumes
  from the last offset ("resuming previous upload" is shown).
- Authorisation: every tus request (`POST`, `HEAD`, `PATCH`, `DELETE`) needs an active
  token. An upload is bound to its link at creation; any other link gets `404` (no oracle
  for whether the upload exists).
- Offsets are controlled by the tus server (`409` on mismatch, no writing past the
  declared length). `Upload-Length` is required (`Upload-Defer-Length` is rejected)
  because the length is the basis of the quota reservation.
- Completion is idempotent: the record goes `uploading → complete` exactly once; the tus
  sidecar is then removed and the upload answers `410`.
- Link expiry/revocation or closing the case blocks `PATCH` immediately (`403`);
  revocation additionally discards that link's in-flight uploads and releases reservations.
- Unfinished uploads live for `INCOMPLETE_UPLOAD_TTL_HOURS`; then cleanup removes the data
  (file + `.json`, or `.info` object + multipart abort) and marks the record `expired`.

### CLI

Plain `curl -T` does **not** resume: an interrupted upload has to be sent again.
`curl -C -` is about downloads and HTTP ranges, not uploads. For large files there is
[`scripts/inletbox-upload.sh`](scripts/inletbox-upload.sh) (also downloadable from the
link page), which implements tus with plain curl:

```bash
INLETBOX_TOKEN='<TOKEN>' ./inletbox-upload.sh https://drop.example.com/api '/path/to/large file.iso'
```

It creates the upload, sends chunks (`INLETBOX_CHUNK_SIZE`, default 32 MiB) and remembers
the upload URL in `~/.cache/inletbox/`. After a broken connection, re-running the same
command asks the server for the offset and continues. The token is read from the
environment and passed to curl through a private temp file, so it stays out of `ps` output.
Limitations: one file per invocation; needs `bash`, `curl`, `tail`, `stat`,
`sha256sum`/`shasum`; each chunk is buffered by curl in memory (do not use hundreds of MB).

---

## 6. Limits and reservations

- Effective per-file limit = `min(MAX_FILE_SIZE, link limit)`. The panel rejects a link
  limit above the global one.
- All limits are checked by the server inside one `BEGIN IMMEDIATE` transaction
  (`node:sqlite` is synchronous, so concurrent requests are serialised): number of files
  (`complete` + `uploading`), declared size, remaining budget
  (`limit − completed − reserved`).
- **Reservation:** a started upload reserves its declared size (`Content-Length` or
  `Upload-Length`). Three parallel 6 MB files against a 10 MB limit → exactly one gets
  through (test `enforces per-link total quota under concurrent uploads`).
- Without `Content-Length` (chunked) the reservation is the maximum this upload could
  legally be (`min(file limit, remaining budget)`); the stream is counted on the fly and
  cut off when exceeded (`413`), and the surplus reservation is released on completion.
- Dropped connection: record → `aborted`, partial data removed, reservation = 0
  (test `cleans up when the client disconnects mid-upload`).
- Browser-side validation (file too large) is only a convenience.

---

## 7. Storage

Abstraction in [`src/storage/types.ts`](src/storage/types.ts): `put` (streaming with a
byte counter and SHA-256), `get`, `stat`, `delete`, `createTusStore`, `removeTusSidecar`,
`cleanupOrphans`, `healthCheck`. Keys are validated (`^[A-Za-z0-9_-]{1,128}$`), so there is
no path traversal.

- **local** — `LOCAL_STORAGE_DIR`, written with the `wx` flag (never overwrites an existing
  key) and mode `0600` in a `0700` directory; tus keeps `<id>.json` next to the file until
  completion.
- **s3** — `@aws-sdk/lib-storage` (streaming multipart, unknown length) for direct uploads,
  `@tus/s3-store` for tus. The bucket must be private; the application exposes neither
  presigned URLs nor credentials to clients. Required permissions: `s3:PutObject`,
  `s3:GetObject`, `s3:DeleteObject`, `s3:ListBucket`, `s3:AbortMultipartUpload`,
  `s3:ListBucketMultipartUploads`, `s3:ListMultipartUploadParts`.

Cleanup (`runCleanup`, every `CLEANUP_INTERVAL_MINUTES` and via the CLI):
1. unfinished uploads older than the TTL → data removed, status `expired`, reservation 0;
2. `complete` files whose object disappeared → status `missing` (shown in the panel);
3. storage artefacts with no database record (sidecars, `.part` objects, abandoned S3
   multipart uploads) older than the TTL → removed; only keys in the application's own
   format are ever touched;
4. expired sessions → removed.

Migrating files between backends is not supported (it was not required).

---

## 8. Reverse proxy

The application does not terminate TLS. Settings **required** for large uploads and streaming:

- no body size limit (or ≥ `UPLOAD_CHUNK_SIZE` and ≥ the largest file sent with `curl -T`);
- **request buffering off** (otherwise the proxy spools the whole upload to disk and the
  limits without `Content-Length` and abort handling do not behave as intended);
- long read/send timeouts (hours for large files);
- `TRUST_PROXY=1` in the application, `X-Forwarded-For`/`-Proto` set by the proxy.

### nginx

```nginx
# Redact the token from /u/<token> in the access log.
map $request_uri $redacted_uri {
    ~^(?<pre>/u/)[^/?]+(?<post>.*)$  "${pre}[redacted]${post}";
    default                          $request_uri;
}
log_format redacted '$remote_addr - [$time_local] "$request_method $redacted_uri $server_protocol" '
                    '$status $body_bytes_sent "$http_user_agent"';

server {
    listen 443 ssl http2;
    server_name drop.example.com;
    # ssl_certificate ...; ssl_certificate_key ...;
    access_log /var/log/nginx/inletbox.log redacted;

    client_max_body_size 0;            # limits are enforced by the application
    proxy_request_buffering off;       # stream uploads to the application
    proxy_buffering off;               # stream downloads to the admin
    proxy_http_version 1.1;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    send_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

### Caddy

```caddyfile
drop.example.com {
    request_body { max_size 0 }
    reverse_proxy 127.0.0.1:3000 {
        flush_interval -1
        transport http { read_timeout 1h  write_timeout 1h }
    }
    log {
        output file /var/log/caddy/inletbox.log
        format filter {
            request>uri replace "/u/[^/?]+" "/u/[redacted]"
        }
    }
}
```

Node: the application disables the default 5-minute `requestTimeout` (it would cut long
uploads) but keeps `headersTimeout` at 60 s and a 5-minute socket idle timeout (slowloris);
an active upload keeps its socket busy, so it is unaffected.

---

## 9. Security

- **Login:** passwords hashed with `scrypt` (N=2¹⁵, r=8, p=1, 16-byte salt) from Node
  `crypto`; constant-time verification even for unknown users; minimum 12 characters.
- **Second factor (TOTP, RFC 6238):** own implementation on `node:crypto` (HMAC-SHA1,
  6 digits, 30 s, ±1 step window), compatible with Aegis/Google Authenticator/1Password.
  Enrolment requires a code from the app (QR + manual key + `otpauth://` link) and produces
  8 one-time recovery codes (stored as SHA-256, shown once). After the password the session
  is "pending" and can reach nothing but the code form; the session id is rotated once the
  code passes. 5 wrong codes destroy the session; 10 wrong codes lock the account's second
  factor for 15 minutes regardless of IP or session. The accepted time step is remembered,
  so the same code cannot be replayed. Disabling TOTP or regenerating recovery codes needs
  a current code, not just the session, and ends every other session. Everything is
  audited. The TOTP secret is stored in clear in the database (as in most implementations):
  protect the database file and its backups.
- **Sessions:** random 256-bit id in an `HttpOnly; SameSite=Lax; Secure` (on HTTPS)
  cookie, only its SHA-256 in the database, configurable TTL, new id on every login.
- **CSRF:** SameSite=Lax + `Origin`/`Sec-Fetch-Site` checks + a per-session synchroniser
  token in every form.
- **Link tokens:** 256 bits from a CSPRNG, stored only as SHA-256 (+ a 6-character hint
  for identification in the panel). The full link is shown once, in the response that
  created it; it cannot be recovered from the database, only replaced by a new link.
- **Expiry/revocation:** checked on every request, including mid-tus-upload.
- **Rate limiting:** failed logins (password and TOTP), unknown-token attempts, general API.
- **File names:** NFC normalisation, path components stripped (`/`, `\`), control
  characters removed, 255-character limit; never used to build a storage path; every HTML
  interpolation is escaped (own `html` tagged template) and `Content-Disposition` is built
  by `content-disposition` (RFC 5987/6266).
- **IDOR:** identifiers are random (96 bits) and every access checks the owner (link) or
  the admin session; unknown or foreign → `404`.
- **No public read path**, no execution or rendering of files; downloads only as
  `attachment` with `nosniff` and `CSP: sandbox`.
- **Headers:** helmet, CSP `default-src 'none'; script-src 'self'; style-src 'self'; …`
  (no `unsafe-inline`), `Referrer-Policy: no-referrer` (the link does not leak through the
  referrer), `X-Frame-Options: DENY`, no external scripts or fonts on the upload page.
- **Process/file hygiene:** `umask 077`, files `0600`, directories `0700`; `TRUST_PROXY=true`
  is refused so clients cannot forge `X-Forwarded-For`.
- **Logs:** JSON on stdout; `/u/<token>` paths, `token=` parameters and uploader-supplied
  file names are redacted; `Authorization`/`Cookie` are never logged; usernames of failed
  logins are not stored (that field routinely receives mistyped passwords).
- **Audit log** (`audit_log`, panel → "Audit log"): logins (successful and failed, incl.
  second-factor events and lockouts), case/link operations, upload start/completion/
  abort/rejection, downloads and deletions, cleanup events; with the client IP.
- **Files are untrusted.** Antivirus scanning is **not part of this version**. Integration
  point: `onUploadFinish` in [`src/http/tus.ts`](src/http/tus.ts) and the end of `direct` in
  [`src/http/public.ts`](src/http/public.ts); both call `completeUpload`, and a scanner
  (e.g. ClamAV via `clamd`) could set an extra status (`quarantined`) there before the file
  is offered to the administrator.

An independent code review was run against this codebase before release; its findings
(account-level TOTP lockout, session rotation, `TRUST_PROXY=true`, file modes, CLI script
input validation, socket idle timeout, log redaction) are all addressed and covered by tests.

---

## 10. Architecture and data model

A single-process Express + SQLite monolith; storage is a plug-in.

```
src/
  config.ts            environment variables → Config (parseSize, branding, …)
  i18n.ts              en/pl dictionaries, Accept-Language negotiation, placeholders
  db.ts                node:sqlite, migrations from migrations/*.sql, transaction()
  crypto.ts            ids, tokens, sha256, scrypt
  totp.ts              RFC 6238 TOTP, base32, recovery codes
  log.ts               JSON logging + redaction
  storage/             types (interface), local, s3, limit (byte counter + hash)
  services/            auth (admins, sessions, TOTP), cases, links, files (reservations), audit, cleanup
  http/
    app.ts             application assembly, static assets, /lang/:lang switcher, 404/500
    brand.ts           /brand/logo, /brand/theme.css
    middleware.ts      helmet/CSP, logger, sessions, CSRF, rate limits, link auth (Bearer)
    admin.ts           panel (SSR forms), login + second factor, security page
    public.ts          /u/<token>, /api/link, /api/files, /api/upload (direct), /api/tus
    tus.ts             @tus/server + hooks (reservation, isolation, finalisation)
    html.ts, views/    escaping tagged template, views
  server.ts            http.Server (timeouts, 100-continue), periodic cleanup, shutdown
  cli.ts               create-admin, reset-password, disable-totp, migrate, cleanup
public/                style.css, upload.js (tus-js-client), admin.js
scripts/inletbox-upload.sh   resumable upload from the CLI
```

Tables ([`migrations/`](migrations/)):

- `admins` (id, username, password_hash, totp_secret, totp_enabled_at, totp_last_step,
  totp_failed_count, totp_locked_until)
- `admin_recovery_codes` (admin_id, code_hash, used_at)
- `sessions` (id_hash, admin_id, csrf_token, expires_at, totp_verified, totp_attempts)
- `cases` (id, name, description, status open|closed)
- `links` (id, case_id, label, token_hash, token_hint, expires_at, revoked_at,
  max_file_bytes, max_files, max_total_bytes, last_used_at)
- `files` (id = storage key = tus id, case_id, link_id, original_name, upload_kind tus|direct,
  status uploading|complete|aborted|expired|missing|deleted, declared_size, reserved_bytes,
  size, sha256, client_ip, created_at, completed_at, deleted_at)
- `audit_log` (ts, actor_type admin|link|system, actor_id, action, case_id, link_id, file_id, ip, details)

Browser upload flow: `POST /api/tus` (Bearer) → `onUploadCreate` reserves quota in a
transaction and creates an `uploading` record → `PATCH …` (offset controlled by tus, every
request verifies the token and the owner) → `onUploadFinish` → `complete`, sidecar removed.
Direct upload: `PUT /api/upload/<name>` → reservation → `storage.put` (stream with counter
and SHA-256) → `complete`.

---

## 11. Tests and security scanning

```bash
npm test                    # local backend (SQLite + a temporary directory per test file)
npm run test:coverage       # the same suite with a V8 coverage report (thresholds enforced)
docker compose --profile minio up -d minio
TEST_S3=1 npm test          # the same suite against MinIO (a temporary bucket per test file)
```

The suite (vitest, 99 tests) boots a real HTTP server on a random port and covers: creating
a case and a link through the forms (full URL once, then only the hint); uploads with
`Content-Length`, chunked, and with **real curl** (`-T` with a space in the path, exit code
22 on error); list isolation between links; no read path by file id for a link holder;
admin download with safe headers, and deletion; limits (file too large, too many files,
quota) also under **concurrent** requests and without `Content-Length`; no overwriting of
duplicates; name sanitisation (traversal, HTML); dropped connections and cleanup; tus:
create/patch/head, wrong offset (409), isolation (404), idempotent finalisation (410),
`tus-js-client` with an interruption and resume from a stored URL, expiry of unfinished
uploads, orphan sweeps and `missing` detection; link expiry/revocation (including aborting
an in-flight upload) and case closure; CSRF and login rate limiting; branding; language negotiation and the cookie switcher.

Security tests (`test/security.test.ts`, `test/totp.test.ts`): headers (CSP without
`unsafe-inline`, `X-Frame-Options: DENY`, `nosniff`, no `X-Powered-By`), cookie attributes
(`HttpOnly`, `SameSite`, `Secure`), session rotation at login and invalidation at logout,
no trust in `X-Forwarded-For` without `TRUST_PROXY`, throttling of unknown tokens, path
traversal through `/static`, malformed identifiers, hostile file names from three channels
(URL, header, tus metadata) including CRLF and XSS, private file modes, no tokens in the
audit log/panel/JSON, tus without a token and across links, `npm audit` with no high/critical
findings; TOTP: RFC 6238 test vectors, time window, replay, pending session without panel
access, session lockout after 5 errors, account lockout after 10 errors across sessions,
one-time recovery codes, code regeneration, disabling with a code (ending other sessions),
CLI `disable-totp`, `ADMIN_REQUIRE_TOTP` mode.

Failure paths get their own file (`test/edges.test.ts`), because that is where leaks
happen: log redaction and the dropping of `authorization`/`cookie`/`token`/`password`
fields, storage keys that try to escape their directory, a storage error surfacing as a
500/410 page with no internal message or path in it, a missing `Authorization` header vs a
token that does not resolve, migrations re-running, service-level input validation, and the
branding endpoints with a logo file that disappeared.

Coverage is measured with the V8 provider and enforced in CI (`npm run test:coverage`);
current run: **93% statements, 86% branches, 96% functions, 98% lines**. `src/server.ts`
and `src/cli.ts` are excluded as process entry points, and `src/storage/s3.ts` is measured
in the `TEST_S3=1` run instead of the local one, where it never executes.

### Security scanning

Every push and pull request runs, besides the tests:

| Check | What it catches |
| --- | --- |
| `npm audit --audit-level=high` | known vulnerabilities in dependencies |
| **CodeQL** (`security-extended`), also weekly | injection, traversal, unsafe flows in our own code |
| **gitleaks** over the working tree *and* the full git history | a token, key or `.env` that made it into a commit |
| **Trivy** filesystem scan (`vuln,misconfig`) | vulnerable lockfile entries, Dockerfile misconfiguration |
| **Trivy** image scan of the built image | vulnerable OS/Node packages in what actually ships |
| **Dependabot** (npm, GitHub Actions, Docker), weekly | updates, with minor/patch grouped into one PR |

Status at release: 99/99 green on the local backend and 99/99 on MinIO
(`quay.io/minio/minio`) on Node 26, the Docker image builds, both Trivy scans
and gitleaks are clean, `npm audit` reports no vulnerabilities, and the CLI script was
verified by hand (killed halfway through an 8 MB file, resumed from the stored offset,
identical content). The same checks run in GitHub Actions on every push.

---

## 12. Limitations and next steps

- **No antivirus scanning** (see §9) and no quarantine.
- Single process / single node: SQLite and the in-memory tus lock. Horizontal scaling would
  need PostgreSQL and a Redis-based tus locker.
- SHA-256 is computed only for direct uploads; for tus it could be added after
  finalisation (reading back from storage) or via the `checksum` extension.
- Cleanup verifies the existence of every completed file (`stat`); with very many S3
  objects limit this to a sample or run it less often.
- Resuming in the browser after a reload requires picking the file again (a browser
  limitation), and the tus-js-client fingerprint depends on name/size/mtime.
- One administrator role; no SSO/WebAuthn (TOTP is available), no permission levels.
- Presigned URLs are not used (downloads always go through the application). For very
  large files a short-lived presigned `GET` scoped to one object could be added.
- No notifications (e-mail/webhook) for new files; the natural hook is the
  `upload.complete` audit event.
- Only English and Polish UI strings exist; adding a language means one more dictionary in
  `src/i18n.ts` (the type system enforces that every key is translated).

---

## License

Apache License 2.0, see [LICENSE](LICENSE).
