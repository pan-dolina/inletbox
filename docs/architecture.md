# Architecture, storage and data model

[← back to the README](../README.md)

## Architecture and data model

A single-process Express + SQLite monolith; storage is a plug-in.

```
src/
  config.ts            environment variables → Config (parseSize, branding, …)
  i18n.ts              language list, Accept-Language negotiation, placeholders
  locales/             one dictionary per language; en.ts defines the keys
  db.ts                node:sqlite, migrations from migrations/*.sql, transaction()
  crypto.ts            ids, tokens, sha256, scrypt
  totp.ts              RFC 6238 TOTP, base32, recovery codes
  log.ts               JSON logging + redaction
  storage/             types (interface), local, s3, limit (byte counter + hash)
  services/            auth (accounts, sessions, TOTP), users (roles, case assignments), cases, links, files (reservations), audit, cleanup
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

Tables ([`migrations/`](../migrations/)):

- `admins` — every panel account, whatever its role (id, username, password_hash,
  role admin|user, disabled_at, must_change_password, last_login_at, totp_secret,
  totp_enabled_at, totp_last_step, totp_failed_count, totp_locked_until)
- `case_members` (case_id, admin_id) — which user may work on which case
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

## Storage

Abstraction in [`src/storage/types.ts`](../src/storage/types.ts): `put` (streaming with a
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

## Limitations and next steps

- **No antivirus scanning** (see [Security](security-model.md#security)) and no quarantine.
- Single process / single node: SQLite and the in-memory tus lock. Horizontal scaling would
  need PostgreSQL and a Redis-based tus locker.
- SHA-256 is computed only for direct uploads; for tus it could be added after
  finalisation (reading back from storage) or via the `checksum` extension.
- Cleanup verifies the existence of every completed file (`stat`); with very many S3
  objects limit this to a sample or run it less often.
- Resuming in the browser after a reload requires picking the file again (a browser
  limitation), and the tus-js-client fingerprint depends on name/size/mtime.
- Two roles and per-case assignment; no finer permissions inside a case (e.g. read-only),
  no SSO/WebAuthn (TOTP is available).
- Presigned URLs are not used (downloads always go through the application). For very
  large files a short-lived presigned `GET` scoped to one object could be added.
- No notifications (e-mail/webhook) for new files; the natural hook is the
  `upload.complete` audit event.
- English and Polish are maintained by people who read them. The other 22 dictionaries
  were translated without review by a native speaker; corrections are welcome and are a
  one-file change in `src/locales/`. Adding a language means one more dictionary there
  plus an entry in `src/i18n.ts` — the types refuse a missing key, and
  `test/i18n.test.ts` refuses a dropped `{placeholder}`.
