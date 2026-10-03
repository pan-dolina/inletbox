# Permissions and security model

[← back to the README](../README.md)

## Permission model

| Who | Can | Cannot |
|---|---|---|
| **Administrator** (cookie session, optional TOTP) | everything a user can, in **every** case; create, disable and delete accounts, change roles, issue new passwords, remove a lost second factor; assign users to cases; read the audit log | change their own role, disable or delete themselves |
| **User** (cookie session, optional TOTP) | in the cases they are **assigned** to: edit/close cases; generate and revoke links, set their expiry and limits; inspect metadata; download and delete files. Create new cases (and are assigned to them) | see or open any other case — it answers `404`, exactly like one that does not exist; manage accounts or assignments; read the audit log |
| **Link holder** (token) | upload files (browser, curl, tus); see the list and status of files uploaded through **that** link | download or preview any file, including their own; delete or overwrite completed files; see files of other links; reach the admin panel |

### Accounts and roles

Every account that existed before 0.5.0 is an administrator. An administrator creates
further accounts under **Users** and picks a role; the application generates a temporary
password (20 characters, shown once) that its owner must replace before they can do
anything else. Assigning someone to a case happens on the case page, under
**Assigned users**; administrators are never listed there, because they see every case.
The access rule lives in one function (`canAccessCase` in `src/services/users.ts`) and is
checked on every route that takes a case, link, file or upload id, including tus.
Role changes, unassignments and disabling take effect on the account's next request, not
at its next login. The instance always keeps at least one active administrator, and no
one can change their own account from the list — their password and 2FA are on
**Security**. `ADMIN_REQUIRE_TOTP` applies to every account, whatever its role.

### Link holders

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

## Security

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
  point: `onUploadFinish` in [`src/http/tus.ts`](../src/http/tus.ts) and the end of `direct` in
  [`src/http/public.ts`](../src/http/public.ts); both call `completeUpload`, and a scanner
  (e.g. ClamAV via `clamd`) could set an extra status (`quarantined`) there before the file
  is offered to the administrator.

An independent code review was run against this codebase before release; its findings
(account-level TOTP lockout, session rotation, `TRUST_PROXY=true`, file modes, CLI script
input validation, socket idle timeout, log redaction) are all addressed and covered by tests.
