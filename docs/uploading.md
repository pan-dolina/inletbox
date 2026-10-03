# Uploading: curl, resumable uploads and limits

[← back to the README](../README.md)

## Uploading from the terminal (curl)

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

## Resumable uploads

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
[`scripts/inletbox-upload.sh`](../scripts/inletbox-upload.sh) (also downloadable from the
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

## Limits and reservations

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
