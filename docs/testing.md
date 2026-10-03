# Tests and security scanning

[← back to the README](../README.md)

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

## Security scanning

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
