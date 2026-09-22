# Contributing

Thanks for looking. This is a small, opinionated project: a private file drop box where
the security model is the product. Changes are welcome, but a patch that makes the code
prettier at the cost of one of the guarantees below will be declined.

## Before you start

Open an issue first for anything beyond a bug fix. It is cheaper to disagree about an
approach in a paragraph than in a pull request.

**Do not report vulnerabilities here.** See [SECURITY.md](SECURITY.md).

## Getting it running

Node 26 or newer is required — `engines` says so, the Docker image ships it, and CI tests
only that. There are no native modules.

```bash
npm install
cp .env.example .env            # for http://localhost set COOKIE_SECURE=false
npm run cli -- create-admin admin
npm run dev                     # http://localhost:3000/admin
```

## The gate

These have to pass. CI runs all of them, so running them first saves a round trip.

```bash
npm run typecheck               # tsc --noEmit
npm test                        # vitest, local SQLite backend
npm run test:coverage           # same, with thresholds enforced (90/85/90/93)
docker run -d -p 127.0.0.1:9000:9000 quay.io/minio/minio server /data
TEST_S3=1 npm test              # the same suite against S3
docker build -t inletbox:local .
```

There is no lint script on purpose; typecheck and the tests are the gate.

### Tests

- Each test file boots a real HTTP server on a random port with its own temporary
  `DATA_DIR`, so files run in parallel safely. See `boot()` in `test/helpers.ts`.
- Assertions expect **English** strings by default. Send `accept-language: pl` to test
  Polish.
- New behaviour needs a test. A bug fix needs a test that fails without it.
- Failure paths belong in `test/edges.test.ts` — that is where a regression leaks an
  internal message or a token, and it is the file that exists to catch it.
- Touching auth, CSRF, or an upload error path? Re-run `test/security.test.ts` and
  `test/totp.test.ts`. They were written after an independent security review.

## Things that look like bugs and are not

The README has the full architecture; these are the ones people try to "fix" first:

- **`Origin: null` is accepted on admin POSTs.** `Referrer-Policy: no-referrer` makes
  Chrome send it on same-origin form posts. Sec-Fetch-Site and the CSRF token are the real
  checks. Tightening this breaks same-site posts.
- **`TRUST_PROXY=true` is refused** by the config loader. Only a hop count or an address
  list is accepted, because `true` lets a client forge `X-Forwarded-For` and defeat the
  rate limits.
- **The token lives in the URL path** (`/u/<token>`), never a query string, and the logger
  redacts it. Query strings end up in access logs and `Referer` headers.
- **A mid-stream upload rejection responds with `Connection: close`.** Reusing that socket
  hung fetch clients in tests.
- **The TOTP replay guard stores the last accepted step** and refuses that step or
  earlier. Tests clear it instead of sleeping 30 seconds; that is deliberate.
- **The dark theme never redefines `--primary`, `--topbar` or `--accent`.**
  `/brand/theme.css` sets those per instance and loads after `style.css`, so redefining
  them silently undoes an operator's branding.
- **`.queue progress` must not get `appearance: none`.** That removes the browser's native
  indeterminate animation, which is the signal that an upload is being finalised rather
  than stalled.

If one of these is genuinely wrong, say so in an issue with the case that breaks it.

## Style

Match the surrounding code: same comment density, same naming, same idiom. A comment
should say *why*, not restate the line below it.

Every view goes through the `html` tagged template in `src/http/html.ts`, which escapes
interpolations. Never build markup by concatenation — client-supplied file names, labels
and case names reach the admin panel.

Every i18n key must exist in all 24 dictionaries in `src/locales/`; `en.ts` defines the
keys and the types refuse a dictionary that lacks one. A new string therefore needs a
translation in every language — if you cannot write one, say so in the pull request
rather than pasting the English in, which `test/i18n.test.ts` notices. Strings shown by
the browser upload script also have to be listed in `clientMessages()`, or they render
as the raw key.

Translations other than English and Polish have not been reviewed by native speakers. A
pull request that fixes wording in one of them is welcome on its own.

## Commits and pull requests

- One logical change per commit. The subject line says what changes for a user or an
  operator; the body says why, and what you decided against.
- Keep the branch rebased on `main`.
- A user-visible change needs an entry in [CHANGELOG.md](CHANGELOG.md) under the
  unreleased version's section. The release workflow reads that file and refuses to
  publish a tag with no section, so this is not optional at release time.
- Say in the PR what you ran and what you did not. "Tested locally" is not a test report.

## Releasing

Maintainers only: add the version's section to `CHANGELOG.md`, bump `version` in
`package.json`, commit, then push an annotated `vX.Y.Z` tag. The Release workflow turns
the tag into a GitHub Release using that changelog section.

Fixing a published release's notes means fixing `CHANGELOG.md` on `main`: the same
workflow rewrites the notes of every existing release whose section changed.
`.github/scripts/release-notes.sh vX.Y.Z` prints what a release will say, locally.
