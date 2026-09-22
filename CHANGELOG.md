# Changelog

Notable changes per release, written for whoever runs this — so entries say what
changes for an operator or a link holder, not which files moved. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The section for a version is what ends up in its
[GitHub Release](https://github.com/pan-dolina/inletbox/releases): `.github/workflows/release.yml`
reads it from this file, refuses to publish a tag that has no section here, and rewrites
a published release's notes whenever its section changes on `main`.

## [0.3.0] - 2026-09-22

### Added

- **The interface speaks all 24 official languages of the European Union.** Every page —
  the admin panel, the upload page, error pages — and every API error message is
  translated. English and Polish are maintained by people who read them; the other 22
  have not yet been reviewed by native speakers, and corrections are welcome.
- The footer language switcher is now a menu listing each language by its own name
  (Deutsch, Français, Ελληνικά…). It works without JavaScript, like the rest of the page.
- The project mark appears in the top bar, opposite the operator's own branding.

### Changed

- **Visitors may see a different language than before.** The page used to be Polish only
  for browsers set to Polish first and English for everyone else; it now follows the
  browser's first language whenever it is one of the 24, so a German browser gets German
  instead of English. A language the browser only lists further down is still ignored in
  favour of English. A choice made in the footer menu overrides this, as before.
- Dates are written the way the chosen language writes them.
- Static files referenced with a content hash are cached by browsers for a year; the
  unhashed ones, such as the downloadable upload script, for an hour, so a new release
  reaches people who fetched the script before.

### Fixed

- The Caddy example in the README did not parse, and its access-log filter did not
  redact upload tokens — it replaced every logged path, including admin ones, with the
  literal pattern. **If you copied it, your access log recorded no paths at all.** The
  corrected example uses `regexp` and has been checked with `caddy validate`.
- The README now documents running behind Cloudflare, where the client address has to
  be taken from `CF-Connecting-IP` at the edge; otherwise the audit log records
  Cloudflare's addresses instead of the uploader's.

## [0.2.0] - 2026-09-21

### Changed

- **Node 26 is now the minimum.** `engines`, `@types/node` and CI all say 26, matching
  the `node:26-alpine` the Docker image already shipped. Operators using Docker are
  unaffected. **Anyone running this outside Docker on Node 24 has to upgrade** — Node 24
  is in maintenance until 2028-04-30, but the types have to describe the oldest supported
  runtime, so keeping 24 meant staying on `@types/node@24` indefinitely.

### Added

- Pushing a `vX.Y.Z` tag now publishes a GitHub Release automatically, with its notes
  taken from this file.

## [0.1.1] - 2026-09-21

### Added

- **Automatic dark theme.** Follows the operating system / browser preference
  (`prefers-color-scheme`). No toggle, no cookie and no JavaScript, so the strict CSP is
  untouched. `BRAND_COLOR_*` values are left alone in dark mode, so an instance keeps its
  own colours — pick ones legible on a light *and* a dark card.
- **The running version is shown in the footer**, read from `package.json` at startup. It
  appends to `BRAND_FOOTER_TEXT` rather than replacing it. Note this makes the version
  visible to anyone holding an upload link, not only to admins.
- Tests for the failure paths — log redaction, storage-key escapes, error pages that must
  not leak internal messages, migrations re-running, a logo file that disappeared (75 →
  101 tests), with coverage thresholds enforced in CI.
- Security scanning on every push: `npm audit`, CodeQL, gitleaks over the working tree and
  the full history, Trivy filesystem and image scans, plus Dependabot for npm, GitHub
  Actions and Docker.

### Changed

- **Upload page**: the terminal snippets are collapsed by default and the drop target is
  larger. The snippets embed the bearer token, so they should not be on screen unless
  someone asks for them.
- Dependencies: TypeScript 7, Vitest 5, content-disposition 3. The last one changes the
  `Content-Disposition` ASCII fallback for non-ASCII file names — every non-ASCII byte now
  becomes `?` where Latin-1 characters used to survive. The `filename*=UTF-8''…` form
  still carries the real name and is what clients actually use.

### Fixed

- **The upload progress bar no longer sits full while the server is still working.** tus
  reports the last chunk as sent before the server has accepted it and written the row, so
  a frozen full bar was indistinguishable from a stalled upload. It now goes indeterminate
  with "all bytes sent, the server is finishing…" and returns to a solid 100% on success.
- The audit log no longer overflows its card. Opaque ids break anywhere and the JSON
  details column is width-capped, so nothing is cut off at the window edge.

## [0.1.0] - 2026-09-18

First release.

### Added

- Cases and per-recipient upload links (Bearer token in the URL path, never a query
  string). A link holder can upload and list only their own files, and can never download
  anything back.
- Resumable uploads over **tus**, from the browser and from a CLI helper script, on local
  disk or S3/MinIO.
- Per-link limits (file size, file count, total size) with quota reserved inside a
  transaction, so concurrent uploads cannot overshoot.
- Admin panel with TOTP 2FA (RFC 6238) and recovery codes, optionally required for every
  admin, plus self-service password change.
- Bilingual UI (English/Polish). Polish only when it is the browser's primary language; a
  footer switcher stores an explicit choice in a cookie.
- Branding without code changes: name, logo, colours and footer text, served same-origin
  so the CSP stays free of `unsafe-inline`.
- A placeholder on the public root instead of a redirect to the admin panel.
- Audit log, retention cleanup for unfinished uploads and orphaned storage objects, and a
  Docker Compose deployment.
- Apache-2.0.

[0.3.0]: https://github.com/pan-dolina/inletbox/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pan-dolina/inletbox/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/pan-dolina/inletbox/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/pan-dolina/inletbox/releases/tag/v0.1.0
