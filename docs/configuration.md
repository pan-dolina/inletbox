# Configuration

[← back to the README](../README.md)

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

## Branding

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

## Interface languages

The interface is available in the 24 official languages of the European Union. There is
nothing to configure. A page follows the browser's primary language (`Accept-Language`)
if it is one of the 24, and English otherwise. The footer has a menu listing every
language by its own name; a choice made there is stored in a cookie and always wins. API
error messages follow the same language.
