# Installation

[← back to the README](../README.md)

## Docker Compose (recommended)

Only two files are needed, `docker-compose.yml` and `.env`; no checkout, no build:

```bash
mkdir inletbox && cd inletbox
curl -fsSLO https://raw.githubusercontent.com/pan-dolina/inletbox/main/docker-compose.yml
curl -fsSL -o .env https://raw.githubusercontent.com/pan-dolina/inletbox/main/.env.example
# set PUBLIC_URL to the address clients will use (https://drop.example.com)
docker compose up -d
docker compose exec app node dist/cli.js create-admin admin      # password prompted interactively, min. 12 characters
```

After the first login enable two-factor authentication in the panel (**Security**) or
enforce it for every account with `ADMIN_REQUIRE_TOTP=true`. Everyone else gets an account
from that administrator under **Users** ([accounts and roles](security-model.md#accounts-and-roles))
— the CLI is only needed for the first one.

Panel: `PUBLIC_URL/admin`. Data (the SQLite database and, with the local backend, the
files) lives on the `inletbox-data` volume mounted at `/data`. The container listens on
`127.0.0.1:3000`; put a TLS-terminating [reverse proxy](reverse-proxy.md) in front of it.

There is no default password. The first administrator is created only through the CLI on
the server (the password can also be piped: `echo "$PASS" | node dist/cli.js create-admin admin --password-stdin`).

## The image

Releases are published to the GitHub Container Registry as
`ghcr.io/pan-dolina/inletbox:<version>` (also `:<major>.<minor>` and `:latest`), for
`linux/amd64` and `linux/arm64`. Each one is built by `.github/workflows/image.yml` from
its release tag, scanned with Trivy before it is pushed, and published with an SBOM and a
signed build provenance attestation. To check that an image really was built from this
repository:

```bash
gh attestation verify oci://ghcr.io/pan-dolina/inletbox:0.6.1 --owner pan-dolina
```

`docker-compose.yml` runs the version set in `.env` as `INLETBOX_VERSION`. Pin it
there: `latest` changes whenever a release is published. `docker compose up -d --build`
builds the checkout instead and tags the result with the same name.

## CLI

```bash
node dist/cli.js create-admin <user> [--password-stdin]
node dist/cli.js reset-password <user>      # also ends that admin's sessions
node dist/cli.js disable-totp <user>        # lost authenticator and recovery codes; ends all their sessions
node dist/cli.js cleanup [--ttl-hours N]    # run the periodic cleanup now
node dist/cli.js migrate
```

In Docker, prefix each with `docker compose exec app`; in a source checkout use
`npm run cli -- <command>`.

## Upgrading

Pending database migrations are applied on start-up, each in its own transaction. Take a
copy of the database first: it runs in WAL mode, so copying `inletbox.sqlite` on its own
can give you a stale file. `VACUUM INTO` produces a consistent one:

```bash
docker compose exec app node -e "new (require('node:sqlite').DatabaseSync)('/data/inletbox.sqlite').exec(\"VACUUM INTO '/data/inletbox-backup.sqlite'\")"
```

Then set `INLETBOX_VERSION` in `.env` to the new release and:

```bash
docker compose pull
docker compose up -d
```

(From a source checkout: `git fetch --tags && git checkout vX.Y.Z && docker compose up -d --build`.)

Going back is the same with the previous version number, plus restoring that copy if a
migration ran in between.

Read the release's section in [CHANGELOG.md](../CHANGELOG.md) before upgrading; anything
that changes behaviour for administrators or link holders is listed there.

## Local development

```bash
npm install
cp .env.example .env            # for http://localhost set COOKIE_SECURE=false
npm run cli -- create-admin admin
npm run dev                     # http://localhost:3000/admin
```

## MinIO test profile

```bash
docker compose --profile minio up -d           # MinIO + creation of the private "inletbox" bucket
# in .env: STORAGE_BACKEND=s3  S3_ENDPOINT=http://minio:9000  S3_BUCKET=inletbox
#          S3_ACCESS_KEY_ID=minioadmin  S3_SECRET_ACCESS_KEY=minioadmin  S3_FORCE_PATH_STYLE=true
docker compose up -d --build app
```

For a real S3 bucket, the required IAM permissions are listed under
[Storage](architecture.md#storage).

## Next steps

- [Configuration](configuration.md) — every environment variable, branding.
- [Reverse proxy](reverse-proxy.md) — nginx and Caddy settings for large uploads, token
  redaction in access logs, running behind Cloudflare.
