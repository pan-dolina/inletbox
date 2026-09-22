# Security policy

inletbox receives files from people outside your organisation, so a flaw here is a flaw
in a trust boundary. Reports are welcome and will be taken seriously.

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/pan-dolina/inletbox/security/advisories/new).
It creates a private thread visible only to you and the maintainers, and it can become a
published advisory with a CVE once a fix is out.

Useful things to include, as far as you have them:

- the version (it is in the page footer, e.g. `v0.3.0`) and the storage backend (local or S3);
- whether the instance runs behind a reverse proxy, and what `TRUST_PROXY` is set to;
- what an attacker gains — reading another link's files, bypassing a quota, reaching the
  admin panel, something else;
- the smallest reproduction you can manage: a request, a file name, a sequence of steps.

You will get an acknowledgement within a few days. This is a small project without a paid
security team, so please allow reasonable time for a fix before disclosing publicly.

There is no bug bounty.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.3.x | yes |
| 0.2.x and older | no — upgrade, the upgrade path is a redeploy |

The project is pre-1.0 and fixes land on `main`. There are no backport branches: a
security fix ships in the next release, and the supported way to take it is to redeploy.

## What is in scope

Anything that breaks one of the guarantees the application is built on:

- a link holder reading, downloading or listing files that are not their own;
- reaching any admin route, or any file, without a valid session;
- bypassing per-link limits or the quota reservation;
- a token appearing somewhere it should not — a log line, the audit view, an API response;
- defeating the TOTP second factor, the session rotation, or the CSRF protection;
- stored or reflected XSS, path traversal into the storage directory, SSRF from the S3
  configuration.

## What is not

- Findings that require an operator to misconfigure the instance in a way the
  documentation warns against — for example setting `TRUST_PROXY=true`, which the config
  loader refuses outright.
- Missing hardening headers on endpoints that serve no content.
- Reports from automated scanners with no demonstrated impact.
- Denial of service through sheer upload volume. Size and count limits are per link; a
  link you were given is a link you were trusted with.
- Anything about the deployment of a particular instance rather than this code.

## How this code is checked

Every push runs, alongside the test suite: `npm audit`, CodeQL (`security-extended`),
gitleaks over the working tree and the full git history, and Trivy scans of both the
repository and the built image. Dependabot watches npm, GitHub Actions and Docker.
`test/security.test.ts` and `test/totp.test.ts` exist because an independent review agent
audited this codebase, and they are the regression net for that review.

None of that replaces a human finding something. Please report.
