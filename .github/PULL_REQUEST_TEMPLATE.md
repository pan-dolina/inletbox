## What changes, and why

<!-- What a user or an operator notices. The why matters more than the diff. -->

## What you ran

<!-- Delete what does not apply. Say what you skipped — that is more useful than a tick. -->

- [ ] `npm run typecheck`
- [ ] `npm test`
- [ ] `TEST_S3=1 npm test` (against MinIO)
- [ ] `npm run test:coverage` (thresholds pass)
- [ ] `docker build .`

## Checklist

- [ ] New behaviour has a test; a fix has a test that fails without it
- [ ] Any new i18n key exists in **both** `en` and `pl`, and in `clientMessages()` if the
      browser script uses it
- [ ] User-visible change has a `CHANGELOG.md` entry
- [ ] No token, password or `.env` content in the diff, the tests or the description
- [ ] Nothing from the "things that look like bugs and are not" list in
      [CONTRIBUTING.md](../CONTRIBUTING.md) was "fixed"
