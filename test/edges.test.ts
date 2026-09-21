/**
 * Edge and failure paths that the happy-path suites never reach: the logger,
 * storage key validation, service-level input validation, and the global
 * 404/500 handlers. These are the places where a regression leaks an internal
 * message, a stack trace or a token into a response or a log line.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
import { migrate, openDatabase } from '../src/db.js';
import { log, setLogLevel } from '../src/log.js';
import { listAudit } from '../src/services/audit.js';
import { setAdminPassword } from '../src/services/auth.js';
import { createCase, updateCase } from '../src/services/cases.js';
import { runCleanup } from '../src/services/cleanup.js';
import { getFile } from '../src/services/files.js';
import { createLink, linkState, resolveToken } from '../src/services/links.js';
import { assertValidKey, createStorage, StorageNotFoundError } from '../src/storage/index.js';
import { LocalStorage } from '../src/storage/local.js';
import { ADMIN_USER, adminDownload, adminPost, bearer, boot, listFiles, putFile, randomBytes, tusCreate, type TestApp } from './helpers.js';

let app: TestApp;
beforeAll(async () => { app = await boot(); });
afterAll(async () => { await app.close(); });
afterEach(() => { vi.restoreAllMocks(); });

/** Runs `fn` with the process output streams captured, at the given log level. */
function captureLog(level: 'debug' | 'info' | 'warn' | 'error', fn: () => void): { out: string; err: string } {
  const out: string[] = [];
  const err: string[] = [];
  vi.spyOn(process.stdout, 'write').mockImplementation((c) => { out.push(String(c)); return true; });
  vi.spyOn(process.stderr, 'write').mockImplementation((c) => { err.push(String(c)); return true; });
  setLogLevel(level);
  try { fn(); } finally { setLogLevel('error'); }
  return { out: out.join(''), err: err.join('') };
}

describe('logger', () => {
  it('drops secret fields, redacts tokens in strings and errors, and routes by severity', () => {
    const { out, err } = captureLog('debug', () => {
      log.info('request', {
        method: 'GET', path: '/u/SuPerSecretToken123', ip: '10.0.0.1',
        authorization: 'Bearer SuPerSecretToken123', cookie: 'sid=abc', token: 'SuPerSecretToken123', password: 'hunter2',
        skipped: undefined, count: 3,
      });
      log.debug('detail', { note: 'see /u/AnotherToken' });
      log.warn('careful', {});
      log.error('failed', { err: new Error('cannot read /u/LeakedToken') });
    });

    expect(out).not.toContain('SuPerSecretToken123');
    expect(err).not.toContain('LeakedToken');
    const info = JSON.parse(out.split('\n')[0]!);
    expect(info).toMatchObject({ level: 'info', msg: 'request', path: '/u/[redacted]', ip: '10.0.0.1', count: 3 });
    expect(info).not.toHaveProperty('authorization');
    expect(info).not.toHaveProperty('cookie');
    expect(info).not.toHaveProperty('token');
    expect(info).not.toHaveProperty('password');
    expect(info).not.toHaveProperty('skipped');
    expect(typeof info.ts).toBe('string');

    // debug/info go to stdout, warn/error to stderr, so an operator can split them.
    expect(out).toContain('/u/[redacted]');
    expect(err).toContain('"level":"warn"');
    const errLine = JSON.parse(err.trim().split('\n').at(-1)!);
    expect(errLine.err).toEqual({ name: 'Error', message: 'cannot read /u/[redacted]' });
    expect(errLine.err).not.toHaveProperty('stack');
  });

  it('suppresses anything below the configured level', () => {
    const { out, err } = captureLog('warn', () => {
      log.debug('nope');
      log.info('nope');
      log.warn('yes');
    });
    expect(out).toBe('');
    expect(err).toContain('"msg":"yes"');
    expect(err).not.toContain('nope');
  });
});

describe('storage backend selection and key handling', () => {
  it('refuses keys that could escape the storage directory', () => {
    for (const bad of ['', '..', '../etc/passwd', 'a/b', 'a.json', 'x'.repeat(129), 'f_1 2']) {
      expect(() => assertValidKey(bad)).toThrow(/invalid storage key/);
    }
    expect(() => assertValidKey('f_0123456789abcdef')).not.toThrow();
  });

  it('builds the backend the configuration asks for', () => {
    expect(createStorage(loadConfig({ DATA_DIR: os.tmpdir() })).kind).toBe('local');
    const s3cfg = loadConfig({ STORAGE_BACKEND: 's3', S3_BUCKET: 'b', S3_REGION: 'us-east-1', S3_ACCESS_KEY_ID: 'k', S3_SECRET_ACCESS_KEY: 's' });
    expect(createStorage(s3cfg).kind).toBe('s3');
  });

  it('reports a missing object as not-found rather than an ENOENT leak, and deletes idempotently', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inletbox-store-'));
    try {
      const store = new LocalStorage(dir);
      await store.healthCheck();
      expect(await store.stat('f_missing')).toBeNull();
      await expect(store.get('f_missing')).rejects.toBeInstanceOf(StorageNotFoundError);
      await expect(store.delete('f_missing')).resolves.toBeUndefined();

      const res = await store.put('f_present', Readable.from([Buffer.from('hello')]), { maxBytes: 1024 });
      expect(res.size).toBe(5);
      expect(await store.stat('f_present')).toEqual({ size: 5 });
      // Files are owner-only: the drop box is often on a shared host.
      expect(fs.statSync(path.join(dir, 'f_present')).mode & 0o777).toBe(0o600);
      await store.delete('f_present');
      expect(await store.stat('f_present')).toBeNull();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('database bootstrap', () => {
  it('applies migrations once and is safe to re-run', () => {
    const db = openDatabase(':memory:');
    try {
      const first = migrate(db);
      expect(first.length).toBeGreaterThan(0);
      expect(migrate(db)).toEqual([]);
      expect(db.prepare('SELECT COUNT(*) AS n FROM cases').get()).toEqual({ n: 0 });
    } finally {
      db.close();
    }
  });
});

describe('service-level validation', () => {
  it('rejects unusable case names and updates of cases that are gone', () => {
    const db = app.ctx.db;
    expect(() => createCase(db, { name: '   ' })).toThrow(/1-200 characters/);
    expect(() => createCase(db, { name: 'x'.repeat(201) })).toThrow(/1-200 characters/);
    expect(updateCase(db, 'c_does_not_exist', { name: 'x' })).toBeNull();

    const c = createCase(db, { name: 'Edge case', description: ' trimmed ' });
    expect(c.description).toBe('trimmed');
    expect(() => updateCase(db, c.id, { name: '' })).toThrow(/1-200 characters/);
    expect(() => updateCase(db, c.id, { status: 'weird' as 'open' })).toThrow(/Invalid status/);
    // An update that omits a field keeps the stored value.
    expect(updateCase(db, c.id, { description: 'new' })!.name).toBe('Edge case');
  });

  it('rejects link limits that cannot be satisfied', () => {
    const db = app.ctx.db;
    const cfg = app.ctx.cfg;
    const c = createCase(db, { name: 'Limits' });
    const base = { caseId: c.id, label: 'R' };
    expect(() => createLink(db, cfg, { ...base, maxFileBytes: 0 })).toThrow(/global limit/);
    expect(() => createLink(db, cfg, { ...base, maxFileBytes: cfg.maxFileBytes + 1 })).toThrow(/global limit/);
    expect(() => createLink(db, cfg, { ...base, maxFiles: 1.5 })).toThrow(/positive integer/);
    expect(() => createLink(db, cfg, { ...base, maxFiles: 0 })).toThrow(/positive integer/);
    expect(() => createLink(db, cfg, { ...base, maxTotalBytes: 0 })).toThrow(/positive/);
    expect(() => createLink(db, cfg, { ...base, expiresAt: new Date(Date.now() - 1000) })).toThrow(/in the future/);
    expect(() => createLink(db, cfg, { caseId: 'c_nope', label: 'R' })).toThrow(/Case not found/);
    // An empty label falls back to a placeholder rather than rendering as blank.
    expect(createLink(db, cfg, { ...base, label: '   ' }).link.label).not.toBe('');
  });

  it('resolves only well-formed, existing tokens and reports the link state', () => {
    const db = app.ctx.db;
    expect(resolveToken(db, 'not a token')).toBeNull();
    expect(resolveToken(db, 'x'.repeat(43))).toBeNull(); // right shape, never issued

    const c = createCase(db, { name: 'States' });
    const { link, token } = createLink(db, app.ctx.cfg, { caseId: c.id, label: 'R' });
    expect(resolveToken(db, token)!.state).toBe('active');
    expect(linkState({ ...link, revoked_at: new Date().toISOString() }, c)).toBe('revoked');
    expect(linkState({ ...link, expires_at: '2000-01-01T00:00:00.000Z' }, c)).toBe('expired');
    expect(linkState(link, { ...c, status: 'closed' })).toBe('case_closed');
  });
});

describe('error handling', () => {
  it('answers unknown API routes with JSON and unknown pages with the branded error page', async () => {
    const l = app.mkLink(app.mkCase().id);
    const api = await fetch(`${app.base}/api/no-such-thing`, { headers: bearer(l.token) });
    expect(api.status).toBe(404);
    expect(api.headers.get('content-type')).toContain('application/json');
    expect(await api.json()).toEqual({ error: 'not_found' });

    const page = await fetch(`${app.base}/no-such-page`);
    expect(page.status).toBe(404);
    expect(page.headers.get('content-type')).toContain('text/html');
    const body = await page.text();
    expect(body).toContain('<!doctype html>');
    expect(body).toContain('href="/"'); // back to the public placeholder, not the admin panel
  });

  it('turns a storage failure into a 500 without leaking the internal message', async () => {
    const s = await app.adminLogin();
    const c = app.mkCase();
    const l = app.mkLink(c.id);
    const up = await putFile(app, l.token, 'doc.bin', randomBytes(64));
    const { id } = await up.json() as { id: string };

    vi.spyOn(app.ctx.storage, 'get').mockRejectedValue(new Error('bucket credentials rejected: AKIA-INTERNAL'));
    const res = await adminDownload(app, s, id);
    expect(res.status).toBe(500);
    const body = await res.text();
    expect(body).not.toContain('AKIA-INTERNAL');
    expect(body).not.toContain('bucket credentials');
    expect(body).toContain('href="/admin"'); // admin context keeps the admin panel as "home"
  });

  it('reports a storage failure mid-upload as an aborted upload and releases the reservation', async () => {
    const c = app.mkCase();
    const l = app.mkLink(c.id, { maxTotalBytes: 1_000_000 });
    vi.spyOn(app.ctx.storage, 'put').mockRejectedValue(new Error('disk on fire: /srv/secret/path'));
    const res = await putFile(app, l.token, 'doc.bin', randomBytes(64));
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string; message: string };
    expect(body.error).toBe('upload_incomplete');
    // The operator sees the real reason in the log and the audit trail; the uploader never does.
    expect(JSON.stringify(body)).not.toContain('/srv/secret/path');

    vi.restoreAllMocks();
    // The failed attempt left no reserved quota behind: the same link can still fill its budget.
    expect((await listFiles(app, l.token)).filter((f) => f.status === 'complete')).toHaveLength(0);
    const retry = await putFile(app, l.token, 'doc.bin', randomBytes(64));
    expect(retry.status).toBe(201);
  });

  it('reports a file whose bytes vanished from storage as gone, not as a broken download', async () => {
    const s = await app.adminLogin();
    const c = app.mkCase();
    const l = app.mkLink(c.id);
    const up = await putFile(app, l.token, 'vanishing.bin', randomBytes(64));
    const { id } = await up.json() as { id: string };

    await app.ctx.storage.delete(id); // simulates an operator wiping the object store
    const res = await adminDownload(app, s, id);
    expect(res.status).toBe(410);
    expect(await res.text()).toContain('<!doctype html>');
  });

  it('rejects an oversized request body with a 400 page rather than an unhandled error', async () => {
    const s = await app.adminLogin();
    const res = await adminPost(app, s, '/admin/cases', { name: 'x'.repeat(200_000) });
    expect(res.status).toBe(413);
    expect(res.headers.get('content-type')).toContain('text/html');
  });

  it('separates a missing Authorization header from a token that does not resolve', async () => {
    for (const headers of [undefined, { authorization: 'Basic abc' }, { authorization: 'Bearer' }]) {
      const res = await fetch(`${app.base}/api/files`, { headers });
      expect(res.status).toBe(401);
      expect((await res.json() as { error: string }).error).toBe('missing_token');
    }
    // A well-formed but unissued token is "unknown link", never "wrong password": the
    // response says nothing about whether the token ever existed.
    const unknown = await fetch(`${app.base}/api/files`, { headers: bearer('x'.repeat(43)) });
    expect(unknown.status).toBe(404);
    expect(await unknown.json()).toEqual({ error: 'invalid_token', message: 'Unknown upload link' });
  });
});

describe('branding endpoints with a broken logo', () => {
  let branded: TestApp;
  let dir: string;
  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inletbox-badlogo-'));
    // Configured, accepted by the config validator, but removed before the server serves it.
    const logo = path.join(dir, 'logo.png');
    fs.writeFileSync(logo, 'not really a png');
    branded = await boot({ BRAND_LOGO_PATH: logo });
    fs.rmSync(logo);
  });
  afterAll(async () => { await branded.close(); fs.rmSync(dir, { recursive: true, force: true }); });

  it('404s instead of crashing, and still serves the colour theme', async () => {
    const logo = await fetch(`${branded.base}/brand/logo`);
    expect(logo.status).toBe(404);
    const theme = await fetch(`${branded.base}/brand/theme.css`);
    expect(theme.status).toBe(200);
    expect(theme.headers.get('content-type')).toContain('text/css');
    expect(await theme.text()).toContain('--primary:');
  });
});

describe('admin case editing and CLI password reset', () => {
  it('renames a case, reports validation errors inline, and ignores malformed ids', async () => {
    const s = await app.adminLogin();
    const c = app.mkCase('Before');

    const renamed = await adminPost(app, s, `/admin/cases/${c.id}`, { name: 'After', description: 'note' });
    expect(renamed.status).toBe(200);
    expect(await renamed.text()).toContain('After');

    const bad = await adminPost(app, s, `/admin/cases/${c.id}`, { name: '' });
    expect(bad.status).toBe(400);
    expect(await bad.text()).toContain('1-200 characters');

    // A junk id is either rejected by the router or falls back to the case list;
    // what matters is that it never reaches the database as a wildcard, never
    // produces a 5xx and is never echoed back into the page.
    for (const id of ['../../etc', "c_' OR 1=1 --", 'c_' + 'x'.repeat(200)]) {
      const res = await fetch(`${app.base}/admin/cases/${encodeURIComponent(id)}`, { headers: { cookie: s.cookie } });
      expect([200, 404]).toContain(res.status);
      const text = await res.text();
      expect(text).not.toContain('OR 1=1');
      expect(text).not.toContain('SQLITE');
    }
  });

  it('resets a password from the CLI path, ending that admin’s sessions', async () => {
    const other = await boot();
    try {
      const s = await other.adminLogin();
      expect((await fetch(`${other.base}/admin`, { headers: { cookie: s.cookie } })).status).toBe(200);

      expect(() => setAdminPassword(other.ctx.db, ADMIN_USER, 'short')).toThrow(/at least 12 characters/);
      expect(setAdminPassword(other.ctx.db, 'nobody', 'a-long-enough-password')).toBe(false);
      expect(setAdminPassword(other.ctx.db, ADMIN_USER, 'a-long-enough-password')).toBe(true);

      const after = await fetch(`${other.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' });
      expect(after.headers.get('location')).toBe('/admin/login');
    } finally {
      await other.close();
    }
  });
});

describe('cleanup', () => {
  it('expires abandoned uploads, flags files whose bytes vanished, and survives a failing orphan sweep', async () => {
    const other = await boot();
    try {
      const c = other.mkCase();
      const l = other.mkLink(c.id);
      const done = await putFile(other, l.token, 'kept.bin', randomBytes(128));
      const { id } = await done.json() as { id: string };
      // The object disappears behind the application's back.
      await other.ctx.storage.delete(id);

      const create = await tusCreate(other, l.token, 4096, 'abandoned.bin');
      expect(create.status).toBe(201);

      vi.spyOn(other.ctx.storage, 'cleanupOrphans').mockRejectedValue(new Error('bucket unreachable'));
      const report = await runCleanup(
        { db: other.ctx.db, cfg: other.ctx.cfg, storage: other.ctx.storage, tusStore: other.ctx.tusStore },
        { ttlMs: 0, verifyFiles: true },
      );

      expect(report.staleUploads).toBe(1);
      expect(report.missingFiles).toBe(1);
      expect(report.orphans).toBe(0); // the sweep failed, but cleanup still finished
      expect(getFile(other.ctx.db, id)!.status).toBe('missing');
      expect(listAudit(other.ctx.db, 50).map((r) => r.action)).toEqual(expect.arrayContaining(['upload.expired', 'file.missing']));
    } finally {
      await other.close();
    }
  });
});

describe('upload page without optional limits', () => {
  it('lists only the limits that actually apply', async () => {
    const c = app.mkCase();
    const unlimited = app.mkLink(c.id);
    const capped = app.mkLink(c.id, { maxFiles: 3, maxTotalBytes: 1024 * 1024 });

    const plain = await (await fetch(`${app.base}/u/${unlimited.token}`)).text();
    expect(plain).toContain('Maximum file size');
    expect(plain).not.toContain('Maximum number of files');
    expect(plain).not.toContain('Total data limit');

    const limited = await (await fetch(`${app.base}/u/${capped.token}`)).text();
    expect(limited).toContain('Maximum number of files');
    expect(limited).toContain('Total data limit');
  });
});

describe('project mark in the top bar', () => {
  it('serves a transparent mark and shows it opposite the operator branding', async () => {
    const res = await fetch(`${app.base}/static/inletbox-mark.png`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('image/png');
    const png = Buffer.from(await res.arrayBuffer());
    expect(png.subarray(0, 8).toString('latin1')).toBe('\x89PNG\r\n\x1a\n');
    // IHDR colour type lives at byte 25; 6 is RGBA. Without an alpha channel the mark
    // would show a white box on the dark top bar.
    expect(png[25]).toBe(6);

    const l = app.mkLink(app.mkCase().id);
    for (const url of [`${app.base}/`, `${app.base}/admin/login`, `${app.base}/u/${l.token}`]) {
      const body = await (await fetch(url)).text();
      expect(body).toContain('class="project-mark"');
      // Opposite the brand: the brand opens the bar, the mark closes it.
      expect(body.indexOf('class="brand"')).toBeLessThan(body.indexOf('class="project-mark"'));
      // Cache-busted with the rest of the static assets.
      expect(body).toMatch(/\/static\/inletbox-mark\.png\?v=[a-f0-9]+/);
    }
  });
});

describe('release version in the footer', () => {
  it('shows the running version on public and admin pages, matching package.json', async () => {
    const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string };
    const l = app.mkLink(app.mkCase().id);
    for (const url of [`${app.base}/`, `${app.base}/admin/login`, `${app.base}/u/${l.token}`]) {
      expect(await (await fetch(url)).text()).toContain(`<span class="version">v${pkg.version}</span>`);
    }
    // A stale hard-coded string is the failure mode this guards against.
    expect(pkg.version).toMatch(/^\d+\.\d+\.\d+$/);
  });
});

describe('theme and upload page layout', () => {
  it('ships an automatic dark theme that leaves the instance brand colours alone', async () => {
    const css = await (await fetch(`${app.base}/static/style.css`)).text();
    expect(css).toContain('color-scheme: light dark');

    const start = css.indexOf('@media (prefers-color-scheme: dark)');
    expect(start).toBeGreaterThan(-1);
    const darkBlock = css.slice(start, css.indexOf('\n}\n', css.indexOf('\n  }', start)));
    // /brand/theme.css sets these per instance and is loaded after style.css:
    // redefining them here would silently undo an operator's branding in dark mode.
    for (const token of ['--primary:', '--topbar:', '--accent:']) {
      expect(darkBlock).not.toContain(token);
    }
    // Surfaces blend against a token, never a literal white, or they stay light in dark mode.
    expect(css).not.toMatch(/color-mix\([^)]*,\s*white\)/);

    // The theme needs no script, so it works under the strict CSP and with JS off.
    const page = await (await fetch(`${app.base}/admin/login`)).text();
    expect(page).toContain('/static/style.css');
    expect(page).not.toContain('prefers-color-scheme');
  });

  it('renders the terminal instructions collapsed while keeping them in the page', async () => {
    const l = app.mkLink(app.mkCase().id);
    const body = await (await fetch(`${app.base}/u/${l.token}`)).text();

    const details = /<details class="collapsible"([^>]*)>/.exec(body);
    expect(details).not.toBeNull();
    expect(details![1]).not.toContain('open'); // folded until asked for
    expect(body).toContain('<summary>Upload from the terminal');
    // Still served (and findable by in-page search / assistive tech), just not unfolded.
    expect(body).toContain('curl --fail-with-body');
    expect(body).toContain('inletbox-upload.sh');
    // The drop target above it is the one thing that is not hidden behind a disclosure.
    expect(body).toContain('class="dropzone"');
    expect(body).toContain('class="dropzone-lead"');
  });
});
