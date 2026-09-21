import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { listAudit } from '../src/services/audit.js';
import { getFile } from '../src/services/files.js';
import { adminDownload, adminPost, boot, listFiles, putFile, randomBytes, type TestApp } from './helpers.js';

let app: TestApp;
beforeAll(async () => { app = await boot(); });
afterAll(async () => { await app.close(); });

describe('admin panel', () => {
  it('redirects anonymous users to the login page and never leaks admin routes', async () => {
    const res = await fetch(`${app.base}/admin`, { redirect: 'manual' });
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/admin/login');
    const dl = await fetch(`${app.base}/admin/files/f_0000000000000000/download`, { redirect: 'manual' });
    expect(dl.status).toBe(302);
  });

  it('shows a placeholder on the public root instead of redirecting to the admin panel', async () => {
    const res = await fetch(`${app.base}/`, { redirect: 'manual' });
    expect(res.status).toBe(200);
    expect(res.headers.get('location')).toBeNull();
    const body = await res.text();
    expect(body).toContain('use the link you were given');
    expect(body).not.toContain('/admin');
  });

  it('creates a case and a link through the HTML forms, showing the full URL once', async () => {
    const s = await app.adminLogin();
    const created = await adminPost(app, s, '/admin/cases', { name: 'Audit <2026>', description: 'desc' });
    expect(created.status).toBe(303);
    const caseId = created.headers.get('location')!.split('/').pop()!;
    expect(caseId).toMatch(/^c_/);

    const page = await fetch(`${app.base}/admin/cases/${caseId}`, { headers: { cookie: s.cookie } });
    const body = await page.text();
    expect(body).toContain('Audit &lt;2026&gt;');
    expect(body).not.toContain('Audit <2026>');

    const linkRes = await adminPost(app, s, `/admin/cases/${caseId}/links`, { label: 'Client "A"', max_file_size: '5MB', max_files: '3', max_total_size: '10MB' });
    expect(linkRes.status).toBe(200);
    const html = await linkRes.text();
    const m = new RegExp(`${app.base.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}/u/([A-Za-z0-9_-]{43})`).exec(html);
    expect(m).not.toBeNull();
    const token = m![1]!;
    // The token is not persisted: the page reloaded later shows only the hint.
    const again = await (await fetch(`${app.base}/admin/cases/${caseId}`, { headers: { cookie: s.cookie } })).text();
    expect(again).not.toContain(token);
    expect(again).toContain(token.slice(0, 6) + '…');

    // Link works for uploads.
    const up = await putFile(app, token, 'hello.txt', Buffer.from('hello'));
    expect(up.status).toBe(201);
  });

  it('rejects per-link limits above the global limit', async () => {
    const s = await app.adminLogin();
    const c = app.mkCase();
    const res = await adminPost(app, s, `/admin/cases/${c.id}/links`, { label: 'x', max_file_size: '999GB' });
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('global limit');
  });

  it('blocks state changes without a CSRF token or from another origin', async () => {
    const s = await app.adminLogin();
    const noToken = await fetch(`${app.base}/admin/cases`, {
      method: 'POST', redirect: 'manual', headers: { cookie: s.cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ name: 'nope' }),
    });
    expect(noToken.status).toBe(403);
    const crossSite = await fetch(`${app.base}/admin/cases`, {
      method: 'POST', redirect: 'manual',
      headers: { cookie: s.cookie, 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example', 'sec-fetch-site': 'cross-site' },
      body: new URLSearchParams({ name: 'nope', _csrf: s.csrf }),
    });
    expect(crossSite.status).toBe(403);
    // Browsers under Referrer-Policy: no-referrer send "Origin: null" on same-origin posts; that must still work.
    const nullOrigin = await fetch(`${app.base}/admin/cases`, {
      method: 'POST', redirect: 'manual',
      headers: { cookie: s.cookie, 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
      body: new URLSearchParams({ name: 'from browser', _csrf: s.csrf }),
    });
    expect(nullOrigin.status).toBe(303);
  });

  it('lets the admin download a file as an attachment with safe headers, and delete it', async () => {
    const s = await app.adminLogin();
    const c = app.mkCase();
    const l = app.mkLink(c.id);
    const data = randomBytes(300_000);
    const up = await putFile(app, l.token, 'za\u017c\u00f3\u0142\u0107 "final".pdf', data);
    expect(up.status).toBe(201);
    const { id } = await up.json() as { id: string };

    const dl = await adminDownload(app, s, id);
    expect(dl.status).toBe(200);
    expect(dl.headers.get('content-type')).toBe('application/octet-stream');
    // Non-ASCII names get a pure-ASCII fallback (every non-ASCII byte becomes "?")
    // plus the RFC 5987 encoded form, which is the one clients actually use.
    expect(dl.headers.get('content-disposition')).toBe(`attachment; filename="za???? \\"final\\".pdf"; filename*=UTF-8''za%C5%BC%C3%B3%C5%82%C4%87%20%22final%22.pdf`);
    expect(dl.headers.get('x-content-type-options')).toBe('nosniff');
    expect(dl.headers.get('content-security-policy')).toContain('sandbox');
    expect(dl.headers.get('content-length')).toBe(String(data.length));
    expect(Buffer.from(await dl.arrayBuffer()).equals(data)).toBe(true);

    const del = await adminPost(app, s, `/admin/files/${id}/delete`);
    expect(del.status).toBe(303);
    expect(getFile(app.ctx.db, id)!.status).toBe('deleted');
    expect(await app.ctx.storage.stat(id)).toBeNull();
    expect((await adminDownload(app, s, id)).status).toBe(404);
    // The uploader no longer sees it either.
    expect((await listFiles(app, l.token)).some((f) => f.id === id)).toBe(false);

    const actions = listAudit(app.ctx.db, 50).map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(['file.delete', 'file.download', 'upload.complete', 'admin.login']));
  });

  it('serves the tus client and helper script locally (no external scripts)', async () => {
    expect((await fetch(`${app.base}/static/vendor/tus.min.js`)).status).toBe(200);
    expect((await fetch(`${app.base}/static/inletbox-upload.sh`)).status).toBe(200);
    expect((await fetch(`${app.base}/static/upload.js`)).status).toBe(200);
  });

  it('rejects wrong credentials and rate limits repeated failures', async () => {
    const attempt = () => fetch(`${app.base}/admin/login`, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'admin', password: 'wrong-password-123' }),
    });
    for (let i = 0; i < 10; i++) expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(429);
  });
});
