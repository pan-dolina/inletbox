import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getFile } from '../src/services/files.js';
import { linkUsage } from '../src/services/links.js';
import { adminPost, bearer, boot, listFiles, putFile, randomBytes, tusCreate, tusHead, tusPatch, type TestApp } from './helpers.js';

let app: TestApp;
beforeAll(async () => { app = await boot(); });
afterAll(async () => { await app.close(); });

describe('link lifecycle', () => {
  it('serves the upload page only for valid, active tokens', async () => {
    const c = app.mkCase('Sprawa <X>'); const l = app.mkLink(c.id, { label: 'Odbiorca & Co' });
    const page = await fetch(l.url);
    expect(page.status).toBe(200);
    const body = await page.text();
    expect(body).toContain('Sprawa &lt;X&gt;');
    expect(body).toContain('Odbiorca &amp; Co');
    expect(body).toContain(`Authorization: Bearer ${l.token}`);
    expect(body).toContain('--fail-with-body');
    expect(body).not.toMatch(/<script[^>]+src="https?:\/\//);
    expect(page.headers.get('referrer-policy')).toBe('no-referrer');
    expect(page.headers.get('content-security-policy')).toContain("script-src 'self'");
    expect(page.headers.get('cache-control')).toBe('no-store');

    expect((await fetch(`${app.base}/u/${'x'.repeat(43)}`)).status).toBe(404);
    expect((await fetch(`${app.base}/u/short`)).status).toBe(404);
  });

  it('expired links are refused everywhere', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { expiresAt: new Date(Date.now() + 60_000) });
    expect((await putFile(app, l.token, 'ok.txt', Buffer.from('x'))).status).toBe(201);
    app.ctx.db.prepare('UPDATE links SET expires_at = ? WHERE id = ?').run(new Date(Date.now() - 1000).toISOString(), l.id);
    const page = await fetch(l.url);
    expect(page.status).toBe(403);
    expect(await page.text()).toContain('expired');
    const api = await fetch(`${app.base}/api/files`, { headers: bearer(l.token) });
    expect(api.status).toBe(403);
    expect((await api.json() as { error: string }).error).toBe('link_expired');
    expect((await putFile(app, l.token, 'late.txt', Buffer.from('x'))).status).toBe(403);
    expect((await tusCreate(app, l.token, 10, 'late.bin')).status).toBe(403);
  });

  it('revoking a link stops uploads immediately, including in-flight resumable ones', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const created = await tusCreate(app, l.token, 1000, 'inflight.bin');
    const location = created.headers.get('location')!;
    const id = location.split('/').pop()!;
    await tusPatch(app, l.token, location, 0, randomBytes(500));

    const s = await app.adminLogin();
    const res = await adminPost(app, s, `/admin/links/${l.id}/revoke`);
    expect(res.status).toBe(303);

    expect((await fetch(l.url)).status).toBe(403);
    const api = await fetch(`${app.base}/api/files`, { headers: bearer(l.token) });
    expect((await api.json() as { error: string }).error).toBe('link_revoked');
    expect((await tusPatch(app, l.token, location, 500, randomBytes(500))).status).toBe(403);
    expect((await tusHead(app, l.token, location)).status).toBe(403);
    expect(getFile(app.ctx.db, id)!.status).toBe('aborted');
    expect(await app.ctx.storage.stat(id)).toBeNull();
    expect(linkUsage(app.ctx.db, l.id).reserved_bytes).toBe(0);
    // Revoking again is a no-op.
    expect((await adminPost(app, s, `/admin/links/${l.id}/revoke`)).status).toBe(303);
  });

  it('closing a case blocks all its links; reopening restores them', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const s = await app.adminLogin();
    expect((await adminPost(app, s, `/admin/cases/${c.id}/status`, { status: 'closed' })).status).toBe(303);
    const api = await fetch(`${app.base}/api/files`, { headers: bearer(l.token) });
    expect(api.status).toBe(403);
    expect((await api.json() as { error: string }).error).toBe('case_closed');
    expect((await fetch(l.url)).status).toBe(403);
    // No new links for a closed case.
    expect((await adminPost(app, s, `/admin/cases/${c.id}/links`, { label: 'x' })).status).toBe(400);
    expect((await adminPost(app, s, `/admin/cases/${c.id}/status`, { status: 'open' })).status).toBe(303);
    expect((await putFile(app, l.token, 'again.txt', Buffer.from('x'))).status).toBe(201);
    expect(await listFiles(app, l.token)).toHaveLength(1);
  });

  it('exposes only non-sensitive link info to the uploader', async () => {
    const c = app.mkCase('Case'); const l = app.mkLink(c.id, { maxFiles: 5, maxTotalBytes: 1_000_000 });
    const info = await (await fetch(`${app.base}/api/link`, { headers: bearer(l.token) })).json() as Record<string, unknown>;
    expect(info).toMatchObject({ case: { name: 'Case' }, link: { label: 'Recipient' }, limits: { maxFiles: 5, maxTotalBytes: 1_000_000 } });
    expect(JSON.stringify(info)).not.toContain('token_hash');
    expect(JSON.stringify(info)).not.toContain(l.id);
  });
});
