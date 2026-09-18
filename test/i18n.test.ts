import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { negotiateLang, t } from '../src/i18n.js';
import { bearer, boot, type TestApp } from './helpers.js';

describe('language negotiation', () => {
  it('picks the best supported language from Accept-Language, defaulting to English', () => {
    expect(negotiateLang(undefined)).toBe('en');
    expect(negotiateLang('pl')).toBe('pl');
    expect(negotiateLang('pl-PL,pl;q=0.9,en-US;q=0.8')).toBe('pl');
    // Only the browser's primary language counts: a German user with Polish as a fallback still gets English.
    expect(negotiateLang('de-DE,de;q=0.9,pl;q=0.7')).toBe('en');
    expect(negotiateLang('de-DE,de;q=0.9')).toBe('en');
    expect(negotiateLang('pl,de;q=0.8')).toBe('pl');
    expect(negotiateLang('en-GB;q=0.5, pl;q=0.9')).toBe('pl');
    expect(negotiateLang('pl;q=0, en')).toBe('en');
    expect(negotiateLang('*')).toBe('en');
    expect(negotiateLang('garbage;;;')).toBe('en');
  });

  it('substitutes placeholders and falls back to English', () => {
    expect(t('pl', 'totp.attempts_left', { n: 3 })).toBe('Pozostałe próby: 3.');
    expect(t('en', 'totp.attempts_left', { n: 3 })).toBe('Attempts left: 3.');
    expect(t('en', 'links.usage', { n: 2 })).toBe('2 files, {size}');
  });
});

describe('language on rendered pages', () => {
  let app: TestApp;
  beforeAll(async () => { app = await boot(); });
  afterAll(async () => { await app.close(); });

  it('renders English by default and Polish for Polish browsers, on admin and public pages', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    for (const url of [`${app.base}/admin/login`, l.url, `${app.base}/nope`]) {
      const en = await (await fetch(url)).text();
      expect(en).toContain('<html lang="en">');
      const pl = await (await fetch(url, { headers: { 'accept-language': 'pl-PL,pl;q=0.9,en;q=0.5' } })).text();
      expect(pl).toContain('<html lang="pl">');
    }
    expect(await (await fetch(`${app.base}/admin/login`)).text()).toContain('Administrator login');
    expect(await (await fetch(`${app.base}/admin/login`, { headers: { 'accept-language': 'pl' } })).text()).toContain('Logowanie administratora');
    expect(await (await fetch(l.url)).text()).toContain('Upload from the terminal');
    expect(await (await fetch(l.url, { headers: { 'accept-language': 'pl' } })).text()).toContain('Upload z terminala');
    // The public page ships its client-side strings in the chosen language.
    expect(await (await fetch(l.url, { headers: { 'accept-language': 'pl' } })).text()).toContain('"upload.js.done":"ukończony"');
    // API error messages follow the language too.
    app.ctx.db.prepare('UPDATE links SET revoked_at = ? WHERE id = ?').run(new Date().toISOString(), l.id);
    expect((await (await fetch(`${app.base}/api/files`, { headers: { ...bearer(l.token), 'accept-language': 'pl' } })).json() as { message: string }).message).toBe('Ten link został unieważniony.');
    expect((await (await fetch(`${app.base}/api/files`, { headers: bearer(l.token) })).json() as { message: string }).message).toBe('This link has been revoked.');
  });

  it('lets the visitor override the browser language with the footer switcher (cookie)', async () => {
    const res = await fetch(`${app.base}/lang/pl?next=/admin/login`, { redirect: 'manual', headers: { 'accept-language': 'en' } });
    expect(res.status).toBe(303);
    expect(res.headers.get('location')).toBe('/admin/login');
    const cookie = res.headers.get('set-cookie')!;
    expect(cookie).toMatch(/^inletbox_lang=pl; Path=\/; SameSite=Lax; Max-Age=\d+/);
    const page = await (await fetch(`${app.base}/admin/login`, { headers: { cookie: 'inletbox_lang=pl', 'accept-language': 'en' } })).text();
    expect(page).toContain('<html lang="pl">');
    expect(page).toContain('href="/lang/en?next=%2Fadmin%2Flogin"');
    // Open redirects are refused; unknown languages are 404.
    expect((await fetch(`${app.base}/lang/en?next=https://evil.example/`, { redirect: 'manual' })).headers.get('location')).toBe('/');
    expect((await fetch(`${app.base}/lang/en?next=//evil.example/`, { redirect: 'manual' })).headers.get('location')).toBe('/');
    expect((await fetch(`${app.base}/lang/de`, { redirect: 'manual' })).status).toBe(404);
    // A bogus cookie value falls back to negotiation.
    expect(await (await fetch(`${app.base}/admin/login`, { headers: { cookie: 'inletbox_lang=xx', 'accept-language': 'pl' } })).text()).toContain('<html lang="pl">');
  });
});
