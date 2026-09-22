import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { dateLocale, LANG_NAMES, LANGS, negotiateLang, t, type MessageKey } from '../src/i18n.js';
import { en } from '../src/locales/en.js';
import { bearer, boot, type TestApp } from './helpers.js';

describe('language negotiation', () => {
  it('picks the best supported language from Accept-Language, defaulting to English', () => {
    expect(negotiateLang(undefined)).toBe('en');
    expect(negotiateLang('pl')).toBe('pl');
    expect(negotiateLang('pl-PL,pl;q=0.9,en-US;q=0.8')).toBe('pl');
    expect(negotiateLang('de-DE,de;q=0.9,pl;q=0.7')).toBe('de');
    expect(negotiateLang('de-AT')).toBe('de');
    expect(negotiateLang('pt-BR,pt;q=0.9')).toBe('pt');
    expect(negotiateLang('el')).toBe('el');
    // Only the browser's primary language counts: someone who reads Japanese first and
    // German second still gets English, not the German entry further down their list.
    expect(negotiateLang('ja,de;q=0.8')).toBe('en');
    expect(negotiateLang('nb-NO,nb;q=0.9,sv;q=0.8')).toBe('en');
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

  it('offers the 24 official EU languages, each named in itself', () => {
    expect(LANGS).toHaveLength(24);
    expect(new Set(Object.keys(LANG_NAMES))).toEqual(new Set(LANGS));
    expect(LANG_NAMES.de).toBe('Deutsch');
    expect(LANG_NAMES.el).toBe('Ελληνικά');
  });

  // TypeScript already refuses a dictionary with a missing key. What it cannot see is a
  // translation that drops or renames a {placeholder} — the page would then show "{n}"
  // literally, or lose the number — or a dictionary that is English pasted over.
  it('keeps every placeholder in every translation, and translates most of the text', () => {
    const placeholders = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
    const keys = Object.keys(en) as MessageKey[];
    for (const lang of LANGS) {
      let same = 0;
      for (const key of keys) {
        const msg = t(lang, key);
        expect(msg, `${lang} ${key}`).not.toBe('');
        expect(placeholders(msg), `${lang} ${key}`).toBe(placeholders(en[key]));
        if (msg === en[key]) same++;
      }
      // Some strings are legitimately identical (IP, "—", the product name, e.g. 500MB).
      if (lang !== 'en') expect(same / keys.length, lang).toBeLessThan(0.1);
    }
  });

  it('formats dates in every language with the runtime ICU data (full-icu in the image)', () => {
    expect(dateLocale('en')).toBe('en-GB');
    expect(dateLocale('pl')).toBe('pl');
    expect(Intl.DateTimeFormat.supportedLocalesOf(LANGS.map(dateLocale))).toHaveLength(LANGS.length);
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
    // The public page ships its client-side strings in the chosen language. A key that is
    // missing from clientMessages() renders as the raw key ("upload.js.finalising") in the UI.
    const plUpload = await (await fetch(l.url, { headers: { 'accept-language': 'pl' } })).text();
    expect(plUpload).toContain('"upload.js.done":"ukończony"');
    expect(plUpload).toContain('"upload.js.finalising":"wysłano wszystkie dane, serwer kończy zapis…"');
    expect(await (await fetch(l.url)).text()).toContain('"upload.js.finalising":"all bytes sent, the server is finishing…"');
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
    expect((await fetch(`${app.base}/lang/xx`, { redirect: 'manual' })).status).toBe(404);
    // The switcher lists every other language by its own name, marked up in that language.
    expect(page).toContain('<a href="/lang/de?next=%2Fadmin%2Flogin" hreflang="de" lang="de">Deutsch</a>');
    expect(page).toContain('<span class="lang-current" lang="pl" aria-current="true">Polski</span>');
    expect(page.match(/hreflang="/g)).toHaveLength(23);
    // A language beyond the original two works end to end.
    const de = await (await fetch(`${app.base}/admin/login`, { headers: { cookie: 'inletbox_lang=de' } })).text();
    expect(de).toContain('<html lang="de">');
    expect(de).toContain('Administrator-Anmeldung');
    // A bogus cookie value falls back to negotiation.
    expect(await (await fetch(`${app.base}/admin/login`, { headers: { cookie: 'inletbox_lang=xx', 'accept-language': 'pl' } })).text()).toContain('<html lang="pl">');
  });
});
