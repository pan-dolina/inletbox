import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { boot, type TestApp } from './helpers.js';

// 1x1 PNG
const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');

describe('branding configuration', () => {
  it('validates colours and logo types', () => {
    expect(() => loadConfig({ BRAND_COLOR_PRIMARY: 'red' })).toThrow(/BRAND_COLOR_PRIMARY/);
    expect(() => loadConfig({ BRAND_COLOR_TOPBAR: '#12345' })).toThrow(/BRAND_COLOR_TOPBAR/);
    expect(() => loadConfig({ BRAND_LOGO_PATH: '/tmp/logo.exe' })).toThrow(/BRAND_LOGO_PATH/);
    const cfg = loadConfig({ BRAND_NAME: '  Acme Drop ', BRAND_COLOR_PRIMARY: '#0F766E' });
    expect(cfg.brand.name).toBe('Acme Drop');
    expect(cfg.brand.colorPrimary).toBe('#0f766e');
    expect(cfg.brand.colorAccent).toBe('#0f766e'); // defaults to primary
    expect(cfg.brand.footerText).toContain('Acme Drop');
    expect(loadConfig({}).brand).toMatchObject({ name: 'inletbox', logoPath: null, colorPrimary: '#1f6feb', colorTopbar: '#101418' });
  });
});

describe('branded instance', () => {
  let app: TestApp;
  let dir: string;
  beforeAll(async () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inletbox-brand-'));
    fs.writeFileSync(path.join(dir, 'logo.png'), PNG);
    app = await boot({
      BRAND_NAME: 'Acme <Drop>', BRAND_LOGO_PATH: path.join(dir, 'logo.png'),
      BRAND_COLOR_PRIMARY: '#0f766e', BRAND_COLOR_TOPBAR: '#1f1b3d', BRAND_FOOTER_TEXT: 'Acme & Co',
    });
  });
  afterAll(async () => { await app.close(); fs.rmSync(dir, { recursive: true, force: true }); });

  it('shows the name, logo and footer on admin and public pages (escaped)', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    for (const url of [`${app.base}/admin/login`, l.url]) {
      const html = await (await fetch(url)).text();
      expect(html).toContain('<title>');
      expect(html).toContain('· Acme &lt;Drop&gt;</title>');
      expect(html).not.toContain('Acme <Drop>');
      expect(html).toContain('<img class="brand-logo" src="/brand/logo" alt="Acme &lt;Drop&gt;">');
      expect(html).toContain('<link rel="stylesheet" href="/brand/theme.css">');
      expect(html).toContain('Acme &amp; Co');
      expect(html).not.toMatch(/<script[^>]+src="https?:\/\//);
    }
  });

  it('serves the logo and the generated theme under the same strict CSP', async () => {
    const logo = await fetch(`${app.base}/brand/logo`);
    expect(logo.status).toBe(200);
    expect(logo.headers.get('content-type')).toContain('image/png');
    expect(logo.headers.get('x-content-type-options')).toBe('nosniff');
    expect(Buffer.from(await logo.arrayBuffer()).equals(PNG)).toBe(true);

    const theme = await fetch(`${app.base}/brand/theme.css`);
    expect(theme.status).toBe(200);
    expect(theme.headers.get('content-type')).toContain('text/css');
    const css = await theme.text();
    expect(css).toContain('--primary: #0f766e;');
    expect(css).toContain('--topbar: #1f1b3d;');
    expect(css).toContain('--accent: #0f766e;');
    expect(theme.headers.get('content-security-policy')).toContain("style-src 'self'");
  });

  it('uses the brand name as the TOTP issuer', async () => {
    const s = await app.adminLogin();
    const res = await fetch(`${app.base}/admin/security/totp/begin`, {
      method: 'POST', redirect: 'manual',
      headers: { cookie: s.cookie, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ _csrf: s.csrf }),
    });
    const html = await res.text();
    expect(html).toContain('otpauth://totp/Acme%20%3CDrop%3E%3Aadmin?');
    expect(html).toContain('issuer=Acme+%3CDrop%3E');
    expect(html).toContain('Wystawca: Acme &lt;Drop&gt;');
  });
});

describe('unbranded instance', () => {
  let app: TestApp;
  beforeAll(async () => { app = await boot(); });
  afterAll(async () => { await app.close(); });

  it('falls back to defaults and has no logo endpoint content', async () => {
    const html = await (await fetch(`${app.base}/admin/login`)).text();
    expect(html).toContain('· inletbox</title>');
    expect(html).toContain('<a class="brand" href="/">inletbox</a>');
    expect(html).not.toContain('brand-logo');
    expect((await fetch(`${app.base}/brand/logo`)).status).toBe(404);
    expect(await (await fetch(`${app.base}/brand/theme.css`)).text()).toContain('--primary: #1f6feb;');
  });
});
