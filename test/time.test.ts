/**
 * Timestamps: the server renders UTC inside <time datetime>, and /static/time.js rewrites
 * them into the browser's own zone. The script is run here in a stub DOM under a fixed TZ.
 */
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { fmtDate, html, layout, tHtml } from '../src/http/html.js';
import { boot, type TestApp } from './helpers.js';

const SCRIPT = fs.readFileSync(path.join(import.meta.dirname, '..', 'public', 'time.js'), 'utf8');
const ORIGINAL_TZ = process.env.TZ;
afterEach(() => { if (ORIGINAL_TZ === undefined) delete process.env.TZ; else process.env.TZ = ORIGINAL_TZ; });

/** Runs time.js over the given <time> elements, as a browser in `tz` would. */
function runInBrowser(tz: string, locale: string, times: Array<{ datetime: string; textContent: string; title?: string }>) {
  process.env.TZ = tz;
  const window: Record<string, unknown> = {};
  const document = {
    body: { getAttribute: (name: string) => (name === 'data-date-locale' ? locale : null) },
    querySelectorAll: () => times.map((t) => Object.assign(t, { getAttribute: () => t.datetime })),
  };
  vm.runInNewContext(SCRIPT, { window, document, Intl, Date, isNaN });
  return window.localTime as (iso: string) => string | null;
}

describe('server-side timestamps', () => {
  it('render UTC inside a machine-readable <time>', () => {
    expect(fmtDate('2026-10-06T13:42:18.105Z', 'pl').value).toBe('<time datetime="2026-10-06T13:42:18.105Z">6.10.2026, 13:42 UTC</time>');
    expect(fmtDate('2026-10-06T13:42:18Z', 'en').value).toContain('>06/10/2026, 13:42 UTC</time>');
    expect(fmtDate(null).value).toBe('—');
    expect(fmtDate('not a date').value).toBe('—');
  });

  it('go into translated messages without letting the message or other values inject markup', () => {
    const out = tHtml('en', 'case.meta', { id: '<b>x</b>', date: fmtDate('2026-10-06T13:42:18Z') }).value;
    expect(out).toContain('&lt;b&gt;x&lt;/b&gt;');
    expect(out).toContain('<time datetime="2026-10-06T13:42:18.000Z">');
  });

  it('come with the script and the date locale on every page', () => {
    const page = layout({ lang: 'en', title: 't', body: html`` });
    expect(page).toContain('<body data-date-locale="en-GB"');
    expect(page).toMatch(/<script src="\/static\/time\.js\?v=[^"]+" defer><\/script>/);
  });
});

describe('time.js', () => {
  it('shows the moment in the browser zone, with the zone named and UTC kept as the tooltip', () => {
    const warsaw = { datetime: '2026-10-06T13:42:18.105Z', textContent: '6.10.2026, 13:42 UTC' };
    const winter = { datetime: '2026-01-15T08:05:00Z', textContent: '15.01.2026, 08:05 UTC' };
    const broken = { datetime: 'garbage', textContent: 'unchanged' };
    const localTime = runInBrowser('Europe/Warsaw', 'pl', [warsaw, winter, broken]);
    expect(warsaw.textContent).toMatch(/^6\.10\.2026, 15:42 .+$/);
    expect(warsaw.textContent).not.toContain('UTC');
    expect(warsaw.title).toBe('6.10.2026, 13:42 UTC');
    expect(winter.textContent).toMatch(/^15\.01\.2026, 09:05 /);
    expect(broken.textContent).toBe('unchanged');
    expect(localTime('garbage')).toBeNull();
  });

  it('names the zone for a reader elsewhere', () => {
    const t = { datetime: '2026-10-06T13:42:00Z', textContent: '' };
    runInBrowser('America/New_York', 'en-GB', [t]);
    expect(t.textContent).toMatch(/^06\/10\/2026, 09:42 (EDT|GMT-4)$/);
  });
});

describe('in the running app', () => {
  let app: TestApp;
  beforeAll(async () => { app = await boot(); });
  afterAll(async () => { await app.close(); });

  it('is the file in public/', async () => {
    const res = await fetch(`${app.base}/static/time.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('javascript');
    expect(await res.text()).toBe(SCRIPT);
  });

  it('marks up the dates on a case page', async () => {
    const session = await app.adminLogin();
    const c = app.mkCase('Dates');
    const page = await (await fetch(`${app.base}/admin/cases/${c.id}`, { headers: { cookie: session.cookie } })).text();
    expect(page).toMatch(/<time datetime="\d{4}-\d\d-\d\dT[\d:.]+Z">[^<]+ UTC<\/time>/);
    expect(page).toContain('/static/time.js?v=');
  });
});
