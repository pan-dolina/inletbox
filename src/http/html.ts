/**
 * Tiny HTML templating: a tagged template that escapes every interpolated
 * value unless it is explicitly marked as trusted with `raw()`.
 * This is what keeps client-supplied file names, labels and case names from
 * becoming XSS in the admin panel and the upload page.
 */
import type { Brand } from '../config.js';
import { LANG_NAMES, LANGS, t, type Lang } from '../i18n.js';

export class SafeHtml {
  constructor(public readonly value: string) {}
  toString(): string { return this.value; }
}

const ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

export function raw(value: string): SafeHtml {
  return new SafeHtml(value);
}

type Interp = string | number | boolean | null | undefined | SafeHtml | Interp[];

function render(v: Interp): string {
  if (v === null || v === undefined || v === false) return '';
  if (v instanceof SafeHtml) return v.value;
  if (Array.isArray(v)) return v.map(render).join('');
  return escapeHtml(v);
}

export function html(strings: TemplateStringsArray, ...values: Interp[]): SafeHtml {
  let out = '';
  strings.forEach((s, i) => {
    out += s;
    if (i < values.length) out += render(values[i]);
  });
  return new SafeHtml(out);
}

/** Embeds JSON safely inside a <script type="application/json"> element. */
export function jsonScript(id: string, data: unknown): SafeHtml {
  const json = JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(new RegExp(String.fromCharCode(0x2028), 'g'), '\\u2028')
    .replace(new RegExp(String.fromCharCode(0x2029), 'g'), '\\u2029');
  return raw(`<script type="application/json" id="${escapeHtml(id)}">${json}</script>`);
}

/** Set once per process by createApp(); views read it when rendering the chrome. */
let currentBrand: Brand = { name: 'inletbox', logoPath: null, colorPrimary: '#1f6feb', colorTopbar: '#101418', colorAccent: '#1f6feb', footerText: '' };
export function setBrand(brand: Brand): void { currentBrand = brand; }
export function getBrand(): Brand { return currentBrand; }

/** Appended as ?v= to our own static assets so browsers never keep a stale stylesheet after an upgrade. */
let assetVersion = 'dev';
export function setAssetVersion(v: string): void { assetVersion = v; }
export function asset(path: string): string { return `${path}?v=${assetVersion}`; }

/** The release, read from package.json at startup and shown in the footer. */
let appVersion = '0.0.0';
export function setAppVersion(v: string): void { appVersion = v; }
export function getAppVersion(): string { return appVersion; }

export interface LayoutOptions {
  lang: Lang;
  title: string;
  body: SafeHtml;
  scripts?: string[];
  nav?: SafeHtml;
  /** Current path, used by the language switcher to come back to the same page. */
  path?: string;
}

export function layout(opts: LayoutOptions): string {
  const b = currentBrand;
  const footer = b.footerText || `${b.name} · ${t(opts.lang, 'app.tagline')}`;
  const next = opts.path && opts.path.startsWith('/') && !opts.path.startsWith('//') ? opts.path : '/';
  // Twenty-four languages do not fit in a footer line, so the switcher is a <details>
  // menu: it opens without JavaScript, which keeps the CSP as strict as it is.
  const switcher = LANGS.map((l) => l === opts.lang
    ? html`<li><span class="lang-current" lang="${l}" aria-current="true">${LANG_NAMES[l]}</span></li>`
    : html`<li><a href="/lang/${l}?next=${encodeURIComponent(next)}" hreflang="${l}" lang="${l}">${LANG_NAMES[l]}</a></li>`);
  return html`<!doctype html>
<html lang="${opts.lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${opts.title} · ${b.name}</title>
<link rel="stylesheet" href="${asset('/static/style.css')}">
<link rel="stylesheet" href="/brand/theme.css">
${b.logoPath ? html`<link rel="icon" href="/brand/logo">` : ''}
</head>
<body data-copied="${t(opts.lang, 'common.copied')}" data-copy-manual="${t(opts.lang, 'common.copy_manual')}">
<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="${opts.nav ? '/admin' : '/'}">${b.logoPath ? html`<img class="brand-logo" src="/brand/logo" alt="${b.name}">` : b.name}</a>
    <div class="topbar-right">
      ${opts.nav ?? ''}
      <!-- The project logo, opposite the operator's branding. Used unmodified, so it
           brings its own white background; the top bar is dark in both themes and
           neither brand colour is readable directly on it. -->
      <img class="project-mark" src="${asset('/static/inletbox-logo.png')}" alt="inletbox" title="inletbox" width="59" height="44">
    </div>
  </div>
</header>
<main class="container">
${opts.body}
</main>
<footer class="footer">${footer} · <span class="version">v${appVersion}</span> · <details class="lang-switch"><summary aria-label="${t(opts.lang, 'common.language')}: ${LANG_NAMES[opts.lang]}">${opts.lang.toUpperCase()} · ${LANG_NAMES[opts.lang]}</summary><ul>${switcher}</ul></details></footer>
${(opts.scripts ?? []).map((s) => html`<script src="${asset(s)}" defer></script>`)}
</body>
</html>`.value;
}
