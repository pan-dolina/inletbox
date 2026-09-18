/**
 * Tiny HTML templating: a tagged template that escapes every interpolated
 * value unless it is explicitly marked as trusted with `raw()`.
 * This is what keeps client-supplied file names, labels and case names from
 * becoming XSS in the admin panel and the upload page.
 */

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

import type { Brand } from '../config.js';

/** Set once per process by createApp(); views read it when rendering the chrome. */
let currentBrand: Brand = { name: 'inletbox', logoPath: null, colorPrimary: '#1f6feb', colorTopbar: '#101418', colorAccent: '#1f6feb', footerText: 'inletbox · prywatna skrzynka wrzutowa' };
export function setBrand(brand: Brand): void { currentBrand = brand; }

/** Appended as ?v= to our own static assets so browsers never keep a stale stylesheet after an upgrade. */
let assetVersion = 'dev';
export function setAssetVersion(v: string): void { assetVersion = v; }
export function asset(path: string): string { return `${path}?v=${assetVersion}`; }
export function getBrand(): Brand { return currentBrand; }

export interface LayoutOptions {
  title: string;
  body: SafeHtml;
  scripts?: string[];
  nav?: SafeHtml;
}

export function layout(opts: LayoutOptions): string {
  const b = currentBrand;
  return html`<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${opts.title} · ${b.name}</title>
<link rel="stylesheet" href="${asset('/static/style.css')}">
<link rel="stylesheet" href="/brand/theme.css">
${b.logoPath ? html`<link rel="icon" href="/brand/logo">` : ''}
</head>
<body>
<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="/">${b.logoPath ? html`<img class="brand-logo" src="/brand/logo" alt="${b.name}">` : b.name}</a>
    ${opts.nav ?? ''}
  </div>
</header>
<main class="container">
${opts.body}
</main>
<footer class="footer">${b.footerText}</footer>
${(opts.scripts ?? []).map((s) => html`<script src="${asset(s)}" defer></script>`)}
</body>
</html>`.value;
}
