import fs from 'node:fs';
import path from 'node:path';
import { Router } from 'express';
import type { Brand } from '../config.js';

const LOGO_TYPES: Record<string, string> = { '.png': 'image/png', '.svg': 'image/svg+xml', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp' };

/**
 * Branding endpoints: the configured logo and a generated stylesheet that
 * overrides the colour tokens in style.css. Both are same-origin, so the strict
 * CSP (img-src/style-src 'self') stays untouched.
 */
export function brandRouter(brand: Brand): Router {
  const r = Router();
  const css = [
    ':root {',
    `  --primary: ${brand.colorPrimary};`,
    `  --topbar: ${brand.colorTopbar};`,
    `  --accent: ${brand.colorAccent};`,
    '}',
    '',
  ].join('\n');

  r.get('/theme.css', (_req, res) => {
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.type('text/css').send(css);
  });

  r.get('/logo', (_req, res) => {
    if (!brand.logoPath) {
      res.status(404).type('text/plain').send('No logo configured');
      return;
    }
    const type = LOGO_TYPES[path.extname(brand.logoPath).toLowerCase()];
    if (!type || !fs.existsSync(brand.logoPath)) {
      res.status(404).type('text/plain').send('Logo file not found');
      return;
    }
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // An SVG logo is an operator-supplied file, but it is still served under a script-less CSP.
    if (type === 'image/svg+xml') res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; sandbox");
    res.type(type);
    fs.createReadStream(brand.logoPath).on('error', () => { if (!res.headersSent) res.status(404).end(); }).pipe(res);
  });

  return r;
}
