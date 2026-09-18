import { describe, expect, it } from 'vitest';
import { formatSize, loadConfig, parseSize } from '../src/config.js';
import { hashPassword, newToken, TOKEN_RE, verifyPassword } from '../src/crypto.js';
import { escapeHtml, html, jsonScript } from '../src/http/html.js';
import { shellQuote } from '../src/http/views/upload.js';
import { redact } from '../src/log.js';
import { sanitizeFilename } from '../src/services/files.js';

describe('config', () => {
  it('parses sizes', () => {
    expect(parseSize('1024')).toBe(1024);
    expect(parseSize('10MB')).toBe(10 * 1024 ** 2);
    expect(parseSize('2 GiB')).toBe(2 * 1024 ** 3);
    expect(parseSize('1.5kb')).toBe(1536);
    expect(() => parseSize('abc')).toThrow();
    expect(() => parseSize('10XB')).toThrow();
    expect(formatSize(1536)).toBe('1.50 KB');
  });
  it('rejects bad configuration', () => {
    expect(() => loadConfig({ PUBLIC_URL: 'ftp://x' })).toThrow(/PUBLIC_URL/);
    expect(() => loadConfig({ STORAGE_BACKEND: 's3' })).toThrow(/S3_BUCKET/);
    expect(() => loadConfig({ STORAGE_BACKEND: 's3', S3_BUCKET: 'b', S3_PART_SIZE: '1MB' })).toThrow(/S3_PART_SIZE/);
    expect(loadConfig({ PUBLIC_URL: 'https://drop.example.com/' }).cookieSecure).toBe(true);
    expect(loadConfig({ PUBLIC_URL: 'https://drop.example.com/' }).publicUrl).toBe('https://drop.example.com');
    expect(() => loadConfig({ TRUST_PROXY: 'true' })).toThrow(/TRUST_PROXY=true/);
    expect(loadConfig({ TRUST_PROXY: '1' }).trustProxy).toBe(1);
    expect(loadConfig({ TRUST_PROXY: '10.0.0.1, loopback' }).trustProxy).toBe('10.0.0.1, loopback');
    expect(() => loadConfig({ DATA_DIR: '/tmp/x', LOCAL_STORAGE_DIR: '/tmp/x' })).toThrow(/LOCAL_STORAGE_DIR/);
  });
});

describe('crypto', () => {
  it('hashes and verifies passwords with scrypt', () => {
    const h = hashPassword('hunter2hunter2');
    expect(h.startsWith('scrypt$')).toBe(true);
    expect(verifyPassword('hunter2hunter2', h)).toBe(true);
    expect(verifyPassword('hunter2hunter3', h)).toBe(false);
    expect(verifyPassword('x', 'garbage')).toBe(false);
  });
  it('generates 256-bit url-safe tokens', () => {
    const t = newToken();
    expect(t).toMatch(TOKEN_RE);
    expect(newToken()).not.toBe(t);
  });
});

describe('filenames', () => {
  it('strips path components and control characters', () => {
    expect(sanitizeFilename('../../etc/passwd')).toBe('passwd');
    expect(sanitizeFilename('C:\\Users\\x\\report.pdf')).toBe('report.pdf');
    expect(sanitizeFilename('a\u0000b\nc.txt')).toBe('abc.txt');
    expect(sanitizeFilename('..')).toBe('unnamed');
    expect(sanitizeFilename('')).toBe('unnamed');
    expect(sanitizeFilename('   ')).toBe('unnamed');
    expect(sanitizeFilename('<script>alert(1)<script>.html')).toBe('<script>alert(1)<script>.html');
    expect(sanitizeFilename('a/b/<i>c</i>.txt')).toBe('i>.txt'); // '/' is always a separator
    expect(sanitizeFilename('zażółć gęślą jaźń.pdf')).toBe('zażółć gęślą jaźń.pdf');
  });
  it('truncates long names but keeps the extension', () => {
    const long = 'a'.repeat(300) + '.tar.gz';
    const out = sanitizeFilename(long);
    expect(out.length).toBe(255);
    expect(out.endsWith('.gz')).toBe(true);
  });
});

describe('html', () => {
  it('escapes interpolations by default', () => {
    const name = '<img src=x onerror=alert(1)>"\'&';
    expect(html`<b>${name}</b>`.value).toBe('<b>&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;</b>');
    expect(escapeHtml(undefined)).toBe('');
  });
  it('embeds JSON without breaking out of the script tag', () => {
    const out = jsonScript('cfg', { s: '</script><script>alert(1)</script>' }).value;
    expect(out).not.toContain('</script><script>');
    expect(out).toContain('\\u003c/script>');
  });
  it('quotes shell arguments safely', () => {
    expect(shellQuote("it's")).toBe(`'it'\\''s'`);
    expect(shellQuote('/path with spaces/x')).toBe(`'/path with spaces/x'`);
  });
});

describe('log redaction', () => {
  it('hides link tokens in paths and query strings', () => {
    expect(redact('/u/AbCdEf123_-xyz')).toBe('/u/[redacted]');
    expect(redact('GET /u/abc?x=1')).toBe('GET /u/[redacted]?x=1');
    expect(redact('/api/files?token=secret&x=1')).toBe('/api/files?token=[redacted]&x=1');
    expect(redact('/admin/cases/c_123')).toBe('/admin/cases/c_123');
    expect(redact('/api/upload/Umowa%20Kowalski.pdf')).toBe('/api/upload/[filename]');
    expect(redact('/api/upload/')).toBe('/api/upload/');
  });
});
