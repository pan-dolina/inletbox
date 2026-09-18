import { execFile } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { getFile } from '../src/services/files.js';
import { linkUsage } from '../src/services/links.js';
import { adminDownload, bearer, boot, listFiles, putChunked, putFile, randomBytes, sleep, type TestApp } from './helpers.js';

const execFileP = promisify(execFile);
let app: TestApp;
beforeAll(async () => { app = await boot(); });
afterAll(async () => { await app.close(); });

describe('direct (curl-style) upload API', () => {
  it('requires a bearer token and rejects unknown ones', async () => {
    expect((await fetch(`${app.base}/api/files`)).status).toBe(401);
    expect((await fetch(`${app.base}/api/files`, { headers: bearer('A'.repeat(43)) })).status).toBe(404);
    // Tokens in the query string are never accepted.
    const c = app.mkCase(); const l = app.mkLink(c.id);
    expect((await fetch(`${app.base}/api/files?token=${l.token}`)).status).toBe(401);
  });

  it('uploads with Content-Length and lists the file with its original name', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const data = randomBytes(2_000_000);
    const res = await putFile(app, l.token, 'zażółć gęślą jaźń.bin', data);
    expect(res.status).toBe(201);
    const body = await res.json() as { id: string; name: string; size: number; status: string; sha256: string };
    expect(body.name).toBe('zażółć gęślą jaźń.bin');
    expect(body.size).toBe(data.length);
    expect(body.status).toBe('complete');
    const files = await listFiles(app, l.token);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatchObject({ id: body.id, name: body.name, size: data.length, status: 'complete' });
    const st = await app.ctx.storage.stat(body.id);
    expect(st?.size).toBe(data.length);
  });

  it('uploads without Content-Length (chunked) and enforces limits mid-stream', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { maxFileBytes: 1_000_000 });
    const ok = await putChunked(app, l.token, 'chunked.bin', [randomBytes(300_000), randomBytes(300_000)]);
    expect(ok.status).toBe(201);
    expect((await ok.json() as { size: number }).size).toBe(600_000);

    const tooBig = await putChunked(app, l.token, 'big.bin', [randomBytes(600_000), randomBytes(600_000)]);
    expect(tooBig.status).toBe(413);
    expect((await tooBig.json() as { error: string }).error).toBe('file_too_large');
    const files = await listFiles(app, l.token);
    expect(files.map((f) => f.name)).toEqual(['chunked.bin']);
    // Nothing partial left behind and no quota still reserved.
    const rows = app.ctx.db.prepare(`SELECT id, status, reserved_bytes FROM files WHERE link_id = ? AND original_name = 'big.bin'`).all(l.id) as Array<{ id: string; status: string; reserved_bytes: number }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.status).toBe('aborted');
    expect(rows[0]!.reserved_bytes).toBe(0);
    expect(await app.ctx.storage.stat(rows[0]!.id)).toBeNull();
  });

  it('rejects oversized Content-Length before reading the body', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { maxFileBytes: 1000 });
    // A Buffer body is sent with Content-Length, exactly like `curl -T file`.
    const res = await fetch(`${app.base}/api/upload/x.bin`, { method: 'PUT', headers: bearer(l.token), body: randomBytes(5000) });
    expect(res.status).toBe(413);
    expect((await res.json() as { error: string }).error).toBe('file_too_large');
    expect(await listFiles(app, l.token)).toHaveLength(0);
    // Nothing was written and no row lingers in 'uploading'.
    const rows = app.ctx.db.prepare(`SELECT status FROM files WHERE link_id = ?`).all(l.id) as Array<{ status: string }>;
    expect(rows).toHaveLength(0);
  });

  it('enforces per-link total quota under concurrent uploads (reservation)', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { maxTotalBytes: 10 * 1024 * 1024 });
    const six = randomBytes(6 * 1024 * 1024);
    const results = await Promise.all([1, 2, 3].map(() => putFile(app, l.token, 'six.bin', six)));
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([201, 413, 413]);
    for (const r of results) if (r.status === 413) expect((await r.json() as { error: string }).error).toBe('quota_exceeded');
    const usage = linkUsage(app.ctx.db, l.id);
    expect(usage.used_bytes).toBe(six.length);
    expect(usage.reserved_bytes).toBe(0);
    // A small file still fits in the remaining 4 MiB.
    expect((await putFile(app, l.token, 'small.bin', randomBytes(1024))).status).toBe(201);
  });

  it('enforces the per-link file count under concurrent uploads', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { maxFiles: 2 });
    const results = await Promise.all([1, 2, 3, 4].map((i) => putFile(app, l.token, `f${i}.txt`, Buffer.from('x'))));
    expect(results.map((r) => r.status).sort()).toEqual([201, 201, 413, 413]);
    expect((await listFiles(app, l.token))).toHaveLength(2);
  });

  it('never overwrites: duplicate names become separate files', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const a = await (await putFile(app, l.token, 'same.txt', Buffer.from('first'))).json() as { id: string };
    const b = await (await putFile(app, l.token, 'same.txt', Buffer.from('second'))).json() as { id: string };
    expect(a.id).not.toBe(b.id);
    const files = await listFiles(app, l.token);
    expect(files.filter((f) => f.name === 'same.txt')).toHaveLength(2);
    const s = await app.adminLogin();
    expect(await (await adminDownload(app, s, a.id)).text()).toBe('first');
    expect(await (await adminDownload(app, s, b.id)).text()).toBe('second');
  });

  it('sanitises path-traversal and HTML in names, and storage keys never derive from names', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const res = await putFile(app, l.token, '../../etc/<b>passwd<b>', Buffer.from('x'));
    expect(res.status).toBe(201);
    const body = await res.json() as { id: string; name: string };
    expect(body.name).toBe('<b>passwd<b>');
    expect(body.id).toMatch(/^f_[A-Za-z0-9_-]{16}$/);
    const s = await app.adminLogin();
    const page = await (await fetch(`${app.base}/admin/cases/${c.id}`, { headers: { cookie: s.cookie } })).text();
    expect(page).toContain('&lt;b&gt;passwd&lt;b&gt;');
    expect(page).not.toContain('<b>passwd<b>');
    if (app.ctx.storage.kind === 'local') {
      expect(fs.existsSync(path.join(app.dataDir, 'etc'))).toBe(false);
      expect(fs.existsSync(app.fileOnDisk(body.id))).toBe(true);
    }
  });

  it('isolates file lists between links of the same case and denies any read access', async () => {
    const c = app.mkCase();
    const a = app.mkLink(c.id, { label: 'A' });
    const b = app.mkLink(c.id, { label: 'B' });
    const fa = await (await putFile(app, a.token, 'a.txt', Buffer.from('A'))).json() as { id: string };
    await putFile(app, b.token, 'b.txt', Buffer.from('B'));
    expect((await listFiles(app, a.token)).map((f) => f.name)).toEqual(['a.txt']);
    expect((await listFiles(app, b.token)).map((f) => f.name)).toEqual(['b.txt']);

    // Knowing a file id gives no read path: not via the API, not via tus, not via admin routes.
    for (const token of [a.token, b.token]) {
      expect((await fetch(`${app.base}/api/files/${fa.id}`, { headers: bearer(token) })).status).toBe(403);
      expect((await fetch(`${app.base}/api/files/${fa.id}/download`, { headers: bearer(token) })).status).toBe(403);
      expect((await fetch(`${app.base}/api/tus/${fa.id}`, { headers: { ...bearer(token), 'tus-resumable': '1.0.0' } })).status).toBe(405);
      expect((await fetch(`${app.base}/api/files/${fa.id}`, { method: 'DELETE', headers: bearer(token) })).status).toBe(403);
      expect((await fetch(`${app.base}/admin/files/${fa.id}/download`, { headers: bearer(token), redirect: 'manual' })).status).toBe(302);
    }
    if (app.ctx.storage.kind === 'local') {
      expect((await fetch(`${app.base}/static/../data/files/${fa.id}`)).status).toBe(404);
    }
  });

  it('cleans up when the client disconnects mid-upload', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { maxTotalBytes: 50 * 1024 * 1024 });
    const url = new URL(`${app.base}/api/upload/partial.bin`);
    await new Promise<void>((resolve) => {
      const req = http.request({ host: url.hostname, port: url.port, path: url.pathname, method: 'PUT', headers: { ...bearer(l.token), 'content-length': String(5_000_000) } });
      req.on('error', () => resolve());
      req.write(randomBytes(200_000), () => {
        setTimeout(() => { req.destroy(); resolve(); }, 100);
      });
    });
    let row: { id: string; status: string; reserved_bytes: number } | undefined;
    for (let i = 0; i < 50; i++) {
      row = app.ctx.db.prepare(`SELECT id, status, reserved_bytes FROM files WHERE link_id = ? AND original_name = 'partial.bin'`).get(l.id) as typeof row;
      if (row && row.status !== 'uploading') break;
      await sleep(100);
    }
    expect(row?.status).toBe('aborted');
    expect(row?.reserved_bytes).toBe(0);
    expect(await app.ctx.storage.stat(row!.id)).toBeNull();
    expect(linkUsage(app.ctx.db, l.id).reserved_bytes).toBe(0);
    expect(await listFiles(app, l.token)).toHaveLength(0);
  });

  it('works with the real curl command shown on the upload page (-T with a path containing spaces)', async () => {
    const curl = await execFileP('curl', ['--version']).catch(() => null);
    if (!curl) return; // curl not installed: nothing to verify here
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inletbox-curl-'));
    const file = path.join(dir, 'my report (final).pdf');
    const data = randomBytes(1_500_000);
    fs.writeFileSync(file, data);
    const { stdout } = await execFileP('curl', ['--silent', '--fail-with-body', '-H', `Authorization: Bearer ${l.token}`, '-T', file, `${app.base}/api/upload/`]);
    const body = JSON.parse(stdout) as { id: string; name: string; size: number };
    expect(body.name).toBe('my report (final).pdf');
    expect(body.size).toBe(data.length);
    expect(getFile(app.ctx.db, body.id)!.status).toBe('complete');

    // Errors surface as a non-zero exit code with the JSON body.
    const tooBig = app.mkLink(c.id, { maxFileBytes: 1000 });
    const err = await execFileP('curl', ['--silent', '--fail-with-body', '-H', `Authorization: Bearer ${tooBig.token}`, '-T', file, `${app.base}/api/upload/`]).catch((e: { code: number; stdout: string }) => e);
    expect(err.code).toBe(22);
    expect(JSON.parse(err.stdout).error).toBe('file_too_large');
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
