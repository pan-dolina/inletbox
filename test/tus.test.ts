import fs from 'node:fs';
import * as tus from 'tus-js-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { runCleanup } from '../src/services/cleanup.js';
import { getFile } from '../src/services/files.js';
import { linkUsage } from '../src/services/links.js';
import { adminDownload, bearer, boot, listFiles, randomBytes, sleep, tusCreate, tusHead, tusPatch, TUS_HEADERS, type TestApp } from './helpers.js';

let app: TestApp;
beforeAll(async () => { app = await boot(); });
afterAll(async () => { await app.close(); });

async function readAll(id: string): Promise<Buffer> {
  const s = await app.adminLogin();
  return Buffer.from(await (await adminDownload(app, s, id)).arrayBuffer());
}

describe('resumable uploads (tus)', () => {
  it('creates, patches in two parts with a HEAD in between, and finalises exactly once', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const data = randomBytes(3_000_000);
    const created = await tusCreate(app, l.token, data.length, 'big file.bin');
    expect(created.status).toBe(201);
    const location = created.headers.get('location')!;
    expect(location).toMatch(/^\/api\/tus\/f_[A-Za-z0-9_-]{16}$/);
    const id = location.split('/').pop()!;
    expect(getFile(app.ctx.db, id)).toMatchObject({ status: 'uploading', reserved_bytes: data.length, original_name: 'big file.bin', upload_kind: 'tus' });
    expect((await listFiles(app, l.token))[0]).toMatchObject({ id, status: 'uploading', size: data.length });

    const half = 1_400_000;
    const p1 = await tusPatch(app, l.token, location, 0, data.subarray(0, half));
    expect(p1.status).toBe(204);
    expect(p1.headers.get('upload-offset')).toBe(String(half));

    const head = await tusHead(app, l.token, location);
    expect(head.status).toBe(200);
    expect(head.headers.get('upload-offset')).toBe(String(half));

    // Wrong offset is a 409 and does not modify the upload.
    expect((await tusPatch(app, l.token, location, 0, data.subarray(0, 10))).status).toBe(409);

    const p2 = await tusPatch(app, l.token, location, half, data.subarray(half));
    expect(p2.status).toBe(204);
    expect(p2.headers.get('upload-offset')).toBe(String(data.length));

    const row = getFile(app.ctx.db, id)!;
    expect(row.status).toBe('complete');
    expect(row.size).toBe(data.length);
    expect(row.reserved_bytes).toBe(0);
    expect((await readAll(id)).equals(data)).toBe(true);
    if (app.ctx.storage.kind === 'local') expect(fs.existsSync(`${app.fileOnDisk(id)}.json`)).toBe(false);

    // Finished uploads cannot be touched again: no PATCH, no HEAD, no DELETE.
    expect((await tusHead(app, l.token, location)).status).toBe(410);
    expect((await tusPatch(app, l.token, location, data.length, Buffer.from('x'))).status).toBe(410);
    expect((await fetch(`${app.base}${location}`, { method: 'DELETE', headers: { ...bearer(l.token), ...TUS_HEADERS } })).status).toBe(410);
    expect((await readAll(id)).equals(data)).toBe(true);
  });

  it('isolates uploads between links: another link cannot see, resume or cancel them', async () => {
    const c = app.mkCase();
    const a = app.mkLink(c.id, { label: 'A' });
    const b = app.mkLink(c.id, { label: 'B' });
    const created = await tusCreate(app, a.token, 100, 'a.bin');
    const location = created.headers.get('location')!;
    await tusPatch(app, a.token, location, 0, randomBytes(50));
    expect((await tusHead(app, b.token, location)).status).toBe(404);
    expect((await tusPatch(app, b.token, location, 50, randomBytes(50))).status).toBe(404);
    expect((await fetch(`${app.base}${location}`, { method: 'DELETE', headers: { ...bearer(b.token), ...TUS_HEADERS } })).status).toBe(404);
    expect((await tusHead(app, a.token, location)).headers.get('upload-offset')).toBe('50');
    expect(await listFiles(app, b.token)).toHaveLength(0);
  });

  it('enforces limits at creation time and requires Upload-Length', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { maxFileBytes: 1000, maxTotalBytes: 1500 });
    const tooBig = await tusCreate(app, l.token, 2000, 'x');
    expect(tooBig.status).toBe(413);
    const first = await tusCreate(app, l.token, 900, 'x');
    expect(first.status).toBe(201);
    // 900 reserved + 900 > 1500 quota, even though nothing was written yet.
    const second = await tusCreate(app, l.token, 900, 'y');
    expect(second.status).toBe(413);
    expect((await second.json() as { error: string }).error).toBe('quota_exceeded');
    const deferred = await fetch(`${app.base}/api/tus`, { method: 'POST', headers: { ...bearer(l.token), ...TUS_HEADERS, 'upload-defer-length': '1' } });
    expect(deferred.status).toBe(400);
    // Cancelling the first releases its reservation.
    const del = await fetch(`${app.base}${first.headers.get('location')}`, { method: 'DELETE', headers: { ...bearer(l.token), ...TUS_HEADERS } });
    expect(del.status).toBe(204);
    expect(linkUsage(app.ctx.db, l.id).reserved_bytes).toBe(0);
    expect((await tusCreate(app, l.token, 900, 'y')).status).toBe(201);
  });

  it('a PATCH cannot write past the declared length', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const created = await tusCreate(app, l.token, 100, 'x');
    const location = created.headers.get('location')!;
    const res = await tusPatch(app, l.token, location, 0, randomBytes(200));
    expect([400, 413]).toContain(res.status);
    const head = await tusHead(app, l.token, location);
    expect(Number(head.headers.get('upload-offset'))).toBeLessThanOrEqual(100);
    expect(getFile(app.ctx.db, location.split('/').pop()!)!.status).toBe('uploading');
  });

  it('works with tus-js-client (the library used by the browser page), including resume from a stored URL', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const data = randomBytes(2_500_000);

    // First attempt: abort after the first chunk to simulate a dropped connection / page reload.
    let url = '';
    await new Promise<void>((resolve, reject) => {
      const upload = new tus.Upload(data, {
        endpoint: `${app.base}/api/tus`, headers: bearer(l.token), chunkSize: 1_000_000, retryDelays: null,
        metadata: { filename: 'client.bin' },
        onError: reject,
        onChunkComplete: () => { url = upload.url!; upload.abort(false).then(() => resolve()); },
        onSuccess: () => resolve(),
      });
      upload.start();
    });
    expect(url).toMatch(/\/api\/tus\/f_/);
    const location = new URL(url).pathname;
    const offsetAfterAbort = Number((await tusHead(app, l.token, location)).headers.get('upload-offset'));
    expect(offsetAfterAbort).toBeGreaterThan(0);
    expect(offsetAfterAbort).toBeLessThan(data.length);

    // Second attempt: resume from the stored upload URL.
    let sentFrom = -1;
    await new Promise<void>((resolve, reject) => {
      const upload = new tus.Upload(data, {
        endpoint: `${app.base}/api/tus`, headers: bearer(l.token), chunkSize: 1_000_000, retryDelays: null,
        metadata: { filename: 'client.bin' },
        onError: reject,
        onProgress: (sent) => { if (sentFrom < 0) sentFrom = sent; },
        onSuccess: () => resolve(),
      });
      upload.resumeFromPreviousUpload({ uploadUrl: url, size: data.length, metadata: { filename: 'client.bin' }, creationTime: new Date().toISOString() });
      upload.start();
    });
    expect(sentFrom).toBeGreaterThanOrEqual(offsetAfterAbort);
    const id = location.split('/').pop()!;
    expect(getFile(app.ctx.db, id)!.status).toBe('complete');
    expect((await readAll(id)).equals(data)).toBe(true);
    expect((await listFiles(app, l.token)).filter((f) => f.status === 'complete')).toHaveLength(1);
  });

  it('expires unfinished uploads and removes their data (cleanup job)', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id, { maxTotalBytes: 10_000_000 });
    const created = await tusCreate(app, l.token, 1_000_000, 'stale.bin');
    const location = created.headers.get('location')!;
    const id = location.split('/').pop()!;
    await tusPatch(app, l.token, location, 0, randomBytes(400_000));
    expect(linkUsage(app.ctx.db, l.id).reserved_bytes).toBe(1_000_000);
    if (app.ctx.storage.kind === 'local') expect(fs.existsSync(`${app.fileOnDisk(id)}.json`)).toBe(true);

    await sleep(20);
    const report = await runCleanup(app.ctx, { ttlMs: 10 });
    expect(report.staleUploads).toBeGreaterThanOrEqual(1);
    expect(getFile(app.ctx.db, id)!.status).toBe('expired');
    expect(linkUsage(app.ctx.db, l.id).reserved_bytes).toBe(0);
    expect(await app.ctx.storage.stat(id)).toBeNull();
    if (app.ctx.storage.kind === 'local') expect(fs.existsSync(`${app.fileOnDisk(id)}.json`)).toBe(false);
    expect((await tusHead(app, l.token, location)).status).toBe(410);
    expect(await listFiles(app, l.token)).toHaveLength(0);
  });

  it('sweeps orphaned storage artefacts and flags files missing from storage', async () => {
    const c = app.mkCase(); const l = app.mkLink(c.id);
    const created = await tusCreate(app, l.token, 10, 'ok.bin');
    const location = created.headers.get('location')!;
    await tusPatch(app, l.token, location, 0, randomBytes(10));
    const id = location.split('/').pop()!;
    expect(getFile(app.ctx.db, id)!.status).toBe('complete');

    if (app.ctx.storage.kind === 'local') {
      const stray = app.fileOnDisk('f_strayorphan000000');
      fs.writeFileSync(stray, 'junk');
      fs.writeFileSync(`${stray}.json`, '{}');
      const old = new Date(Date.now() - 3_600_000);
      fs.utimesSync(stray, old, old); fs.utimesSync(`${stray}.json`, old, old);
      const before = await runCleanup(app.ctx, { ttlMs: 60_000 });
      expect(before.orphans).toBe(2);
      expect(fs.existsSync(stray)).toBe(false);
    }

    await app.ctx.storage.delete(id); // simulate storage loss
    const report = await runCleanup(app.ctx, { ttlMs: 60_000 });
    expect(report.missingFiles).toBe(1);
    expect(getFile(app.ctx.db, id)!.status).toBe('missing');
  });
});
