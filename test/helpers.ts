import { randomFillSync } from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { CreateBucketCommand, DeleteBucketCommand, DeleteObjectCommand, ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import { startServer, type RunningServer } from '../src/server.js';
import { createAdmin } from '../src/services/auth.js';
import { createCase } from '../src/services/cases.js';
import { createLink, type CreateLinkInput } from '../src/services/links.js';

export const USE_S3 = process.env.TEST_S3 === '1';
const S3_ENDPOINT = process.env.TEST_S3_ENDPOINT ?? 'http://127.0.0.1:9000';
const S3_KEY = process.env.TEST_S3_ACCESS_KEY ?? 'minioadmin';
const S3_SECRET = process.env.TEST_S3_SECRET_KEY ?? 'minioadmin';

export const ADMIN_USER = 'admin';
export const ADMIN_PASS = 'correct-horse-battery-staple';

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
    srv.on('error', reject);
  });
}

export interface TestApp extends RunningServer {
  base: string;
  dataDir: string;
  adminLogin(): Promise<AdminSession>;
  mkCase(name?: string): { id: string; name: string };
  mkLink(caseId: string, opts?: Partial<CreateLinkInput>): { id: string; token: string; url: string };
  fileOnDisk(id: string): string;
}

export interface AdminSession { cookie: string; csrf: string }

export async function boot(env: Record<string, string> = {}): Promise<TestApp> {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'inletbox-test-'));
  const base = `http://127.0.0.1:${port}`;
  let bucket = '';
  let s3: S3Client | undefined;
  const fullEnv: Record<string, string> = {
    PUBLIC_URL: base, HOST: '127.0.0.1', PORT: String(port), DATA_DIR: dataDir,
    STORAGE_BACKEND: 'local', MAX_FILE_SIZE: '50MB', UPLOAD_CHUNK_SIZE: '1MB',
    CLEANUP_INTERVAL_MINUTES: '0', LOG_LEVEL: 'error', COOKIE_SECURE: 'false',
    LOGIN_RATE_LIMIT_PER_15MIN: '10', TOKEN_FAILURE_RATE_LIMIT_PER_15MIN: '1000', PUBLIC_RATE_LIMIT_PER_MINUTE: '100000',
    ...env,
  };
  if (USE_S3) {
    bucket = `inletbox-test-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    s3 = new S3Client({ region: 'us-east-1', endpoint: S3_ENDPOINT, forcePathStyle: true, credentials: { accessKeyId: S3_KEY, secretAccessKey: S3_SECRET } });
    await s3.send(new CreateBucketCommand({ Bucket: bucket }));
    Object.assign(fullEnv, {
      STORAGE_BACKEND: 's3', S3_ENDPOINT, S3_REGION: 'us-east-1', S3_BUCKET: bucket, S3_ACCESS_KEY_ID: S3_KEY, S3_SECRET_ACCESS_KEY: S3_SECRET,
      S3_FORCE_PATH_STYLE: 'true', S3_PART_SIZE: '5MB',
    });
  }
  const running = await startServer(fullEnv, { host: '127.0.0.1', port });
  createAdmin(running.ctx.db, ADMIN_USER, ADMIN_PASS);

  const app: TestApp = {
    ...running,
    base,
    dataDir,
    close: async () => {
      await running.close();
      fs.rmSync(dataDir, { recursive: true, force: true });
      if (s3 && bucket) {
        let token: string | undefined;
        do {
          const res = await s3.send(new ListObjectsV2Command({ Bucket: bucket, ContinuationToken: token }));
          for (const o of res.Contents ?? []) await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: o.Key! }));
          token = res.IsTruncated ? res.NextContinuationToken : undefined;
        } while (token);
        await s3.send(new DeleteBucketCommand({ Bucket: bucket })).catch(() => undefined);
      }
    },
    async adminLogin() {
      const res = await fetch(`${base}/admin/login`, {
        method: 'POST', redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username: ADMIN_USER, password: ADMIN_PASS }),
      });
      if (res.status !== 303) throw new Error(`login failed: ${res.status}`);
      const cookie = res.headers.get('set-cookie')!.split(';')[0]!;
      const page = await fetch(`${base}/admin`, { headers: { cookie } });
      const csrf = /name="_csrf" value="([^"]+)"/.exec(await page.text())![1]!;
      return { cookie, csrf };
    },
    mkCase(name = 'Test case') {
      const c = createCase(running.ctx.db, { name });
      return { id: c.id, name: c.name };
    },
    mkLink(caseId, opts = {}) {
      const { link, token, url } = createLink(running.ctx.db, running.ctx.cfg, { caseId, label: 'Recipient', ...opts });
      return { id: link.id, token, url };
    },
    fileOnDisk: (id) => path.join(running.ctx.cfg.localStorageDir, id),
  };
  return app;
}

export function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

/** PUT a buffer as a "curl -T" style upload. */
export async function putFile(app: TestApp, token: string, name: string, body: Buffer | Uint8Array): Promise<Response> {
  return fetch(`${app.base}/api/upload/${encodeURIComponent(name)}`, { method: 'PUT', headers: bearer(token), body });
}

/** Same, but with chunked transfer encoding (no Content-Length). */
export async function putChunked(app: TestApp, token: string, name: string, chunks: Uint8Array[]): Promise<Response> {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) { for (const c of chunks) controller.enqueue(c); controller.close(); },
  });
  return fetch(`${app.base}/api/upload/${encodeURIComponent(name)}`, {
    method: 'PUT', headers: bearer(token), body: stream,
    // @ts-expect-error undici option
    duplex: 'half',
  });
}

export async function listFiles(app: TestApp, token: string): Promise<Array<{ id: string; name: string; size: number | null; status: string }>> {
  const res = await fetch(`${app.base}/api/files`, { headers: bearer(token) });
  if (!res.ok) throw new Error(`list failed ${res.status}`);
  return (await res.json() as { files: Array<{ id: string; name: string; size: number | null; status: string }> }).files;
}

export async function adminDownload(app: TestApp, session: AdminSession, fileId: string): Promise<Response> {
  return fetch(`${app.base}/admin/files/${fileId}/download`, { headers: { cookie: session.cookie }, redirect: 'manual' });
}

export async function adminPost(app: TestApp, session: AdminSession, urlPath: string, fields: Record<string, string> = {}): Promise<Response> {
  return fetch(`${app.base}${urlPath}`, {
    method: 'POST', redirect: 'manual',
    headers: { cookie: session.cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ _csrf: session.csrf, ...fields }),
  });
}

export function randomBytes(n: number): Buffer {
  return randomFillSync(Buffer.alloc(n));
}

export const TUS_HEADERS = { 'tus-resumable': '1.0.0' };

export function b64(s: string): string { return Buffer.from(s, 'utf8').toString('base64'); }

export async function tusCreate(app: TestApp, token: string, size: number, filename: string): Promise<Response> {
  return fetch(`${app.base}/api/tus`, {
    method: 'POST',
    headers: { ...bearer(token), ...TUS_HEADERS, 'upload-length': String(size), 'upload-metadata': `filename ${b64(filename)}` },
  });
}

export async function tusPatch(app: TestApp, token: string, location: string, offset: number, data: Uint8Array): Promise<Response> {
  return fetch(`${app.base}${location}`, {
    method: 'PATCH',
    headers: { ...bearer(token), ...TUS_HEADERS, 'upload-offset': String(offset), 'content-type': 'application/offset+octet-stream' },
    body: data,
  });
}

export async function tusHead(app: TestApp, token: string, location: string): Promise<Response> {
  return fetch(`${app.base}${location}`, { method: 'HEAD', headers: { ...bearer(token), ...TUS_HEADERS } });
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
