import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import type { Readable } from 'node:stream';
import { FileStore } from '@tus/file-store';
import type { DataStore } from '@tus/utils';
import { LimitHashStream } from './limit.js';
import { assertValidKey, StorageNotFoundError, type OrphanCleanupOptions, type PutResult, type StorageBackend } from './types.js';

export class LocalStorage implements StorageBackend {
  readonly kind = 'local' as const;

  constructor(private readonly directory: string) {
    fs.mkdirSync(directory, { recursive: true });
  }

  private resolve(key: string): string {
    assertValidKey(key);
    const full = path.join(this.directory, key);
    // Belt and braces: keys are validated, but never trust path joins blindly.
    if (path.dirname(full) !== path.resolve(this.directory)) throw new Error('invalid storage key');
    return full;
  }

  async put(key: string, source: Readable, opts: { maxBytes: number }): Promise<PutResult> {
    const full = this.resolve(key);
    const limiter = new LimitHashStream(opts.maxBytes);
    // 'wx' fails if the key already exists: duplicates can never overwrite.
    const out = fs.createWriteStream(full, { flags: 'wx' });
    try {
      await pipeline(source, limiter, out);
    } catch (err) {
      await fsp.rm(full, { force: true });
      throw err;
    }
    return { size: limiter.size, sha256: limiter.digestHex() };
  }

  async get(key: string): Promise<Readable> {
    const full = this.resolve(key);
    try {
      const handle = await fsp.open(full, 'r');
      return handle.createReadStream();
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') throw new StorageNotFoundError(key);
      throw err;
    }
  }

  async stat(key: string): Promise<{ size: number } | null> {
    try {
      const st = await fsp.stat(this.resolve(key));
      return st.isFile() ? { size: st.size } : null;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
  }

  async delete(key: string): Promise<void> {
    await fsp.rm(this.resolve(key), { force: true });
    await fsp.rm(`${this.resolve(key)}.json`, { force: true });
  }

  createTusStore(opts: { expirationMs: number }): DataStore {
    return new FileStore({ directory: this.directory, expirationPeriodInMilliseconds: opts.expirationMs });
  }

  async removeTusSidecar(key: string): Promise<void> {
    await fsp.rm(`${this.resolve(key)}.json`, { force: true });
  }

  async cleanupOrphans(opts: OrphanCleanupOptions): Promise<{ removed: number }> {
    const cutoff = Date.now() - opts.olderThanMs;
    let removed = 0;
    for (const entry of await fsp.readdir(this.directory, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const key = entry.name.endsWith('.json') ? entry.name.slice(0, -5) : entry.name;
      if (opts.isLive(key)) continue;
      const full = path.join(this.directory, entry.name);
      const st = await fsp.stat(full).catch(() => null);
      if (!st || st.mtimeMs > cutoff) continue;
      await fsp.rm(full, { force: true });
      removed++;
    }
    return { removed };
  }

  async healthCheck(): Promise<void> {
    await fsp.access(this.directory, fs.constants.W_OK);
  }
}
