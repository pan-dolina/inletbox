import { createHash } from 'node:crypto';
import { Transform } from 'node:stream';
import { StorageLimitError } from './types.js';

/**
 * Pass-through stream that counts bytes, hashes them and fails as soon as the
 * byte count exceeds `maxBytes`. Used by both backends so limits are enforced
 * even without a Content-Length header.
 */
export class LimitHashStream extends Transform {
  size = 0;
  private readonly hash = createHash('sha256');

  constructor(private readonly maxBytes: number) {
    super();
  }

  override _transform(chunk: Buffer, _enc: BufferEncoding, cb: (err?: Error | null, data?: Buffer) => void): void {
    this.size += chunk.length;
    if (this.size > this.maxBytes) {
      cb(new StorageLimitError(this.maxBytes));
      return;
    }
    this.hash.update(chunk);
    cb(null, chunk);
  }

  digestHex(): string {
    return this.hash.digest('hex');
  }
}
