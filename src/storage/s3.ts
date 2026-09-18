import type { Readable } from 'node:stream';
import { PassThrough } from 'node:stream';
import {
  AbortMultipartUploadCommand, DeleteObjectCommand, GetObjectCommand, HeadBucketCommand, HeadObjectCommand,
  ListMultipartUploadsCommand, ListObjectsV2Command, S3Client,
} from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { S3Store } from '@tus/s3-store';
import type { DataStore } from '@tus/utils';
import type { Config } from '../config.js';
import { LimitHashStream } from './limit.js';
import { assertValidKey, StorageLimitError, StorageNotFoundError, type OrphanCleanupOptions, type PutResult, type StorageBackend } from './types.js';

export class S3Storage implements StorageBackend {
  readonly kind = 's3' as const;
  private readonly client: S3Client;
  private readonly bucket: string;

  constructor(private readonly cfg: Config['s3']) {
    this.bucket = cfg.bucket;
    this.client = new S3Client(this.clientConfig());
  }

  private clientConfig() {
    return {
      region: this.cfg.region,
      endpoint: this.cfg.endpoint,
      forcePathStyle: this.cfg.forcePathStyle,
      credentials: this.cfg.accessKeyId && this.cfg.secretAccessKey
        ? { accessKeyId: this.cfg.accessKeyId, secretAccessKey: this.cfg.secretAccessKey }
        : undefined,
    };
  }

  async put(key: string, source: Readable, opts: { maxBytes: number }): Promise<PutResult> {
    assertValidKey(key);
    const limiter = new LimitHashStream(opts.maxBytes);
    const body = new PassThrough();
    // Errors on the source/limiter must surface to the S3 upload, which then aborts the multipart upload.
    let failure: Error | undefined;
    source.on('error', (e) => { failure = e; body.destroy(e); });
    limiter.on('error', (e) => { failure = e; body.destroy(e); });
    source.pipe(limiter).pipe(body);

    const upload = new Upload({
      client: this.client,
      params: { Bucket: this.bucket, Key: key, Body: body, ContentType: 'application/octet-stream' },
      partSize: Math.max(this.cfg.partSize, 5 * 1024 * 1024),
      queueSize: 2,
      leavePartsOnError: false,
    });
    try {
      await upload.done();
    } catch (err) {
      // lib-storage aborts the multipart upload on failure; nothing to clean here.
      throw failure ?? err;
    }
    if (failure) throw failure;
    return { size: limiter.size, sha256: limiter.digestHex() };
  }

  async get(key: string): Promise<Readable> {
    assertValidKey(key);
    try {
      const res = await this.client.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
      if (!res.Body) throw new StorageNotFoundError(key);
      return res.Body as Readable;
    } catch (err) {
      if (isNotFound(err)) throw new StorageNotFoundError(key);
      throw err;
    }
  }

  async stat(key: string): Promise<{ size: number } | null> {
    assertValidKey(key);
    try {
      const res = await this.client.send(new HeadObjectCommand({ Bucket: this.bucket, Key: key }));
      return { size: res.ContentLength ?? 0 };
    } catch (err) {
      if (isNotFound(err)) return null;
      throw err;
    }
  }

  async delete(key: string): Promise<void> {
    assertValidKey(key);
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: `${key}.info` }));
  }

  createTusStore(opts: { expirationMs: number }): DataStore {
    return new S3Store({
      partSize: this.cfg.partSize,
      expirationPeriodInMilliseconds: opts.expirationMs,
      s3ClientConfig: { ...this.clientConfig(), bucket: this.bucket },
    });
  }

  async removeTusSidecar(key: string): Promise<void> {
    assertValidKey(key);
    await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: `${key}.info` }));
  }

  async cleanupOrphans(opts: OrphanCleanupOptions): Promise<{ removed: number }> {
    const cutoff = Date.now() - opts.olderThanMs;
    let removed = 0;

    // 1. Multipart uploads nobody will ever finish (e.g. app crashed mid-upload).
    let keyMarker: string | undefined;
    let uploadIdMarker: string | undefined;
    do {
      const res = await this.client.send(new ListMultipartUploadsCommand({ Bucket: this.bucket, KeyMarker: keyMarker, UploadIdMarker: uploadIdMarker }));
      for (const u of res.Uploads ?? []) {
        if (!u.Key || !u.UploadId) continue;
        const initiated = u.Initiated?.getTime() ?? 0;
        if (initiated > cutoff || opts.isLive(u.Key)) continue;
        await this.client.send(new AbortMultipartUploadCommand({ Bucket: this.bucket, Key: u.Key, UploadId: u.UploadId }));
        removed++;
      }
      keyMarker = res.IsTruncated ? res.NextKeyMarker : undefined;
      uploadIdMarker = res.IsTruncated ? res.NextUploadIdMarker : undefined;
    } while (keyMarker || uploadIdMarker);

    // 2. Objects (data, .info, .part) not referenced by any live file.
    let token: string | undefined;
    do {
      const res = await this.client.send(new ListObjectsV2Command({ Bucket: this.bucket, ContinuationToken: token }));
      for (const obj of res.Contents ?? []) {
        if (!obj.Key) continue;
        const base = obj.Key.replace(/\.(info|part)$/, '');
        if (opts.isLive(base)) continue;
        if ((obj.LastModified?.getTime() ?? 0) > cutoff) continue;
        await this.client.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: obj.Key }));
        removed++;
      }
      token = res.IsTruncated ? res.NextContinuationToken : undefined;
    } while (token);

    return { removed };
  }

  async healthCheck(): Promise<void> {
    await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }));
  }
}

function isNotFound(err: unknown): boolean {
  const e = err as { name?: string; $metadata?: { httpStatusCode?: number } };
  return e?.name === 'NoSuchKey' || e?.name === 'NotFound' || e?.$metadata?.httpStatusCode === 404;
}

export { StorageLimitError };
