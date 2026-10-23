/**
 * A software stand-in for a passkey, and for a browser's DBSC key: real key pairs,
 * producing exactly the bytes a browser would send, so the server is tested against
 * real signatures rather than mocks.
 */
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

type Alg = -7 | -8 | -257;

export class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  signCount: number;
  private readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;

  constructor(readonly alg: Alg = -7, opts: { counter?: boolean } = {}) {
    const pair = alg === -8 ? generateKeyPairSync('ed25519')
      : alg === -7 ? generateKeyPairSync('ec', { namedCurve: 'P-256' })
        : generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
    // Most passkeys report 0 for ever; security keys count up.
    this.signCount = opts.counter ? 1 : 0;
  }

  private authData(rpId: string, flags: number, attested: boolean): Buffer {
    const head = Buffer.alloc(37);
    createHash('sha256').update(rpId).digest().copy(head, 0);
    head[32] = flags | (attested ? 0x40 : 0);
    head.writeUInt32BE(this.signCount, 33);
    if (!attested) return head;
    const len = Buffer.alloc(2);
    len.writeUInt16BE(this.credentialId.length);
    // aaguid (zeros, as with attestation "none") + id + a stand-in for the COSE key
    return Buffer.concat([head, Buffer.alloc(16), len, this.credentialId, Buffer.from([0xa0])]);
  }

  private clientData(type: string, challenge: string, origin: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }

  /** The fields passkey.js posts after navigator.credentials.create(). */
  register(o: { challenge: string; origin: string; rpId: string; flags?: number }): Record<string, string> {
    return {
      credential_id: this.credentialId.toString('base64url'),
      client_data: this.clientData('webauthn.create', o.challenge, o.origin).toString('base64url'),
      authenticator_data: this.authData(o.rpId, o.flags ?? 0x05, true).toString('base64url'),
      public_key: (this.publicKey.export({ format: 'der', type: 'spki' }) as Buffer).toString('base64url'),
      algorithm: String(this.alg),
    };
  }

  /** The fields passkey.js posts after navigator.credentials.get(). */
  assert(o: { challenge: string; origin: string; rpId: string; flags?: number; type?: string }): Record<string, string> {
    if (this.signCount > 0) this.signCount += 1;
    const authData = this.authData(o.rpId, o.flags ?? 0x05, false);
    const clientData = this.clientData(o.type ?? 'webauthn.get', o.challenge, o.origin);
    const signed = Buffer.concat([authData, createHash('sha256').update(clientData).digest()]);
    const signature = this.alg === -8 ? sign(null, signed, this.privateKey) : sign('sha256', signed, this.privateKey);
    return {
      credential_id: this.credentialId.toString('base64url'),
      client_data: clientData.toString('base64url'),
      authenticator_data: authData.toString('base64url'),
      signature: signature.toString('base64url'),
    };
  }
}

/** A browser's DBSC key: signs `dbsc+jwt` proofs. */
export class SoftDbscKey {
  private readonly privateKey: KeyObject;
  readonly jwk: Record<string, unknown>;

  constructor(readonly alg: 'ES256' | 'RS256' = 'ES256') {
    const pair = alg === 'ES256' ? generateKeyPairSync('ec', { namedCurve: 'P-256' }) : generateKeyPairSync('rsa', { modulusLength: 2048 });
    this.privateKey = pair.privateKey;
    this.jwk = pair.publicKey.export({ format: 'jwk' }) as Record<string, unknown>;
  }

  /** A proof answering `challenge`; with `withKey` it carries the public key (registration). */
  proof(challenge: string, opts: { withKey?: boolean; typ?: string; alg?: string } = {}): string {
    const header = { typ: opts.typ ?? 'dbsc+jwt', alg: opts.alg ?? this.alg, ...(opts.withKey ? { jwk: this.jwk } : {}) };
    const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const input = `${b64(header)}.${b64({ jti: challenge, iat: Math.floor(Date.now() / 1000) })}`;
    const sig = this.alg === 'ES256'
      ? sign('sha256', Buffer.from(input), { key: this.privateKey, dsaEncoding: 'ieee-p1363' })
      : sign('sha256', Buffer.from(input), this.privateKey);
    return `${input}.${sig.toString('base64url')}`;
  }
}
