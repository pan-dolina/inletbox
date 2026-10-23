/**
 * Device Bound Session Credentials: the exchange Chrome performs, played with a real
 * key (test/authenticator.ts), and what it buys — a session cookie on its own stops
 * working once the short-lived bound cookie it travelled with has expired.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DbscError, proofFromHeader, verifyProof } from '../src/dbsc.js';
import { SoftDbscKey } from './authenticator.js';
import { boot, type AdminSession, type TestApp } from './helpers.js';

describe('DBSC proofs', () => {
  for (const alg of ['ES256', 'RS256'] as const) {
    it(`verifies a ${alg} proof with the key it carries, then with the stored key`, () => {
      const k = new SoftDbscKey(alg);
      const reg = verifyProof(k.proof('c1', { withKey: true }));
      expect(reg).toMatchObject({ alg, jti: 'c1' });
      expect(verifyProof(k.proof('c2'), { alg, jwk: reg.jwk! }).jti).toBe('c2');
    });
  }

  it('refuses unsigned, mistyped, foreign and malformed proofs', () => {
    const k = new SoftDbscKey();
    const jwk = verifyProof(k.proof('c', { withKey: true })).jwk!;
    expect(() => verifyProof(k.proof('c', { withKey: true, typ: 'JWT' }))).toThrow('wrong typ');
    expect(() => verifyProof(k.proof('c', { withKey: true, alg: 'none' }))).toThrow('unsupported alg');
    expect(() => verifyProof(new SoftDbscKey().proof('c'), { alg: 'ES256', jwk })).toThrow('bad signature');
    expect(() => verifyProof(k.proof('c'), { alg: 'RS256', jwk })).toThrow(DbscError);
    expect(() => verifyProof(k.proof('c'))).toThrow('missing key');
    expect(() => verifyProof('a.b')).toThrow('malformed');
    const [h, p, sig] = k.proof('c', { withKey: true }).split('.');
    const withPrivate = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(h!, 'base64url').toString()), jwk: { ...k.jwk, d: 'secret' } })).toString('base64url');
    expect(() => verifyProof(`${withPrivate}.${p}.${sig}`)).toThrow('unsupported key');
    expect(proofFromHeader('"abc.def.ghi"')).toBe('abc.def.ghi');
    expect(proofFromHeader('abc.def.ghi')).toBe('abc.def.ghi');
    expect(proofFromHeader('"a b"')).toBeNull();
  });
});

describe('device-bound sessions', () => {
  let app: TestApp;
  beforeAll(async () => { app = await boot({ COOKIE_SECURE: 'true' }); });
  afterAll(async () => { await app.close(); });

  const doc = { 'sec-fetch-dest': 'document' };
  const cookieOf = (res: Response, name: string) => res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`))?.split(';')[0];

  /** Logs in and plays Chrome: takes the offer and registers a key. */
  async function bind(key = new SoftDbscKey()): Promise<{ s: AdminSession; bound: string; id: string; key: SoftDbscKey }> {
    const s = await app.adminLogin();
    const page = await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie, ...doc } });
    const offer = page.headers.get('secure-session-registration')!;
    expect(offer).toMatch(/^\(ES256 RS256\);path="\/admin\/dbsc\/register";challenge="[A-Za-z0-9_-]+"$/);
    // Offered once per session.
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie, ...doc } })).headers.get('secure-session-registration')).toBeNull();
    const challenge = /challenge="([^"]+)"/.exec(offer)![1]!;
    const res = await fetch(`${app.base}/admin/dbsc/register`, { method: 'POST', headers: { cookie: s.cookie, 'secure-session-response': `"${key.proof(challenge, { withKey: true })}"` } });
    expect(res.status).toBe(200);
    const config = (await res.json()) as { session_identifier: string; refresh_url: string; credentials: Array<{ name: string; attributes: string }>; scope: { origin: string } };
    expect(config).toMatchObject({ refresh_url: '/admin/dbsc/refresh', scope: { origin: app.base, include_site: false }, credentials: [{ type: 'cookie', name: 'inletbox_bound' }] });
    expect(config.credentials[0]!.attributes).toContain('Path=/admin');
    const bound = cookieOf(res, 'inletbox_bound')!;
    expect(res.headers.getSetCookie().join()).toContain('Max-Age=600');
    return { s, bound, id: config.session_identifier, key };
  }

  it('binds a session, then refuses its cookie without the bound one', async () => {
    const { s, bound } = await bind();
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: `${s.cookie}; ${bound}` }, redirect: 'manual' })).status).toBe(200);
    // What a thief with the session cookie alone gets.
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie }, redirect: 'manual' })).headers.get('location')).toBe('/admin/login');
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: `${s.cookie}; inletbox_bound=forged` }, redirect: 'manual' })).status).toBe(302);
    // The session list says so.
    expect(await (await fetch(`${app.base}/admin/security`, { headers: { cookie: `${s.cookie}; ${bound}` } })).text()).toContain('bound to this device');
  });

  it('renews the bound cookie only against a signature over a fresh challenge', async () => {
    const { s, bound, id, key } = await bind();
    const refresh = (proof?: string) => fetch(`${app.base}/admin/dbsc/refresh`, {
      method: 'POST', redirect: 'manual', headers: { cookie: s.cookie, 'sec-secure-session-id': id, ...(proof ? { 'secure-session-response': `"${proof}"` } : {}) },
    });
    const first = await refresh();
    expect(first.status).toBe(403);
    const ch = first.headers.get('secure-session-challenge')!;
    expect(ch).toMatch(new RegExp(`^"[A-Za-z0-9_-]+";id="${id}"$`));
    const challenge = /^"([^"]+)"/.exec(ch)![1]!;

    // A proof by another key is final; one for a stale challenge just gets a new challenge.
    expect((await refresh(new SoftDbscKey().proof(challenge))).status).toBe(401);
    const stale = await refresh(key.proof('not-the-challenge'));
    expect(stale.status).toBe(403);
    const current = /^"([^"]+)"/.exec(stale.headers.get('secure-session-challenge')!)![1]!;

    const ok = await refresh(key.proof(current));
    expect(ok.status).toBe(200);
    const renewed = cookieOf(ok, 'inletbox_bound')!;
    expect(renewed).not.toBe(bound);
    expect(ok.headers.get('secure-session-challenge')).toMatch(/;id="/);
    expect(ok.headers.get('location')).toBeNull();
    // Both the new cookie and, briefly, the previous one work: requests in flight survive.
    for (const c of [renewed, bound]) expect((await fetch(`${app.base}/admin`, { headers: { cookie: `${s.cookie}; ${c}` }, redirect: 'manual' })).status).toBe(200);
    // A replayed proof does not renew twice.
    expect((await refresh(key.proof(current))).status).toBe(403);

    // Once its lifetime is over (plus grace), a bound cookie is worthless.
    app.ctx.db.prepare('UPDATE session_bindings SET cookie_expires_at = ?, prev_cookie_expires_at = ? WHERE id = ?')
      .run(new Date(Date.now() - 120_000).toISOString(), new Date(Date.now() - 120_000).toISOString(), id);
    expect((await fetch(`${app.base}/admin`, { headers: { cookie: `${s.cookie}; ${renewed}` }, redirect: 'manual' })).status).toBe(302);
  });

  it('refuses a second registration, a wrong challenge, and ends the binding with the session', async () => {
    const s = await app.adminLogin();
    const offer = (await fetch(`${app.base}/admin`, { headers: { cookie: s.cookie, ...doc } })).headers.get('secure-session-registration')!;
    const challenge = /challenge="([^"]+)"/.exec(offer)![1]!;
    const key = new SoftDbscKey('RS256');
    const register = (proof: string) => fetch(`${app.base}/admin/dbsc/register`, { method: 'POST', headers: { cookie: s.cookie, 'secure-session-response': `"${proof}"` } });
    expect((await register(key.proof('guessed', { withKey: true }))).status).toBe(400);
    const ok = await register(key.proof(challenge, { withKey: true }));
    expect(ok.status).toBe(200);
    const { session_identifier: id } = (await ok.json()) as { session_identifier: string };
    // A thief who took the cookie in that moment cannot swap in their own key.
    expect((await register(new SoftDbscKey().proof(challenge, { withKey: true }))).status).toBe(400);
    // Nor can an unauthenticated caller register anything.
    expect((await fetch(`${app.base}/admin/dbsc/register`, { method: 'POST', headers: { 'secure-session-response': `"${key.proof(challenge, { withKey: true })}"` } })).status).toBe(400);

    const bound = cookieOf(ok, 'inletbox_bound')!;
    const csrf = /name="_csrf" value="([^"]+)"/.exec(await (await fetch(`${app.base}/admin/security`, { headers: { cookie: `${s.cookie}; ${bound}` } })).text())![1]!;
    const out = await fetch(`${app.base}/admin/logout`, { method: 'POST', redirect: 'manual', headers: { cookie: `${s.cookie}; ${bound}`, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ _csrf: csrf }) });
    expect(out.headers.getSetCookie().some((c) => c.startsWith('inletbox_bound=;'))).toBe(true);
    const after = await fetch(`${app.base}/admin/dbsc/refresh`, { method: 'POST', headers: { 'sec-secure-session-id': id } });
    expect(after.status).toBe(401);
    expect(await after.json()).toEqual({ continue: false });
    expect(app.ctx.db.prepare('SELECT COUNT(*) AS n FROM session_bindings WHERE id = ?').get(id)).toEqual({ n: 0 });
  });

  it('offers nothing over plain HTTP or when turned off', async () => {
    for (const env of [{ COOKIE_SECURE: 'false' }, { COOKIE_SECURE: 'true', DEVICE_BOUND_SESSIONS: 'false' }]) {
      const other = await boot(env);
      try {
        const s = await other.adminLogin();
        expect((await fetch(`${other.base}/admin`, { headers: { cookie: s.cookie, ...doc } })).headers.get('secure-session-registration')).toBeNull();
      } finally {
        await other.close();
      }
    }
  });
});
