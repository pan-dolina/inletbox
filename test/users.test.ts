import fs from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { newTempPassword } from '../src/crypto.js';
import { migrate, openDatabase } from '../src/db.js';
import { listAudit } from '../src/services/audit.js';
import { findAdminByUsername } from '../src/services/auth.js';
import { getCase } from '../src/services/cases.js';
import { getFile } from '../src/services/files.js';
import { getLink } from '../src/services/links.js';
import { addCaseMember, getUser, listUsers, setUserDisabled, setUserRole, UserError } from '../src/services/users.js';
import { ADMIN_USER, adminDownload, adminPost, boot, listFiles, putFile, randomBytes, type AdminSession, type TestApp } from './helpers.js';

let app: TestApp;
beforeAll(async () => { app = await boot(); });
afterAll(async () => { await app.close(); });

const get = (s: AdminSession, path: string) => fetch(`${app.base}${path}`, { headers: { cookie: s.cookie }, redirect: 'manual' });
const issuedPassword = (body: string) => /readonly value="([^"]+)" data-copy-source/.exec(body)![1]!;
const adminId = () => findAdminByUsername(app.ctx.db, ADMIN_USER)!.id;

describe('accounts', () => {
  it('issues a password once, and its owner has to replace it before anything else', async () => {
    const admin = await app.adminLogin();
    const res = await adminPost(app, admin, '/admin/users', { username: 'anna@example.com', role: 'user' });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('Account anna@example.com created');
    const password = issuedPassword(body);
    expect(password).toMatch(/^[a-z2-9]{5}(-[a-z2-9]{5}){3}$/);
    // Nothing stored in clear, and the list afterwards does not show it again.
    const list = await (await get(admin, '/admin/users')).text();
    expect(list).not.toContain(password);
    // Destructive actions ask first (admin.js reads data-confirm); one's own row offers none.
    expect(list).toContain('data-confirm="Delete the account anna@example.com?');
    expect(list).toContain('data-confirm="Disable anna@example.com?');
    expect(list).not.toContain(`/admin/users/${adminId()}/`);
    expect(listAudit(app.ctx.db, 5).find((r) => r.action === 'user.create')!.details).toContain('anna@example.com');

    const login = await fetch(`${app.base}/admin/login`, {
      method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: 'anna@example.com', password }),
    });
    expect(login.headers.get('location')).toBe('/admin/security');
    const anna = await app.login('anna@example.com', password);
    expect((await get(anna, '/admin')).headers.get('location')).toBe('/admin/security');
    expect((await adminPost(app, anna, '/admin/cases', { name: 'Too early' })).status).toBe(403);
    expect(await (await get(anna, '/admin/security')).text()).toContain('Your password was issued by an administrator');

    const same = await adminPost(app, anna, '/admin/security/password', { current_password: password, new_password: password, new_password_confirm: password });
    expect(same.status).toBe(400);
    const changed = await adminPost(app, anna, '/admin/security/password', { current_password: password, new_password: 'annas-own-password', new_password_confirm: 'annas-own-password' });
    expect(changed.status).toBe(200);
    expect((await get(anna, '/admin')).status).toBe(200);
    expect(getUser(app.ctx.db, findAdminByUsername(app.ctx.db, 'anna@example.com')!.id)!.last_login_at).not.toBeNull();
  });

  it('generates temporary passwords from an unambiguous alphabet', () => {
    const seen = new Set(Array.from({ length: 50 }, newTempPassword));
    expect(seen.size).toBe(50);
    for (const p of seen) expect(p).not.toMatch(/[01ilo]/);
  });

  it('refuses a taken or malformed username', async () => {
    const admin = await app.adminLogin();
    const dup = await adminPost(app, admin, '/admin/users', { username: ADMIN_USER, role: 'user' });
    expect(dup.status).toBe(400);
    expect(await dup.text()).toContain(`An account named ${ADMIN_USER} already exists`);
    const bad = await adminPost(app, admin, '/admin/users', { username: 'no spaces', role: 'user' });
    expect(bad.status).toBe(400);
    expect(await bad.text()).toContain('A username has 2–64 characters');
    // An unknown role is not an error to report: the form only offers two, anything else becomes the lesser one.
    const odd = await adminPost(app, admin, '/admin/users', { username: 'odd-role', role: 'root' });
    expect(odd.status).toBe(200);
    expect(findAdminByUsername(app.ctx.db, 'odd-role')!.role).toBe('user');
  });
});

describe('a user and the cases assigned to them', () => {
  it('sees and works on assigned cases only; every other case answers as missing', async () => {
    const admin = await app.adminLogin();
    const bob = app.mkUser('bob');
    const visible = app.mkCase('Visible to Bob');
    const hidden = app.mkCase('Hidden from Bob');
    const assigned = await adminPost(app, admin, `/admin/cases/${visible.id}/members`, { user_id: bob.id });
    expect(await assigned.text()).toContain('The account bob is now assigned to this case');

    const hiddenLink = app.mkLink(hidden.id);
    expect((await putFile(app, hiddenLink.token, 'secret.bin', randomBytes(64))).status).toBe(201);
    const [hiddenFile] = await listFiles(app, hiddenLink.token);

    const s = await app.login(bob.username, bob.password);
    const list = await (await get(s, '/admin')).text();
    expect(list).toContain('Visible to Bob');
    expect(list).not.toContain('Hidden from Bob');
    // No administrator pages in the navigation.
    expect(list).not.toContain('href="/admin/users"');
    expect(list).not.toContain('href="/admin/audit"');

    expect((await get(s, `/admin/cases/${hidden.id}`)).status).toBe(404);
    expect((await adminPost(app, s, `/admin/cases/${hidden.id}`, { name: 'Renamed', description: '' })).status).toBe(404);
    expect((await adminPost(app, s, `/admin/cases/${hidden.id}/status`, { status: 'closed' })).status).toBe(404);
    expect((await adminPost(app, s, `/admin/cases/${hidden.id}/links`, { label: 'Sneaky' })).status).toBe(404);
    expect((await adminPost(app, s, `/admin/links/${hiddenLink.id}/revoke`)).status).toBe(404);
    expect((await adminDownload(app, s, hiddenFile!.id)).status).toBe(404);
    expect((await adminPost(app, s, `/admin/files/${hiddenFile!.id}/delete`)).status).toBe(404);
    expect(getCase(app.ctx.db, hidden.id)).toMatchObject({ name: 'Hidden from Bob', status: 'open' });
    expect(getLink(app.ctx.db, hiddenLink.id)!.revoked_at).toBeNull();
    expect(getFile(app.ctx.db, hiddenFile!.id)!.status).toBe('complete');

    const page = await (await get(s, `/admin/cases/${visible.id}`)).text();
    expect(page).toContain('Visible to Bob');
    expect(page).toContain('<span>bob</span>');
    expect(page).not.toContain(`/admin/cases/${visible.id}/members`);
    const link = await adminPost(app, s, `/admin/cases/${visible.id}/links`, { label: 'For the client' });
    expect(await link.text()).toContain('/u/');
  });

  it('cannot reach accounts, assignments or the audit log', async () => {
    const carol = app.mkUser('carol');
    const c = app.mkCase('Carol works here');
    addCaseMember(app.ctx.db, c.id, carol.id);
    const s = await app.login(carol.username, carol.password);
    expect((await get(s, '/admin/users')).status).toBe(403);
    expect((await get(s, '/admin/audit')).status).toBe(403);
    expect((await adminPost(app, s, '/admin/users', { username: 'carols-friend', role: 'admin' })).status).toBe(403);
    expect(findAdminByUsername(app.ctx.db, 'carols-friend')).toBeNull();
    expect((await adminPost(app, s, `/admin/users/${adminId()}/disable`)).status).toBe(403);
    expect((await adminPost(app, s, `/admin/cases/${c.id}/members/${carol.id}/remove`)).status).toBe(403);
    expect((await get(s, `/admin/cases/${c.id}`)).status).toBe(200);
  });

  it('is assigned to the cases they create', async () => {
    const dave = app.mkUser('dave');
    const s = await app.login(dave.username, dave.password);
    const created = await adminPost(app, s, '/admin/cases', { name: 'Dave opened this' });
    expect(created.status).toBe(303);
    const caseId = created.headers.get('location')!.split('/').pop()!;
    expect((await get(s, `/admin/cases/${caseId}`)).status).toBe(200);
    expect(await (await get(s, '/admin')).text()).toContain('Dave opened this');
  });
});

describe('changes an administrator makes', () => {
  it('apply to a signed-in user at once', async () => {
    const admin = await app.adminLogin();
    const erin = app.mkUser('erin');
    const c = app.mkCase('Erin case');
    const other = app.mkCase('Not Erin case');
    addCaseMember(app.ctx.db, c.id, erin.id);
    const s = await app.login(erin.username, erin.password);
    expect((await get(s, `/admin/cases/${c.id}`)).status).toBe(200);

    // Unassigned: the case is gone for her.
    await adminPost(app, admin, `/admin/cases/${c.id}/members/${erin.id}/remove`);
    expect((await get(s, `/admin/cases/${c.id}`)).status).toBe(404);

    // Promoted: every case and the account list; demoted again: neither.
    await adminPost(app, admin, `/admin/users/${erin.id}/role`, { role: 'admin' });
    expect((await get(s, `/admin/cases/${other.id}`)).status).toBe(200);
    expect((await get(s, '/admin/users')).status).toBe(200);
    await adminPost(app, admin, `/admin/users/${erin.id}/role`, { role: 'user' });
    expect((await get(s, `/admin/cases/${other.id}`)).status).toBe(404);
    expect((await get(s, '/admin/users')).status).toBe(403);

    // Disabled: the session is over and the password no longer opens anything.
    const disabled = await adminPost(app, admin, `/admin/users/${erin.id}/disable`);
    expect(await disabled.text()).toContain('The account erin was disabled');
    expect((await get(s, '/admin')).headers.get('location')).toBe('/admin/login');
    await expect(app.login(erin.username, erin.password)).rejects.toThrow(/401/);
    await adminPost(app, admin, `/admin/users/${erin.id}/enable`);
    const again = await app.login(erin.username, erin.password);

    // A new password ends the session and the old password.
    const reset = await adminPost(app, admin, `/admin/users/${erin.id}/password`);
    const fresh = issuedPassword(await reset.text());
    expect((await get(again, '/admin')).headers.get('location')).toBe('/admin/login');
    await expect(app.login(erin.username, erin.password)).rejects.toThrow(/401/);
    expect((await get(await app.login(erin.username, fresh), '/admin')).headers.get('location')).toBe('/admin/security');

    // Deleted: gone, but what she did stays in the audit log under her id.
    await adminPost(app, admin, `/admin/users/${erin.id}/delete`);
    expect(getUser(app.ctx.db, erin.id)).toBeNull();
    await expect(app.login(erin.username, fresh)).rejects.toThrow(/401/);
    expect(listAudit(app.ctx.db, 50).some((r) => r.actor_id === erin.id)).toBe(true);
  });

  it('can remove a lost second factor', async () => {
    const admin = await app.adminLogin();
    const frank = app.mkUser('frank');
    app.ctx.db.prepare("UPDATE admins SET totp_secret = 'JBSWY3DPEHPK3PXP', totp_enabled_at = '2026-09-30T00:00:00.000Z' WHERE id = ?").run(frank.id);
    expect(getUser(app.ctx.db, frank.id)!.totp_enabled).toBe(true);
    const res = await adminPost(app, admin, `/admin/users/${frank.id}/totp`);
    expect(await res.text()).toContain('Two-factor authentication was removed from the account frank');
    expect(getUser(app.ctx.db, frank.id)!.totp_enabled).toBe(false);
  });

  it('never touch their own account, and never the last active administrator', async () => {
    const admin = await app.adminLogin();
    for (const action of ['role', 'disable', 'delete', 'password', 'totp']) {
      const res = await adminPost(app, admin, `/admin/users/${adminId()}/${action}`, { role: 'user' });
      expect(res.status, action).toBe(400);
      expect(await res.text(), action).toContain('You cannot change your own account here');
    }
    expect(findAdminByUsername(app.ctx.db, ADMIN_USER)!.role).toBe('admin');
    // Through the service, with another actor, the invariant still holds.
    const others = listUsers(app.ctx.db).filter((u) => u.role === 'admin' && u.id !== adminId() && !u.disabled_at);
    for (const u of others) setUserDisabled(app.ctx.db, adminId(), u.id, true);
    expect(() => setUserRole(app.ctx.db, 'a_someoneelse0000', adminId(), 'user')).toThrow(UserError);
    expect(() => setUserDisabled(app.ctx.db, 'a_someoneelse0000', adminId(), true)).toThrow(/users.last_admin/);
  });

  it('show the account name in the audit log', async () => {
    const admin = await app.adminLogin();
    const page = await (await get(admin, '/admin/audit')).text();
    expect(page).toContain(`${ADMIN_USER}<br><span class="muted">${adminId()}</span>`);
  });
});

describe('upgrading', () => {
  it('keeps every existing account an administrator', () => {
    const db = openDatabase(':memory:');
    db.exec('CREATE TABLE schema_migrations (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)');
    const dir = new URL('../migrations/', import.meta.url);
    for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.sql')).sort()) {
      if (f.includes('users')) break;
      db.exec(fs.readFileSync(new URL(f, dir), 'utf8'));
      db.prepare('INSERT INTO schema_migrations VALUES (?, ?)').run(f, 't');
    }
    db.prepare("INSERT INTO admins (id, username, password_hash, created_at) VALUES ('a_before000000000', 'old-admin', 'x', 't')").run();
    expect(migrate(db).some((f) => f.includes('users'))).toBe(true);
    expect(db.prepare('SELECT role, disabled_at, must_change_password FROM admins').get()).toEqual({ role: 'admin', disabled_at: null, must_change_password: 0 });
    db.close();
  });
});
