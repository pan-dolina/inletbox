import { formatSize } from '../../config.js';
import type { Config } from '../../config.js';
import { translator, type Lang, type Translator } from '../../i18n.js';
import type { AuditRow } from '../../services/audit.js';
import type { Case, CaseSummary } from '../../services/cases.js';
import type { AdminFileView } from '../../services/files.js';
import type { Link, LinkUsage } from '../../services/links.js';
import { linkState } from '../../services/links.js';
import { html, layout, raw, type SafeHtml } from '../html.js';

export interface AdminViewContext { lang: Lang; csrfToken: string; username: string; path: string }

export function adminNav(v: AdminViewContext): SafeHtml {
  const t = translator(v.lang);
  return html`<nav class="nav">
    <a href="/admin">${t('nav.cases')}</a>
    <a href="/admin/audit">${t('nav.audit')}</a>
    <a href="/admin/security">${t('nav.security')}</a>
    <span class="muted">${v.username}</span>
    <form method="post" action="/admin/logout" class="inline"><input type="hidden" name="_csrf" value="${v.csrfToken}"><button class="btn btn-link" type="submit">${t('nav.logout')}</button></form>
  </nav>`;
}

export function fmtDate(iso: string | null | undefined, lang: Lang = 'en'): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString(lang === 'pl' ? 'pl-PL' : 'en-GB', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

function flash(msg?: string, kind: 'error' | 'ok' = 'error'): SafeHtml {
  return msg ? html`<div class="flash flash-${kind}">${msg}</div>` : html``;
}

/** Public root: no case/link context here, so there is nothing useful to show or redirect to. */
export function homePage(lang: Lang): string {
  const t = translator(lang);
  return layout({
    lang, title: t('home.title'), path: '/',
    body: html`<section class="card narrow"><h1>${t('home.title')}</h1><p>${t('home.message')}</p></section>`,
  });
}

export function loginPage(lang: Lang, opts: { error?: string }): string {
  const t = translator(lang);
  return layout({
    lang, title: t('login.title'), path: '/admin/login',
    body: html`<section class="card narrow">
      <h1>${t('login.title')}</h1>
      ${flash(opts.error)}
      <form method="post" action="/admin/login">
        <label>${t('login.username')} <input name="username" required autocomplete="username" autofocus></label>
        <label>${t('login.password')} <input name="password" type="password" required autocomplete="current-password"></label>
        <button class="btn btn-primary" type="submit">${t('login.submit')}</button>
      </form>
    </section>`,
  });
}

export function casesPage(v: AdminViewContext, cases: CaseSummary[], opts: { error?: string } = {}): string {
  const t = translator(v.lang);
  return layout({
    lang: v.lang, title: t('nav.cases'), nav: adminNav(v), path: v.path,
    body: html`
      <section class="card">
        <h1>${t('cases.new')}</h1>
        ${flash(opts.error)}
        <form method="post" action="/admin/cases" class="row">
          <input type="hidden" name="_csrf" value="${v.csrfToken}">
          <label class="grow">${t('cases.name')} <input name="name" required maxlength="200" placeholder="${t('cases.name_placeholder')}"></label>
          <label class="grow">${t('cases.description_optional')} <input name="description" maxlength="5000"></label>
          <button class="btn btn-primary" type="submit">${t('common.create')}</button>
        </form>
      </section>
      <section class="card">
        <h1>${t('cases.list')}</h1>
        ${cases.length === 0 ? html`<p class="muted">${t('cases.empty')}</p>` : html`
        <table>
          <thead><tr><th>${t('cases.col.name')}</th><th>${t('cases.col.status')}</th><th>${t('cases.col.links')}</th><th>${t('cases.col.files')}</th><th>${t('cases.col.size')}</th><th>${t('cases.col.created')}</th></tr></thead>
          <tbody>
          ${cases.map((c) => html`<tr>
            <td><a href="/admin/cases/${c.id}">${c.name}</a></td>
            <td><span class="badge badge-${c.status}">${t(c.status === 'open' ? 'case.open' : 'case.closed')}</span></td>
            <td>${c.link_count}</td><td>${c.file_count}</td><td>${formatSize(c.total_bytes)}</td><td>${fmtDate(c.created_at, v.lang)}</td>
          </tr>`)}
          </tbody>
        </table>`}
      </section>`,
  });
}

export interface CasePageData {
  case: Case;
  links: Array<Link & LinkUsage>;
  files: AdminFileView[];
  cfg: Config;
  newLink?: { label: string; url: string };
  error?: string;
  ok?: string;
}

function fileStatus(t: Translator, status: string): string {
  const key = `files.status.${status}` as Parameters<Translator>[0];
  return t(key) === key ? status : t(key);
}

export function casePage(v: AdminViewContext, d: CasePageData): string {
  const t = translator(v.lang);
  const c = d.case;
  const csrf = html`<input type="hidden" name="_csrf" value="${v.csrfToken}">`;
  return layout({
    lang: v.lang, title: c.name, nav: adminNav(v), path: v.path,
    scripts: ['/static/admin.js'],
    body: html`
      <p><a href="/admin">${t('common.back_to_cases')}</a></p>
      <section class="card">
        <div class="row space-between">
          <h1>${c.name} <span class="badge badge-${c.status}">${t(c.status === 'open' ? 'case.open' : 'case.closed')}</span></h1>
          <form method="post" action="/admin/cases/${c.id}/status" class="inline">${csrf}
            <input type="hidden" name="status" value="${c.status === 'open' ? 'closed' : 'open'}">
            <button class="btn" type="submit">${t(c.status === 'open' ? 'case.close' : 'case.reopen')}</button>
          </form>
        </div>
        ${flash(d.error)}${flash(d.ok, 'ok')}
        <form method="post" action="/admin/cases/${c.id}" class="row">${csrf}
          <label class="grow">${t('cases.name')} <input name="name" value="${c.name}" required maxlength="200"></label>
          <label class="grow">${t('cases.description')} <input name="description" value="${c.description}" maxlength="5000"></label>
          <button class="btn" type="submit">${t('common.save')}</button>
        </form>
        <p class="muted small">${t('case.meta', { id: c.id, date: fmtDate(c.created_at, v.lang) })}</p>
      </section>

      ${d.newLink ? html`<section class="card highlight">
        <h2>${t('case.new_link.title', { label: d.newLink.label })}</h2>
        <p><strong>${t('case.new_link.copy_now')}</strong> ${t('case.new_link.intro')}</p>
        <div class="copy-row"><input class="mono" readonly value="${d.newLink.url}" data-copy-source><button class="btn" type="button" data-copy>${t('common.copy')}</button></div>
      </section>` : ''}

      <section class="card">
        <h2>${t('links.title')}</h2>
        <p class="muted small">${t('links.intro')}</p>
        <details ${c.status === 'open' ? 'open' : ''}>
          <summary>${t('links.generate')}</summary>
          <form method="post" action="/admin/cases/${c.id}/links" class="grid">${csrf}
            <label>${t('links.label')} <input name="label" required maxlength="200" placeholder="${t('links.label_placeholder')}"></label>
            <label>${t('links.expires')} <input name="expires_at" type="datetime-local"></label>
            <label>${t('links.max_file', { max: formatSize(d.cfg.maxFileBytes) })} <input name="max_file_size" placeholder="${t('links.max_file_placeholder')}"></label>
            <label>${t('links.max_files')} <input name="max_files" type="number" min="1" step="1"></label>
            <label>${t('links.max_total')} <input name="max_total_size" placeholder="${t('links.max_total_placeholder')}"></label>
            <div><button class="btn btn-primary" type="submit" ${c.status !== 'open' ? 'disabled' : ''}>${t('links.submit')}</button></div>
          </form>
        </details>
        ${d.links.length === 0 ? html`<p class="muted">${t('links.empty')}</p>` : html`
        <table>
          <thead><tr><th>${t('links.col.recipient')}</th><th>${t('links.col.state')}</th><th>${t('links.col.expires')}</th><th>${t('links.col.limits')}</th><th>${t('links.col.usage')}</th><th>${t('links.col.last_used')}</th><th></th></tr></thead>
          <tbody>${d.links.map((l) => {
            const state = linkState(l, c);
            return html`<tr>
              <td>${l.label}<br><span class="muted small mono">${l.token_hint}…</span></td>
              <td><span class="badge badge-${state}">${t(`links.state.${state}`)}</span></td>
              <td>${l.expires_at ? fmtDate(l.expires_at, v.lang) : t('common.unlimited')}</td>
              <td class="small">${t('links.limit.file', { max: formatSize(Math.min(d.cfg.maxFileBytes, l.max_file_bytes ?? d.cfg.maxFileBytes)) })}<br>
                ${l.max_files != null ? html`${t('links.limit.files', { n: l.max_files })}<br>` : ''}
                ${l.max_total_bytes != null ? t('links.limit.total', { max: formatSize(l.max_total_bytes) }) : ''}</td>
              <td class="small">${t('links.usage', { n: l.file_count, size: formatSize(l.used_bytes) })}${l.uploading_count > 0 ? html`<br>${t('links.usage_in_progress', { n: l.uploading_count, size: formatSize(l.reserved_bytes) })}` : ''}</td>
              <td>${fmtDate(l.last_used_at, v.lang)}</td>
              <td>${l.revoked_at ? '' : html`<form method="post" action="/admin/links/${l.id}/revoke" class="inline" data-confirm="${t('links.revoke_confirm', { label: l.label })}">${csrf}<button class="btn btn-danger" type="submit">${t('links.revoke')}</button></form>`}</td>
            </tr>`;
          })}</tbody>
        </table>`}
      </section>

      <section class="card">
        <h2>${t('files.title')}</h2>
        ${d.files.length === 0 ? html`<p class="muted">${t('files.empty')}</p>` : html`
        <table>
          <thead><tr><th>${t('files.col.name')}</th><th>${t('files.col.recipient')}</th><th>${t('files.col.size')}</th><th>${t('files.col.status')}</th><th>${t('files.col.uploaded')}</th><th>SHA-256</th><th></th></tr></thead>
          <tbody>${d.files.map((f) => html`<tr>
            <td class="filename">${f.original_name}</td>
            <td>${f.link_label}</td>
            <td>${f.size != null ? formatSize(f.size) : f.declared_size != null ? html`<span class="muted">${t('files.declared', { size: formatSize(f.declared_size) })}</span>` : '—'}</td>
            <td><span class="badge badge-${f.status}">${fileStatus(t, f.status)}</span></td>
            <td>${fmtDate(f.completed_at ?? f.created_at, v.lang)}</td>
            <td class="mono small">${f.sha256 ? f.sha256.slice(0, 12) + '…' : '—'}</td>
            <td class="nowrap">
              ${f.status === 'complete' ? html`<a class="btn" href="/admin/files/${f.id}/download">${t('files.download')}</a> ` : ''}
              ${['complete', 'missing'].includes(f.status) ? html`<form method="post" action="/admin/files/${f.id}/delete" class="inline" data-confirm="${t('files.delete_confirm', { name: f.original_name })}">${csrf}<button class="btn btn-danger" type="submit">${t('files.delete')}</button></form>` : ''}
            </td>
          </tr>`)}</tbody>
        </table>`}
        <p class="muted small">${t('files.untrusted')}</p>
      </section>`,
  });
}

export function auditPage(v: AdminViewContext, rows: AuditRow[]): string {
  const t = translator(v.lang);
  return layout({
    lang: v.lang, title: t('nav.audit'), nav: adminNav(v), path: v.path,
    body: html`<section class="card">
      <h1>${t('audit.title', { n: rows.length })}</h1>
      <table class="small">
        <thead><tr><th>${t('audit.col.time')}</th><th>${t('audit.col.actor')}</th><th>${t('audit.col.action')}</th><th>${t('audit.col.case')}</th><th>${t('audit.col.link')}</th><th>${t('audit.col.file')}</th><th>${t('audit.col.ip')}</th><th>${t('audit.col.details')}</th></tr></thead>
        <tbody>${rows.map((r) => html`<tr>
          <td class="nowrap">${fmtDate(r.ts, v.lang)}</td><td>${r.actor_type}:${r.actor_id ?? '-'}</td><td>${r.action}</td>
          <td class="mono">${r.case_id ? html`<a href="/admin/cases/${r.case_id}">${r.case_id}</a>` : ''}</td>
          <td class="mono">${r.link_id ?? ''}</td><td class="mono">${r.file_id ?? ''}</td><td>${r.ip ?? ''}</td>
          <td class="mono">${r.details ?? ''}</td>
        </tr>`)}</tbody>
      </table>
    </section>`,
  });
}

export function errorPage(lang: Lang, title: string, message: string, status = 404, path = '/', homeHref = '/'): { status: number; body: string } {
  const t = translator(lang);
  return { status, body: layout({ lang, title, path, body: html`<section class="card narrow"><h1>${title}</h1><p>${message}</p><p><a href="${homeHref}">${t('common.home')}</a></p></section>` }) };
}

export { raw };
