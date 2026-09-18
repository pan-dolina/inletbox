import { formatSize } from '../../config.js';
import type { Config } from '../../config.js';
import type { AuditRow } from '../../services/audit.js';
import type { Case, CaseSummary } from '../../services/cases.js';
import type { AdminFileView } from '../../services/files.js';
import type { Link, LinkUsage } from '../../services/links.js';
import { linkState } from '../../services/links.js';
import { html, layout, raw, type SafeHtml } from '../html.js';

export interface AdminViewContext { csrfToken: string; username: string }

export function adminNav(username: string, csrfToken: string): SafeHtml {
  return html`<nav class="nav">
    <a href="/admin">Sprawy</a>
    <a href="/admin/audit">Dziennik</a>
    <a href="/admin/security">Bezpieczeństwo</a>
    <span class="muted">${username}</span>
    <form method="post" action="/admin/logout" class="inline"><input type="hidden" name="_csrf" value="${csrfToken}"><button class="btn btn-link" type="submit">Wyloguj</button></form>
  </nav>`;
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleString('pl-PL', { dateStyle: 'short', timeStyle: 'short', timeZone: 'UTC' }) + ' UTC';
}

function flash(msg?: string, kind: 'error' | 'ok' = 'error'): SafeHtml {
  return msg ? html`<div class="flash flash-${kind}">${msg}</div>` : html``;
}

export function loginPage(opts: { error?: string }): string {
  return layout({
    title: 'Logowanie',
    body: html`<section class="card narrow">
      <h1>Logowanie administratora</h1>
      ${flash(opts.error)}
      <form method="post" action="/admin/login">
        <label>Nazwa użytkownika <input name="username" required autocomplete="username" autofocus></label>
        <label>Hasło <input name="password" type="password" required autocomplete="current-password"></label>
        <button class="btn btn-primary" type="submit">Zaloguj</button>
      </form>
    </section>`,
  });
}

export function casesPage(v: AdminViewContext, cases: CaseSummary[], opts: { error?: string } = {}): string {
  return layout({
    title: 'Sprawy',
    nav: adminNav(v.username, v.csrfToken),
    body: html`
      <section class="card">
        <h1>Nowa sprawa</h1>
        ${flash(opts.error)}
        <form method="post" action="/admin/cases" class="row">
          <input type="hidden" name="_csrf" value="${v.csrfToken}">
          <label class="grow">Nazwa <input name="name" required maxlength="200" placeholder="np. Audyt 2026/09 – Klient X"></label>
          <label class="grow">Opis (opcjonalnie) <input name="description" maxlength="5000"></label>
          <button class="btn btn-primary" type="submit">Utwórz</button>
        </form>
      </section>
      <section class="card">
        <h1>Sprawy</h1>
        ${cases.length === 0 ? html`<p class="muted">Brak spraw.</p>` : html`
        <table>
          <thead><tr><th>Nazwa</th><th>Status</th><th>Aktywne linki</th><th>Pliki</th><th>Rozmiar</th><th>Utworzono</th></tr></thead>
          <tbody>
          ${cases.map((c) => html`<tr>
            <td><a href="/admin/cases/${c.id}">${c.name}</a></td>
            <td><span class="badge badge-${c.status}">${c.status === 'open' ? 'otwarta' : 'zamknięta'}</span></td>
            <td>${c.link_count}</td><td>${c.file_count}</td><td>${formatSize(c.total_bytes)}</td><td>${fmtDate(c.created_at)}</td>
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

const FILE_STATUS_PL: Record<string, string> = {
  uploading: 'w trakcie', complete: 'ukończony', aborted: 'przerwany', expired: 'wygasły', missing: 'brak w storage', deleted: 'usunięty',
};

export function casePage(v: AdminViewContext, d: CasePageData): string {
  const c = d.case;
  const csrf = html`<input type="hidden" name="_csrf" value="${v.csrfToken}">`;
  return layout({
    title: c.name,
    nav: adminNav(v.username, v.csrfToken),
    scripts: ['/static/admin.js'],
    body: html`
      <p><a href="/admin">← Sprawy</a></p>
      <section class="card">
        <div class="row space-between">
          <h1>${c.name} <span class="badge badge-${c.status}">${c.status === 'open' ? 'otwarta' : 'zamknięta'}</span></h1>
          <form method="post" action="/admin/cases/${c.id}/status" class="inline">${csrf}
            <input type="hidden" name="status" value="${c.status === 'open' ? 'closed' : 'open'}">
            <button class="btn" type="submit">${c.status === 'open' ? 'Zamknij sprawę' : 'Otwórz ponownie'}</button>
          </form>
        </div>
        ${flash(d.error)}${flash(d.ok, 'ok')}
        <form method="post" action="/admin/cases/${c.id}" class="row">${csrf}
          <label class="grow">Nazwa <input name="name" value="${c.name}" required maxlength="200"></label>
          <label class="grow">Opis <input name="description" value="${c.description}" maxlength="5000"></label>
          <button class="btn" type="submit">Zapisz</button>
        </form>
        <p class="muted small">ID: ${c.id} · utworzono ${fmtDate(c.created_at)}. Zamknięta sprawa nie przyjmuje uploadów przez żaden ze swoich linków.</p>
      </section>

      ${d.newLink ? html`<section class="card highlight">
        <h2>Nowy link dla „${d.newLink.label}”</h2>
        <p><strong>Skopiuj go teraz.</strong> Token jest przechowywany wyłącznie jako skrót i nie da się go później odzyskać – można jedynie wygenerować nowy link.</p>
        <div class="copy-row"><input class="mono" readonly value="${d.newLink.url}" data-copy-source><button class="btn" type="button" data-copy>Kopiuj</button></div>
      </section>` : ''}

      <section class="card">
        <h2>Linki do uploadu</h2>
        <p class="muted small">Każdy link to osobny odbiorca i osobny zakres widoczności: osoba z linkiem widzi tylko pliki wysłane tym linkiem, nie może ich pobrać ani usunąć. Wszyscy, którzy znają ten sam link, mają identyczny dostęp – aplikacja nie rozróżnia osób posługujących się tym samym linkiem.</p>
        <details ${c.status === 'open' ? 'open' : ''}>
          <summary>Wygeneruj nowy link</summary>
          <form method="post" action="/admin/cases/${c.id}/links" class="grid">${csrf}
            <label>Etykieta odbiorcy <input name="label" required maxlength="200" placeholder="np. Jan Kowalski – księgowość"></label>
            <label>Ważny do (UTC, opcjonalnie) <input name="expires_at" type="datetime-local"></label>
            <label>Maks. rozmiar pliku (opcjonalnie, ≤ ${formatSize(d.cfg.maxFileBytes)}) <input name="max_file_size" placeholder="np. 500MB"></label>
            <label>Maks. liczba plików (opcjonalnie) <input name="max_files" type="number" min="1" step="1"></label>
            <label>Maks. łączny rozmiar (opcjonalnie) <input name="max_total_size" placeholder="np. 2GB"></label>
            <div><button class="btn btn-primary" type="submit" ${c.status !== 'open' ? 'disabled' : ''}>Wygeneruj link</button></div>
          </form>
        </details>
        ${d.links.length === 0 ? html`<p class="muted">Brak linków.</p>` : html`
        <table>
          <thead><tr><th>Odbiorca</th><th>Stan</th><th>Ważny do</th><th>Limity</th><th>Użycie</th><th>Ostatnio użyty</th><th></th></tr></thead>
          <tbody>${d.links.map((l) => {
            const state = linkState(l, c);
            const statePl = { active: 'aktywny', expired: 'wygasł', revoked: 'unieważniony', case_closed: 'sprawa zamknięta' }[state];
            return html`<tr>
              <td>${l.label}<br><span class="muted small mono">${l.token_hint}…</span></td>
              <td><span class="badge badge-${state}">${statePl}</span></td>
              <td>${l.expires_at ? fmtDate(l.expires_at) : 'bezterminowo'}</td>
              <td class="small">plik ≤ ${formatSize(Math.min(d.cfg.maxFileBytes, l.max_file_bytes ?? d.cfg.maxFileBytes))}<br>
                ${l.max_files != null ? html`pliki ≤ ${l.max_files}<br>` : ''}
                ${l.max_total_bytes != null ? html`łącznie ≤ ${formatSize(l.max_total_bytes)}` : ''}</td>
              <td class="small">${l.file_count} plików, ${formatSize(l.used_bytes)}${l.uploading_count > 0 ? html`<br>${l.uploading_count} w trakcie (${formatSize(l.reserved_bytes)} zarezerwowane)` : ''}</td>
              <td>${fmtDate(l.last_used_at)}</td>
              <td>${l.revoked_at ? '' : html`<form method="post" action="/admin/links/${l.id}/revoke" class="inline" data-confirm="Unieważnić link „${l.label}”? Trwające uploady zostaną przerwane.">${csrf}<button class="btn btn-danger" type="submit">Unieważnij</button></form>`}</td>
            </tr>`;
          })}</tbody>
        </table>`}
      </section>

      <section class="card">
        <h2>Pliki</h2>
        ${d.files.length === 0 ? html`<p class="muted">Brak plików.</p>` : html`
        <table>
          <thead><tr><th>Nazwa</th><th>Odbiorca (link)</th><th>Rozmiar</th><th>Status</th><th>Przesłano</th><th>SHA-256</th><th></th></tr></thead>
          <tbody>${d.files.map((f) => html`<tr>
            <td class="filename">${f.original_name}</td>
            <td>${f.link_label}</td>
            <td>${f.size != null ? formatSize(f.size) : f.declared_size != null ? html`<span class="muted">${formatSize(f.declared_size)} (deklarowany)</span>` : '—'}</td>
            <td><span class="badge badge-${f.status}">${FILE_STATUS_PL[f.status] ?? f.status}</span></td>
            <td>${fmtDate(f.completed_at ?? f.created_at)}</td>
            <td class="mono small">${f.sha256 ? f.sha256.slice(0, 12) + '…' : '—'}</td>
            <td class="nowrap">
              ${f.status === 'complete' ? html`<a class="btn" href="/admin/files/${f.id}/download">Pobierz</a> ` : ''}
              ${['complete', 'missing'].includes(f.status) ? html`<form method="post" action="/admin/files/${f.id}/delete" class="inline" data-confirm="Usunąć plik „${f.original_name}”? Tej operacji nie da się cofnąć.">${csrf}<button class="btn btn-danger" type="submit">Usuń</button></form>` : ''}
            </td>
          </tr>`)}</tbody>
        </table>`}
        <p class="muted small">Pliki są traktowane jako niezaufane: pobieranie odbywa się zawsze jako załącznik, nic nie jest renderowane ani wykonywane po stronie serwera. Skanowanie antywirusowe nie jest częścią tej wersji.</p>
      </section>`,
  });
}

export function auditPage(v: AdminViewContext, rows: AuditRow[]): string {
  return layout({
    title: 'Dziennik zdarzeń',
    nav: adminNav(v.username, v.csrfToken),
    body: html`<section class="card">
      <h1>Dziennik zdarzeń (ostatnie ${rows.length})</h1>
      <table class="small">
        <thead><tr><th>Czas</th><th>Aktor</th><th>Zdarzenie</th><th>Sprawa</th><th>Link</th><th>Plik</th><th>IP</th><th>Szczegóły</th></tr></thead>
        <tbody>${rows.map((r) => html`<tr>
          <td class="nowrap">${fmtDate(r.ts)}</td><td>${r.actor_type}:${r.actor_id ?? '-'}</td><td>${r.action}</td>
          <td class="mono">${r.case_id ? html`<a href="/admin/cases/${r.case_id}">${r.case_id}</a>` : ''}</td>
          <td class="mono">${r.link_id ?? ''}</td><td class="mono">${r.file_id ?? ''}</td><td>${r.ip ?? ''}</td>
          <td class="mono">${r.details ?? ''}</td>
        </tr>`)}</tbody>
      </table>
    </section>`,
  });
}

export function errorPage(title: string, message: string, status = 404): { status: number; body: string } {
  return { status, body: layout({ title, body: html`<section class="card narrow"><h1>${title}</h1><p>${message}</p><p><a href="/">Strona główna</a></p></section>` }) };
}

export { raw };
