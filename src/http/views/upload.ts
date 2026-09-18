import { formatSize } from '../../config.js';
import type { Config } from '../../config.js';
import { clientMessages, translator, type Lang } from '../../i18n.js';
import type { Case } from '../../services/cases.js';
import type { EffectiveLimits, Link, LinkUsage } from '../../services/links.js';
import { html, jsonScript, layout, raw } from '../html.js';
import { fmtDate } from './admin.js';

export interface UploadPageData {
  lang: Lang;
  cfg: Config;
  case: Case;
  link: Link;
  limits: EffectiveLimits;
  usage: LinkUsage;
  token: string;
  path: string;
}

/** Wraps a value in single quotes for POSIX shells (safe for any characters). */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function uploadPage(d: UploadPageData): string {
  const t = translator(d.lang);
  const apiBase = `${d.cfg.publicUrl}/api`;
  const authHeader = `Authorization: Bearer ${d.token}`;
  const p1 = t('upload.path_placeholder');
  const curlSingle = `curl --fail-with-body -H ${shellQuote(authHeader)} -T ${shellQuote(p1)} ${shellQuote(`${apiBase}/upload/`)}`;
  const curlMulti = `for f in ${shellQuote(t('upload.path_placeholder2'))} ${shellQuote(t('upload.path_placeholder3'))}; do\n  curl --fail-with-body -H ${shellQuote(authHeader)} -T "$f" ${shellQuote(`${apiBase}/upload/`)}; echo\ndone`;
  const curlEnv = ` export INLETBOX_TOKEN=${shellQuote(d.token)}\ncurl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" -T ${shellQuote(p1)} ${shellQuote(`${apiBase}/upload/`)}`;
  const curlList = `curl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" ${shellQuote(`${apiBase}/files`)}`;
  const resumable = `INLETBOX_TOKEN="$INLETBOX_TOKEN" ./inletbox-upload.sh ${shellQuote(apiBase)} ${shellQuote(t('upload.path_placeholder_big'))}`;

  const clientConfig = {
    tusEndpoint: `${apiBase}/tus`,
    filesEndpoint: `${apiBase}/files`,
    linkEndpoint: `${apiBase}/link`,
    chunkSize: d.cfg.uploadChunkBytes,
    maxFileBytes: d.limits.maxFileBytes,
    maxFiles: d.limits.maxFiles,
    maxTotalBytes: d.limits.maxTotalBytes,
    lang: d.lang,
    i18n: clientMessages(d.lang),
  };

  const snippet = (title: string | ReturnType<typeof html>, code: string) => html`<div class="snippet"><div class="snippet-head">${title} <button class="btn btn-small" type="button" data-copy>${t('common.copy')}</button></div><pre data-copy-source>${code}</pre></div>`;

  return layout({
    lang: d.lang, title: t('upload.title', { case: d.case.name }), path: d.path,
    scripts: ['/static/vendor/tus.min.js', '/static/upload.js'],
    body: html`
      ${jsonScript('inletbox-config', clientConfig)}
      <section class="card">
        <h1>${d.case.name}</h1>
        ${d.case.description ? html`<p>${d.case.description}</p>` : ''}
        <p class="muted">${t('upload.link_for')} <strong>${d.link.label}</strong>${d.link.expires_at ? html` · ${t('upload.valid_until', { date: fmtDate(d.link.expires_at, d.lang) })}` : ''}</p>
        <ul class="limits small">
          <li>${t('upload.limit.file')} <strong>${formatSize(d.limits.maxFileBytes)}</strong></li>
          ${d.limits.maxFiles != null ? html`<li>${t('upload.limit.files')} <strong>${d.limits.maxFiles}</strong> ${t('upload.used_n', { n: d.usage.file_count })}</li>` : ''}
          ${d.limits.maxTotalBytes != null ? html`<li>${t('upload.limit.total')} <strong>${formatSize(d.limits.maxTotalBytes)}</strong> ${t('upload.used_size', { size: formatSize(d.usage.used_bytes) })}</li>` : ''}
        </ul>
      </section>

      <section class="card">
        <h2>${t('upload.send')}</h2>
        <div id="dropzone" class="dropzone" tabindex="0">
          <p><strong>${t('upload.drop_here')}</strong> ${t('upload.or')} <label class="link" for="file-input">${t('upload.choose')}</label>.</p>
          <input id="file-input" type="file" multiple hidden>
          <p class="muted small">${t('upload.resume_hint')}</p>
        </div>
        <ul id="queue" class="queue"></ul>
      </section>

      <section class="card">
        <h2>${t('upload.your_files')}</h2>
        <p class="muted small">${t('upload.your_files_intro')}</p>
        <table id="files-table"><thead><tr><th>${t('upload.col.name')}</th><th>${t('upload.col.size')}</th><th>${t('upload.col.date')}</th><th>${t('upload.col.status')}</th></tr></thead><tbody><tr><td colspan="4" class="muted">${t('common.loading')}</td></tr></tbody></table>
      </section>

      <section class="card">
        <h2>${t('upload.terminal')}</h2>
        <p class="small">${raw(t('upload.terminal_intro', { path: `<code>${p1}</code>` }))}</p>
        ${snippet(t('upload.snippet.single'), curlSingle)}
        ${snippet(t('upload.snippet.multi'), curlMulti)}
        ${snippet(t('upload.snippet.env'), curlEnv)}
        ${snippet(t('upload.snippet.list'), curlList)}
        ${snippet(raw(t('upload.snippet.resumable', { script: '<a href="/static/inletbox-upload.sh" download>inletbox-upload.sh</a>' })), resumable)}
        <p class="warning small">${raw(t('upload.history_warning', { file: '<code>~/.bash_history</code>', opt: '<code>HISTCONTROL=ignorespace</code>' }))}</p>
      </section>`,
  });
}

export function linkUnavailablePage(lang: Lang, title: string, message: string): string {
  const t = translator(lang);
  return layout({ lang, title, path: '/', body: html`<section class="card narrow"><h1>${title}</h1><p>${message}</p><p class="muted small">${t('link.contact')}</p></section>` });
}
