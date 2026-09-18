import { formatSize } from '../../config.js';
import type { Config } from '../../config.js';
import type { Case } from '../../services/cases.js';
import type { EffectiveLimits, Link, LinkUsage } from '../../services/links.js';
import { html, jsonScript, layout } from '../html.js';
import { fmtDate } from './admin.js';

export interface UploadPageData {
  cfg: Config;
  case: Case;
  link: Link;
  limits: EffectiveLimits;
  usage: LinkUsage;
  token: string;
}

/** Wraps a value in single quotes for POSIX shells (safe for any characters). */
export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function uploadPage(d: UploadPageData): string {
  const apiBase = `${d.cfg.publicUrl}/api`;
  const authHeader = `Authorization: Bearer ${d.token}`;
  const curlSingle = `curl --fail-with-body -H ${shellQuote(authHeader)} -T '/ścieżka/do/pliku.pdf' ${shellQuote(`${apiBase}/upload/`)}`;
  const curlMulti = `for f in '/ścieżka/raport.pdf' '/ścieżka/zdjęcie 1.jpg'; do\n  curl --fail-with-body -H ${shellQuote(authHeader)} -T "$f" ${shellQuote(`${apiBase}/upload/`)}; echo\ndone`;
  const curlEnv = ` export INLETBOX_TOKEN=${shellQuote(d.token)}\ncurl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" -T '/ścieżka/do/pliku.pdf' ${shellQuote(`${apiBase}/upload/`)}`;
  const curlList = `curl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" ${shellQuote(`${apiBase}/files`)}`;
  const resumable = `INLETBOX_TOKEN="$INLETBOX_TOKEN" ./inletbox-upload.sh ${shellQuote(apiBase)} '/ścieżka/do/dużego pliku.iso'`;

  const clientConfig = {
    tusEndpoint: `${apiBase}/tus`,
    filesEndpoint: `${apiBase}/files`,
    linkEndpoint: `${apiBase}/link`,
    chunkSize: d.cfg.uploadChunkBytes,
    maxFileBytes: d.limits.maxFileBytes,
    maxFiles: d.limits.maxFiles,
    maxTotalBytes: d.limits.maxTotalBytes,
  };

  return layout({
    title: `Upload: ${d.case.name}`,
    scripts: ['/static/vendor/tus.min.js', '/static/upload.js'],
    body: html`
      ${jsonScript('inletbox-config', clientConfig)}
      <section class="card">
        <h1>${d.case.name}</h1>
        ${d.case.description ? html`<p>${d.case.description}</p>` : ''}
        <p class="muted">Link dla: <strong>${d.link.label}</strong>${d.link.expires_at ? html` · ważny do ${fmtDate(d.link.expires_at)}` : ''}</p>
        <ul class="limits small">
          <li>Maksymalny rozmiar pliku: <strong>${formatSize(d.limits.maxFileBytes)}</strong></li>
          ${d.limits.maxFiles != null ? html`<li>Maksymalna liczba plików: <strong>${d.limits.maxFiles}</strong> (użyto ${d.usage.file_count})</li>` : ''}
          ${d.limits.maxTotalBytes != null ? html`<li>Łączny limit danych: <strong>${formatSize(d.limits.maxTotalBytes)}</strong> (użyto ${formatSize(d.usage.used_bytes)})</li>` : ''}
        </ul>
      </section>

      <section class="card">
        <h2>Prześlij pliki</h2>
        <div id="dropzone" class="dropzone" tabindex="0">
          <p><strong>Przeciągnij pliki tutaj</strong> albo <label class="link" for="file-input">wybierz z dysku</label>.</p>
          <input id="file-input" type="file" multiple hidden>
          <p class="muted small">Duże pliki są przesyłane w częściach i można je wznowić po utracie połączenia. Po odświeżeniu strony wskaż ten sam plik ponownie, a upload zostanie wznowiony od miejsca przerwania.</p>
        </div>
        <ul id="queue" class="queue"></ul>
      </section>

      <section class="card">
        <h2>Twoje pliki</h2>
        <p class="muted small">Widzisz wyłącznie pliki przesłane tym linkiem. Pliki nie mogą być pobrane ani usunięte z tego miejsca – odbiera je administrator.</p>
        <table id="files-table"><thead><tr><th>Nazwa</th><th>Rozmiar</th><th>Data</th><th>Status</th></tr></thead><tbody><tr><td colspan="4" class="muted">Ładowanie…</td></tr></tbody></table>
      </section>

      <section class="card">
        <h2>Upload z terminala</h2>
        <p class="small">Zastąp <code>/ścieżka/do/pliku.pdf</code> ścieżką do swojego pliku (może zawierać spacje). Kod wyjścia różny od zera oznacza błąd; odpowiedź to JSON.</p>
        <div class="snippet"><div class="snippet-head">Jeden plik <button class="btn btn-small" type="button" data-copy>Kopiuj</button></div><pre data-copy-source>${curlSingle}</pre></div>
        <div class="snippet"><div class="snippet-head">Kilka plików <button class="btn btn-small" type="button" data-copy>Kopiuj</button></div><pre data-copy-source>${curlMulti}</pre></div>
        <div class="snippet"><div class="snippet-head">Token w zmiennej środowiskowej (zalecane) <button class="btn btn-small" type="button" data-copy>Kopiuj</button></div><pre data-copy-source>${curlEnv}</pre></div>
        <div class="snippet"><div class="snippet-head">Lista przesłanych plików <button class="btn btn-small" type="button" data-copy>Kopiuj</button></div><pre data-copy-source>${curlList}</pre></div>
        <div class="snippet"><div class="snippet-head">Duży plik z wznawianiem (skrypt <a href="/static/inletbox-upload.sh" download>inletbox-upload.sh</a>) <button class="btn btn-small" type="button" data-copy>Kopiuj</button></div><pre data-copy-source>${resumable}</pre></div>
        <p class="warning small">Uwaga: polecenie zawierające token trafia do historii powłoki (np. <code>~/.bash_history</code>). Wariant z <code>export</code> poprzedzony spacją nie jest zapisywany w historii, gdy ustawione jest <code>HISTCONTROL=ignorespace</code>. Traktuj ten link jak hasło i nie przekazuj go dalej.</p>
      </section>`,
  });
}

export function linkUnavailablePage(title: string, message: string): string {
  return layout({ title, body: html`<section class="card narrow"><h1>${title}</h1><p>${message}</p><p class="muted small">Skontaktuj się z osobą, która przekazała Ci link.</p></section>` });
}
