/* inletbox upload page. No external scripts: tus-js-client is served from this instance. */
(function () {
  'use strict';

  var cfg = JSON.parse(document.getElementById('inletbox-config').textContent);
  var token = decodeURIComponent(location.pathname.split('/').filter(Boolean).pop() || '');
  var authHeaders = { Authorization: 'Bearer ' + token };

  var dropzone = document.getElementById('dropzone');
  var input = document.getElementById('file-input');
  var queue = document.getElementById('queue');
  var filesBody = document.querySelector('#files-table tbody');

  function fmtSize(b) {
    if (b == null) return '—';
    if (b < 1024) return b + ' B';
    var u = ['KB', 'MB', 'GB', 'TB'], v = b / 1024, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)) + ' ' + u[i];
  }
  function fmtDate(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    return d.toLocaleString();
  }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // ---- own files list -----------------------------------------------------
  function refreshFiles() {
    fetch(cfg.filesEndpoint, { headers: authHeaders, cache: 'no-store' })
      .then(function (r) { return r.ok ? r.json() : r.json().then(function (j) { throw new Error(j.message || r.status); }); })
      .then(function (data) {
        filesBody.textContent = '';
        if (!data.files.length) {
          var tr = el('tr'); var td = el('td', 'muted', 'Brak przesłanych plików.'); td.colSpan = 4; tr.appendChild(td); filesBody.appendChild(tr);
          return;
        }
        data.files.forEach(function (f) {
          var tr = el('tr');
          var tdName = el('td', 'filename', f.name); tdName.setAttribute('data-label', 'Nazwa');
          var tdSize = el('td', null, fmtSize(f.size)); tdSize.setAttribute('data-label', 'Rozmiar');
          var tdDate = el('td', null, fmtDate(f.completed_at || f.created_at)); tdDate.setAttribute('data-label', 'Data');
          var tdStatus = el('td'); tdStatus.setAttribute('data-label', 'Status');
          tdStatus.appendChild(el('span', 'badge badge-' + f.status, f.status === 'complete' ? 'ukończony' : 'w trakcie'));
          tr.appendChild(tdName); tr.appendChild(tdSize); tr.appendChild(tdDate); tr.appendChild(tdStatus);
          filesBody.appendChild(tr);
        });
      })
      .catch(function (err) {
        filesBody.textContent = '';
        var tr = el('tr'); var td = el('td', 'muted', 'Nie udało się pobrać listy: ' + err.message); td.colSpan = 4; tr.appendChild(td); filesBody.appendChild(tr);
      });
  }

  // ---- upload queue -------------------------------------------------------
  function parseError(err) {
    // tus-js-client wraps HTTP errors; the server returns JSON {error, message}.
    var res = err && err.originalResponse;
    if (res) {
      try {
        var body = JSON.parse(res.getBody());
        if (body && body.message) return body.message + ' (HTTP ' + res.getStatus() + ')';
      } catch (e) { /* not JSON */ }
      return 'HTTP ' + res.getStatus();
    }
    return (err && err.message) || String(err);
  }

  function enqueue(file) {
    var li = el('li');
    var head = el('div', 'q-head');
    var name = el('span', 'q-name', file.name);
    var status = el('span', 'q-status', 'w kolejce…');
    head.appendChild(name); head.appendChild(status);
    var bar = document.createElement('progress'); bar.max = 100; bar.value = 0;
    var actions = el('div', 'q-actions');
    var cancelBtn = el('button', 'btn btn-small', 'Anuluj'); cancelBtn.type = 'button';
    var retryBtn = el('button', 'btn btn-small', 'Ponów'); retryBtn.type = 'button'; retryBtn.hidden = true;
    actions.appendChild(cancelBtn); actions.appendChild(retryBtn);
    li.appendChild(head); li.appendChild(bar); li.appendChild(actions);
    queue.insertBefore(li, queue.firstChild);

    var sizeNote = ' (' + fmtSize(file.size) + ')';
    if (file.size > cfg.maxFileBytes) {
      status.textContent = 'za duży: limit ' + fmtSize(cfg.maxFileBytes) + sizeNote;
      status.className = 'q-status error'; cancelBtn.hidden = true; bar.remove();
      return;
    }

    var upload = new tus.Upload(file, {
      endpoint: cfg.tusEndpoint,
      headers: authHeaders,
      chunkSize: cfg.chunkSize,
      retryDelays: [0, 1000, 3000, 5000, 10000, 20000],
      storeFingerprintForResuming: true,
      removeFingerprintOnSuccess: true,
      metadata: { filename: file.name, filetype: file.type || 'application/octet-stream' },
      onShouldRetry: function (err, retryAttempt, options) {
        var st = err.originalResponse ? err.originalResponse.getStatus() : 0;
        // 4xx are final (limits, revoked link, conflict); network errors / 5xx are retried.
        return !(st >= 400 && st < 500);
      },
      onError: function (err) {
        status.textContent = 'błąd: ' + parseError(err);
        status.className = 'q-status error';
        retryBtn.hidden = false; cancelBtn.hidden = true;
        refreshFiles();
      },
      onProgress: function (sent, total) {
        var pct = total ? Math.floor(sent * 100 / total) : 0;
        bar.value = pct;
        status.textContent = pct + '% · ' + fmtSize(sent) + ' / ' + fmtSize(total);
        status.className = 'q-status';
      },
      onSuccess: function () {
        bar.value = 100;
        status.textContent = 'ukończony' + sizeNote;
        status.className = 'q-status done';
        cancelBtn.hidden = true; retryBtn.hidden = true;
        refreshFiles();
      },
    });

    cancelBtn.addEventListener('click', function () {
      upload.abort(true).then(function () {
        status.textContent = 'anulowano'; status.className = 'q-status error'; cancelBtn.hidden = true; refreshFiles();
      }).catch(function () { status.textContent = 'anulowano (lokalnie)'; status.className = 'q-status error'; cancelBtn.hidden = true; });
    });
    retryBtn.addEventListener('click', function () {
      retryBtn.hidden = true; cancelBtn.hidden = false; status.className = 'q-status'; status.textContent = 'ponawianie…';
      startOrResume();
    });

    function startOrResume() {
      // Resume: tus-js-client remembers upload URLs per file fingerprint (name+size+mtime+endpoint) in localStorage.
      upload.findPreviousUploads().then(function (previous) {
        if (previous.length) {
          upload.resumeFromPreviousUpload(previous[0]);
          status.textContent = 'wznawianie poprzedniego uploadu…';
        } else {
          status.textContent = 'rozpoczynanie…';
        }
        upload.start();
      }).catch(function () { upload.start(); });
    }
    startOrResume();
  }

  function handleFiles(list) {
    Array.prototype.forEach.call(list, enqueue);
  }

  input.addEventListener('change', function () { handleFiles(input.files); input.value = ''; });
  ['dragenter', 'dragover'].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.add('dragover'); });
  });
  ['dragleave', 'drop'].forEach(function (ev) {
    dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.remove('dragover'); });
  });
  dropzone.addEventListener('drop', function (e) {
    if (e.dataTransfer && e.dataTransfer.files) handleFiles(e.dataTransfer.files);
  });
  dropzone.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } });
  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('drop', function (e) { e.preventDefault(); });

  // ---- copy buttons ---------------------------------------------------------
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var src = btn.closest('.snippet, .copy-row').querySelector('[data-copy-source]');
      var text = src.value != null && src.tagName === 'INPUT' ? src.value : src.textContent;
      navigator.clipboard.writeText(text).then(function () {
        var old = btn.textContent; btn.textContent = 'Skopiowano'; setTimeout(function () { btn.textContent = old; }, 1500);
      }).catch(function () { btn.textContent = 'Zaznacz i skopiuj ręcznie'; });
    });
  });

  refreshFiles();
})();
