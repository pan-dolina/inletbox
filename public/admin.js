/* inletbox admin panel: copy-to-clipboard and confirmation dialogs. */
(function () {
  'use strict';
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var src = btn.closest('.copy-row, .snippet').querySelector('[data-copy-source]');
      var text = src.tagName === 'INPUT' ? src.value : src.textContent;
      navigator.clipboard.writeText(text).then(function () {
        var old = btn.textContent; btn.textContent = 'Skopiowano'; setTimeout(function () { btn.textContent = old; }, 1500);
      }).catch(function () { src.select && src.select(); });
    });
  });
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.getAttribute('data-confirm'))) e.preventDefault();
    });
  });
})();
