// Shows every <time datetime> in the browser's own time zone. The server renders the same
// moment in UTC, which stays as the fallback without JavaScript and as the tooltip.
(function () {
  'use strict';
  var locale = document.body.getAttribute('data-date-locale') || undefined;

  function zoneName(d) {
    try {
      var parts = new Intl.DateTimeFormat(locale, { hour: 'numeric', timeZoneName: 'short' }).formatToParts(d);
      for (var i = 0; i < parts.length; i++) if (parts[i].type === 'timeZoneName') return parts[i].value;
    } catch (e) { /* no Intl support: leave the zone out */ }
    return '';
  }

  /** A timestamp as local date and time plus the zone, or null for something unparseable. */
  function format(iso) {
    var d = new Date(iso);
    if (isNaN(d.getTime())) return null;
    var text = d.toLocaleString(locale, { dateStyle: 'short', timeStyle: 'short' });
    var zone = zoneName(d);
    return zone ? text + ' ' + zone : text;
  }

  window.localTime = format;

  var times = document.querySelectorAll('time[datetime]');
  for (var i = 0; i < times.length; i++) {
    var local = format(times[i].getAttribute('datetime'));
    if (!local) continue;
    times[i].title = times[i].textContent;
    times[i].textContent = local;
  }
})();
