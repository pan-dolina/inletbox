/**
 * Minimal i18n: one dictionary per language in src/locales/ with identical keys,
 * `{param}` placeholders, language detected per request from a cookie or
 * Accept-Language (default: en).
 *
 * The languages are the 24 official languages of the European Union. English is the
 * source; every other dictionary is typed as `Messages`, so a missing key is a compile
 * error, and test/i18n.test.ts checks that each translation keeps the placeholders.
 */
import { bg } from './locales/bg.js';
import { cs } from './locales/cs.js';
import { da } from './locales/da.js';
import { de } from './locales/de.js';
import { el } from './locales/el.js';
import { en } from './locales/en.js';
import { es } from './locales/es.js';
import { et } from './locales/et.js';
import { fi } from './locales/fi.js';
import { fr } from './locales/fr.js';
import { ga } from './locales/ga.js';
import { hr } from './locales/hr.js';
import { hu } from './locales/hu.js';
import { it } from './locales/it.js';
import { lt } from './locales/lt.js';
import { lv } from './locales/lv.js';
import { mt } from './locales/mt.js';
import { nl } from './locales/nl.js';
import { pl } from './locales/pl.js';
import { pt } from './locales/pt.js';
import { ro } from './locales/ro.js';
import { sk } from './locales/sk.js';
import { sl } from './locales/sl.js';
import { sv } from './locales/sv.js';

export type Lang =
  | 'bg' | 'cs' | 'da' | 'de' | 'el' | 'en' | 'es' | 'et' | 'fi' | 'fr' | 'ga' | 'hr'
  | 'hu' | 'it' | 'lt' | 'lv' | 'mt' | 'nl' | 'pl' | 'pt' | 'ro' | 'sk' | 'sl' | 'sv';
export const DEFAULT_LANG: Lang = 'en';
export const LANG_COOKIE = 'inletbox_lang';

export type MessageKey = keyof typeof en;
export type Messages = Record<MessageKey, string>;

const DICT: Record<Lang, Messages> = {
  bg, cs, da, de, el, en, es, et, fi, fr, ga, hr, hu, it, lt, lv, mt, nl, pl, pt, ro, sk, sl, sv,
};
export const LANGS = Object.keys(DICT) as Lang[];

/** Each language's name in itself, for the switcher: a reader looks for the word they can read. */
export const LANG_NAMES: Record<Lang, string> = {
  bg: 'Български', cs: 'Čeština', da: 'Dansk', de: 'Deutsch', el: 'Ελληνικά', en: 'English',
  es: 'Español', et: 'Eesti', fi: 'Suomi', fr: 'Français', ga: 'Gaeilge', hr: 'Hrvatski',
  hu: 'Magyar', it: 'Italiano', lt: 'Lietuvių', lv: 'Latviešu', mt: 'Malti', nl: 'Nederlands',
  pl: 'Polski', pt: 'Português', ro: 'Română', sk: 'Slovenčina', sl: 'Slovenščina', sv: 'Svenska',
};

/** The locale dates are formatted in. Plain `en` would mean US month/day order, so English uses en-GB. */
export function dateLocale(lang: Lang): string {
  return lang === 'en' ? 'en-GB' : lang;
}

export type Params = Record<string, string | number>;

/** Translates `key` for `lang`, replacing `{name}` placeholders. Unknown languages fall back to English. */
export function t(lang: Lang, key: MessageKey, params?: Params): string {
  const msg = DICT[lang]?.[key] ?? en[key] ?? key;
  if (!params) return msg;
  return msg.replace(/\{(\w+)\}/g, (_m, name: string) => (name in params ? String(params[name]) : `{${name}}`));
}

/** A translator bound to one language; convenient inside views. */
export type Translator = (key: MessageKey, params?: Params) => string;
export function translator(lang: Lang): Translator {
  return (key, params) => t(lang, key, params);
}

export function isLang(v: unknown): v is Lang {
  return typeof v === 'string' && Object.hasOwn(DICT, v);
}

/**
 * Picks the UI language from Accept-Language: the browser's top-ranked language when we
 * have it, English otherwise. Lower-ranked entries are deliberately ignored — someone
 * whose first language is Japanese and who lists German fourth is still more likely to
 * read English than German. Regions collapse onto the language (de-AT → de, pt-BR → pt).
 */
export function negotiateLang(acceptLanguage: string | undefined): Lang {
  if (!acceptLanguage) return DEFAULT_LANG;
  const ranked = acceptLanguage
    .split(',')
    .map((part, index) => {
      const [tag, ...params] = part.trim().split(';');
      const q = params.map((p) => /^\s*q=([0-9.]+)/.exec(p)).find(Boolean);
      return { tag: (tag ?? '').trim().toLowerCase(), q: q ? Number(q[1]) : 1, index };
    })
    .filter((e) => e.tag && e.q > 0)
    .sort((a, b) => b.q - a.q || a.index - b.index);
  const top = ranked[0]?.tag.split('-')[0];
  return isLang(top) ? top : DEFAULT_LANG;
}

/** Strings the browser-side upload script needs, already in the right language. */
export function clientMessages(lang: Lang): Record<string, string> {
  const keys: MessageKey[] = [
    'upload.js.queued', 'upload.js.too_large', 'upload.js.error', 'upload.js.starting', 'upload.js.resuming', 'upload.js.retrying',
    'upload.js.done', 'upload.js.finalising', 'upload.js.cancelled', 'upload.js.cancelled_local',
    'upload.js.status.uploading', 'upload.js.status.complete',
    'upload.none_yet', 'upload.list_failed', 'common.copied', 'common.copy_manual', 'common.cancel', 'common.retry',
  ];
  return Object.fromEntries(keys.map((k) => [k, t(lang, k)]));
}
