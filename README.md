# inletbox

Prywatna, self‑hosted **skrzynka wrzutowa na pliki**. Administrator zakłada sprawę,
generuje link, przekazuje go klientowi. Klient wrzuca pliki z przeglądarki lub przez
`curl`, widzi wyłącznie listę plików przesłanych **swoim** linkiem i **nie może ich
pobrać**. Pliki odbiera administrator.

To nie jest dysk sieciowy ani narzędzie do współdzielenia: brak podglądu, brak
publicznego pobierania, brak rejestracji.

- **Stack:** Node.js 24+ (TypeScript, Express 5), SQLite (`node:sqlite`, wbudowane),
  storage lokalny lub S3/MinIO, wznawianie uploadów przez protokół **tus**
  (`@tus/server` + `tus-js-client`). Zero natywnych modułów.
- **Uruchomienie:** jeden kontener + wolumen; opcjonalnie MinIO do testów S3.

---

## Spis treści

1. [Szybki start](#1-szybki-start)
2. [Model uprawnień](#2-model-uprawnień)
3. [Konfiguracja](#3-konfiguracja)
4. [Upload z terminala (curl)](#4-upload-z-terminala-curl)
5. [Wznawianie uploadów](#5-wznawianie-uploadów)
6. [Limity i rezerwacje](#6-limity-i-rezerwacje)
7. [Storage](#7-storage)
8. [Reverse proxy](#8-reverse-proxy)
9. [Bezpieczeństwo](#9-bezpieczeństwo)
10. [Architektura i model danych](#10-architektura-i-model-danych)
11. [Testy](#11-testy)
12. [Ograniczenia i dalsze kroki](#12-ograniczenia-i-dalsze-kroki)

---

## 1. Szybki start

### Docker Compose (zalecane)

```bash
cp .env.example .env
# ustaw PUBLIC_URL na adres, pod którym instancja będzie widoczna (https://drop.example.com)
docker compose up -d --build
docker compose exec app node dist/cli.js create-admin admin      # hasło pytane interaktywnie, min. 12 znaków
```

Po pierwszym logowaniu włącz uwierzytelnianie dwuskładnikowe w panelu (**Bezpieczeństwo**)
lub wymuś je dla wszystkich administratorów przez `ADMIN_REQUIRE_TOTP=true`.

Panel: `PUBLIC_URL/admin`. Dane (baza SQLite + pliki przy backendzie lokalnym) trafiają na
wolumen `inletbox-data` zamontowany pod `/data`.

Nie ma domyślnego hasła. Pierwszego administratora tworzy się wyłącznie przez CLI na
serwerze (hasło można też podać na stdin: `echo "$PASS" | node dist/cli.js create-admin admin --password-stdin`).
`reset-password <user>` zmienia hasło i unieważnia sesje tego administratora;
`disable-totp <user>` zdejmuje drugi składnik, gdy administrator stracił aplikację i kody zapasowe.

### Lokalnie (dev)

```bash
npm install
cp .env.example .env            # dla http://localhost ustaw COOKIE_SECURE=false
npm run cli -- create-admin admin
npm run dev                     # http://localhost:3000/admin
```

### Testowy profil z MinIO

```bash
docker compose --profile minio up -d           # MinIO + inicjalizacja prywatnego bucketa "inletbox"
# w .env: STORAGE_BACKEND=s3  S3_ENDPOINT=http://minio:9000  S3_BUCKET=inletbox
#         S3_ACCESS_KEY_ID=minioadmin  S3_SECRET_ACCESS_KEY=minioadmin  S3_FORCE_PATH_STYLE=true
docker compose up -d --build app
```

---

## 2. Model uprawnień

| Kto | Może | Nie może |
|---|---|---|
| **Administrator** (sesja cookie) | tworzyć/edytować/zamykać sprawy; generować i unieważniać linki, ustawiać ich ważność i limity; przeglądać metadane; pobierać i usuwać pliki; czytać dziennik zdarzeń | — |
| **Posiadacz linku** (token) | przesyłać pliki (przeglądarka, curl, tus); widzieć listę i status plików przesłanych **tym** linkiem | pobierać ani podglądać jakichkolwiek plików, także własnych; usuwać lub nadpisywać ukończone pliki; widzieć pliki innych linków; wejść do panelu |

**Jeden case = wiele linków. Każdy link = osobny odbiorca i osobny zakres widoczności.**
Aplikacja nie rozróżnia osób posługujących się tym samym linkiem: kto zna link, ten ma
dokładnie ten sam dostęp (wysyłanie + lista własnych plików). Jeśli dwie osoby mają być
rozdzielone, dostają dwa linki. Ta informacja jest też pokazana w panelu przy linkach.

Zakaz pobierania jest egzekwowany w backendzie i storage, nie w UI:

- nie istnieje żaden endpoint zwracający treść pliku dla tokenu linku (`GET /api/files/:id`,
  `GET /api/files/:id/download`, `DELETE /api/files/:id` odpowiadają `403` i są w testach);
- endpoint tus odrzuca `GET` (`405`), więc nie działa jako endpoint odczytu;
- pliki leżą poza katalogiem serwowanym statycznie (`DATA_DIR/files`), a bucket S3 jest
  prywatny; aplikacja nie generuje presigned URL‑i;
- klucz w storage to losowy identyfikator (`f_…`), nigdy nazwa podana przez klienta;
- pobranie wymaga sesji administratora i odbywa się przez aplikację (streaming) jako
  `Content-Disposition: attachment`, `application/octet-stream`, `nosniff`, `CSP: sandbox`.

Po ukończeniu uploadu tus usuwa metadane („sidecar”) w storage, więc ukończonego pliku
nie da się już zaadresować przez `HEAD`/`PATCH`/`DELETE` (odpowiedź `410`).

---

## 3. Konfiguracja

Wszystko przez zmienne środowiskowe (`.env.example` zawiera pełną listę; brak sekretów).
Rozmiary: `1048576`, `500MB`, `2GB`, `512KiB` (jednostki binarne).

| Zmienna | Domyślnie | Opis |
|---|---|---|
| `PUBLIC_URL` | `http://localhost:3000` | Publiczny adres instancji; buduje linki i komendy curl, ustala origin dla CSRF. |
| `HOST`, `PORT` | `0.0.0.0`, `3000` | Adres nasłuchu. |
| `TRUST_PROXY` | `false` | `true`/liczba hopów za reverse proxy (IP z `X-Forwarded-For` do rate limitingu i dziennika). |
| `DATA_DIR` | `./data` | Baza SQLite (`inletbox.sqlite`) i pliki (`files/`). |
| `STORAGE_BACKEND` | `local` | `local` lub `s3`. |
| `LOCAL_STORAGE_DIR` | `$DATA_DIR/files` | Katalog plików (poza katalogami publicznymi). |
| `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_FORCE_PATH_STYLE`, `S3_PART_SIZE` | — | Backend S3; `S3_FORCE_PATH_STYLE=true` dla MinIO; part ≥ 5MB. |
| `MAX_FILE_SIZE` | `10GB` | Globalny limit pojedynczego pliku; limity per link nie mogą go przekroczyć. |
| `UPLOAD_CHUNK_SIZE` | `32MB` | Rozmiar żądania PATCH w przeglądarce; musi mieścić się w limicie body reverse proxy. |
| `INCOMPLETE_UPLOAD_TTL_HOURS` | `24` | Po tym czasie nieukończone uploady są usuwane, a rezerwacja zwalniana. |
| `CLEANUP_INTERVAL_MINUTES` | `30` | Częstotliwość sprzątania w procesie aplikacji (`0` wyłącza; `node dist/cli.js cleanup` uruchamia ręcznie). |
| `SESSION_TTL_HOURS` | `12` | Ważność sesji administratora. |
| `ADMIN_REQUIRE_TOTP` | `false` | Wymusza włączenie TOTP: administrator bez drugiego składnika widzi tylko stronę „Bezpieczeństwo”. |
| `COOKIE_SECURE` | auto (`https` → `true`) | `false` tylko dla lokalnego developmentu po HTTP. |
| `LOGIN_RATE_LIMIT_PER_15MIN` | `10` | Nieudane logowania per IP. |
| `TOKEN_FAILURE_RATE_LIMIT_PER_15MIN` | `30` | Nieudane próby użycia tokenu per IP (brute force). |
| `PUBLIC_RATE_LIMIT_PER_MINUTE` | `600` | Ogólny limit żądań API per IP (w tym fragmenty tus). |
| `LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error`. |

Limity per link (rozmiar pliku, liczba plików, łączna ilość danych) i termin ważności
ustawia się w panelu przy generowaniu linku.

---

## 4. Upload z terminala (curl)

Strona linku ma sekcję „Upload z terminala” z gotowymi komendami (rzeczywisty adres,
token, przycisk „Kopiuj”). API zwraca JSON i poprawne kody HTTP; `--fail-with-body`
daje niezerowy kod wyjścia (22) przy błędzie, ale nadal wypisuje treść błędu.

```bash
# jeden plik: curl -T dokleja nazwę pliku do adresu zakończonego "/"
curl --fail-with-body -H 'Authorization: Bearer <TOKEN>' \
  -T '/ścieżka/do/pliku.pdf' 'https://drop.example.com/api/upload/'

# kilka plików (ścieżki ze spacjami są bezpieczne)
for f in '/ścieżka/raport.pdf' '/ścieżka/zdjęcie 1.jpg'; do
  curl --fail-with-body -H 'Authorization: Bearer <TOKEN>' -T "$f" 'https://drop.example.com/api/upload/'; echo
done

# token w zmiennej środowiskowej (zalecane; spacja na początku omija historię przy HISTCONTROL=ignorespace)
 export INLETBOX_TOKEN='<TOKEN>'
curl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" -T '/ścieżka/do/pliku.pdf' 'https://drop.example.com/api/upload/'

# lista własnych plików
curl --fail-with-body -H "Authorization: Bearer $INLETBOX_TOKEN" 'https://drop.example.com/api/files'
```

Odpowiedź `201`:

```json
{"id":"f_3kq9…","name":"plik.pdf","size":1234567,"sha256":"…","status":"complete"}
```

Błędy: `401 missing_token`, `404 invalid_token`, `403 link_expired | link_revoked | case_closed`,
`413 file_too_large | too_many_files | quota_exceeded`, `429 rate_limited`.

Endpoint przyjmuje surowe body (`PUT`/`POST /api/upload/<nazwa>`, alternatywnie nagłówek
`X-File-Name`), z `Content-Length` lub `Transfer-Encoding: chunked`, obsługuje
`Expect: 100-continue`. Token wyłącznie w nagłówku `Authorization` — nie jest akceptowany
w query stringu, żeby nie trafiał do logów.

**Uwaga:** polecenie z tokenem zostaje w historii powłoki (`~/.bash_history`, `~/.zsh_history`).
Link traktuj jak hasło.

---

## 5. Wznawianie uploadów

### Porównanie

| Podejście | Za | Przeciw |
|---|---|---|
| **tus** (`@tus/server`, `tus-js-client`) | dojrzały, otwarty protokół; store dla dysku lokalnego i S3 w tej samej bibliotece; klient przeglądarkowy z fingerprintem i retry; jasna semantyka `HEAD`/`PATCH`/offsetów | dodatkowy protokół do zrozumienia; klient CLI wymaga skryptu (kilka wywołań curl) |
| własne fragmenty + offsety | pełna kontrola, brak zależności | ponowne wynalezienie tus: locking, ekspiracja, sidecary, błędy brzegowe, brak gotowego klienta |
| S3 multipart upload | natywny dla S3, równoległe części | to mechanizm **backendu**: sam nie definiuje protokołu klient↔aplikacja (identyfikacja uploadu, offsety, autoryzacja wznowienia); nie działa z dyskiem lokalnym |

**Decyzja:** tus, działający od pierwszej wersji z oboma backendami. Dla S3 tus używa pod
spodem multipart uploadu (`@tus/s3-store`), dla dysku pisze do pliku z offsetem.

### Jak to działa

- Przeglądarka używa `tus-js-client` (serwowany lokalnie, bez CDN) z fragmentami
  `UPLOAD_CHUNK_SIZE`, automatycznymi ponowieniami przy błędach sieci/5xx i zapisem
  adresu uploadu w `localStorage` (fingerprint: nazwa + rozmiar + mtime + endpoint).
  Po utracie połączenia upload kontynuuje się sam. **Po odświeżeniu strony trzeba
  ponownie wskazać ten sam plik** — przeglądarka nie może sama otworzyć pliku z dysku;
  wtedy upload wznawia się od ostatniego offsetu (widać „wznawianie poprzedniego uploadu”).
- Autoryzacja: każde żądanie tus (`POST`, `HEAD`, `PATCH`, `DELETE`) wymaga aktywnego
  tokenu. Upload jest przypisany do linku przy tworzeniu; inny link dostaje `404`
  (bez wycieku informacji, czy upload istnieje).
- Offsety kontroluje serwer tus (`409` przy niezgodności, brak możliwości zapisu poza
  zadeklarowaną długość). `Upload-Length` jest wymagany (brak `Upload-Defer-Length`),
  bo długość jest podstawą rezerwacji limitu.
- Finalizacja jest idempotentna: rekord przechodzi `uploading → complete` dokładnie raz;
  potem sidecar tus znika i upload odpowiada `410`.
- Wygaśnięcie/unieważnienie linku lub zamknięcie sprawy natychmiast blokuje `PATCH`
  (`403`); unieważnienie dodatkowo usuwa trwające uploady tego linku i zwalnia rezerwacje.
- Nieukończone uploady żyją `INCOMPLETE_UPLOAD_TTL_HOURS`, potem sprzątanie usuwa dane
  (plik + `.json` lub obiekt `.info` + abort multipart) i oznacza rekord `expired`.

### CLI

Zwykły `curl -T` **nie** wznawia — przerwany upload trzeba wysłać od nowa. `curl -C -`
dotyczy pobierania i zakresów HTTP, nie uploadów. Dla dużych plików jest skrypt
[`scripts/inletbox-upload.sh`](scripts/inletbox-upload.sh) (do pobrania też ze strony
linku), implementujący tus zwykłym curlem:

```bash
INLETBOX_TOKEN='<TOKEN>' ./inletbox-upload.sh https://drop.example.com/api '/ścieżka/do/dużego pliku.iso'
```

Tworzy upload, wysyła fragmenty (`INLETBOX_CHUNK_SIZE`, domyślnie 32 MiB) i zapisuje adres
uploadu w `~/.cache/inletbox/`. Po zerwaniu połączenia ponowne uruchomienie tej samej
komendy pyta serwer o offset i kontynuuje. Ograniczenia: jeden plik na wywołanie, wymaga
`bash`, `curl`, `tail`, `stat`, `sha256sum`/`shasum`; fragment jest buforowany przez curl
w pamięci (nie ustawiaj setek MB).

---

## 6. Limity i rezerwacje

- Efektywny limit pliku = `min(MAX_FILE_SIZE, limit linku)`. Panel odrzuca limit linku
  wyższy od globalnego.
- Wszystkie limity sprawdza serwer w jednej transakcji `BEGIN IMMEDIATE` (SQLite jest
  synchroniczne w `node:sqlite`, więc równoległe żądania są serializowane):
  liczba plików (`complete` + `uploading`), rozmiar zadeklarowany, pozostały budżet
  (`limit − ukończone − zarezerwowane`).
- **Rezerwacja:** rozpoczęty upload rezerwuje zadeklarowany rozmiar (`Content-Length`
  lub `Upload-Length`). Trzy równoległe pliki po 6 MB przy limicie 10 MB → dokładnie jeden
  przechodzi (test `enforces per-link total quota under concurrent uploads`).
- Bez `Content-Length` (chunked) rezerwowane jest maksimum, jakie ten upload może
  legalnie mieć (`min(limit pliku, pozostały budżet)`); strumień jest liczony na bieżąco
  i ucinany po przekroczeniu (`413`), a nadwyżka rezerwacji zwalniana po zakończeniu.
- Przerwanie połączenia: rekord → `aborted`, dane częściowe usunięte, rezerwacja = 0
  (test `cleans up when the client disconnects mid-upload`).
- Walidacja w przeglądarce (za duży plik) to tylko ułatwienie.

---

## 7. Storage

Abstrakcja [`src/storage/types.ts`](src/storage/types.ts): `put` (streaming z licznikiem i
SHA‑256), `get`, `stat`, `delete`, `createTusStore`, `removeTusSidecar`, `cleanupOrphans`,
`healthCheck`. Klucze są walidowane (`^[A-Za-z0-9_-]{1,128}$`) — brak path traversal.

- **local** — `LOCAL_STORAGE_DIR`, zapis z flagą `wx` (nigdy nie nadpisze istniejącego
  klucza), tus zapisuje obok `<id>.json` do czasu ukończenia.
- **s3** — `@aws-sdk/lib-storage` (multipart streaming, nieznana długość) dla uploadu
  bezpośredniego, `@tus/s3-store` dla tus. Bucket ma być prywatny; aplikacja nie wystawia
  presigned URL‑i ani poświadczeń klientowi. Wymagane uprawnienia: `s3:PutObject`,
  `s3:GetObject`, `s3:DeleteObject`, `s3:ListBucket`, `s3:AbortMultipartUpload`,
  `s3:ListBucketMultipartUploads`, `s3:ListMultipartUploadParts`.

Sprzątanie (`runCleanup`, co `CLEANUP_INTERVAL_MINUTES` i przez CLI):
1. nieukończone uploady starsze niż TTL → dane usunięte, status `expired`, rezerwacja 0;
2. pliki `complete`, których obiekt zniknął → status `missing` (widoczny w panelu);
3. artefakty w storage bez rekordu w bazie (sidecary, `.part`, porzucone multipart
   uploady w S3) starsze niż TTL → usunięte;
4. wygasłe sesje → usunięte.

Migracja plików między backendami nie jest wspierana (nie było wymagane).

---

## 8. Reverse proxy

Aplikacja nie robi TLS. Ustawienia **niezbędne** dla dużych uploadów i streamingu:

- brak limitu body (lub ≥ `UPLOAD_CHUNK_SIZE` i ≥ największy plik przez `curl -T`);
- **wyłączony buffering żądań** (inaczej proxy zapisuje cały upload na dysk, a limity
  „bez Content-Length” i przerwania nie działają jak należy);
- długie timeouty odczytu/wysyłki (godziny dla dużych plików);
- `TRUST_PROXY=1` w aplikacji, `X-Forwarded-For`/`-Proto` z proxy.

### nginx

```nginx
# Redakcja tokenu z adresu /u/<token> w access logu.
map $request_uri $redacted_uri {
    ~^(?<pre>/u/)[^/?]+(?<post>.*)$  "${pre}[redacted]${post}";
    default                          $request_uri;
}
log_format redacted '$remote_addr - [$time_local] "$request_method $redacted_uri $server_protocol" '
                    '$status $body_bytes_sent "$http_user_agent"';

server {
    listen 443 ssl http2;
    server_name drop.example.com;
    # ssl_certificate ...; ssl_certificate_key ...;
    access_log /var/log/nginx/inletbox.log redacted;

    client_max_body_size 0;            # limity egzekwuje aplikacja
    proxy_request_buffering off;       # streaming uploadu do aplikacji
    proxy_buffering off;               # streaming pobierania do admina
    proxy_http_version 1.1;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    send_timeout 3600s;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

### Caddy

```caddyfile
drop.example.com {
    request_body { max_size 0 }
    reverse_proxy 127.0.0.1:3000 {
        flush_interval -1
        transport http { read_timeout 1h  write_timeout 1h }
    }
    log {
        output file /var/log/caddy/inletbox.log
        format filter {
            request>uri replace "/u/[^/?]+" "/u/[redacted]"
        }
    }
}
```

Node: aplikacja wyłącza domyślny 5‑minutowy `requestTimeout` (inaczej długie uploady
byłyby ucinane), `headersTimeout` = 60 s.

---

## 9. Bezpieczeństwo

- **Logowanie:** hasła hashowane `scrypt` (N=2¹⁵, r=8, p=1, sól 16 B) z Node `crypto`;
  weryfikacja w stałym czasie także dla nieistniejącego użytkownika; min. 12 znaków.
- **Drugi składnik (TOTP, RFC 6238):** własna implementacja na `node:crypto` (HMAC‑SHA1,
  6 cyfr, 30 s, okno ±1 krok), zgodna z Aegis/Google Authenticator/1Password. Włączanie
  wymaga potwierdzenia kodem z aplikacji (QR + klucz do wpisania ręcznie), generuje 8
  jednorazowych kodów zapasowych (w bazie tylko SHA‑256, pokazane raz). Po haśle sesja jest
  „oczekująca” i nie ma dostępu do niczego poza formularzem kodu; 5 błędnych kodów niszczy
  sesję; zaakceptowany krok czasu jest zapamiętywany, więc ten sam kod nie zadziała
  drugi raz (ochrona przed replay). Wyłączenie lub wymiana kodów zapasowych wymaga
  bieżącego kodu, nie samej sesji. Wszystko trafia do dziennika zdarzeń. Sekret TOTP jest
  przechowywany w bazie w postaci jawnej (jak w większości implementacji); zabezpiecz plik
  bazy i backupy.
- **Sesje:** losowy identyfikator 256‑bit w cookie `HttpOnly; SameSite=Lax; Secure`
  (przy HTTPS), w bazie tylko jego SHA‑256, TTL konfigurowalny.
- **CSRF:** SameSite=Lax + kontrola `Origin`/`Sec-Fetch-Site` + token synchronizujący
  w każdym formularzu (per sesja).
- **Tokeny linków:** 256 bitów z CSPRNG, w bazie wyłącznie SHA‑256 (+ 6‑znakowa
  podpowiedź do identyfikacji w panelu). Pełny link jest pokazany raz, w odpowiedzi na
  utworzenie — nie da się go odzyskać z bazy, można tylko wygenerować nowy.
- **Wygasanie/unieważnianie:** sprawdzane przy każdym żądaniu, także w trakcie tus.
- **Rate limiting:** logowanie (nieudane), nieudane użycia tokenu, ogólny limit API.
- **Nazwy plików:** normalizacja NFC, odcięcie ścieżek (`/`, `\`), usunięcie znaków
  sterujących, limit 255 znaków; nigdy nie tworzą ścieżki w storage; w HTML wszystkie
  interpolacje są escapowane (własny tagged template `html`), a `Content-Disposition`
  buduje `content-disposition` (RFC 5987/6266).
- **IDOR:** identyfikatory są losowe (96 bit), a każdy dostęp sprawdza właściciela
  (link) lub sesję administratora; nieznane/cudze → `404`.
- **Brak publicznego odczytu**, brak wykonywania/renderowania plików, pobranie tylko
  jako `attachment` z `nosniff` i `CSP: sandbox`.
- **Nagłówki:** helmet, CSP `default-src 'none'; script-src 'self'; …`,
  `Referrer-Policy: no-referrer` (link nie wycieka przez referer), `frame-ancestors 'none'`,
  brak zewnętrznych skryptów/fontów na stronie uploadu.
- **Logi:** JSON na stdout; ścieżki `/u/<token>` i parametry `token=` są redagowane, nagłówki
  `Authorization`/`Cookie` nie są logowane; przykłady w README nie zawierają prawdziwych tokenów.
- **Dziennik zdarzeń** (`audit_log`, panel → „Dziennik”): logowania (udane i nie), operacje
  na sprawach/linkach, start/ukończenie/przerwanie/odrzucenie uploadu, pobrania i usunięcia,
  zdarzenia sprzątania; z IP klienta.
- **Pliki są niezaufane.** Skanowanie antywirusowe **nie jest częścią tej wersji**. Miejsce
  na integrację: `onUploadFinish` w [`src/http/tus.ts`](src/http/tus.ts) i zakończenie
  `direct` w [`src/http/public.ts`](src/http/public.ts) — oba wywołują
  `completeUpload`; skaner (np. ClamAV przez `clamd`) może tam ustawiać dodatkowy status
  (`quarantined`) przed udostępnieniem pliku administratorowi.

---

## 10. Architektura i model danych

Monolit Express + SQLite w jednym procesie; storage jako wtyczka.

```
src/
  config.ts            zmienne środowiskowe → Config (parseSize itd.)
  db.ts                node:sqlite, migracje z migrations/*.sql, transaction()
  crypto.ts            id, tokeny, sha256, scrypt
  log.ts               JSON log + redakcja
  storage/             types (interfejs), local, s3, limit (licznik+hash)
  services/            auth (admin+sesje), cases, links, files (rezerwacje), audit, cleanup
  http/
    app.ts             składanie aplikacji, static, 404/500
    middleware.ts      helmet/CSP, logger, sesje, CSRF, rate limity, auth linku (Bearer)
    admin.ts           panel (SSR, formularze)
    public.ts          /u/<token>, /api/link, /api/files, /api/upload (direct), /api/tus
    tus.ts             @tus/server + hooki (rezerwacja, izolacja, finalizacja)
    html.ts, views/    tagged template z escapowaniem, widoki
  server.ts            http.Server (timeouty, 100-continue), sprzątanie cykliczne, shutdown
  cli.ts               create-admin, reset-password, migrate, cleanup
public/                style.css, upload.js (tus-js-client), admin.js
scripts/inletbox-upload.sh   wznawialny upload z CLI
```

Tabele ([`migrations/001_init.sql`](migrations/001_init.sql)):

- `admins` (id, username, password_hash)
- `sessions` (id_hash, admin_id, csrf_token, expires_at)
- `cases` (id, name, description, status open|closed)
- `links` (id, case_id, label, token_hash, token_hint, expires_at, revoked_at,
  max_file_bytes, max_files, max_total_bytes, last_used_at)
- `files` (id = klucz storage = id tus, case_id, link_id, original_name, upload_kind tus|direct,
  status uploading|complete|aborted|expired|missing|deleted, declared_size, reserved_bytes,
  size, sha256, client_ip, created_at, completed_at, deleted_at)
- `audit_log` (ts, actor_type admin|link|system, actor_id, action, case_id, link_id, file_id, ip, details)

Przepływ uploadu z przeglądarki: `POST /api/tus` (Bearer) → `onUploadCreate` rezerwuje limit
w transakcji i tworzy rekord `uploading` → `PATCH …` (offset kontrolowany przez tus, każdy
request weryfikuje token i właściciela) → `onUploadFinish` → `complete`, sidecar usunięty.
Upload bezpośredni: `PUT /api/upload/<nazwa>` → rezerwacja → `storage.put` (strumień z
licznikiem i SHA‑256) → `complete`.

---

## 11. Testy

```bash
npm test                    # backend lokalny (SQLite + katalog tymczasowy per plik testów)
docker compose --profile minio up -d minio
TEST_S3=1 npm test          # ten sam zestaw przeciwko MinIO (bucket tymczasowy per plik testów)
```

Zestaw (vitest, 64 testy) uruchamia prawdziwy serwer HTTP na losowym porcie i obejmuje:
utworzenie sprawy i linku przez formularze (pełny URL raz, potem tylko podpowiedź);
upload z `Content-Length`, chunked i **prawdziwym curlem** (`-T` ze spacją w ścieżce,
kod wyjścia 22 przy błędzie); izolację list między linkami; brak jakiejkolwiek drogi
odczytu po ID pliku dla posiadacza linku; pobranie przez administratora z bezpiecznymi
nagłówkami i usunięcie; limity (za duży plik, nadmiar plików, budżet) także przy
**równoległych** żądaniach i bez `Content-Length`; brak nadpisywania duplikatów;
sanityzację nazw (traversal, HTML); przerwanie połączenia i sprzątanie; tus: create/patch/head,
zły offset (409), izolacja (404), finalizacja idempotentna (410), `tus-js-client` z przerwaniem
i wznowieniem od zapisanego URL, wygaszanie nieukończonych uploadów, sprzątanie sierot i
oznaczanie plików `missing`; wygaśnięcie/unieważnienie linku (w tym przerwanie trwającego
uploadu) i zamknięcie sprawy; CSRF i rate limit logowania.

Testy bezpieczeństwa (`test/security.test.ts`, `test/totp.test.ts`): nagłówki (CSP bez
`unsafe-inline`, `X-Frame-Options: DENY`, `nosniff`, brak `X-Powered-By`), atrybuty cookie
(`HttpOnly`, `SameSite`, `Secure`), rotacja sesji przy logowaniu i unieważnienie przy
wylogowaniu, brak zaufania do `X-Forwarded-For` bez `TRUST_PROXY`, throttling nieudanych
tokenów, path traversal przez `/static`, nieprawidłowe identyfikatory, wrogie nazwy plików
z trzech kanałów (URL, nagłówek, metadane tus) włącznie z CRLF i XSS, brak tokenów w
dzienniku/panelu/JSON, tus bez tokenu i między linkami, `npm audit` bez podatności
high/critical; TOTP: wektory testowe RFC 6238, okno czasowe, replay, sesja oczekująca bez
dostępu do panelu, blokada po 5 błędach, kody zapasowe jednorazowe, wymiana kodów,
wyłączanie z kodem, CLI `disable-totp`, tryb `ADMIN_REQUIRE_TOTP`.

Stan na dzień oddania: 64/64 zielonych na backendzie lokalnym i 64/64 na MinIO
(`quay.io/minio/minio`), obraz Dockera buduje się poprawnie, skrypt CLI zweryfikowany
ręcznie (zabity w połowie 8 MB pliku, wznowiony od zapisanego offsetu, treść identyczna).

---

## 12. Ograniczenia i dalsze kroki

- **Brak skanowania AV** (patrz §9) i brak kwarantanny.
- Jeden proces / jeden węzeł: SQLite i lock tus w pamięci. Skalowanie poziome wymagałoby
  Postgresa i lockera tus opartego np. o Redis.
- SHA‑256 liczone tylko dla uploadu bezpośredniego; dla tus można dodać hashowanie po
  finalizacji (odczyt ze storage) lub rozszerzenie `checksum`.
- Sprzątanie weryfikuje istnienie każdego ukończonego pliku (`stat`); przy bardzo dużej
  liczbie obiektów w S3 warto ograniczyć to do próbki lub uruchamiać rzadziej.
- Wznawianie w przeglądarce po odświeżeniu wymaga ponownego wskazania pliku (ograniczenie
  przeglądarek), a fingerprint tus‑js‑client zależy od nazwy/rozmiaru/mtime.
- Jedna rola administratora; brak SSO/WebAuthn (jest TOTP), brak wielu poziomów uprawnień.
- Presigned URL‑e nie są używane (pobranie zawsze przez aplikację). Dla bardzo dużych
  plików można dodać krótkotrwały presigned `GET` ograniczony do jednego obiektu.
- Brak powiadomień (e‑mail/webhook) o nowych plikach — naturalne miejsce: `upload.complete`
  w `audit`.
- Nazwa: `inletbox` nie ma repozytoriów na GitHubie (stan z dnia sprawdzenia); rejestracja
  nazwy w npm/Docker Hub nie była sprawdzana.
