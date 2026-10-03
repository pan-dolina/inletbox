# Reverse proxy

[← back to the README](../README.md)

The application does not terminate TLS. Settings **required** for large uploads and streaming:

- no body size limit (or ≥ `UPLOAD_CHUNK_SIZE` and ≥ the largest file sent with `curl -T`);
- **request buffering off** (otherwise the proxy spools the whole upload to disk and the
  limits without `Content-Length` and abort handling do not behave as intended);
- long read/send timeouts (hours for large files);
- `TRUST_PROXY=1` in the application, `X-Forwarded-For`/`-Proto` set by the proxy.

## nginx

```nginx
# Redact the token from /u/<token> in the access log.
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

    client_max_body_size 0;            # limits are enforced by the application
    proxy_request_buffering off;       # stream uploads to the application
    proxy_buffering off;               # stream downloads to the admin
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

## Caddy

```caddyfile
drop.example.com {
    request_body {
        max_size 0
    }
    reverse_proxy 127.0.0.1:3000 {
        flush_interval -1
        transport http {
            read_timeout 1h
            write_timeout 1h
        }
    }
    log {
        output file /var/log/caddy/inletbox.log
        # regexp, not replace: the replace filter takes one static value and would
        # rewrite *every* logged URI to it, destroying the access log while looking
        # like redaction. Without a filter at all, the token is written in clear.
        format filter {
            wrap json
            request>uri regexp "/u/[^/?]+" "/u/[redacted]"
            request>uri regexp "(/api/upload/)[^?]+" "${1}[filename]"
        }
    }
}
```

### Behind Cloudflare

If Caddy itself sits behind Cloudflare, the address the application sees is a Cloudflare
edge IP (`162.158.x`, `172.64.x`, …), not the visitor. Every IP in the audit log and every
rate-limit bucket is then wrong.

**Do not fix this by raising `TRUST_PROXY` to 2.** Cloudflare *appends* the visitor to any
`X-Forwarded-For` the client sent, so the header arrives as
`<whatever the client made up>, <visitor>, <Cloudflare edge>`. Counting hops from the right
happens to work; counting to the left of it does not, and either way the client controls
part of the header. Resolve the address at the edge instead and hand the application a
single value it can trust.

```caddyfile
{
    servers {
        # Only these peers may set the client address. Cloudflare publishes the list at
        # https://www.cloudflare.com/ips-v4 and /ips-v6 and it does change — regenerate it
        # (a cron job, or a plugin that maintains the ranges dynamically) rather than
        # pasting it once and forgetting.
        trusted_proxies static \
            173.245.48.0/20 \
            103.21.244.0/22 \
            103.22.200.0/22 \
            103.31.4.0/22 \
            141.101.64.0/18 \
            108.162.192.0/18 \
            190.93.240.0/20 \
            188.114.96.0/20 \
            197.234.240.0/22 \
            198.41.128.0/17 \
            162.158.0.0/15 \
            104.16.0.0/13 \
            104.24.0.0/14 \
            172.64.0.0/13 \
            131.0.72.0/22 \
            2400:cb00::/32 \
            2606:4700::/32 \
            2803:f800::/32 \
            2405:b500::/32 \
            2405:8100::/32 \
            2a06:98c0::/29 \
            2c0f:f248::/32

        # Cloudflare overwrites this header with the real connecting address, unlike
        # X-Forwarded-For which it only appends to. Listing it alone is deliberate: a
        # request that did not come through Cloudflare has no CF-Connecting-IP, and Caddy
        # then falls back to the actual remote address rather than to something forgeable.
        client_ip_headers Cf-Connecting-IP

        # Parse right-to-left. Caddy's default is left-to-right, which takes the
        # client-supplied entry. Caddy 2.8+.
        trusted_proxies_strict
    }
}

drop.example.com {
    request_body {
        max_size 0
    }
    reverse_proxy 127.0.0.1:3000 {
        flush_interval -1
        transport http {
            read_timeout 1h
            write_timeout 1h
        }

        # Replace X-Forwarded-For instead of appending to it, so the application receives
        # exactly one address: the one Caddy resolved. TRUST_PROXY=1 is then correct.
        # It is {client_ip}, not {http.request.client_ip} — the long form is not
        # substituted here and would be forwarded to the application as that literal
        # string, which then lands in the audit log where an IP should be.
        header_up X-Forwarded-For {client_ip}
        header_up X-Real-IP {client_ip}
    }

    log {
        output file /var/log/caddy/inletbox.log
        format filter {
            wrap json
            request>uri regexp "/u/[^/?]+" "/u/[redacted]"
            request>uri regexp "(/api/upload/)[^?]+" "${1}[filename]"
        }
    }
}
```

The log filter is not optional. `/u/<token>` is the whole credential, and a plain
`format json` writes it to disk on every request — where it then survives in rotated
copies and in whatever ships those logs onwards.

Two things this does not solve:

- **Anyone who reaches the origin directly bypasses all of it.** With `TRUST_PROXY=1` the
  application believes the `X-Forwarded-For` of whoever connects to it, so the origin must
  not be reachable except from Cloudflare — firewall the port to the published ranges, use
  authenticated origin pulls, or a tunnel. Publishing the container port on `0.0.0.0` and
  relying on the network being private is not enough.
- **Verify it rather than assume it.** After reloading Caddy, upload through a link and
  check the IP recorded in the audit log. A Cloudflare range there means the header is
  still not being resolved.

Node: the application disables the default 5-minute `requestTimeout` (it would cut long
uploads) but keeps `headersTimeout` at 60 s and a 5-minute socket idle timeout (slowloris);
an active upload keeps its socket busy, so it is unaffected.
