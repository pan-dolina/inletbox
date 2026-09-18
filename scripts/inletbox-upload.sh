#!/usr/bin/env bash
# inletbox-upload.sh — resumable upload of a single (large) file using the tus
# protocol and plain curl. Works against the same endpoint the browser uses.
#
#   INLETBOX_TOKEN='<token>' ./inletbox-upload.sh https://host/api '/path/to/big file.iso'
#
# Behaviour:
#   * creates the upload (POST), then sends the file in chunks (PATCH) from the
#     current server offset (HEAD) until it is complete;
#   * the upload URL is remembered in ~/.cache/inletbox/<hash>.url, so re-running
#     the same command after a network failure resumes instead of starting over;
#   * exits non-zero on any HTTP error; the server answers with JSON.
#
# Limitations:
#   * requires bash, curl, tail, stat and sha256sum/shasum (macOS: shasum);
#   * one file per invocation; loop over files in the shell for several;
#   * the token is read from the environment and handed to curl through a
#     private temp file, so it stays out of shell history and `ps` output.
set -euo pipefail

API="${1:-}"
FILE="${2:-}"
CHUNK_SIZE="${INLETBOX_CHUNK_SIZE:-33554432}"   # 32 MiB

if [[ -z "$API" || -z "$FILE" || -z "${INLETBOX_TOKEN:-}" ]]; then
  echo "usage: INLETBOX_TOKEN=<token> $0 <https://host/api> <file>" >&2
  exit 2
fi
[[ -f "$FILE" ]] || { echo "not a file: $FILE" >&2; exit 2; }

API="${API%/}"
TUS="$API/tus"
AUTH="Authorization: Bearer $INLETBOX_TOKEN"

if stat -f %z "$FILE" >/dev/null 2>&1; then SIZE=$(stat -f %z "$FILE"); else SIZE=$(stat -c %s "$FILE"); fi
NAME=$(basename "$FILE")
NAME_B64=$(printf '%s' "$NAME" | base64 | tr -d '\n')

if command -v sha256sum >/dev/null; then hasher=sha256sum; else hasher="shasum -a 256"; fi
KEY=$(printf '%s|%s|%s' "$TUS" "$FILE" "$SIZE" | $hasher | cut -c1-32)
CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/inletbox"
mkdir -p "$CACHE_DIR"
STATE="$CACHE_DIR/$KEY.url"

# The Authorization header is passed through a file descriptor, not as an argument, so it
# does not show up in `ps` output for other users on the machine.
HDR_FILE=$(mktemp)
trap 'rm -f "$HDR_FILE"' EXIT
chmod 600 "$HDR_FILE"
printf '%s\n' "$AUTH" > "$HDR_FILE"
curl_common=(--silent --show-error --fail-with-body -H "@$HDR_FILE" -H 'Tus-Resumable: 1.0.0' -H 'Expect:')

# Anything the server sends back is untrusted input: only plain integers are ever used in arithmetic.
is_int() { [[ "$1" =~ ^[0-9]+$ ]]; }

fail() { echo "error: $*" >&2; exit 1; }

get_offset() {
  # Prints the current Upload-Offset, or "gone" when the server no longer knows the upload.
  local hdrs code
  hdrs=$(curl --silent --show-error -o /dev/null -D - -X HEAD -I -H "@$HDR_FILE" -H 'Tus-Resumable: 1.0.0' "$1" 2>/dev/null || true)
  code=$(printf '%s' "$hdrs" | head -n1 | awk '{print $2}')
  case "$code" in
    200|204)
      local off
      off=$(printf '%s' "$hdrs" | tr -d '\r' | awk 'tolower($1)=="upload-offset:" {print $2}')
      is_int "$off" || fail "server returned a malformed Upload-Offset"
      printf '%s' "$off" ;;
    404|410|403) echo gone ;;
    *) fail "HEAD $1 returned HTTP ${code:-none}" ;;
  esac
}

UPLOAD_URL=""
if [[ -f "$STATE" ]]; then
  UPLOAD_URL=$(cat "$STATE")
  OFFSET=$(get_offset "$UPLOAD_URL")
  if [[ "$OFFSET" == "gone" || -z "$OFFSET" ]]; then
    echo "previous upload no longer exists on the server; starting over" >&2
    rm -f "$STATE"; UPLOAD_URL=""
  else
    echo "resuming $NAME from offset $OFFSET / $SIZE" >&2
  fi
fi

if [[ -z "$UPLOAD_URL" ]]; then
  resp=$(curl "${curl_common[@]}" -o /dev/null -D - -X POST \
    -H "Upload-Length: $SIZE" -H "Upload-Metadata: filename $NAME_B64" -H 'Content-Length: 0' "$TUS/") \
    || fail "could not create upload (check the token, limits and link validity)"
  loc=$(printf '%s' "$resp" | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}')
  [[ -n "$loc" ]] || fail "server did not return an upload URL"
  case "$loc" in
    http://*|https://*) UPLOAD_URL="$loc" ;;
    /*) UPLOAD_URL="${API%/api}$loc" ;;
    *) UPLOAD_URL="$TUS/$loc" ;;
  esac
  printf '%s' "$UPLOAD_URL" > "$STATE"
  OFFSET=0
  echo "created upload for $NAME ($SIZE bytes)" >&2
fi

while (( OFFSET < SIZE )); do
  remaining=$(( SIZE - OFFSET ))
  len=$(( remaining < CHUNK_SIZE ? remaining : CHUNK_SIZE ))
  # pipefail is disabled inside the subshell: `head` closing the pipe early makes `tail` exit
  # with SIGPIPE, which is expected. The subshell's status is curl's (the last command).
  resp=$( set +o pipefail; tail -c +$(( OFFSET + 1 )) "$FILE" 2>/dev/null | head -c "$len" | \
    curl "${curl_common[@]}" -o /dev/null -D - -X PATCH \
      -H 'Content-Type: application/offset+octet-stream' -H "Upload-Offset: $OFFSET" -H "Content-Length: $len" \
      --data-binary @- "$UPLOAD_URL" ) || { echo "chunk at offset $OFFSET failed; re-run to resume" >&2; exit 1; }
  new_offset=$(printf '%s' "$resp" | tr -d '\r' | awk 'tolower($1)=="upload-offset:" {print $2}')
  is_int "$new_offset" || fail "malformed or missing Upload-Offset in response"
  OFFSET=$new_offset
  printf '\r%3d%% (%s / %s)' $(( OFFSET * 100 / (SIZE == 0 ? 1 : SIZE) )) "$OFFSET" "$SIZE" >&2
done
echo >&2
rm -f "$STATE"
echo "{\"name\":\"$NAME\",\"size\":$SIZE,\"status\":\"complete\"}"
