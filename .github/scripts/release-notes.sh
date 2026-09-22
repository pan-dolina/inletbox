#!/usr/bin/env bash
# Prints the release notes for a tag: its section of CHANGELOG.md, followed by a compare
# link to the previous tag. Exits 1 without printing notes when the tag does not exist
# or the changelog has no section for it — the caller decides whether that is an error
# (publishing a new tag) or only worth a warning (re-syncing old releases).
#
# Usage: .github/scripts/release-notes.sh vX.Y.Z   (run from the repository root)
set -euo pipefail

tag="${1:?usage: release-notes.sh vX.Y.Z}"
if ! git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  echo "tag ${tag} does not exist" >&2
  exit 1
fi

# The section runs from "## [x.y.z]" to the next section or to the link definitions at
# the bottom of the file. Blank lines right after the heading are dropped.
section=$(awk -v v="${tag#v}" '
  $0 ~ "^## \\[" v "\\]" { found = 1; next }
  found && /^## \[/       { exit }
  found && /^\[[^]]+\]: / { exit }
  found && !started && /^[[:space:]]*$/ { next }
  found                   { started = 1; print }
' CHANGELOG.md)

if [ -z "$(printf '%s' "${section}" | tr -d '[:space:]')" ]; then
  echo "CHANGELOG.md has no section for ${tag#v}" >&2
  exit 1
fi

printf '%s\n' "${section}"

prev=$(git describe --tags --abbrev=0 "${tag}^" 2>/dev/null || true)
if [ -n "${prev}" ]; then
  printf '\n**Full Changelog**: %s/%s/compare/%s...%s\n' \
    "${GITHUB_SERVER_URL:-https://github.com}" "${GITHUB_REPOSITORY:?}" "${prev}" "${tag}"
fi
