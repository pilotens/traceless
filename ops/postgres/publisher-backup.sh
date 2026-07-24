#!/usr/bin/env bash
set -euo pipefail

: "${PUBLISHER_DATABASE_URL:?Set PUBLISHER_DATABASE_URL}"
output="${1:-publisher-$(date -u +%Y%m%dT%H%M%SZ).dump}"
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

umask 077
pg_dump --format=custom --compress=9 --no-owner --no-acl \
  --dbname "$PUBLISHER_DATABASE_URL" --file "$output"
sha256sum "$output" > "$output.sha256"
size_bytes="$(wc -c < "$output" | tr -d ' ')"
sha256="$(cut -d' ' -f1 "$output.sha256")"
printf '{"created_at":"%s","file":"%s","format":"pg_dump_custom","size_bytes":%s,"sha256":"%s"}\n' \
  "$created_at" "$(basename "$output")" "$size_bytes" "$sha256" > "$output.manifest.json"

if [[ -n "${PUBLISHER_BACKUP_AGE_RECIPIENT:-}" ]]; then
  command -v age >/dev/null 2>&1 || {
    echo "PUBLISHER_BACKUP_AGE_RECIPIENT is set but age is unavailable" >&2
    exit 2
  }
  age --recipient "$PUBLISHER_BACKUP_AGE_RECIPIENT" --output "$output.age" "$output"
  sha256sum "$output.age" > "$output.age.sha256"
  if [[ "${PUBLISHER_BACKUP_KEEP_PLAINTEXT:-false}" != "true" ]]; then
    rm -f "$output" "$output.sha256"
  fi
  printf 'Created encrypted backup %s and manifest %s\n' "$output.age" "$output.manifest.json"
else
  echo "WARNING: backup is not encrypted; set PUBLISHER_BACKUP_AGE_RECIPIENT for offsite storage" >&2
  printf 'Created %s, %s and %s\n' "$output" "$output.sha256" "$output.manifest.json"
fi
