#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <backup.dump|backup.dump.age> <empty verification database URL>" >&2
  exit 2
fi
backup="$1"
database_url="$2"
temporary=""
trap '[[ -n "$temporary" ]] && rm -f "$temporary"' EXIT

if [[ "$backup" == *.age ]]; then
  command -v age >/dev/null 2>&1 || { echo "age is required to decrypt $backup" >&2; exit 2; }
  sha256sum --check "$backup.sha256"
  temporary="$(mktemp)"
  age --decrypt --output "$temporary" "$backup"
  restore_source="$temporary"
else
  sha256sum --check "$backup.sha256"
  restore_source="$backup"
fi

pg_restore --exit-on-error --clean --if-exists --no-owner --no-acl \
  --dbname "$database_url" "$restore_source"

psql "$database_url" --set ON_ERROR_STOP=1 --tuples-only --no-align <<'SQL'
SELECT json_build_object(
  'schema_revision', (SELECT version_num FROM alembic_version),
  'records', (SELECT count(*) FROM publisher_records),
  'revisions', (SELECT count(*) FROM publisher_revisions),
  'changes', (SELECT count(*) FROM publisher_changes),
  'clients', (SELECT count(*) FROM publisher_clients),
  'installations', (SELECT count(*) FROM publisher_installations),
  'record_digest', COALESCE((
    SELECT md5(string_agg(provider_key || ':' || external_id || ':' || id::text, '|' ORDER BY provider_key, external_id))
    FROM publisher_records
  ), md5('')),
  'revision_digest', COALESCE((
    SELECT md5(string_agg(record_id::text || ':' || revision_number::text || ':' || payload_sha256, '|' ORDER BY record_id, revision_number))
    FROM publisher_revisions
  ), md5('')),
  'change_digest', COALESCE((
    SELECT md5(string_agg(sequence::text || ':' || revision_id::text || ':' || projection, '|' ORDER BY sequence))
    FROM publisher_changes
  ), md5(''))
);
SQL
printf 'Restore verification completed for %s\n' "$database_url"
