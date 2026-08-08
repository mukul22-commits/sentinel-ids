#!/usr/bin/env bash
#
# Sentinel IDS - PostgreSQL backup helper (Phase 12)
#
# Dumps the sentinel_ids database with pg_dump, gzip-compresses it, writes a
# machine-readable manifest next to the archive, refreshes a `latest.sql.gz`
# symlink, and prunes backups older than KEEP_DAYS days.
#
# Run from a host with pg_dump installed and network access to the database.
#
# Env:
#   PG_HOST      database host (default: localhost)
#   PG_PORT      database port (default: 5432)
#   PG_USER      database user (default: sentinel)
#   PG_PASSWORD  database password (required)
#   PG_DB        database name (default: sentinel_ids)
#   BACKUP_DIR   where archives are written (default: ./backups)
#   KEEP_DAYS    prune archives older than this (default: 14)
#
# Schedule via cron (adjust path/time/credentials to taste):
#   30 1 * * * PG_HOST=postgres PG_PASSWORD='***' BACKUP_DIR=/var/backups/sentinel /opt/sentinel/scripts/backup.sh >> /var/log/sentinel-backup.log 2>&1

set -euo pipefail

PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-sentinel}"
PG_PASSWORD="${PG_PASSWORD:-}"
PG_DB="${PG_DB:-sentinel_ids}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP_DAYS="${KEEP_DAYS:-14}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_FILE="${BACKUP_DIR}/sentinel_ids_${TS}.sql.gz"
MANIFEST="${BACKUP_FILE}.manifest"

if [ -z "${PG_PASSWORD}" ]; then
  echo "[backup] PG_PASSWORD is not set" >&2
  exit 1
fi
export PGPASSWORD="${PG_PASSWORD}"

mkdir -p "${BACKUP_DIR}"

echo "[backup] dumping ${PG_DB} from ${PG_HOST}:${PG_PORT} as ${PG_USER}"

# --no-owner / --no-privileges make the archive portable across environments.
pg_dump \
  --host "${PG_HOST}" \
  --port "${PG_PORT}" \
  --username "${PG_USER}" \
  --dbname "${PG_DB}" \
  --no-owner \
  --no-privileges \
  | gzip -9 > "${BACKUP_FILE}"

SIZE_BYTES="$(wc -c < "${BACKUP_FILE}" | tr -d ' ')"
CHECKSUM="$(sha256sum "${BACKUP_FILE}" | awk '{print $1}')"

cat > "${MANIFEST}" <<EOF
file:       ${BACKUP_FILE}
created:    ${TS}
host:       ${PG_HOST}:${PG_PORT}
database:   ${PG_DB}
tool:       pg_dump + gzip -9
size_bytes: ${SIZE_BYTES}
sha256:     ${CHECKSUM}
EOF

ln -sfn "sentinel_ids_${TS}.sql.gz" "${BACKUP_DIR}/latest.sql.gz"

echo "[backup] wrote ${BACKUP_FILE} (${SIZE_BYTES} bytes)"
echo "[backup] manifest: ${MANIFEST}"
echo "[backup] sha256:   ${CHECKSUM}"

# Prune archives older than KEEP_DAYS days (and their manifests).
find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'sentinel_ids_*.sql.gz' -mtime "+${KEEP_DAYS}" -delete
find "${BACKUP_DIR}" -maxdepth 1 -type f -name 'sentinel_ids_*.sql.gz.manifest' -mtime "+${KEEP_DAYS}" -delete

echo "[backup] done; keeping archives newer than ${KEEP_DAYS} days"
