#!/usr/bin/env bash
#
# Sentinel IDS - backup restore + sanity test (Phase 12)
#
# Restores the latest (or a given) gzip'd pg_dump into a throwaway scratch
# database `sentinel_ids_restore_<ts>`, runs a sanity check
# (`SELECT count(*) FROM users;`), then drops the scratch database unless
# KEEP_RESTORE=1.
#
# Safe to run repeatedly: the scratch name is timestamped, so runs never
# collide, and a failure drops the scratch DB via a trap.
#
# Usage:
#   ./restore_test.sh                  # restore ./backups/latest.sql.gz
#   ./restore_test.sh /path/to/file.sql.gz
#
# Env:
#   PG_HOST, PG_PORT, PG_USER, PG_PASSWORD  connection to the TARGET database
#   PG_DB        source database name, used for the maintenance connection
#                (default: sentinel_ids)
#   BACKUP_DIR   where to look for latest.sql.gz (default: ./backups)
#   KEEP_RESTORE set to "1" to keep the scratch DB for inspection
#
# Prerequisites: psql + gunzip on the PATH, network access to PG_HOST.

set -euo pipefail

PG_HOST="${PG_HOST:-localhost}"
PG_PORT="${PG_PORT:-5432}"
PG_USER="${PG_USER:-sentinel}"
PG_PASSWORD="${PG_PASSWORD:-}"
PG_DB="${PG_DB:-sentinel_ids}"
BACKUP_DIR="${BACKUP_DIR:-./backups}"
KEEP_RESTORE="${KEEP_RESTORE:-0}"

if [ -z "${PG_PASSWORD}" ]; then
  echo "[restore] PG_PASSWORD is not set" >&2
  exit 1
fi
export PGPASSWORD="${PG_PASSWORD}"

PSQL=(psql --host "${PG_HOST}" --port "${PG_PORT}" --username "${PG_USER}" --set ON_ERROR_STOP=1)

SCRATCH_DB="sentinel_ids_restore_$(date -u +%Y%m%dT%H%M%SZ)"

cleanup() {
  if [ "${KEEP_RESTORE}" != "1" ] && [ -n "${SCRATCH_DB}" ]; then
    echo "[restore] dropping scratch database ${SCRATCH_DB}"
    "${PSQL[@]}" --dbname "${PG_DB}" --quiet --command "DROP DATABASE IF EXISTS \"${SCRATCH_DB}\" WITH (FORCE);"
  fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Resolve the backup file
# ---------------------------------------------------------------------------

BACKUP_FILE="${1:-}"
if [ -z "${BACKUP_FILE}" ]; then
  BACKUP_FILE="${BACKUP_DIR}/latest.sql.gz"
fi

if [ ! -f "${BACKUP_FILE}" ]; then
  echo "[restore] backup not found: ${BACKUP_FILE}" >&2
  exit 1
fi

echo "[restore] using backup: ${BACKUP_FILE}"

# Integrity check before touching the database.
gunzip -t "${BACKUP_FILE}"

# ---------------------------------------------------------------------------
# Create scratch DB and restore
# ---------------------------------------------------------------------------

echo "[restore] creating scratch database ${SCRATCH_DB}"
"${PSQL[@]}" --dbname "${PG_DB}" --quiet --command "CREATE DATABASE \"${SCRATCH_DB}\" OWNER \"${PG_USER}\";"

echo "[restore] restoring archive into ${SCRATCH_DB}"
gunzip -c "${BACKUP_FILE}" | "${PSQL[@]}" --dbname "${SCRATCH_DB}" --quiet

# ---------------------------------------------------------------------------
# Sanity check
# ---------------------------------------------------------------------------

echo "[restore] sanity check: SELECT count(*) FROM users;"
USER_COUNT="$("${PSQL[@]}" --dbname "${SCRATCH_DB}" --tuples-only --no-align --command "SELECT count(*) FROM users;")"
echo "[restore] users rows restored: ${USER_COUNT}"

if [ "${KEEP_RESTORE}" = "1" ]; then
  echo "[restore] KEEP_RESTORE=1 - leaving scratch database ${SCRATCH_DB} in place for inspection"
else
  echo "[restore] OK - restore + sanity check passed; scratch database dropped"
fi
