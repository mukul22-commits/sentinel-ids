# Sentinel IDS - backup / restore scripts (Phase 12)

Two shell scripts for the Sentinel IDS PostgreSQL (TimescaleDB) database,
usable against any deployment flavor (Docker Compose, Kubernetes, bare-metal,
AWS).

| Script                 | Purpose                                                    |
|------------------------|------------------------------------------------------------|
| `backup.sh`            | `pg_dump` + gzip + manifest + retention (KEEP_DAYS)        |
| `restore_test.sh`      | restore into a scratch DB, sanity check, then drop         |

## Prerequisites

- `psql` and `pg_dump` client binaries (matching the server major version),
  and `sha256sum` / `gzip` (present on all mainstream Linux distros).
- Network access to the target PostgreSQL host on port 5432.
- Read/write access to `BACKUP_DIR`.

Both scripts require `PG_PASSWORD`; the rest have sensible defaults
(`sentinel` / `sentinel_ids` / `localhost:5432`, matching the Compose and
Kubernetes defaults).

## backup.sh

```bash
# Against the compose stack:
PG_HOST=localhost PG_PASSWORD=sentinel ./scripts/backup.sh

# Against Kubernetes (from a host with kubectl + pg_dump; port-forward first):
kubectl -n sentinel-ids port-forward svc/postgres 5432:5432 &
PG_HOST=127.0.0.1 PG_PASSWORD="$(kubectl -n sentinel-ids get secret sentinel-secrets -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)" \
  BACKUP_DIR=/var/backups/sentinel ./scripts/backup.sh
```

Output: `sentinel_ids_<UTC-timestamp>.sql.gz` + `.manifest` (size, sha256,
metadata), a `latest.sql.gz` symlink, and automatic pruning of archives older
than `KEEP_DAYS` (default 14).

Schedule with cron (example, 01:30 daily):

```cron
30 1 * * * PG_HOST=postgres PG_PASSWORD='***' BACKUP_DIR=/var/backups/sentinel /opt/sentinel/scripts/backup.sh >> /var/log/sentinel-backup.log 2>&1
```

## restore_test.sh

Restores the latest backup (or a given file) into a throwaway DB
`sentinel_ids_restore_<ts>`, checks `SELECT count(*) FROM users;`, then drops
the scratch DB (unless `KEEP_RESTORE=1`). A failing restore cleans up after
itself via a trap, so the script is safe to run in automation.

```bash
PG_HOST=localhost PG_PASSWORD=sentinel ./scripts/restore_test.sh
PG_HOST=localhost PG_PASSWORD=sentinel KEEP_RESTORE=1 ./scripts/restore_test.sh /var/backups/sentinel/sentinel_ids_20260808T013000Z.sql.gz
```

This is the Disaster Recovery drill: if it fails, investigate before trusting
the backup chain.

## DR runbook summary

1. Take a fresh backup before any destructive change (`backup.sh`).
2. Verify restorability after every schema migration (`restore_test.sh`).
3. Restore to a live empty database: create the DB (or reuse the scratch one),
   `gunzip -c <backup> | psql -d sentinel_ids`, then re-run
   `alembic upgrade head` if the schema moved past the backup.
4. Full recovery procedure: see `docs/deploy/runbooks.md`
   (Backup restore drill).
