# Sentinel IDS - operations runbooks (Phase 12)

Practical runbooks for the Sentinel IDS stack. They assume the Kubernetes
flavor where noted, but translate to Compose / ECS / bare metal easily.
Before touching anything: note the incident start time, save the dashboard,
and involve the on-call channel if impact exceeds the runbook's scope.

Contents:

1. [Backend / API service down](#1-backend--api-service-down)
2. [Database full](#2-database-full)
3. [Redis down](#3-redis-down)
4. [Celery worker stuck](#4-celery-worker-stuck)
5. [Alert flood / incident response](#5-alert-flood--incident-response)
6. [Certificate expiry](#6-certificate-expiry)
7. [Backup restore drill](#7-backup-restore-drill)
8. [Secrets rotation](#8-secrets-rotation)
9. [Scaling out](#9-scaling-out)
10. [p99 latency degradation](#10-p99-latency-degradation)

---

## 1. Backend / API service down

**Symptoms:** 502/504 from the ALB/ingress, `/health` failing, P1 alerts.

1. Confirm scope: `kubectl -n sentinel-ids get pods` and
   `kubectl -n sentinel-ids get deploy/backend`.
2. Check pods:
   ```bash
   kubectl -n sentinel-ids describe deploy/backend
   kubectl -n sentinel-ids logs deploy/backend --tail=200 --previous
   ```
3. Probe endpoints manually:
   ```bash
   kubectl -n sentinel-ids exec deploy/backend -- curl -fsS http://127.0.0.1:8000/health/ready
   ```
   A 503 on `/health/ready` means Postgres or Redis is unreachable - see
   runbooks 2 and 3.
4. Common fixes:
   - CrashLoopBackOff: read the last logs; often a bad `SECRET_KEY`
     (>= 32 chars for `ENVIRONMENT=prod`) or a failed migration.
   - ImagePullBackOff: image tag not published / registry creds missing.
   - OOMKilled: raise the memory `limit` (now 512Mi) before scaling.
5. Roll back a bad deploy:
   ```bash
   kubectl -n sentinel-ids rollout undo deploy/backend
   ```
6. If migrations raced between replicas, run a single one-shot migration first
   (see `infra/k8s/README.md`), then restart.

## 2. Database full

**Symptoms:** insert errors, `database is full` logs, disk alerts on the PVC.

1. Check usage:
   ```bash
   kubectl -n sentinel-ids exec postgres-0 -- \
     sh -c 'psql -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT pg_database_size(current_database());"'
   kubectl -n sentinel-ids get pvc
   ```
2. Find the biggest tables (Timescale chunks included):
   ```bash
   kubectl -n sentinel-ids exec postgres-0 -- \
     sh -c 'psql -U $POSTGRES_USER -d $POSTGRES_DB -c "SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 20;"'
   ```
3. Verify retention jobs ran; if the chunk interval is too coarse, re-check
   `TIMESCALE_CHUNK_INTERVAL_DAYS` (1 day) and retention/drop policies.
4. Take a backup FIRST (`scripts/backup.sh`), then prune:
   - Raw packet/event tables with an old ingest time are the usual candidates
     for a `DELETE` + `drop_chunks` policy; keep audit-required rows.
5. Grow the PVC if the data is genuinely needed (resize `postgres-data`, the
   underlying StorageClass must allow expansion):
   ```bash
   kubectl -n sentinel-ids patch pvc postgres-data -p '{"spec":{"resources":{"requests":{"storage":"40Gi"}}}}'
   ```
6. Watch: `kubectl -n sentinel-ids get pvc postgres-data -w`.

## 3. Redis down

**Symptoms:** backend `/health/ready` flips to 503, Celery queues stall,
rate limiting stops working, cache misses spike.

1. Confirm:
   ```bash
   kubectl -n sentinel-ids get pods -l app=redis
   kubectl -n sentinel-ids logs deploy/redis --tail=100
   ```
2. Restart and wait for readiness: `kubectl -n sentinel-ids rollout restart deploy/redis`.
3. Because Redis is the Celery broker, jobs queued during the outage are lost
   unless `CELERY_TASK_ALWAYS_EAGER` or a durable transport is in play.
   After recovery, re-trigger scheduled/periodic tasks
   (`CELERY_BEAT_SCHEDULE_ENABLED=true` restarts the beat schedule).
4. Verify the worker reconnects:
   ```bash
   kubectl -n sentinel-ids exec deploy/worker -- \
     celery -A app.core.celery_app inspect ping
   ```
5. Long-term: enable AOF persistence on the redis Deployment (`redis.yaml`
   already ships `--appendonly yes` + periodic saves; the volume is emptyDir,
   swap for a PVC if Redis data must survive node restarts).

## 4. Celery worker stuck

**Symptoms:** task queue grows, jobs never complete, "unacked" messages, no
worker heartbeat.

1. Check workers:
   ```bash
   kubectl -n sentinel-ids get pods -l app=worker
   kubectl -n sentinel-ids logs deploy/worker --tail=200
   ```
2. Ping workers from the backend pod:
   ```bash
   kubectl -n sentinel-ids exec deploy/worker -- \
     celery -A app.core.celery_app inspect ping --timeout 5
   ```
3. A single stuck task can wedge a prefetching worker. The sane move is a
   rolling restart (`kubectl -n sentinel-ids rollout restart deploy/worker`)
   so unacked tasks are redelivered.
4. If a specific task always fails, disable it via
   `CELERY_TASK_ALWAYS_EAGER`? No - set its `retry` budget down or disable the
   offending task temporarily, then fix the code. Set
   `CELERY_WORKER_MAX_TASKS_PER_CHILD=200` (already default) so memory leaks
   recycle workers automatically.
5. Broker trouble: see runbook 3. Queue metrics live on the Prometheus
   `/metrics` endpoint of the worker/backend.

## 5. Alert flood / incident response

**Symptoms:** a real detection triggers thousands of correlated alerts; on-call
channel is overwhelmed; dashboards red.

1. STOP. Never silence everything blindly - narrow first:
   - Which sensor/target/rule drives the flood? (Grafana: alerts by rule,
     source IP, signature.)
   - Is it a real attack or a misconfiguration (e.g. a broken parser emitting
     malformed flows, or a stale rule firing on benign traffic)?
2. Reduce noise, keep signal:
   - Pause the offending YARA/flow/UEBA rule or detector
     (`DETECTION_ENABLED`, `YARA_DETECTOR_ENABLED`, `UEBA_ENABLED` are env
     toggles) rather than disabling all detection.
   - Raise alert thresholds / severity mapping for the false-positive source.
3. Communicate: one page in the incident channel with status, blast radius,
   and the person investigating. Update hourly.
4. If it IS an attack: preserve evidence (Loki logs, DB snapshots via
   `scripts/backup.sh`), block the source via the OPNsense connector or at the
   ingress/WAF, then run the mitigation from the playbook, not ad hoc.
5. Aftermath: post-incident review with timeline, root cause, and a rule change
   so the same flood cannot repeat.

## 6. Certificate expiry

**Symptoms:** TLS handshake errors, `SSL certificate has expired`, cert-manager
warnings, browser "not secure".

1. Check expiry:
   ```bash
   kubectl -n sentinel-ids get certificate sentinel-tls
   kubectl -n sentinel-ids get secret sentinel-tls -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -noout -enddate
   ```
   Bare metal: `openssl x509 -enddate -noout -in /etc/letsencrypt/live/sentinel.example.com/fullchain.pem`.
2. Kubernetes: cert-manager renews automatically (letsencrypt-prod issuer).
   If renewal stalls, check `kubectl -n sentinel-ids get certificaterequest`
   and the cert-manager logs; usually DNS validation or the ClusterIssuer.
3. Manual renewal: re-run certbot (`certbot renew`), reload nginx
   (`nginx -t && systemctl reload nginx`).
4. Alert on expiry with a Prometheus rule (e.g.
   `time() - process_start_time_seconds` trick or
   `certmanager_certificate_expiration_timestamp_seconds`).

## 7. Backup restore drill

**Goal:** prove backups restorable before you need them. Run monthly, or after
any schema migration.

1. Take a fresh backup: `scripts/backup.sh`.
2. Restore into a scratch DB: `scripts/restore_test.sh` (sanity-checks
   `SELECT count(*) FROM users;` and drops the scratch DB).
3. For a full DR restore into the live DB (or a new cluster):
   ```bash
   gunzip -c /var/backups/sentinel/latest.sql.gz | psql -h <pg-host> -U sentinel -d sentinel_ids
   # if the schema moved past the backup:
   alembic upgrade head
   ```
4. Verify: log in, check alert counts, compare row counts vs. the manifest
   `size_bytes`/`sha256`.
5. RDS flavor: rely on automated snapshots as the primary chain and keep the
   `scripts/` chain for portability.

## 8. Secrets rotation

Rotate credentials on a schedule or after a leak. The app resolves
`SECRET_KEY` as env -> `SECRET_KEY_FILE` -> Vault
(`backend/app/services/secrets.py`), so rotation should not require a code
deploy.

1. Generate new values (>= 32 chars):
   ```bash
   openssl rand -base64 32
   ```
2. Kubernetes:
   - Patch the Secret: `kubectl -n sentinel-ids edit secret sentinel-secrets`
     (or regenerate via `kustomize build | kubectl apply -k` if using the
     generator).
   - Roll the consumers so pods pick it up:
     `kubectl -n sentinel-ids rollout restart deploy/backend deploy/worker`
   - **Order matters for the DB password**: update `POSTGRES_PASSWORD` and the
     backend `DATABASE_URL` (which embeds the password) in lockstep, otherwise
     pods lose their DB connection.
3. AWS: update the `sentinel/env` secret in Secrets Manager, then
   `aws ecs update-service --service backend --force-new-deployment`.
4. JWT: rotating `SECRET_KEY` invalidates existing tokens - schedule during
   low traffic and expect a mass re-login.
5. Verify: `/health/ready` green, a login works, worker pings.

## 9. Scaling out

**Signals:** sustained CPU > 60% on the backend, queue depth on the worker,
p95 latency rising, or memory near the 512Mi limit.

1. Backend API (stateless):
   ```bash
   kubectl -n sentinel-ids scale deploy/backend --replicas=4
   ```
   Remember per-pod `UVICORN_WORKERS=2` already multiplies concurrency; prefer
   more pods over more workers when CPU is the constraint. Raise the pod CPU
   limit above 500m only if latency is CPU-bound and not just saturation.
2. Worker (queue throughput): scale `deploy/worker`; tune
   `CELERY_WORKER_CONCURRENCY` in the ConfigMap. Idle workers are cheap, so
   over-provision slightly to absorb bursts.
3. Postgres: single-writer. Scale storage and connections first
   (`DB_POOL_SIZE`, `DB_MAX_OVERFLOW` in the ConfigMap); if reads saturate,
   move read replicas (TimescaleDB + streaming replication).
4. Frontend: stateless nginx - scale freely.
5. AWS: raise `desired_count` in `aws_ecs_service.*` or enable Application
   Autoscaling on CPU.
6. After scaling, re-check p99 (runbook 10) and the Prometheus
   `/metrics` `process_cpu_seconds_total` trends.

## 10. p99 latency degradation

**Symptoms:** p99 rises while p50 is fine (tail latency), timeouts on long
requests, WebSocket drops.

1. Get the numbers from Grafana: request duration by route
   (`prometheus_fastapi_instrumentator` histograms on `/metrics`), upstream
   response times, GC/prometheus scrape cost.
2. Typical causes in order of likelihood:
   - **Saturated Postgres** (see runbook 2): index-worthy queries, missing
     `DROP CHUNK` retention, connection pool exhaustion
     (`DB_POOL_TIMEOUT` alarms).
   - **Redis cache misses** hammering the DB (check
     `REDIS_CACHE_TTL_SECONDS`).
   - **Lock contention** in the in-memory WS hub or slow Celery tasks that
     block on shared resources.
   - **Slow outliers**: JSON payloads > 10m are rejected at the proxy; large
     flow/event queries without a chunk-friendly WHERE (always filter by time).
3. Fixes: add missing indexes on time-partitioned hypertables; increase
   connection pool size up to the DB limit; raise the nginx/ingress
   `proxy_read_timeout` only where real long-polls exist (never globally for
   the API).
4. Confirm with a load test against staging (Compose flavor) before rolling to
   prod, then watch p99 for 24h.
