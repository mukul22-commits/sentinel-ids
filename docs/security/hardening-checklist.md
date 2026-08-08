# Sentinel IDS v3 - Production Hardening Checklist

Owner: <PLATFORM OWNER>. Review this list before every production rollout and after any
infrastructure change. Each item is a checkbox with a one-line rationale. Items marked `(*)`
are the highest priority - they are residual risks from `threat-model.md`.

## 1. Backend configuration

- [ ] `SECRET_KEY` rotated from any default and >= 32 characters; the app refuses the default
  value in `prod` (`backend/app/core/config.py`), but rotation must be an operational habit.
- [ ] (*) Secrets resolved via `SECRET_KEY_FILE` or HashiCorp Vault, not plain env vars, so
  credentials are not readable from the process environment or compose files
  (`backend/app/services/secrets.py`).
- [ ] `CORS_ORIGINS` set to the exact production origin(s); never `*`, and no
  `http://localhost` origins in prod (`backend/app/core/config.py`).
- [ ] `FRONTEND_URL` matches the production origin used for the OIDC redirect
  (`backend/app/api/v1/routes/auth.py`).
- [ ] `ENVIRONMENT=prod` set so HSTS is emitted (`backend/app/core/middleware.py`) and the
  secret-key guard is active.
- [ ] `RATE_LIMIT_AUTH` / `RATE_LIMIT_API` reviewed for the production traffic profile
  (defaults 5/min and 100/min).
- [ ] Redis-backed rate limiting confirmed (`rate_limit_storage_uri` returns the Redis URL in
  prod; `memory://` is test-only).
- [ ] Pydantic schemas configured with `extra="forbid"` where feasible so unknown fields are
  rejected instead of silently ignored (mass-assignment hardening, TH-10).
- [ ] Reverse proxy overwrites `X-Forwarded-For` from the connection socket so the app never
  trusts a client-supplied header (TH-09).
- [ ] `/metrics` not exposed publicly; either LB-blocked or behind authentication, as it leaks
  internal counters.
- [ ] `/docs` and `/openapi.json` exposure policy decided (blocked publicly or explicitly
  accepted as a documented inventory).
- [ ] `UVICORN_WORKERS` and resource limits sized for the expected alert rate; add
  `--limit-max-requests`/graceful-timeout tuning before prod load.

## 2. Database (PostgreSQL / TimescaleDB)

- [ ] (*) Least-privilege DB roles: the application connects with a role that can
  `SELECT`/`INSERT`/`UPDATE`/`DELETE` on app tables but NOT `ALTER`/`DROP` schema, and the
  `audit_logs` table is append-only for the app role (TH-14).
- [ ] Strong `POSTGRES_PASSWORD` (never the compose default `sentinel`) supplied via secrets,
  not compose defaults (`infra/docker-compose.yml`).
- [ ] TLS between backend and PostgreSQL enabled (`sslmode=require` in `DATABASE_URL`).
- [ ] Database port not published to the public internet (`POSTGRES_PORT` binding limited to
  the host/private network).
- [ ] Automated backups configured with tested restore; `pg_dump` or volume snapshots with a
  retention policy covering the SIEM export window.
- [ ] Backups encrypted at rest and stored separately from the primary host.
- [ ] Connection pool limits reviewed (`DB_POOL_SIZE`, `DB_MAX_OVERFLOW`) so a burst of API
  traffic cannot exhaust the database connections.

## 3. Redis

- [ ] `REDIS_URL` uses a strong password (`redis://:<password>@...`) - the compose default is
  unauthenticated (`infra/docker-compose.yml`).
- [ ] TLS (or a trusted private network) for Redis; the token store and rate limiter hold
  session-relevant data (TH-02, TH-09).
- [ ] Redis port bound to the private network only; never exposed publicly.
- [ ] `rename-command` hardening for dangerous commands (`FLUSHALL`, `KEYS`) if the Redis
  instance is reachable beyond the app network.
- [ ] Persistence (`AOF`) enabled so rate-limit and token-revocation state survive restarts;
  accept the tradeoff against eviction of the blocklist.

## 4. Frontend

- [ ] (*) Tokens stored in `httpOnly`, `Secure`, `SameSite` cookies rather than `localStorage`
  to reduce XSS token theft (TH-02). If the SPA continues to use `localStorage`, document the
  accepted risk and pair with a strict CSP.
- [ ] `Content-Security-Policy` header added at nginx: `default-src 'self'`; allow only the
  API origin and the WebSocket origin; block `unsafe-inline`/`unsafe-eval` in prod
  (`frontend/nginx.conf` currently sets no CSP - gap).
- [ ] No secrets, API keys, or default credentials baked into the frontend bundle (search the
  built `dist/` output in CI).
- [ ] Referrer policy and frame-ancestors configured to prevent clickjacking
  (backend already sends `X-Frame-Options: DENY`).
- [ ] Frontend nginx adds the same security-header set (`nosniff`, `frame-options`,
  `Referrer-Policy`, `Cache-Control: no-store`) since the API middleware does not cover SPA
  responses.
- [ ] `/ws` proxy does not log the `token` query parameter (TH-16); redact full URLs in nginx
  access logs.

## 5. Deployment

- [ ] Backend and worker run as a non-root user (already `USER appuser` in
  `backend/Dockerfile`); confirm the entrypoint does not require root at runtime.
- [ ] Containers use read-only root filesystems where feasible (`read_only: true`), with
  writable volumes only where the app writes (e.g. `/tmp/sentinel-prom`, model dirs).
- [ ] Resource limits (`mem_limit`, `cpus`) set per service so one container cannot starve
  the stack (TH-15).
- [ ] `restart: unless-stopped` reviewed; healthchecks confirmed on backend, postgres, redis,
  worker (`infra/docker-compose.yml`).
- [ ] Docker images pinned by digest in production, not mutable tags (`python:3.12-slim`,
  `node:22-alpine`, base images in `backend/Dockerfile`, `frontend/Dockerfile.prod`).
- [ ] Container images scanned with Trivy in CI before push (see `dependency-scanning.md`).
- [ ] No Docker socket mounted into app containers (promtail's socket mount is an observability
  exception - keep it read-only and scoped).
- [ ] OIDC, connector, SIEM, SMTP credentials injected at deploy time via secrets; `.env`
  files never committed.
- [ ] Grafana/Flower dev services excluded from production profile (Flower is already
  `profiles: ["dev"]`); Grafana admin password forced and sign-up disabled.

## 6. Monitoring

- [ ] Audit log coverage verified: register, login, login_failed, lockout, refresh, logout,
  change/reset password, user updates, rule/ioc/policy/sensor mutations, response-action
  execution (`backend/app/services/audit.py`).
- [ ] Alerting on `auth.login_failed` bursts and `auth.login_blocked` events via Prometheus +
  Grafana rules (`infra/prometheus/alerts.yml`).
- [ ] Alerting on 5xx rate, detection-engine errors, SIEM export failures, and stale sensors
  (`SENSOR_STALE_AFTER_SECONDS`).
- [ ] Access logs shipped to Loki (promtail) with `X-Request-ID` correlation
  (`backend/app/core/middleware.py`).
- [ ] Log retention and access policy defined; logs treated as sensitive (they may contain
  IPs and email addresses).
- [ ] PagerDuty/email escalation defined for `critical` alerts; runbook links included.

## 7. Incident response

- [ ] Runbook for account takeover: revoke user tokens (`revoke_user_tokens`), rotate sensor
  tokens, review audit trail (`user.update`, `auth.*`).
- [ ] Runbook for SIEM/connector compromise: disable `SIEM_EXPORT_ENABLED`, rotate
  `SIEM_AUTH_TOKEN` and connector credentials, review `SiemExportRun` failures.
- [ ] Runbook for detection-engine DoS: throttle ingest (`RATE_LIMIT_API`), disable
  expensive detectors, scale the worker.
- [ ] Defined severity/response SLA for the findings in `pen-test-report-*.md`.
- [ ] Backup restore drill performed at least quarterly and recorded.
- [ ] Key rotation drill: `SECRET_KEY`, DB password, Redis password, sensor tokens - with a
  documented "rotate everything" checklist.
- [ ] Post-incident review template used and findings fed back into `threat-model.md`.

## Sign-off

| Role | Name | Date |
| --- | --- | --- |
| Platform owner | <NAME> | <YYYY-MM-DD> |
| Security lead | <NAME> | <YYYY-MM-DD> |
