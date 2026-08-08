# Sentinel IDS Platform v3.0

**Detect, Analyze, Respond – Secure Every Packet, Every Time.**

Sentinel is an enterprise Network Intrusion Detection & Response (NIDS/NIDR) platform. This
repository ships the full platform through **Phase 12**: core backend (auth, detection,
incident response), a React SPA, fleet/sensor management, ML + UEBA analytics, and deploy
artifacts (Docker Compose, Kubernetes, Terraform/AWS, CI/CD).

## Repository layout

```
sentinel-ids/
├── .github/workflows/ci.yml        # CI: lint, test, build, security, e2e, load, zap
├── backend/                        # FastAPI + SQLAlchemy 2.0 (Python 3.12)
│   ├── app/
│   │   ├── main.py                 # app factory, middleware, /metrics
│   │   ├── api/v1/                 # router aggregator + endpoint modules
│   │   ├── core/                   # config, logging, middleware, celery_app, security
│   │   ├── models/                 # users, packets, alerts, rules, incidents, iocs, sensors…
│   │   ├── schemas/                # Pydantic v2 (incl. response Envelope)
│   │   ├── services/               # detection, connectors, cache, ml, ueba, yara
│   │   ├── tasks/                  # Celery beat + queued tasks
│   │   └── db/                     # async engine, session, DeclarativeBase
│   ├── tests/                      # pytest (asyncio_mode=auto, ~100% route coverage)
│   ├── alembic/                    # async migrations (0001…0008)
│   ├── Dockerfile                  # multi-stage, non-root appuser + HEALTHCHECK
│   ├── pyproject.toml              # Black / Ruff / mypy / pytest config
│   └── requirements.txt            # pinned dependencies
├── frontend/                       # React 19 + TypeScript + Vite + Tailwind v4
│   ├── src/                        # api client, auth, realtime, components, pages, hooks
│   ├── vite.config.ts              # dev proxy /api, /ws -> localhost:8000
│   ├── Dockerfile                  # dev (vite) + Dockerfile.prod (non-root nginx)
│   └── nginx.conf                  # SPA + /api + /ws reverse proxy for prod image
├── infra/
│   ├── docker-compose.yml          # postgres(Timescale), redis, backend, worker, flower, frontend, observability
│   ├── docker-compose.override.yml # dev hot-reload volumes
│   ├── docker-compose.e2e.yml      # CI test/e2e rate-limit overrides
│   ├── postgres/init/              # timescaledb extension bootstrap
│   ├── prometheus|grafana|loki|promtail/  # observability configs + dashboards
│   ├── k8s/                        # Kubernetes manifests
│   ├── nginx/                      # standalone nginx reverse-proxy config
│   └── terraform/aws/              # AWS: VPC, ECS Fargate, ALB (HTTP/HTTPS), ECR
├── e2e/                            # Playwright end-to-end suite
├── scripts/                        # helper tooling
├── zap/                            # OWASP ZAP DAST policy
├── docs/                           # architecture, security, deploy, load
├── .pre-commit-config.yaml
└── Makefile                        # make up / lint / test / ...
```

## Prerequisites

- **Docker Desktop** (Docker Engine 24+ with Compose v2)
- **Python 3.12** (for native lint/test runs; Docker uses its own 3.12 image)
- **Node.js 22+** and **npm 11+** (for native frontend runs)
- **GNU Make** (Linux/macOS built-in; on Windows use WSL2 or Git Bash)
- **Git** 2.40+

## Quick start (Docker)

```bash
# 1. Create environment files from templates
cp .env.example .env
cp backend/.env.example backend/.env        # optional; matches defaults

# 2. Start everything (postgres, redis, worker, backend, frontend)
make up                     # or: docker compose -f infra/docker-compose.yml up -d --build

# 3. Apply the initial migration
make backend-shell          # then inside the container:
alembic upgrade head

# 4. Verify (see "Verification" below)
```

### Service URLs

| Service  | URL                                |
| -------- | ---------------------------------- |
| Frontend | http://localhost:5173              |
| Backend  | http://localhost:8000              |
| API docs | http://localhost:8000/docs         |
| Metrics  | http://localhost:8000/metrics      |
| Flower (Celery UI) | http://localhost:5555 (profile `dev`) |
| PostgreSQL (TimescaleDB) | localhost:5432 (`sentinel` / `sentinel`) |
| Redis    | localhost:6379                     |
| Prometheus | http://localhost:9090              |
| Grafana  | http://localhost:3000 (admin / admin) |
| Loki     | http://localhost:3100              |

## API endpoints

| Method | Path                | Description                              |
| ------ | ------------------- | ---------------------------------------- |
| GET    | `/health`           | Liveness + DB/Redis connectivity (Phase 1 shape) |
| GET    | `/health/ready`     | 200 only when Postgres + Redis reachable (503 otherwise) |
| GET    | `/health/live`      | Process liveness, always 200             |
| GET    | `/metrics`          | Prometheus metrics (label `app="sentinel-ids"`) |
| GET    | `/api/v1/ping`      | `{"success": true, "data": "pong", ...}` |
| GET    | `/api/v1/system/info`  | App metadata (enveloped)              |
| GET    | `/api/v1/system/stats` | Uptime stats, Redis-cached (`X-Cache` header) |
| GET    | `/api/v1/packets`      | List captured packets (filters: src/dst IP+port, protocol, since) |
| POST   | `/api/v1/packets`      | Ingest pcap upload, run detection, return ingest + alert summary |
| POST   | `/api/v1/packets/import` | Bulk pcap import (same detection pipeline) |
| GET    | `/api/v1/alerts`       | List alerts (filters: severity, status, detector, src_ip, since) |
| POST   | `/api/v1/alerts`       | Batch-create alerts (≤500)            |
| GET    | `/api/v1/alerts/{id}`  | Alert detail                          |
| PATCH  | `/api/v1/alerts/{id}/status` | Update alert status (open/in_progress/resolved/closed) |
| GET    | `/api/v1/rules`        | List detection rules (search, severity, enabled filters) |
| POST   | `/api/v1/rules`        | Create YAML signature rule            |
| GET/PATCH/DELETE | `/api/v1/rules/{id}` | Read / update (version-bumped) / delete a rule |
| GET    | `/api/v1/iocs`         | List IOCs (type, source, search filters) |
| POST   | `/api/v1/iocs`         | Create IOC                          |
| POST   | `/api/v1/iocs/bulk`    | Upsert 1–500 IOCs at once          |
| GET/PATCH/DELETE | `/api/v1/iocs/{id}` | Read / update / delete an IOC      |
| GET    | `/api/v1/captures`     | List live-capture cycle runs (adapter, status, packet/alert counts) |
| GET    | `/api/v1/captures/status` | Adapter status + last run per source (scapy_sniff/suricata_eve/zeek_conn) |
| POST   | `/api/v1/captures/run` | Run one capture cycle on demand (admin) |
| GET    | `/api/v1/policies`     | List response policies (admin/analyst) |
| POST   | `/api/v1/policies`     | Create a response policy (admin)      |
| GET/PATCH/DELETE | `/api/v1/policies/{id}` | Read / update / delete a policy   |
| GET    | `/api/v1/system/ml`    | ML model artifact + retrain config status |
| POST   | `/api/v1/system/ml/retrain` | Retrain the ML detector from packet history (admin) |
| GET    | `/api/v1/system/connectors` | List response connector plugins + enabled state |
| POST   | `/api/v1/system/connectors/{name}/test` | Probe a connector's endpoint (admin) |
| GET    | `/api/v1/system/siem/status` | SIEM export status, pending alert count, last run |
| POST   | `/api/v1/system/siem/test` | Send a CEF connectivity test event to the SIEM (admin) |
| POST   | `/api/v1/system/siem/export` | Run one SIEM export cycle now (admin) |
| GET    | `/api/v1/sensors/fleet`   | Fleet summary (totals + alerts/captures per sensor, last 24h) |
| GET    | `/api/v1/sensors`         | List sensors (status filter, paginated) |
| POST   | `/api/v1/sensors`         | Register a sensor (returns its one-time plaintext token) |
| GET/PATCH/DELETE | `/api/v1/sensors/{id}` | Read / update (rename, enable, identity) / delete a sensor |
| POST   | `/api/v1/sensors/{id}/rotate-token` | Rotate a sensor's token (old token invalidated) |
| POST   | `/api/v1/sensors/heartbeat` | Sensor health report (X-Sensor-Token auth) |
| GET    | `/api/v1/sensors/config`  | Effective capture config for a sensor (X-Sensor-Token auth) |

All `/api/v1/*` responses use the envelope:
`{"success": bool, "data": ..., "error": null, "request_id": "..."}`. Every response carries
`X-Request-ID`, `X-Process-Time`, and security headers.

## Verification

Backend health + ping:

```bash
curl http://localhost:8000/health
# {"status":"ok","version":"3.0.0","database":"connected","redis":"connected"}

curl http://localhost:8000/api/v1/ping
# {"success":true,"data":"pong","error":null,"request_id":"<uuid>"}
```

Cache behavior (`X-Cache` MISS then HIT) and metrics:

```bash
curl -i http://localhost:8000/api/v1/system/stats   # X-Cache: MISS
curl -i http://localhost:8000/api/v1/system/stats   # X-Cache: HIT
curl http://localhost:8000/metrics | grep sentinel_app_info
```

Hypertable check (after `alembic upgrade head`):

```bash
make backend-shell
psql "$DATABASE_URL" -c "SELECT hypertable_name, chunk_time_interval FROM timescaledb_information.hypertables;"
```

Phase 7 operational probes (admin token required for the auth-gated routes):

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/system/connectors
curl -H "Authorization: Bearer <token>" -X POST http://localhost:8000/api/v1/system/connectors/log_plan/test
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/system/siem/status
curl -H "Authorization: Bearer <token>" -X POST http://localhost:8000/api/v1/system/siem/export
```

HA note: scale the API with `UVICORN_WORKERS` (set `PROMETHEUS_MULTIPROC_DIR` for
multi-worker `/metrics` aggregation); the container runs migrations on boot and drains
gracefully on shutdown.

Frontend: open http://localhost:5173 — sign in (register an account) and land on the
Operations dashboard with incident KPIs, severity/status charts, and realtime WebSocket
updates. See [docs/architecture.md](docs/architecture.md) for the phase roadmap,
[e2e/README.md](e2e/README.md) for the Playwright suite, and
[docs/deploy/README.md](docs/deploy/README.md) for deployment options.

## Celery worker & Flower

- **Worker** runs beat tasks (`demo.health_check` every 30s, live-capture cycles,
  daily ML retraining, and periodic SIEM export) and processes queued tasks. Logs are
  JSON lines; a successful run logs `demo.health_check completed`.
- **Flower** is optional (profile `dev`):

```bash
docker compose -f infra/docker-compose.yml --profile dev up -d flower
open http://localhost:5555
```

To trigger the demo task manually:

```bash
make backend-shell
python -c "from app.tasks.demo import demo_health_check; print(demo_health_check.delay().get())"
```

## Commands

| Command              | Description                                          |
| -------------------- | ---------------------------------------------------- |
| `make up`            | Build + start all services                           |
| `make down`          | Stop services                                        |
| `make logs`          | Tail logs for all services                           |
| `make backend-shell` | Shell inside the backend container (run alembic etc.) |
| `make lint`          | ruff, black --check, mypy, eslint, prettier, tsc     |
| `make test`          | pytest (backend)                                     |
| `make format`        | black + ruff --fix, prettier --write                 |
| `make build`         | Build Docker images                                  |

## Running tests & linters natively

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest                  # unit tests (DB round-trip skips when Postgres is down)
ruff check .            # lint
black --check .         # formatting
mypy app                # type checks (strict)

# Frontend
cd frontend
npm ci
npm run lint            # ESLint
npm run format:check    # Prettier
npm run typecheck       # tsc --noEmit
npm run build           # production build
```

## Database migrations (Alembic)

Migrations run inside the backend container (or natively with the venv active):

```bash
make backend-shell
alembic upgrade head
alembic revision --autogenerate -m "add next model"   # Phase 3+
```

The async `env.py` reads `DATABASE_URL` from the application settings, so no
`alembic.ini` edits are needed. Migration `0001_initial_schema` creates all core tables and
converts `packets` into a TimescaleDB hypertable on `ts` (1-day chunks). Because TimescaleDB
requires unique indexes to include the partition column, the `packets` primary key is the
composite `(id, ts)`.

## Environment variables

| Variable         | Where        | Purpose                          |
| ---------------- | ------------ | -------------------------------- |
| `POSTGRES_USER/PASSWORD/DB` | root `.env` | compose postgres bootstrap |
| `POSTGRES_PORT`/`REDIS_PORT` | root `.env` | host port mappings |
| `APP_NAME`/`APP_VERSION` | backend env | app metadata |
| `ENVIRONMENT`    | backend env  | `dev` / `test` / `prod` (validated) |
| `DATABASE_URL`   | backend env  | asyncpg DSN (validated to use asyncpg) |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` / `DB_POOL_RECYCLE_SECONDS` | backend env | async pool tuning |
| `REDIS_URL` / `REDIS_CACHE_TTL_SECONDS` | backend env | cache + Celery broker/backend |
| `CELERY_TASK_ALWAYS_EAGER` / `CELERY_WORKER_CONCURRENCY` / `CELERY_BEAT_SCHEDULE_ENABLED` | backend env | Celery config |
| `TIMESCALE_CHUNK_INTERVAL_DAYS` | backend env | hypertable chunk interval |
| `CORS_ORIGINS`   | backend env  | JSON list of allowed browser origins |
| `SECRET_KEY`     | backend env  | placeholder — Phase 3 (auth)     |
| `LOG_LEVEL` / `UVICORN_WORKERS` / `UVICORN_GRACEFUL_TIMEOUT` | backend env | log level + multi-worker uvicorn + graceful drain (Phase 7) |
| `PROMETHEUS_MULTIPROC_DIR` | backend env | Prometheus multi-worker aggregation dir (Phase 7) |
| `DB_POOL_PRE_PING` / `DB_POOL_TIMEOUT` | backend env | pool health validation + acquire timeout |
| `HTTP_CONNECTOR_URL` / `HTTP_CONNECTOR_TOKEN` | backend env | webhook enforcement connector (block/quarantine) |
| `EMAIL_SMTP_HOST` / `EMAIL_SMTP_PORT` / `EMAIL_SMTP_USERNAME` / `EMAIL_SMTP_PASSWORD` / `EMAIL_FROM_ADDR` | backend env | SMTP email connector (notify) |
| `SIEM_EXPORT_ENABLED` / `SIEM_CEF_ENDPOINT_URL` / `SIEM_AUTH_TOKEN` / `SIEM_BATCH_SIZE` / `SIEM_EXPORT_SECONDS` | backend env | ArcSight CEF export to an external SIEM |
| `CAPTURE_ENABLED` / `CAPTURE_CYCLE_SECONDS` | backend env | live capture master switch + beat interval |
| `SNIFF_INTERFACE` / `SNIFF_COUNT` / `SNIFF_TIMEOUT` | backend env | Scapy live-sniff adapter (requires Npcap/libpcap; leave unset to disable) |
| `SURICATA_EVE_PATH` / `ZEEK_CONN_LOG_PATH` | backend env | Suricata `eve.json` / Zeek `conn.log` paths (file or dir) for those adapters |
| `ML_RETRAIN_MIN_SAMPLES` / `ML_RETRAIN_CONTAMINATION` | backend env | ML retraining threshold + anomaly contamination |
| `SENSOR_TOKEN_BYTES` | backend env | entropy (bytes) per sensor token (default 32) |
| `SENSOR_STALE_AFTER_SECONDS` / `SENSOR_WATCHDOG_SECONDS` | backend env | heartbeat window before a sensor flips offline + watchdog beat interval |

## Git workflow

- **Trunk-based**: `main` is always deployable; short-lived branches off it.
- Branch naming: `feature/phase-<N>-<slug>`, e.g. `feature/phase-2-core-backend`.
- **Conventional Commits**: `feat:`, `fix:`, `chore:`, `docs:`, `test:`.
- Pre-commit hooks run on every commit: `pre-commit install`.

## CI/CD

`.github/workflows/ci.yml` runs on push to `main` and on pull requests:

- **lint** — ruff, black --check, mypy (Python 3.12) + ESLint, Prettier, tsc, frontend unit tests (Node 22)
- **test** — boots postgres + redis via docker compose, runs the backend pytest suite
- **build** — `docker compose build` verifies the dev images + builds the non-root `Dockerfile.prod`
- **security** — gitleaks secret scan, Bandit SAST, Semgrep, pip-audit, npm audit, Trivy (backend + frontend)
- **e2e** — Playwright against a live compose stack (chromium)
- **load** / **zap** — manual-run Locust load test and ZAP DAST API scan (workflow_dispatch)

## Frontend stack note

Frontend runs **Tailwind v4** (v4.3) via the `@tailwindcss/vite` plugin — CSS-first config
(`@import "tailwindcss"` in `src/index.css`), no `tailwind.config.js` / `postcss.config.js`.

## Troubleshooting

- **Ports already in use** — stop local Postgres/Redis or change `POSTGRES_PORT`/`REDIS_PORT` in `.env`.
- **Backend shows `database: disconnected`** — postgres is still starting; wait for the healthcheck then `make logs` to confirm "Application startup complete".
- **Worker not healthy** — confirm Redis is up; `celery inspect ping` needs the broker reachable.
- **Hot reload not picking up changes** — confirm `docker-compose.override.yml` is next to `docker-compose.yml` and you started via `make up`.
- **Redis `NOAUTH` errors** — the compose Redis now requires the `REDIS_PASSWORD` (default `sentinel_redis`). Set `REDIS_PASSWORD` in your root `.env` and keep `REDIS_URL` in sync (`redis://:PASSWORD@redis:6379/0`).

See [docs/architecture.md](docs/architecture.md) for the v3.0 architecture and phase roadmap.
