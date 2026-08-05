# Sentinel IDS Platform v3.0 — Architecture

## Overview

Sentinel is an enterprise Network Intrusion Detection & Response platform spanning the full
detection pipeline: packet acquisition, normalization, detection, alerting, and response.
This document summarizes the target v3.0 architecture and maps each phase to the work that
lands in this repository.

## Technology stack

| Layer        | Technology                                              |
| ------------ | ------------------------------------------------------- |
| Backend API  | Python 3.12, FastAPI, Pydantic v2                        |
| ORM / DB     | SQLAlchemy 2.0 (async), Alembic, PostgreSQL 16 + TimescaleDB |
| Queue / Cache| Celery, Redis 7                                          |
| Realtime     | WebSockets (backend), Socket.io client (frontend)        |
| Frontend     | React 19, TypeScript, Vite, Tailwind CSS, React Router, TanStack Query, Recharts/ApexCharts |
| Packet/AI    | Scapy, PyShark, Suricata, Zeek, YARA, scikit-learn, PyTorch |
| Observability| Prometheus, Grafana, ELK/Loki                            |

## Backend layout (Phases 1–2)

```
backend/
  app/
    main.py          # app factory, lifespan, middleware stack, /metrics
    api/v1/
      router.py      # v1 aggregator (/ping) + health/system/packets/alerts routers
      endpoints/     # health.py, system.py, packets.py, alerts.py
      deps.py        # get_request_id dependency
    core/
      config.py      # pydantic-settings + environment validation
      logging.py     # JSON formatter (logstash-compatible) on stdout
      middleware.py  # X-Request-ID, X-Process-Time, security headers, access log
      celery_app.py  # Celery instance (Redis broker/backend) + beat placeholder
    models/          # SQLAlchemy 2.0 Mapped[] ORM: users, packets, alerts, rules,
                     #   incidents, audit_logs, iocs
    schemas/         # Pydantic v2 models + response Envelope
    services/        # cache.py (async Redis helpers), packet/alert stubs
    tasks/demo.py    # demo.health_check Celery task
    db/              # base.py (DeclarativeBase), session.py (async engine + checks)
  alembic/           # async env.py + 0001_initial_schema
  tests/             # pytest with asyncio_mode=auto
```

### Key behaviors

- **Response envelope** for every v1 endpoint:
  `{"success": bool, "data": ..., "error": null, "request_id": "..."}`.
- **Middleware**: `X-Request-ID` (uuid4, echoed in response + access logs), `X-Process-Time`,
  security headers (`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`).
  Access logs are one JSON line per request with `request_id`, `method`, `path`, `status`,
  `duration_ms` — ELK/Loki-ready via Filebeat later.
- **Health**: `/health` (Phase 1 shape), `/health/ready` (503 when DB/Redis down),
  `/health/live` (process liveness).
- **Metrics**: `prometheus-fastapi-instrumentator` exposes `/metrics`; a
  `sentinel_app_info{app="sentinel-ids", version=...}` gauge labels the app.
- **Cache**: `services/cache.py` async `get_json`/`set_json`/`delete` with TTL; `/system/stats`
  is cached and reports `X-Cache: HIT|MISS`.
- **Celery**: `demo.health_check` pings Postgres + Redis from the worker; beat schedule
  placeholder every 30s; eager mode enabled under `ENVIRONMENT=test`.
- **TimescaleDB**: `packets` is a hypertable on `ts` (1-day chunks). Because TimescaleDB
  requires unique indexes to include the partition column, `packets` uses the composite
  primary key `(id, ts)`.

## Infra topology

- `infra/docker-compose.yml`: `postgres` (timescale/timescaledb:latest-pg16, extension enabled
  via `postgres/init/01-extensions.sql`), `redis` (7-alpine), `worker` (celery), `backend`
  (multi-stage, non-root), `frontend` (Node 22 + Vite), `flower` (profile `dev`).
- `infra/docker-compose.override.yml`: dev-only source mounts + `--reload`.
- CI (`ci.yml`): lint (ruff/black/mypy + ESLint/Prettier/tsc), test (compose services +
  pytest incl. DB round-trip), build (docker compose build). Deps cached for pip and npm.

## Data flow (target)

1. **Capture** — Suricata/Zeek + Scapy ingest raw traffic from mirrored ports / pcap replay.
2. **Normalize & store** — packet/flow records in TimescaleDB hypertables; Redis for hot state.
3. **Detect** — signature (YARA/Suricata rules) + behavioral (scikit-learn/PyTorch) engines
   executed by Celery workers; alerts streamed to the UI over WebSockets.
4. **Respond** — policy-driven actions (block, quarantine, notify) via the orchestration layer.
5. **Observe** — Prometheus metrics, Grafana dashboards, Loki/ELK log aggregation.

## Phase map

| Phase | Scope                                                        | Status  |
| ----- | ------------------------------------------------------------ | ------- |
| 1     | Monorepo, Docker Compose, CI/CD, backend + frontend scaffolds, tooling | **Done** |
| 2     | Core backend: models, schemas, migration (hypertables), Redis cache, Celery worker, middleware, Prometheus, envelope API | **Done (this PR)** |
| 3     | Authn/authz (JWT), users + audit-log enforcement, real `SECRET_KEY` | Next    |
| 4     | Response orchestration, alerting, WebSocket realtime UI, dashboards (Recharts/ApexCharts) | Planned |
| 5     | Packet capture + detection engine (signature + ML), rules/IOC management, Prometheus/Grafana/Loki observability, Tailwind v4 | Planned |

## Deferred items (intentional)

- No auth (Phase 3); no packet capture/detection logic (Phase 5).
- `SECRET_KEY` remains a placeholder; production requires an override.
- `packets`/`alerts` endpoints are envelope-shaped stubs returning empty lists.
- Autogenerated migrations beyond `0001` will be produced against the live database in Phase 3.
