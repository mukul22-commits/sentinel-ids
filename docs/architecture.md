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
| Realtime     | WebSockets (backend + frontend)                            |
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
  (multi-stage, non-root), `frontend` (Node 22 + Vite), `flower` (profile `dev`), plus the
  observability stack: `prometheus` (scrapes backend `/metrics` + promtail), `loki`
  (log aggregation), `promtail` (Docker log driver → Loki via docker service discovery),
  and `grafana` (auto-provisioned datasources + `sentinel-overview` dashboard).
- `infra/docker-compose.override.yml`: dev-only source mounts + `--reload`.
- CI (`ci.yml`): lint (ruff/black/mypy + ESLint/Prettier/tsc), test (compose services +
  pytest incl. DB round-trip), build (docker compose build). Deps cached for pip and npm.

## Phase 5 detection core

- **Ingestion** — `services/packet_capture.py` parses pcap uploads with Scapy (magic-byte
  validation, SHA-256 payload hash, TCP/UDP ports); `services/packet_service.py` bulk-inserts
  into the `packets` hypertable. Uploads run the detection engine and return an ingest + alert
  summary.
- **Rules engine** — `services/rule_service.py` validates YAML rules (name, `match` section,
  severity ∈ low/medium/high/critical, metadata); edits bump the rule version. Managed through
  `/api/v1/rules`.
- **IOCs** — `services/ioc_service.py` upserts indicators on `(type, value)`, refreshing
  `last_seen`; `POST /api/v1/iocs/bulk` handles 1–500 at once.
- **Detection engine** — `services/detection/engine.py` composes `Detector` plugins.
  `signature.py` evaluates rule `match` trees (scalars case-insensitive, lists-as-any,
  operators `eq/ne/in/not_in/contains/regex/exists/gt/lt/ge/le`, CIDR for IPs, `any`/`all`/
  `not` combinators) against captured packet fields. `ml.py` scores 5-dim flow features with an
  IsolationForest (joblib), enabled when `ML_DETECTOR_ENABLED` + a trained model exist
  (`scripts/train_ml_detector.py`). Alerts are deduped per `(rule, detector, src/dst ip+port)`,
  persisted with severity-mapped risk, broadcast over WebSockets, and surfaced via
  `sentinel_alerts_created_total{severity,detector}` in `/metrics`.
- **Observability** — backend logs are structured JSON (Loki-ready); Prometheus alert rules
  (`AlertSpike`, `HttpErrors`) ship in `infra/prometheus/alerts.yml`; the Grafana dashboard
  panels cover HTTP rate/p95, alert rate by severity, error rate, and Loki log queries.

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
| 3     | Authn/authz (JWT), users + audit-log enforcement, real `SECRET_KEY` | **Done** |
| 4     | Response orchestration, alerting, WebSocket realtime UI, dashboards (Recharts/ApexCharts) | **Done** |
| 5     | Packet capture + detection engine (signature + ML), rules/IOC management, Prometheus/Grafana/Loki observability, Tailwind v4 | **Done** |
| 6     | Live capture integration (Scapy sniff, Suricata EVE, Zeek logs), response automation, ML retraining pipeline | **Done** |
| 7     | Production hardening (HA, external SIEM export, connector plugins) | **Done** |

## Phase 6 live capture, automation, and model lifecycle

- **Capture adapters** — `services/capture/` defines a `CaptureAdapter` interface
  (`enabled()`/`collect()` → normalized `PacketCreate` records). `SniffCaptureAdapter`
  runs a bounded Scapy `sniff` window on `SNIFF_INTERFACE` (Npcap/libpcap); `SuricataEveAdapter`
  ingests the trailing lines of Suricata `eve.json` (file or directory of `*.json`);
  `ZeekLogAdapter` parses Zeek `conn.log` (TSV header/rows). `CaptureManager.run_cycle`
  feeds each adapter's batch through ingestion + the detection engine and records a
  `capture_runs` row (`/api/v1/captures`, `/api/v1/captures/status`,
  `POST /api/v1/captures/run`). The `capture.cycle` Celery beat task runs cycles on a timer.
  Adapters self-disable when their source is unconfigured, so the stack runs with zero
  extra setup and live capture lights up as env vars are set.
- **Response automation** — `ResponsePolicy` (table `response_policies`) maps alert
  conditions (severity, detector, category, min risk score) to a playbook of response
  actions (`block`/`quarantine`/`notify`) with `{{src_ip}}`/`{{dst_ip}}` target templates
  and a per-`(policy, target)` Redis cooldown. `automation_service.trigger_automation`
  runs after every detection batch (wired into `DetectionEngine.run`), auto-creating an
  incident, planning + executing the policy's actions, and notifying staff. Policies are
  managed via `/api/v1/policies` (admin) and evaluated automatically thereafter.
- **ML retraining pipeline** — `services/detection/retrain.py` pulls recent flows from the
  `packets` hypertable, fits an IsolationForest, and atomically swaps
  `ML_MODEL_PATH` (temp file + `os.replace`, so inference never reads a partial model).
  It refuses to overwrite a working model when fewer than `ML_RETRAIN_MIN_SAMPLES` flows
  exist. Exposed as `GET /api/v1/system/ml` (metadata) and `POST /api/v1/system/ml/retrain`
  (admin), with a `ml.retrain` Celery beat task (daily).
- **Deployment note** — the sniff adapter runs inside the worker; live interface capture in
  Docker needs the `NET_ADMIN` capability + `SNIFF_INTERFACE`. Suricata/Zeek adapters only
  require mounted log files.

## Phase 7 production hardening, connectors, and SIEM export

- **Connector plugins** — `services/connectors/` defines a `Connector` plugin
  interface (`enabled()`/`execute()`/`test()`). The default set is `http_webhook`
  (block/quarantine via HTTP/S webhook with bearer auth), `smtp_email` (notify via
  SMTP, STARTTLS/implicit TLS, stdlib `smtplib` on a thread pool), and the always-on
  `log_plan` fallback that records the deterministic Phase 4 plan when no real
  integration is configured. `select_connector(action_type)` prefers the enabled
  connector for the action kind and falls back to `log_plan`, so response automation
  keeps working with zero configuration. `execute_response_action` now dispatches
  through connectors; failures mark the action `failed` (with the error in
  `details`) without breaking automation. Connector inventory + connectivity probes:
  `GET /api/v1/system/connectors`, `POST /api/v1/system/connectors/{name}/test`.
- **External SIEM export (ArcSight CEF)** — `services/siem/` renders each alert as a
  CEF line (severity mapped to the 0–10 scale, header/extension escaping) and pushes
  newline-delimited batches to `SIEM_CEF_ENDPOINT_URL`. Export is durable: a
  `siem_exports` table records each run and `alerts.siem_exported_at` is a watermark
  (partial index `ix_alerts_siem_pending` keeps the pending scan fast). The batch
  query uses `SELECT ... FOR UPDATE SKIP LOCKED`, so concurrent workers each claim
  disjoint alerts (HA-safe). Export runs on the `siem.export_alerts` Celery beat task
  (default 60s) or on demand (`POST /api/v1/system/siem/export`); status and endpoint
  connectivity via `GET /api/v1/system/siem/status` and `POST /api/v1/system/siem/test`.
- **Production hardening (HA)** — the API runs multiple uvicorn workers
  (`UVICORN_WORKERS`, graceful drain via `--timeout-graceful-shutdown`); the container
  entrypoint runs `alembic upgrade head` on boot (skip with `SKIP_MIGRATIONS=1`).
  Prometheus metrics aggregate across workers via `PROMETHEUS_MULTIPROC_DIR` and a
  `MultiProcessCollector` on `/metrics`. DB pool uses `pool_pre_ping` + `pool_timeout`
  for resilience; Celery uses `task_acks_late`, prefetch 1, and per-child task limits.
  API responses are `no-store` with hardened security headers (HSTS in prod), and
  `LOG_LEVEL` drives structured JSON logging.

## Deferred items (intentional)

- Connector implementations beyond webhook/SMTP (firewall SDKs, EDR, SOAR) are
  drop-in plugins behind the same interface.
- `SECRET_KEY` remains a placeholder; production requires an override (enforced).
- Schema evolution is tracked in committed Alembic migrations: `0001` (initial),
  `0002` (response_actions, notifications), `0003` (Phase 3 auth columns),
  `0004` (Phase 5 alert title/detector/details), `0005` (Phase 6
  `response_policies` + `capture_runs`), `0006` (Phase 7 `alerts.siem_exported_at`
  watermark + `siem_exports`).
