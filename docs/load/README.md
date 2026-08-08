# Sentinel IDS v3 — Load Testing

## Purpose

Validate capacity, latency percentiles, and error rates under sustained load for the
Sentinel IDS v3 backend. The scenarios in `locustfile.py` exercise the most frequent
user-facing and write paths:

- system status, alert/incident/rule/sensor listing (read path)
- alert and incident creation (write path)
- authentication bootstrap (register/login) per simulated user

Results are captured as Locust HTML and CSV reports and, where available, cross-checked
against Prometheus/Grafana metrics on the deployed stack.

## Prerequisites

- Local stack running from the repository root:

  ```bash
  docker compose -f infra/docker-compose.yml up -d --wait postgres redis backend frontend
  ```

  The backend is reachable on `http://localhost:8000`.
- Python 3.11+ with `pip install locust`.
- Confirm the API is healthy before starting a run:

  ```bash
  curl -s http://localhost:8000/api/v1/ping
  ```

## How to run

Install the driver (once):

```bash
pip install locust
```

Run a representative 10-minute sustained test headlessly:

```bash
locust -f locustfile.py --host http://localhost:8000 \
  --users 50 --spawn-rate 5 --run-time 10m \
  --headless --html reports/load.html --csv reports/load
```

Artifacts land in `reports/` (`load.html`, `load_stats.csv`,
`load_stats_history.csv`, `load_failures.csv`). The target host can be overridden
without editing the file:

```bash
export TARGET_HOST=http://staging.example.com
```

For an interactive run with the web UI, drop `--headless --run-time` and browse to
`http://localhost:8089`.

## Sizing guide

| Scenario | Users | Spawn rate | Duration | Notes |
| -------- | ----- | ---------- | -------- | ----- |
| Smoke    | 10    | 2/s        | 5 min    | Sanity check after deploy; verify wiring and rate limits |
| Baseline | 50    | 5/s        | 10 min   | Standard sustained run used for the acceptance report |
| Soak     | 100   | 10/s       | 30 min   | Memory leaks, connection churn, DB growth |
| Spike    | ramp to 500 | 50/s  | ~5 min   | Autoscaling / worker saturation behavior, then recovery |

The seed pool holds 50 pre-generated users (`load_0@load.test` … `load_49@load.test`).
For runs above 50 users the pool wraps; for soak/spike runs consider bumping
`SEED_USER_COUNT` in `locustfile.py` and pre-seeding accounts beforehand.

## Targets and thresholds

| Metric | Threshold | Notes |
| ------ | --------- | ----- |
| p95 latency (GET endpoints) | < 300 ms | System status, alerts, incidents, rules, sensors |
| p99 latency (all endpoints) | < 1 s | Reference value; write endpoints are expected to be slower |
| Error rate | < 0.1% | Any non-2xx/3xx response counts |
| 5xx responses | 0 | Any 5xx is a regression |
| Backend CPU | < 70% | Observable via Prometheus on the dashboard |

## Notes

- **Rate limiting and X-Forwarded-For.** slowapi keys auth requests by client IP
  (and authenticated requests by user id). Each simulated user sends a stable
  `X-Forwarded-For` value (`10.200.<n/250>.<n%250>`), so per-user IP buckets are
  realistic and shared buckets do not throttle the run.
- **Open registration.** Registration is open outside production, so the on_start
  pre-seed works without an admin bootstrap step. 409 responses during register are
  expected and tolerated when a seed account already exists.
- **Scratch Redis.** Use a disposable Redis for the token store during load runs so
  refresh-token/blocked-JTI state from previous runs does not affect results. The
  compose `redis` service is fine; reset it (`docker compose -f infra/docker-compose.yml
  rm -sf redis && docker compose -f infra/docker-compose.yml up -d --wait redis`) between
  serious runs.
- **Interpreting percentiles.** Locust CSV files report min/mean/median and the 95th
  and 99th percentile columns per endpoint; read `p95`/`p99` from `load_stats.csv` and
  correlate with the HTML report and Grafana dashboards. Failures land in
  `load_failures.csv` for triage.
- **Write amplification.** Creating alerts/incidents grows the database every run.
  Point the compose Postgres at a fresh volume for repeatable soak results, or run
  against the `prometheus`/scratch stack only.
- **CI note.** A scheduled or manual Locust job may be wired to run against a staging
  deploy (documented in CI configuration). It is not executed from this repository
  without the Docker stack, and any automated run should gate on the thresholds above
  and tear down its infrastructure afterwards.
