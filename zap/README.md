# ZAP scanning for Sentinel IDS v3

OWASP ZAP (baseline + API scan) configuration for the Sentinel IDS platform.

## Why ZAP runs in CI, not on the local machine

The local development machine has **no Docker available**, and the full stack
(PostgreSQL/TimescaleDB, Redis, worker, frontend) only runs as a compose stack
(`infra/docker-compose.yml`). ZAP therefore runs **in CI against a staged compose stack**
provisioned for the scan, never against the local machine or against production. This keeps
scan targets deterministic and repeatable and avoids scanning live production data.

## How to run

The entrypoint is the ZAP Docker image. From the repository root:

```bash
# Baseline passive scan (API focus; spiders disabled, OpenAPI-driven)
docker run -t --rm -e TARGET_URL=https://<host> \
  -v "$PWD/zap":/zap/wrk ghcr.io/zaproxy/zaproxy \
  sh -c 'zap-baseline.py -t "$TARGET_URL" -c /zap/wrk/zap.yaml \
    -r /zap/wrk/report.html -J /zap/wrk/report.json -z "-X"'
```

Replace `<host>` with the staging host (e.g. `staging.example.com`). This is the exact form
given in the plan; note two details about the ZAP CLI:

- `-z "-X"` runs the ZAP daemon headless (no GUI/X server), which is required in containers
  and CI.
- `-J report.json` produces the JSON report. (The `-j` flag in some ZAP script versions
  consumes JVM options; prefer `-J` for the JSON report. Both flags appear in ZAP
  documentation - use `-J` for JSON output.)
- `-d` disables the spider and `-a` disables the AJAX spider. For an API scan these are
  already disabled in `zap.yaml`; pass the flags too so the behavior is explicit regardless
  of config parsing.

### API scan from the OpenAPI spec (preferred)

`zap-api-scan.py` imports the FastAPI spec the backend serves at `/openapi.json`:

```bash
docker run -t --rm -e TARGET_URL=https://<host> \
  -v "$PWD/zap":/zap/wrk ghcr.io/zaproxy/zaproxy \
  sh -c 'zap-api-scan.py -t "$TARGET_URL/openapi.json" -f openapi \
    -c /zap/wrk/zap.yaml \
    -r /zap/wrk/report.html -J /zap/wrk/report.json -z "-X"'
```

### Full active scan (scheduled, not per-PR)

```bash
docker run -t --rm -e TARGET_URL=https://<host> \
  -v "$PWD/zap":/zap/wrk ghcr.io/zaproxy/zaproxy \
  sh -c 'zap-full-scan.py -t "$TARGET_URL" -c /zap/wrk/zap.yaml \
    -r /zap/wrk/report.html -J /zap/wrk/report.json -d -a -z "-X"'
```

Use the active scan on a scheduled cadence (e.g. nightly on a cloned dataset) because it is
slower and may write state (alerts/incidents); the baseline scan runs per-PR.

## How CI runs it

1. On pull requests and merges, a GitHub Actions job builds and starts the staged compose
   stack (`infra/docker-compose.yml`) with seeded fixtures.
2. The job waits for the backend `/health` and then runs the baseline scan command above with
   `TARGET_URL` set to the staged host.
3. The nightly job runs the active scan (`zap-full-scan.py`) against the same staged stack.
4. `report.html` and `report.json` are uploaded as workflow artifacts.
5. The baseline job is informational by default (it posts the artifact and a PR comment with
   the finding count). The gate policy - `failOnError: true`, `failOnWarning: false` in
   `zap.yaml` - means only `FAIL`-level alerts fail CI; WARN-level alerts are triaged
   manually. Raise it to `failOnWarning: true` once the finding baseline is clean.

## Config contents

`zap.yaml` disables both spiders (`spider`/`ajaxSpider`) for the API scan, defines alert
thresholds for the issues most relevant to this stack (timestamp disclosure 10096,
application error disclosure 90022, CSP 10038, CORS 10017, cookie flags, security headers,
HSTS, cacheability), and documents the OpenAPI path `/openapi.json`. The base target comes
from the `TARGET_URL` environment variable or the `-t` argument.

## Triage of findings

1. Open the uploaded `report.json`/`report.html` from the workflow artifact.
2. Confirm the alert against the target behavior:
   - **10096 Timestamp Disclosure / 100000 Server header** - low risk; confirm timestamps and
     server banners are only in expected places (Prometheus/health endpoints are the usual
     false positives).
   - **90022 Application Error Disclosure** - confirm the API returns the generic envelope
     (`backend/app/api/v1/errors.py`) and that the flagged response is not leaking a stack
     trace; if it is, treat as HIGH.
   - **10038 CSP** - expected today: the backend middleware does not emit CSP and nginx
     (`frontend/nginx.conf`) sets none. Tracked in `hardening-checklist.md`; acceptable as
     WARN until the CSP is added.
   - **10017 CORS** - verify the flagged Origin is inside `CORS_ORIGINS`; a non-allowlisted
     origin returning CORS headers is HIGH.
   - **10049 Non-Storable Content** - the API already sends `Cache-Control: no-store`; a
     flagged static asset under nginx is expected and can be ignored.
3. Map the finding to a threat ID in `docs/security/threat-model.md` (TH-xx) and to the PT-xx
   test in `docs/security/pen-test-plan.md`, then file or close the issue.
4. Findings that become real bugs are fixed with a regression test; accepted items are
   recorded in the report template (`docs/security/pen-test-report-TEMPLATE.md`).

## Reference

- ZAP baseline scripts: <https://www.zaproxy.org/docs/docker/available-images/>
- Alert list: <https://www.zaproxy.org/docs/alerts/>
