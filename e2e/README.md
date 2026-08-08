# Sentinel IDS — End-to-End Tests

Playwright (TypeScript) suite covering the Sentinel IDS web app: auth (register /
login), dashboard, alerts widget, and incidents list + detail.

## Prerequisites

- Node.js >= 20
- The Sentinel stack running (see below). The suite does **not** start servers —
  `globalSetup` only logs the assumption and probes the frontend (non-fatal).

## Install

```bash
cd e2e
npm install
npx playwright install chromium
```

## Start the stack

```bash
docker compose -f infra/docker-compose.yml up -d --wait postgres redis backend frontend
```

- Frontend (Vite dev server): http://localhost:5173
- Backend (FastAPI): http://localhost:8000
- The Vite dev server proxies `/api` and `/ws` to the backend (see
  `frontend/vite.config.ts`), so the browser only needs to talk to `:5173`.

## Run the tests

```bash
cd e2e

# Run all tests (Chromium)
npm run test:e2e

# Run headed (watch the browser)
npm run test:e2e:headed

# Open the HTML report from the last run
npm run test:e2e:report
```

Configuration is in `playwright.config.ts`:

- `testDir`: `./tests`
- `timeout`: 60s per test, `retries`: 1, `workers`: 2
- `baseURL`: `process.env.E2E_BASE_URL ?? "http://localhost:5173"`
- `trace`: `on-first-retry`, `screenshot`: `only-on-failure`,
  `video`: `retain-on-failure`
- Reporter: list + HTML report in `e2e/playwright-report/`

### Environment variables

| Variable         | Default               | Purpose                                                    |
| ---------------- | --------------------- | ---------------------------------------------------------- |
| `E2E_BASE_URL`   | `http://localhost:5173` | Frontend origin the browser tests hit                     |
| `E2E_API_URL`    | unset (use frontend proxy) | Direct backend origin for API helper calls, e.g. `http://localhost:8000` |

## What the suite covers

| File                   | Scenario                                                                          |
| ---------------------- | --------------------------------------------------------------------------------- |
| `tests/auth.spec.ts`   | Register via API + login via UI (email and username), UI signup form, invalid-credentials error |
| `tests/dashboard.spec.ts` | Authenticated dashboard: app shell (nav) + KPI stat cards                          |
| `tests/alerts.spec.ts` | Alerts surface on the dashboard ("Unread alerts" widget + recent-incidents feed, empty state or rows) |
| `tests/incidents.spec.ts` | Incidents list renders; row click navigates to `/incidents/:id` detail (falls back to empty-state assertion) |

Helpers live in `tests/helpers/auth.ts`:

- Users are registered via `POST /api/v1/auth/register` with a unique
  `e2e.<random>@example.com` email and a strong password.
- Tokens come from `POST /api/v1/auth/login`.
- The frontend stores tokens in `localStorage`
  (`sentinel.access_token`, `sentinel.refresh_token`); `seedTokens()` injects
  them with `page.addInitScript` before navigation so `AuthContext` restores the
  session.

## CI integration

The CI workflow (`.github/workflows/ci.yml`) is expected to run a job like:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: "22"
    cache: "npm"
    cache-dependency-path: e2e/package-lock.json
- name: Start the stack
  working-directory: infra
  run: |
    cp ../.env.example ../.env
    docker compose up -d --wait postgres redis backend frontend
    docker compose ps
- name: Run e2e tests
  working-directory: e2e
  env:
    E2E_BASE_URL: http://localhost:5173
  run: |
    npm ci
    npx playwright install --with-deps chromium
    npm run test:e2e
```

Commit `e2e/package-lock.json` so `npm ci` resolves deterministically.

## Troubleshooting

- **Proxy not configured** — the suite talks to the backend through the Vite
  proxy by default. If you run the frontend without a proxy, point API helper
  calls at the backend directly:
  `E2E_API_URL=http://localhost:8000 npm run test:e2e` (the browser still uses
  `E2E_BASE_URL` for the UI).
- **Token storage** — the app stores `sentinel.access_token` and
  `sentinel.refresh_token` in `localStorage`
  (`frontend/src/api/client.ts`). The suite seeds them via `addInitScript`; if
  storage keys ever change, update `seedTokens()` in `tests/helpers/auth.ts`.
- **Empty state instead of rows** — incidents tests create a row via the API and
  fall back to asserting the empty-state message when creation is rejected.
- **Realtime "Offline" indicator** — the frontend shows "Offline" when the
  `/ws` socket is unreachable. That is non-fatal for these tests (assertions do
  not depend on live events).
- **Strict mode violations** — buttons on the login page are duplicated ("Sign
  in"/"Create account" appear both as mode toggles and submit buttons); the
  suite scopes submit-button lookups to the `<form>` element.
- **Auth rate limit (429s)** — the backend limits auth endpoints to
  `5/minute` per client IP (`RATE_LIMIT_AUTH` in `backend/app/core/config.py`).
  The suite performs ~14 auth requests (register/login per test), so a full run
  may exceed the default. For e2e runs, temporarily raise the limit for the dev
  backend, e.g. set `RATE_LIMIT_AUTH=100/minute` in the backend environment
  before starting the stack. If you see "Rate limit exceeded" in the login UI,
  this is the cause.
- **Docker not ready** — `--wait` ensures postgres/redis are healthy; if tests
  still fail with timeouts, check `docker compose ps` and the backend logs.
