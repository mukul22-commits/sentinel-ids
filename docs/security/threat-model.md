# Sentinel IDS v3 - Threat Model

| Field | Value |
| --- | --- |
| Document version | 1.0 (Phase 11) |
| Applies to | Sentinel IDS Platform 3.0.0 |
| Review cycle | Quarterly, or on any material architecture change |
| Owner | Security lead / Platform team |
| Methodology | STRIDE per component, DREAD-aligned likelihood/impact ratings |

This document describes the security trust boundaries, actors, and the highest-priority
threats to the platform. It references concrete application behavior so mitigations can be
verified against the source. It is input to the penetration test plan
(`pen-test-plan.md`) and the production hardening checklist (`hardening-checklist.md`).

## 1. Scope

The scope is the entire Sentinel IDS stack: the FastAPI backend, the React SPA and its
nginx proxy, PostgreSQL/TimescaleDB, Redis, the Celery worker/beat, distributed capture
sensors, and the outbound connectors (HTTP webhook, OPNsense, EDR, SMTP email) and the
external SIEM CEF export. Purely client-side concerns (compromise of an operator's own
workstation) are out of scope.

## 2. Assets and trust boundaries

| # | Asset | Description | Trust level |
| --- | --- | --- | --- |
| A1 | Backend API | FastAPI app (`backend/app/main.py`), port 8000, `/api/v1/*` routers, `/openapi.json`, `/docs`, `/metrics`, WebSocket `/ws/incidents` | Core trusted component |
| A2 | PostgreSQL / TimescaleDB | Primary datastore: users, rules, alerts, incidents, IOCs, sensors, audit log | Core trusted component |
| A3 | Redis | Token revocation store, rate-limit counters, cache, Celery broker/result backend | Core trusted component |
| A4 | Celery worker | Runs export/capture/retraining tasks, connects to Redis and outbound connectors | Core trusted component |
| A5 | Frontend (React SPA + nginx) | Serves UI, proxies `/api` and `/ws` to backend, delivers the access/refresh tokens in browser storage | Semi-trusted (attacker-controlled browser) |
| A6 | Capture sensors | Remote agents authenticating with `X-Sensor-Token`, posting heartbeats, pulling config | Low trust (device may be in hostile network) |
| A7 | External SIEM connector | Outbound CEF export to a configured collector endpoint (`SIEM_CEF_ENDPOINT_URL`) | Zero trust (external endpoint) |
| A8 | SOAR/EDR/firewall connectors | Outbound HTTP(S) calls to webhook/OPNsense/EDR enforcement endpoints | Zero trust (external endpoints) |

### Trust boundaries

1. **Internet / operator browser to A5, then nginx reverse proxy to A1.** nginx terminates
   nothing today (no TLS in the compose stack); TLS is expected at an upstream LB in staging/prod.
2. **A1 to A2 and A3** is an internal network boundary; credentials come from environment.
3. **A6 sensors to A1** authenticate with an opaque token (SHA-256 hash stored) rather than a
   user identity - a separate trust domain from human users.
4. **A1/A4 to A7/A8** is the highest-trust egress boundary; the platform must never let a
   low-privilege actor steer these calls (no user-supplied URLs are accepted).

## 3. Actors

| Actor | Description | Authorization |
| --- | --- | --- |
| Anonymous user | Unauthenticated caller | Register/login/forgot-password only |
| Registered user | Self-registered (role `analyst` on registration) | Own account; `read`-level permissions via RBAC matrix |
| Analyst | Staff member triaging alerts/incidents | `read` + `respond` + incident handling per `PERMISSION_MATRIX` |
| Admin | Platform administrator | All permissions, user/rule/system management |
| Sensor agent | Headless capture node | `X-Sensor-Token` (opaque, hash stored); heartbeat/config endpoints only |
| External SIEM | Collector receiving CEF events | Outbound; no inbound API surface |
| Connector target | Webhook/OPNsense/EDR endpoints receiving enforcement calls | Outbound bearer token / HMAC-SHA512 |

## 4. STRIDE threat register (TH-01..TH-16)

Likelihood (L) and Impact (I) are High/Medium/Low (H/M/L). Priority = L x I, with priority
1 highest. "Existing mitigations" cite concrete behavior in the current source.

| ID | Threat | STRIDE | Component | L | I | Priority |
| --- | --- | --- | --- | --- | --- | --- |
| TH-01 | Auth bypass / credential stuffing | Spoofing | A1, A5 | H | H | 1 |
| TH-02 | JWT token theft / refresh misuse | Spoofing | A1, A3 | M | H | 1 |
| TH-03 | IDOR on incidents/users/sensors/alerts/iocs | Info disclosure | A1, A2 | M | H | 1 |
| TH-04 | Privilege escalation analyst -> admin | Elevation | A1, A2 | M | H | 2 |
| TH-05 | SQL injection | Tampering | A1, A2 | L | H | 2 |
| TH-06 | YAML rule deserialization / injection | Tampering | A1, A4 | M | H | 2 |
| TH-07 | SSRF via connectors | Info disclosure / Tampering | A1, A4 | L | H | 2 |
| TH-08 | Command injection via response actions | RCE | A1, A4, A8 | L | H | 2 |
| TH-09 | Rate-limit bypass | DoS | A1, A3 | M | M | 3 |
| TH-10 | Mass assignment | Elevation | A1 | M | M | 3 |
| TH-11 | Sensor token leakage | Spoofing | A1, A6 | M | M | 3 |
| TH-12 | SIEM CEF endpoint compromise | Tampering / Spoofing | A4, A7 | L | M | 3 |
| TH-13 | Dependency supply chain | Tampering | All | M | M | 3 |
| TH-14 | Log injection / forgery | Repudiation | A1, A4 | M | M | 3 |
| TH-15 | DoS on the detection engine | DoS | A1, A4 | M | M | 3 |
| TH-16 | Access token exposure via WebSocket query string | Spoofing | A1, A5 | L | M | 3 |

### TH-01 - Auth bypass / credential stuffing

- **Description:** Brute-force or credential-stuffing attacks against `POST /api/v1/auth/login`
  and `register`, attempting to guess passwords or replay leaked credentials.
- **Affected component:** Backend API auth router (`backend/app/api/v1/routes/auth.py`).
- **Likelihood/Impact:** H / H.
- **Existing mitigations:**
  - bcrypt hashing enforced at >= 12 rounds (`core/security.py:63`).
  - Password strength validation: minimum 12 chars, common-password denylist, username/email
    local-part match rejection (`core/security.py:79`).
  - Account lockout after 5 failed attempts for 15 minutes (`routes/auth.py:150-163`,
    `LOGIN_MAX_FAILED_ATTEMPTS`/`LOGIN_LOCKOUT_MINUTES`).
  - Rate limit 5/min per IP on auth endpoints via slowapi (`core/limiter.py`, `RATE_LIMIT_AUTH`).
  - Uniform "Invalid credentials" response (no user enumeration on the login path).
- **Recommended controls:** Enforce a proper lockout keyed by account rather than IP alone;
  add CAPTCHA/device verification behind a threshold; monitor `auth.login_failed` audit rows
  with an alert (Grafana); consider MFA (TOTP/WebAuthn) for staff accounts.
- **Priority:** 1.

### TH-02 - JWT token theft / refresh misuse

- **Description:** An attacker who steals an access or refresh token (XSS, browser extension,
  proxy log) reuses it, or replays a rotated refresh token.
- **Affected component:** Backend auth (`core/security.py`, `core/token_store.py`, `routes/auth.py`).
- **Likelihood/Impact:** M / H.
- **Existing mitigations:**
  - Short-lived access tokens (15 min) and refresh tokens (7 days) with `iss`, `aud`, `jti`,
    `exp`, `iat`, `typ` claims (`core/security.py:94-159`).
  - Decode restricts the algorithm whitelist to `[HS256]` and validates audience and issuer,
    which blocks `alg=none` and RS256->HS256 confusion (`core/security.py:127-143`).
  - Refresh tokens are single-use: reuse detection revokes the whole token family
    (`routes/auth.py:208-211`); a per-user revocation watermark invalidates every earlier token
    (`core/token_store.py:124-154`).
  - Logout blocklists the access-token `jti` and revokes the user (`routes/auth.py:243-245`).
- **Recommended controls:** Store tokens in `httpOnly` + `Secure` + `SameSite` cookies rather
  than `localStorage` (frontend change); bind tokens to user-agent/fingerprint; shorten
  refresh lifetime or add rotation; ensure proxies do not log query strings (see TH-16).
- **Priority:** 1.

### TH-03 - IDOR on incidents / users / sensors / alerts / iocs

- **Description:** A viewer-level caller enumerates `/{id}` resources (incidents, alerts, IOCs,
  sensors, users, rules) that should be out of scope, or a lower-privilege actor mutates
  another tenant's data.
- **Affected component:** Resource routers (`routes/incidents.py`, `routes/users.py`,
  `routes/sensors.py`, `endpoints/alerts.py`, `routes/iocs.py`, `routes/rules.py`).
- **Likelihood/Impact:** M / H.
- **Existing mitigations:**
  - All resource routes are behind `require_permission(...)` guards; the RBAC matrix is the
    single source of truth (`core/rbac.py`, `api/v1/deps.py:129-137`).
  - Currently the platform is single-tenant: all authenticated staff share one dataset, so
    cross-tenant IDOR does not yet apply; the residual risk is a missing-permission check on
    any new router (e.g. forgetting the guard on a new endpoint).
- **Recommended controls:** Automated permission-matrix test (every endpoint x every role)
  as a regression gate; review all new routers for the dependency guard; if multi-tenancy is
  ever introduced, scope all queries by `tenant_id` and re-test.
- **Priority:** 1.

### TH-04 - Privilege escalation analyst -> admin

- **Description:** An analyst tries to change their own role, elevate a co-account, or reach
  admin-only functionality.
- **Affected component:** User management (`routes/users.py`), RBAC (`core/rbac.py`).
- **Likelihood/Impact:** M / H.
- **Existing mitigations:**
  - `PATCH /users/{id}` requires `manage_users` (admin-only) and rejects changing your own role
    or deactivating yourself (`routes/users.py:71-82`).
  - Roles are validated against `valid_role()` before assignment; role is not a client-supplied
    field on register (registration hard-codes `analyst`, `routes/auth.py:98-104`).
  - Access tokens embed the role at issue time, but every route re-checks the DB user role via
    `require_permission`.
- **Recommended controls:** Make the privilege matrix test part of CI (see `pen-test-plan.md`
  PT-09/PT-11); consider requiring a second admin approval for role changes and auditing every
  role transition (audit already records `user.update`).
- **Priority:** 2.

### TH-05 - SQL injection

- **Description:** Attacker-controlled input reaches SQL. Attack surface: list filters
  (`search`, `q`, `src_ip`, `since/until`), IDs, and create/update payloads.
- **Affected component:** Backend data layer (SQLAlchemy ORM across all services).
- **Likelihood/Impact:** L / H.
- **Existing mitigations:**
  - All queries are built with the SQLAlchemy expression API with bound parameters
    (e.g. `Rule.name.ilike(f"%{search}%")` in `services/rule_service.py:77`); no string
    interpolation of user input into SQL is present in the audited paths.
  - Pydantic validates request bodies and FastAPI coerces query params before the DB layer.
- **Recommended controls:** Keep the "no raw SQL with concatenated input" rule in code review;
  add a sqlmap pass (PT-13) and a bandit/semgrep rule banning f-string SQL; apply a Postgres
  least-privilege DB role so even a successful injection cannot `DROP` schema (A2 hardening).
- **Priority:** 2.

### TH-06 - YAML rule deserialization / injection

- **Description:** Detection rules are authored in YAML (`Rule.yaml_content`). A malicious
  or naive rule could attempt to abuse YAML deserialization (Python-object tags, alias-bomb
  "billion laughs", resource exhaustion) or inject malformed match logic that breaks the engine.
- **Affected component:** Rules service (`services/rule_service.py`), detection engine
  (`services/detection/*`).
- **Likelihood/Impact:** M / H.
- **Existing mitigations:**
  - Rules are parsed with `yaml.safe_load` (`rule_service.py:22`), which rejects arbitrary
    object construction, so Python-object payloads cannot be deserialized.
  - YAML is validated to be a mapping with a `match` mapping and consistent `name`
    (`rule_service.py:30-55`).
- **Recommended controls:** Add a YAML size/complexity cap (alias-depth and document size) to
  block alias bombs that `safe_load` alone does not fully prevent; restrict rule authoring to
  analysts/admins (already enforced via `manage_rules`); run detection on bounded payloads
  (`YARA_MAX_PAYLOAD_BYTES` already caps YARA payloads, `config.py:119`).
- **Priority:** 2.

### TH-07 - SSRF via connectors

- **Description:** An attacker makes the backend reach an internal service or cloud metadata
  endpoint by steering connector/export URLs.
- **Affected component:** Connector services (`services/connectors/*`, `services/siem/export.py`),
  connector test endpoints (`routes/connectors.py`, `routes/siem.py`).
- **Likelihood/Impact:** L / H.
- **Existing mitigations:**
  - Connector and SIEM URLs come exclusively from environment settings
    (`HTTP_CONNECTOR_URL`, `OPNSENSE_CONNECTOR_URL`, `EDR_CONNECTOR_URL`,
    `SIEM_CEF_ENDPOINT_URL`); there is **no user-supplied URL field** on any connector or SIEM
    route (only `test`/`status`/`export` operations gated by `manage_system`).
  - Outbound timeouts are bounded (`HTTP_CONNECTOR_TIMEOUT_SECONDS`, `SIEM_HTTP_TIMEOUT_SECONDS`).
- **Recommended controls:** Keep URL configuration env-only (regression test asserting no
  request field maps to a target URL); where the deployment allows, add an egress allowlist /
  proxy for the worker so it can only reach the configured SIEM and connector endpoints.
- **Priority:** 2.

### TH-08 - Command injection via response actions

- **Description:** A responder's `target_value` (IP/host) is passed to an enforcement
  connector and, if shelled out or interpolated into a command, yields RCE. Today all
  connectors are HTTP(S)-only; there is no `os.system`/`subprocess` in the response-action path.
- **Affected component:** Response action orchestration (`services/response_action_service.py`),
  connectors (`services/connectors/http.py`, `opnsense.py`, `edr.py`).
- **Likelihood/Impact:** L / H.
- **Existing mitigations:**
  - `action_type` and `target_type` are validated against constant enumerations
    (`routes/incidents.py:416-420`); target values travel inside JSON bodies to HTTP endpoints
    only (no shell).
  - The OPNsense path interpolates `ip` into a URL path segment but the value is sent to the
    firewall's REST API, not a shell (`opnsense.py:50-58`).
- **Recommended controls:** Validate/restrict `target_value` format (CIDR/domain whitelist);
  forbid introducing shell-based connectors; run a SAST rule (bandit/semgrep) that fails on
  `subprocess`/`os.system` in the connectors package.
- **Priority:** 2.

### TH-09 - Rate-limit bypass

- **Description:** An attacker bypasses per-IP throttling by spoofing `X-Forwarded-For`, or
  evades the per-user limit by rotating accounts, to brute-force or flood the API.
- **Affected component:** Rate limiter (`core/limiter.py`), auth and API routes.
- **Likelihood/Impact:** M / M.
- **Existing mitigations:**
  - slowapi limits keyed by user id when authenticated, else by client IP, honoring
    `X-Forwarded-For` first value (`core/limiter.py:32-41`); storage is Redis in dev/prod.
  - Limits: `RATE_LIMIT_AUTH = 5/minute`, `RATE_LIMIT_API = 100/minute`.
- **Recommended controls:** At the reverse proxy, overwrite `X-Forwarded-For` from the
  connection socket (never trust the client header) - the app currently trusts it; this is the
  primary bypass vector. Add an IP-allowlist for the health endpoint and a proxy-level rate
  limit (nginx `limit_req`).
- **Priority:** 3.

### TH-10 - Mass assignment

- **Description:** An attacker submits extra JSON fields that get applied to server-side
  objects (role, is_active, token_hash, etc.).
- **Affected component:** All create/update routes (users, sensors, incidents, policies).
- **Likelihood/Impact:** M / M.
- **Existing mitigations:**
  - Every mutation uses explicit Pydantic create/update schemas and copies only named fields
    onto the model (e.g. `routes/users.py:71-82`, `routes/policies.py:76-82`,
    `services/sensors/service.py:105-115` with `exclude_unset=True` but only whitelisted keys).
  - `UserUpdate`, `SensorUpdate` etc. define exactly which fields are writable; Pydantic
    drops unknown fields by default in most configs.
- **Recommended controls:** Configure Pydantic schemas with `model_config = ConfigDict(extra='forbid')`
  so unknown fields fail validation (currently ignored) - this turns silent mass-assignment
  attempts into 422s; add a test that posts `role: "admin"` to non-admin schemas (PT-11).
- **Priority:** 3.

### TH-11 - Sensor token leakage

- **Description:** A sensor token leaks via logs, error messages, the `/metrics` endpoint, or
  the frontend bundle, letting an attacker impersonate a sensor.
- **Affected component:** Sensor auth (`api/v1/deps.py:106-123`, `services/sensors/service.py`).
- **Likelihood/Impact:** M / M.
- **Existing mitigations:**
  - Tokens are opaque, url-safe, 32-byte random (`services/sensors/service.py:35-37`), stored
    only as a SHA-256 hash (`token_hash`), so a DB leak does not reveal usable credentials.
  - Registration returns the plaintext once; rotation invalidates the previous token
    immediately (`routes/sensors.py:185-203`).
  - Disabled sensors are rejected with 403 (`deps.py:120-121`).
- **Recommended controls:** Verify tokens never appear in audit details or app logs; confirm
  they are not in `SensorRead` responses (only `token_hash`-free metadata); add a scanning
  rule for the `X-Sensor-Token` header pattern in logs; enforce sensor tokens over TLS.
- **Priority:** 3.

### TH-12 - SIEM CEF endpoint compromise

- **Description:** The CEF export endpoint is misconfigured (plain HTTP, no auth) so an
  attacker on-path can read exported alert data, or a malicious collector receives crafted CEF
  with payload injection in headers/extension fields.
- **Affected component:** SIEM export (`services/siem/export.py`, `services/siem/cef.py`).
- **Likelihood/Impact:** L / M.
- **Existing mitigations:**
  - Optional bearer auth (`SIEM_AUTH_TOKEN`) and bounded timeout
    (`services/siem/export.py:47-52`); export is disabled unless
    `SIEM_EXPORT_ENABLED` and a URL are configured.
  - `SELECT ... FOR UPDATE SKIP LOCKED` batching keeps concurrent workers safe
    (`services/siem/export.py:73-85`).
- **Recommended controls:** Require `https://` for the endpoint URL in prod; escape CEF field
  delimiters (`|` and `=`) in alert values (verify in `cef.py`); treat the collector as
  untrusted and never ship raw credentials in CEF events.
- **Priority:** 3.

### TH-13 - Dependency supply chain

- **Description:** A compromised PyPI/npm package (direct or transitive) is pulled at build
  time and ships malicious code to the backend or frontend.
- **Affected component:** `backend/requirements.txt` (pinned exact versions), `frontend/package.json`
  (caret ranges), Docker base images (`python:3.12-slim`, `node:22-alpine`, `nginx:1.27-alpine`).
- **Likelihood/Impact:** M / M.
- **Existing mitigations:**
  - Backend requirements are fully pinned; frontend relies on `package-lock.json` (npm ci).
  - Container base images are tagged (not `latest`); a non-root runtime user is used
    (`backend/Dockerfile`).
- **Recommended controls:** Run `pip-audit`, `npm audit`, and Trivy on images in CI
  (see `dependency-scanning.md`); enable Dependabot/Renovate; pin the frontend lockfile and
  review high-severity advisories before merge; pin Docker images by digest in prod.
- **Priority:** 3.

### TH-14 - Log injection / forgery

- **Description:** An attacker injects CR/LF or forged fields into logs (via user-controlled
  text such as incident titles, notes, user-agent) to forge audit events, evade detection, or
  poison the SIEM feed; or destroys forensic value by modifying the audit log.
- **Affected component:** Audit service (`services/audit.py`), access logging
  (`core/middleware.py`), SIEM export.
- **Likelihood/Impact:** M / M.
- **Existing mitigations:**
  - Audit rows are JSON-encoded details committed immediately (`services/audit.py:31-41`) and
    stored in the DB (append-only by design; no update/delete route exists).
  - Access logs are structured JSON emitted by the logging layer, reducing line-splitting risk.
- **Recommended controls:** Normalize CR/LF in `details` and user-controlled text at the log
  boundary; restrict DB grants so the app role cannot `UPDATE`/`DELETE` the `audit_logs` table
  (currently it likely can - the app owns the schema); forward logs to Loki with an
  integrity/retention policy and alert on audit-log deletion anomalies.
- **Priority:** 3.

### TH-15 - Denial of service on the detection engine

- **Description:** An attacker floods packet/alert ingest, submits a huge pcap, or creates an
  expensive rule/UEBA retrain to exhaust the worker, DB, or API.
- **Affected component:** Detection engine (`services/detection/*`), ingest endpoints
  (`endpoints/packets.py`), ML retraining.
- **Likelihood/Impact:** M / M.
- **Existing mitigations:**
  - Batch caps on ingest (10k packets/request, 500 alerts/request) and page-size caps on reads.
  - YARA payloads capped at `YARA_MAX_PAYLOAD_BYTES` (1 MiB).
  - API-wide rate limit 100/min per user.
- **Recommended controls:** Cap pcap upload size and add a read-size limit before
  `parse_pcap_bytes` (`endpoints/packets.py:130` currently reads the whole file); constrain
  detection engine CPU via a task timeout and `CELERY_WORKER_MAX_TASKS_PER_CHILD`; consider a
  separate ingest budget per sensor token.
- **Priority:** 3.

### TH-16 - Access token exposure via WebSocket query string

- **Description:** The WebSocket endpoint authenticates via `?token=` in the URL
  (`routes/ws.py`, `api/v1/deps.py:80-92`). Access tokens are short-lived, but tokens in query
  strings can be captured by proxies, access logs, browser history, and referrer headers.
- **Affected component:** WebSocket auth (`api/v1/deps.py:80-92`, `routes/ws.py`).
- **Likelihood/Impact:** L / M.
- **Existing mitigations:**
  - Access tokens expire in 15 minutes, limiting the window; the `jti` blocklist and
    revocation watermark apply to WS-validated tokens too (`deps.py:41-66`).
  - The `Referrer-Policy: strict-origin-when-cross-origin` header reduces referrer leakage.
- **Recommended controls:** Migrate to `Sec-WebSocket-Protocol` (subprotocol) token passing
  (works in browsers and avoids URL logging); if query-string auth is kept, ensure nginx
  `access_log` redacts the `token` parameter and the LB never logs full URLs.
- **Priority:** 3.

## 5. Residual risk summary

Residual risk is what remains after the current controls and the recommended controls above.
These items are accepted by the platform owner until remediated.

| Risk area | Residual risk | Current status | Owner | Review |
| --- | --- | --- | --- | --- |
| Credential attacks | Account lockout is per-IP rate limited but keyed to account only after attempts; no MFA on staff accounts | Acceptable for Phase 11; MFA planned | Platform lead | Next security review |
| Token theft | Tokens in `localStorage` (XSS exposure) and WebSocket query string | Mitigated by 15-min lifetime + revocation; cookie migration planned | Frontend lead | Next security review |
| IDOR / missing guards | Single-tenant; risk is a missing permission dependency on a new router | Regression test planned (PT-03) | Backend lead | Each release |
| Rate-limit spoofing | App trusts client `X-Forwarded-For`; proxy must overwrite it | Proxy configuration required at deploy time | DevOps | Staging rollout |
| Audit integrity | App DB role can technically modify audit tables | Restrict grants to `audit_logs` in prod migration | DB owner | Prod hardening |
| Supply chain | Transitive deps unvetted; images not digest-pinned | CI scanning to be wired (Phase 11) | DevOps | Each release |
| Detection DoS | Unbounded pcap upload size | Upload cap to be added | Backend lead | Next sprint |
| YAML alias bombs | `safe_load` blocks object construction but not deep alias expansion | Complexity cap to be added | Backend lead | Next sprint |

Sign-off: <SECURITY-LEAD> date <YYYY-MM-DD>; <PLATFORM-OWNER> date <YYYY-MM-DD>.
