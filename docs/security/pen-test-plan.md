# Sentinel IDS v3 - Penetration Test Plan

| Field | Value |
| --- | --- |
| Document version | 1.0 (Phase 11) |
| Standard | OWASP ASVS 4.x Level 2 (L2) and OWASP API Security Top 10 (2023) |
| Target | Sentinel IDS Platform 3.0.0 backend API + frontend SPA |
| Environment | Staging compose stack (see `infra/docker-compose.yml`); never localhost |
| Frequency | Before major releases and at least once per quarter |

How to use: each test case is standalone and repeatable. Record results against
`pen-test-report-TEMPLATE.md`. Unless stated otherwise, assume a registered user, an analyst,
and an admin account are available, and that `TARGET_URL` points at the staging API base
(e.g. `https://staging.example.com`).

Legend: PASS / FAIL / N/A per test. A FAIL is a finding and must be entered in the report.

## Test environment notes

- ZAP and Burp run in CI or from a hardened runner against the **staged compose stack**
  (API, DB, Redis, worker, frontend). No Docker is available on the local machine.
- Reset the stack (`docker compose -f infra/docker-compose.yml down && up -d --build`) between
  destructive tests.
- Baseline dataset: 2 users (analyst, admin), 3 sensors, 2 rules, 2 alerts, 1 incident.

## Test case matrix

| ID | Area | ASVS L2 | API Top 10 | Title |
| --- | --- | --- | --- | --- |
| PT-01 | Auth | V2.1/V2.3 | API2 | Registration & password policy |
| PT-02 | Auth | V2.2 | API2 | Login & credential verification |
| PT-03 | Auth | V2.2.6 | API2 | Account lockout & anti-brute-force |
| PT-04 | Auth | V2.6/V3.5 | API2 | Refresh token rotation & reuse detection |
| PT-05 | Auth | V3.2/V3.3 | API2 | Logout & token revocation |
| PT-06 | Auth | V2.4/V2.5 | API2 | Change / forgot / reset password |
| PT-07 | Auth | V3.5.1 | API2 | JWT algorithm confusion |
| PT-08 | Auth | V3.1/V3.5 | API2 | JWT claims validation & token-type confusion |
| PT-09 | Authz | V4.1/V4.2 | API5 | Role-based permission matrix |
| PT-10 | Authz | V4.1.3/V4.2.1 | API1 | IDOR on object routes |
| PT-11 | Authz | V4.2 | API3 | Privilege escalation & mass assignment |
| PT-12 | Authz | V4.3 | API2 | Sensor token authentication |
| PT-13 | Input | V5.1-V5.3 | API3/API4 | Injection in filters, rules, IOCs, policies |
| PT-14 | Input | V5.1 | API3 | YAML rule payload abuse |
| PT-15 | Input | V5.4/V12 | API4 | pcap file upload |
| PT-16 | SSRF | V5.2.3 | API7 | Connector / SIEM endpoint steering |
| PT-17 | Input | V1.8/V5 | API10 | Response action target injection |
| PT-18 | Input | V7.4 | API9 | Log injection & audit forgery |
| PT-19 | Config | V14.2/V14.4 | API8 | Security headers |
| PT-20 | Config | V14.5 | API8 | CORS configuration |
| PT-21 | Config | V1.7 | API4 | Rate limiting & X-Forwarded-For bypass |
| PT-22 | Secrets | V6 | API9 | Secret & endpoint exposure |
| PT-23 | TLS | V9 | API8 | Transport security |
| PT-24 | Errors | V7.4/V13 | API9 | Error handling & information leakage |
| PT-25 | Deps | V14.2 | API9 | Dependency & container scanning gates |
| PT-26 | Realtime | V3.3/V8 | API2 | WebSocket authentication |

## Detailed test cases

### PT-01 - Registration & password policy (ASVS V2.1/V2.3, API2)

- **Steps:**
  1. `POST /api/v1/auth/register` with a strong password (>= 12 chars, not in the common
     denylist) -> expect 200/201 and role `analyst`.
  2. Register with `password: "password123"`, a password matching the username or the email
     local part, and a 6-char password -> expect 400.
  3. Re-register the same email and the same username -> expect 409.
  4. Verify the stored hash is a bcrypt hash with cost factor 12+ (`BCRYPT_ROUNDS`).
- **Expected result:** Weak passwords rejected; duplicate identifiers rejected; role is never
  client-supplied; hash cost >= 12.
- **Tooling:** curl/httpx.

### PT-02 - Login & credential verification (ASVS V2.2, API2)

- **Steps:**
  1. `POST /api/v1/auth/login` with correct credentials -> 200 with `access_token`,
     `refresh_token`, `expires_in`.
  2. Wrong password -> 401 "Invalid credentials" (uniform message).
  3. Login with non-existent identifier -> 401 (not 404; no enumeration).
  4. Confirm email lookup is case-insensitive but the response does not reveal which field
     matched.
- **Expected result:** Uniform 401s; no user enumeration; token pair returned only on success.
- **Tooling:** curl/httpx, Burp Intruder (username field, observe identical responses).

### PT-03 - Account lockout & anti-brute-force (ASVS V2.2.6, API2)

- **Steps:**
  1. Attempt login 5 times with a wrong password for one account (pace requests to stay under
     the 5/min auth rate limit; use a distinct IP or wait between batches).
  2. Expect the 6th attempt to return 403 "Account is temporarily locked".
  3. Verify the account unlocks after `LOGIN_LOCKOUT_MINUTES` (15 min) or via an admin reset.
  4. Confirm audit rows `auth.login_failed` and `auth.login_blocked` were written for each event.
- **Expected result:** Lockout enforced server-side and reflected in the audit log.
- **Tooling:** curl/httpx, ZAP fuzzer.

### PT-04 - Refresh token rotation & reuse detection (ASVS V2.6/V3.5, API2)

- **Steps:**
  1. Login, then `POST /api/v1/auth/refresh` -> new token pair.
  2. Replay the just-used refresh token -> expect 401 "Refresh token already used" and the
     whole token family revoked (`auth.refresh` then `auth.refresh` reuse both fail).
  3. Present an access token to `/refresh` and a refresh token to a protected route -> 401.
  4. Tamper `exp`/`sub`/`fid` in the refresh token -> 401.
- **Expected result:** Refresh tokens are single-use; reuse triggers family-wide revocation;
  token-type confusion rejected.
- **Tooling:** curl/httpx, jwt.io / python-jwt to forge tokens.

### PT-05 - Logout & token revocation (ASVS V3.2/V3.3, API2)

- **Steps:**
  1. Login, then `POST /api/v1/auth/logout` with the access token.
  2. Immediately reuse the access token on `/api/v1/auth/me` -> 401 (jti blocklist).
  3. Reuse the refresh token -> 401 (per-user revocation watermark).
  4. Repeat with a "logout everywhere" scenario from a second session.
- **Expected result:** Both the access token and all refresh tokens for the user are invalid
  immediately after logout.
- **Tooling:** curl/httpx.

### PT-06 - Change / forgot / reset password (ASVS V2.4/V2.5, API2)

- **Steps:**
  1. `POST /change-password` with wrong current password -> 400; with a weak new password -> 400.
  2. Verify all sessions are revoked after a successful change.
  3. `POST /forgot-password` for an existing and a non-existing email -> identical 200 response.
  4. `POST /reset-password` with a valid token -> 200; replay the same token -> 400
     (single-use); tamper the token -> 400; use a token after `PASSWORD_RESET_TTL_MINUTES`
     (15 min) -> 400.
- **Expected result:** No enumeration; reset tokens single-use with short TTL; password
  strength enforced on reset.
- **Tooling:** curl/httpx.

### PT-07 - JWT algorithm confusion (ASVS V3.5.1, API2)

- **Steps:**
  1. Take a valid access token; re-sign with `alg: "none"` and remove the signature -> 401.
  2. Try `alg: "RS256"` signed with a key derived from the public `SECRET_KEY` value or the
     JWT itself -> 401.
  3. Try `alg: "HS256"` with an attacker-chosen key -> 401.
- **Expected result:** All forged tokens rejected; the decode whitelist
   (`algorithms=[ALGORITHM]`) and `aud`/`iss` checks are enforced
   (`backend/app/core/security.py:127`).
- **Tooling:** curl + python `jwt` library / jwt.io.

### PT-08 - JWT claims validation & token-type confusion (ASVS V3.1/V3.5, API2)

- **Steps:**
  1. Swap the `aud`, `iss`, `typ`, or `role` claim of a valid token (re-sign with the real
     signing key only if test harness has it; otherwise verify rejection paths) -> 401.
  2. Present a refresh token to a protected `/api/v1/*` route -> 401 ("Token type is invalid").
  3. Present an access token to `/auth/refresh` -> 401.
- **Expected result:** Only `typ=access` tokens are accepted on protected routes; only
  `typ=refresh` on refresh; bad audience/issuer rejected.
- **Tooling:** curl/httpx, python-jwt.

### PT-09 - Role-based permission matrix (ASVS V4.1/V4.2, API5)

- **Steps:** Build the endpoint x role matrix from the routers and `PERMISSION_MATRIX`
  (`backend/app/core/rbac.py`), then for each of viewer / analyst / admin call every route:
  1. GETs (`/alerts`, `/rules`, `/iocs`, `/incidents`, `/sensors`, `/users`, `/policies`)
  2. Mutations (`POST`/`PATCH`/`DELETE` for rules, iocs, policies, incidents, alerts, sensors,
     `/auth/change-password`)
  3. System routes (`/system/connectors/*`, `/system/siem/*`, `/system/detection/*`)
- **Expected result:** Only roles holding the corresponding permission succeed; everyone else
  gets 403 (or 401 unauthenticated). No 500s, no accidental 200s.
- **Tooling:** A scripted httpx matrix runner; record PASS/FAIL per cell.

### PT-10 - IDOR on object routes (ASVS V4.1.3/V4.2.1, API1)

- **Steps:**
  1. As a viewer, enumerate `GET /incidents/{id}`, `/alerts/{id}`, `/iocs/{id}`,
     `/sensors/{id}`, `/rules/{id}` for ids that exist and ids that do not.
  2. As a viewer, attempt `PATCH/DELETE` on those objects -> 403.
  3. Attempt to reach `/users/{id}` (admin-only) as analyst -> 403, and `/users` as analyst.
  4. Confirm 404 for missing objects is consistent (no 403/404 oracle differences for objects
     the caller may legitimately not see - single-tenant today, so focus on permission checks).
- **Expected result:** Any object access without the correct permission returns 403; missing
  objects return 404 consistently.
- **Tooling:** curl/httpx, Burp Repeater; ZAP active scan against object routes.

### PT-11 - Privilege escalation & mass assignment (ASVS V4.2, API3)

- **Steps:**
  1. As analyst, `PATCH /api/v1/users/{self_id}` with `{"role": "admin"}` -> 403 (manage_users
     required) and `{"role": "admin"}` on the *own* update path -> 400 "Cannot change your own role".
  2. As admin, attempt to deactivate yourself -> 400.
  3. Post extra fields (`role`, `is_active`, `token_hash`, `hashed_password`) to:
     `POST /auth/register`, `PATCH /sensors/{id}`, `PATCH /incidents/{id}` -> fields must be
     ignored or rejected (422), never applied.
  4. As analyst, `PATCH /users/{admin_id}` -> 403.
- **Expected result:** No path allows role/flag escalation; unknown fields are never bound.
- **Tooling:** curl/httpx.

### PT-12 - Sensor token authentication (ASVS V4.3, API2)

- **Steps:**
  1. `POST /sensors/heartbeat` and `GET /sensors/config` with a valid `X-Sensor-Token` -> 200.
  2. Without the header, with a wrong token, and with a disabled sensor's token -> 401/403.
  3. Rotate the token via admin (`POST /sensors/{id}/rotate-token`) and confirm the old token
     now fails and the new one succeeds.
  4. Confirm no response and no audit entry ever contains the raw token; the DB stores only
     `token_hash`.
- **Expected result:** Opaque token auth enforced; rotation invalidates immediately; token
  never leaked in responses.
- **Tooling:** curl/httpx.

### PT-13 - Injection in filters, rules, IOCs, policies (ASVS V5.1-V5.3, API3/API4)

- **Steps:**
  1. SQLi probes in query filters: `/alerts?src_ip=' OR '1'='1`, `/rules?search='; DROP TABLE
     rules;--`, `/iocs?search=...`, `/incidents?severity=...` (feed the same payloads through
     sqlmap with `--level 3` against a staged copy).
  2. XSS/HTML injection in create/update text fields: alert titles, incident titles/notes,
     rule names, IOC values, policy names -> must be stored as inert data, never executed in
     the SPA (verify the frontend renders with React's default escaping).
  3. Oversized list payloads: `/packets` with > 10,000 items and `/alerts` with > 500 items
     -> 422.
  4. Malformed severity/status/category filter values -> 422.
- **Expected result:** No SQL injection (ORM parameterization); no stored XSS; size and
  enum validation enforced.
- **Tooling:** curl/httpx, sqlmap, ZAP active scan (SQL injection, XSS rules), Burp.

### PT-14 - YAML rule payload abuse (ASVS V5.1, API3)

- **Steps:**
  1. `POST /rules` with non-YAML text -> 422 "Invalid YAML".
  2. With YAML that is not a mapping, missing `match`, or whose `name` differs from the body
     name -> 422.
  3. With a Python object tag (`!!python/object/apply:os.system [...]`) -> must fail, never
     execute (safe_load).
  4. Alias bomb (billion laughs) and a multi-megabyte YAML body -> bounded time/memory; 422 or
     413 expected.
- **Expected result:** Malicious YAML never deserializes objects and does not exhaust the
  worker; rule authoring remains restricted to `manage_rules`.
- **Tooling:** curl/httpx, custom YAML payloads.

### PT-15 - pcap file upload (ASVS V5.4/V12, API4)

- **Steps:**
  1. `POST /packets/import` with a valid small pcap -> 200 with ingest counts.
  2. With a non-pcap content type (e.g. `text/html`) -> 422.
  3. With a file whose `content_type` is spoofed to `application/vnd.tcpdump.pcap` but garbage
     bytes -> 422 (parse failure).
  4. With an oversized pcap (100+ MiB) -> the current code reads the whole file; record
     behavior (memory/time). This test may be N/A until an upload cap is added; it is a
     known residual risk (TH-15).
  5. Empty/zero-IP packet pcap -> 422 "No IP packets found".
- **Expected result:** Type checks and parse validation work; upload size bounded (or the gap
  is recorded as a finding).
- **Tooling:** curl with `-F file=@`, custom generated pcaps.

### PT-16 - Connector / SIEM endpoint steering (SSRF) (ASVS V5.2.3, API7)

- **Steps:**
  1. Confirm no create/update API accepts a URL for `HTTP_CONNECTOR_URL`, SIEM endpoint, or
     connector endpoints (inspect `routes/connectors.py`, `routes/siem.py`, schemas).
  2. As `manage_system` only, exercise `POST /system/connectors/{name}/test` and
     `POST /system/siem/test` against the env-configured endpoints and confirm the response
     only reveals connectivity status.
  3. Attempt to reach loopback/metadata endpoints by manipulating `target_value` in a response
     action (e.g. `target_value=http://169.254.169.254/`) -> must be sent to the configured
     connector, not fetched by the platform.
- **Expected result:** No user-controlled URL field exists; egress is config-driven.
- **Tooling:** curl/httpx; source review.

### PT-17 - Response action target injection (ASVS V1.8/V5, API10)

- **Steps:**
  1. `POST /incidents/{id}/actions` with an invalid `action_type` or `target_type` -> 422.
  2. `POST .../actions/{id}/execute` for an action that is not `pending`/`failed` -> 400.
  3. Craft `target_value` with CRLF/JSON-injection characters and confirm the connector
     payload is JSON-encoded (no header splitting) and the CEF export escapes delimiters.
- **Expected result:** Enumerations validated; payloads remain structured data; no shell
  execution path exists.
- **Tooling:** curl/httpx, ZAP, source review of `services/connectors/*`.

### PT-18 - Log injection & audit forgery (ASVS V7.4, API9)

- **Steps:**
  1. Submit incident titles / timeline notes containing `\r\n`, fake severity, or
     `X-Request-ID`-style fields -> confirm stored JSON-encoded in audit `details`.
  2. Confirm there is no API that can `UPDATE`/`DELETE` an `audit_logs` row.
  3. Send a crafted `User-Agent` and confirm it is stored as a field, not executed as a log
     line.
- **Expected result:** No CR/LF injection into log semantics; audit trail append-only via the
  API surface.
- **Tooling:** curl/httpx; DB inspection (read-only).

### PT-19 - Security headers (ASVS V14.2/V14.4, API8)

- **Steps:** `curl -sI $TARGET_URL/health` and a SPA page; assert presence of
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `Cache-Control: no-store`,
  `X-Permitted-Cross-Domain-Policies: none`, and (in prod profile) `Strict-Transport-Security`.
  The API applies these in `core/middleware.py`; nginx serves the SPA separately - verify the
  SPA response includes at least `X-Frame-Options`, `nosniff`, and a `Content-Security-Policy`
  (CSP is currently a gap; record a finding if absent).
- **Expected result:** Full header set present; no `Server` version disclosure if possible;
  CSP present or flagged.
- **Tooling:** curl, ZAP passive scan rule 10038/10020/10021, securityheaders.com (external).

### PT-20 - CORS configuration (ASVS V14.5, API8)

- **Steps:**
  1. `OPTIONS /api/v1/...` with `Origin: http://localhost:5173` -> allowed (dev default).
  2. Same request with `Origin: https://evil.example` -> no `Access-Control-Allow-Origin` echo.
  3. Confirm `allow_credentials=True` only pairs with the allowlist
     (`CORS_ORIGINS` from config, `backend/app/main.py:78`).
- **Expected result:** Origins not in the allowlist never receive CORS headers; credentials
  never sent cross-origin.
- **Tooling:** curl, ZAP rule 10017.

### PT-21 - Rate limiting & X-Forwarded-For bypass (ASVS V1.7, API4)

- **Steps:**
  1. Fire > 5 `/auth/login` requests from one IP in a minute -> 429 envelope.
  2. Fire > 100 authenticated `/alerts` requests per minute -> 429.
  3. Repeat the login burst while rotating the `X-Forwarded-For` header -> record whether the
     limit is bypassed (the limiter trusts the header's first value,
     `core/limiter.py:37-41`). The proxy must overwrite `X-Forwarded-For`; if it does not,
     this is a finding (TH-09).
- **Expected result:** 429 returned; header spoofing ineffective behind a properly configured
  proxy.
- **Tooling:** curl/httpx loop, ZAP, custom script.

### PT-22 - Secrets & endpoint exposure (ASVS V6, API9)

- **Steps:**
  1. Confirm `GET /metrics` reveals no token values, no `SECRET_KEY`, and no connector
     credentials.
  2. Confirm `/docs` and `/openapi.json` are gated or acceptable to expose (decide policy);
     record whether they are reachable from the internet LB.
  3. Confirm production startup fails if `SECRET_KEY` is the default or < 32 chars
     (`core/config.py:179`).
  4. Check `.env.example` contains only placeholders and no real secrets; scan the repo for
     committed secrets (gitleaks/trufflehog).
- **Expected result:** No secrets exposed via API, metrics, or docs; repo secret scan clean.
- **Tooling:** curl, gitleaks, manual review.

### PT-23 - Transport security (ASVS V9, API8)

- **Steps:**
  1. From outside the stack, confirm all traffic is HTTPS (LB terminates TLS; nginx/API
     HTTP-only internally is acceptable).
  2. TLS version/cipher scan with `testssl.sh` or `sslyze` -> no TLS 1.0/1.1, no weak ciphers.
  3. Confirm HSTS header present on prod responses.
- **Expected result:** TLS 1.2+ enforced, HSTS active, no plaintext internet exposure.
- **Tooling:** curl, testssl.sh, sslyze, ZAP (passive TLS rules).

### PT-24 - Error handling & information leakage (ASVS V7.4/V13, API9)

- **Steps:**
  1. Trigger an unhandled error path (e.g. malformed DB state) -> response must be the generic
     500 `"Internal server error"` with an `X-Request-ID`; no traceback, no library versions.
  2. Trigger a validation error -> 422 with a generic message, no internal detail.
  3. Confirm `X-Request-ID` is echoed and can be correlated with Loki logs
     (`core/middleware.py`).
- **Expected result:** No stack traces or internal detail in responses; correlation ID present.
- **Tooling:** curl, ZAP rule 90022.

### PT-25 - Dependency & container scanning gates (ASVS V14.2, API9)

- **Steps:**
  1. Run `pip-audit`, `npm audit`, `bandit`, `semgrep`, and Trivy per
     `dependency-scanning.md`; confirm the CI gate is configured (any blocking severity
     fails the build).
  2. Confirm the lockfile and `requirements.txt` are scanned, not just the manifest.
  3. Triage any finding per the triage flow in that doc.
- **Expected result:** No open critical/high advisories on the staged build; gates wired.
- **Tooling:** pip-audit, npm audit, bandit, semgrep, trivy (CI runner).

### PT-26 - WebSocket authentication (ASVS V3.3/V8, API2)

- **Steps:**
  1. Connect to `/ws/incidents` with a valid `?token=` -> handshake accepted, `ping` -> `pong`.
  2. Connect with no/malformed/expired token -> rejected with code 1008.
  3. Connect as viewer vs analyst/admin -> messages are broadcast to all authenticated staff
     (single-tenant); confirm an unauthenticated connection can never join.
  4. Note that the token is in the query string (TH-16); verify the reverse proxy does not log
     full URLs or, if it does, redacts the `token` parameter - otherwise record a finding.
- **Expected result:** WS connections require a valid access token; rejected connections never
  receive events.
- **Tooling:** wscat/websocat, curl for HTTP paths, proxy log review.

## Execution notes

1. Run PT-01..PT-08 and PT-26 against a fresh DB (reset stack) so lockouts/tokens are clean.
2. Run PT-09..PT-12 with the three-role account set.
3. Destructive tests (PT-13..PT-18) can be run last on a cloned dataset.
4. Every finding gets an ID (see report template); re-verify each remediation on a subsequent
   run and mark the finding closed.
