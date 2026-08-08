# Sentinel IDS v3 - SAST / Dependency / Container Scanning

This document describes how static analysis and software-composition analysis are wired into
CI for the platform, what each tool does, the exact commands used, the gate policy, and how to
triage findings. It is written to match a GitHub Actions workflow (the workflow file itself is
not included here).

## 1. Tools and purpose

| Tool | Stage | Purpose | Scope |
| --- | --- | --- | --- |
| Bandit | SAST | Security-oriented static analysis of Python source | `backend/` |
| Semgrep | SAST | Custom + built-in rules (SQL injection, YAML deserialization, subprocess, secrets-in-code) | `backend/`, `frontend/` |
| pip-audit | SCA | Audit of Python dependencies against the OSV/PyPA vulnerability feed | `backend/requirements.txt` |
| npm audit | SCA | Audit of frontend dependencies against the npm advisory database | `frontend/package-lock.json` |
| Trivy | Container SCA | Scan of final container images for OS packages and language-level CVEs | `backend/`, `frontend/` images |

Why five tools: Bandit and Semgrep catch code-level issues the scanners cannot see; pip-audit
and npm audit catch known CVEs in direct/transitive dependencies; Trivy covers the base OS
layer (debian/alpine packages) that language audits miss. No single tool overlaps all four
concerns.

## 2. Commands and expected output

### 2.1 Bandit (Python SAST)

```bash
cd backend
python -m bandit -r app -c pyproject.toml 2>/dev/null || bandit -r app -f json -o bandit-report.json
```

- Expected output: JSON (or severity-ranged) findings with confidence. Clean run prints
  `No issues identified.`
- CI gate: fail on `HIGH` severity (default). Tune with an `exclude_dirs`/`skips` section in
  `pyproject.toml` rather than `-x` one-offs so the policy is reviewable.

### 2.2 Semgrep

```bash
semgrep scan --config=auto --error --json -o semgrep-report.json backend/ frontend/src/
```

- Expected output: matches with rule metadata (CWE, OWASP link). A clean run exits 0 with
  `No findings.`
- CI gate: `--error` fails on any finding at the default severity. Add repo rules in
  `backend/.semgrep.yml` / `frontend/.semgrep.yml`, for example:
  - `sqlalchemy text()` usage without parameters
  - `yaml.load(` calls without `Loader` argument (should be `yaml.safe_load`)
  - `subprocess`/`os.system` in `backend/app/services/connectors/` (TH-08)
  - assignment to `role`/`is_active`/`token_hash` outside whitelisted paths (TH-10)

### 2.3 pip-audit (Python SCA)

```bash
cd backend
pip-audit -r requirements.txt --desc on
```

- Expected output: `No known vulnerabilities found` or a table of `(package, version, CVE,
  advisory)` records.
- CI gate: fail on any `HIGH`/`CRITICAL` advisory; allow `MEDIUM`/`LOW` to pass with a
  tracked `deps-review.md` note. Use `--vuln-service osv` for the same feed the frontend
  tools use.

### 2.4 npm audit (Frontend SCA)

```bash
cd frontend
npm audit --json
```

- Expected output: JSON summary with `vulnerabilities` counts by severity.
- CI gate: fail on `high`/`critical` (`npm audit --audit-level=high`). `moderate` findings are
  tracked and re-reviewed on each release.

### 2.5 Trivy (Container SCA)

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 \
  --format json --output trivy-backend.json sentinel-backend:ci
# same for sentinel-frontend:ci
```

- Expected output: table/JSON of CVEs found in the image (OS + language packages).
- CI gate: `--exit-code 1` fails the job when HIGH/CRITICAL findings exist with a fix.
  `--ignore-unfixed` avoids failing on issues that have no upstream fix yet (those become
  `wontfix` in the tracking issue).

### 2.6 Suggested CI wiring (GitHub Actions)

Jobs are `backend-scan` and `frontend-scan`, run on `push`/`pull_request`:

1. `actions/checkout@v4`
2. Set up Python 3.12 (backend job) and Node 22 (frontend job).
3. Run each command above; upload `*-report.json` as workflow artifacts.
4. A final job aggregates `exit-code` from each scanner and fails the build if any scanner
   exited nonzero.
5. The ZAP job (`zap/zap.yaml`) runs separately against the staged compose stack
   (see `zap/README.md`) and does not block the PR by default - it posts a report artifact.

## 3. Gate policy (summary)

| Tool | Fails on | Passes with note | Never blocks |
| --- | --- | --- | --- |
| Bandit | HIGH | MEDIUM (tracked) | INFO |
| Semgrep | any `--error` match | - | - |
| pip-audit | HIGH / CRITICAL | MEDIUM / LOW (tracked) | - |
| npm audit | high / critical | moderate (tracked) | info |
| Trivy | HIGH / CRITICAL with fix | HIGH/CRITICAL without fix (`wontfix` issue) | MEDIUM / LOW |

A single tracked backlog issue, `Security scan findings (release <X>)`, holds every
"passes with note" item so nothing is silently accepted.

## 4. Triage flow

1. **Reproduce locally** with the same command/pinned versions to confirm the finding is real
   in the current tree.
2. **Assess exploitability** in this codebase, not in the abstract:
   - Is the vulnerable code path reachable from an attacker-controlled input?
   - Is it reachable only behind `require_permission`? Record which role.
   - Is there a compensating control (e.g. `yaml.safe_load`, ORM parameterization)?
   - See `threat-model.md` for whether the finding maps to a registered threat (TH-xx).
3. **Classify:**
   - `Real & reachable` -> fix in the same release; add a regression test (map to a PT-xx
     test in `pen-test-plan.md`).
   - `Real but not exploitable` (compensating control) -> document the control, no code change.
   - `False positive` -> record the reason; adjust the rule/policy rather than suppressing.
   - `No upstream fix` -> open a `wontfix` tracking issue, note the version to re-check.
4. **Remediate:** pin/upgrade the dependency, backport the patch, or refactor the code path.
5. **Verify:** re-run the scanner for the affected package/module, plus the relevant PT-xx
   test and `pytest`.
6. **Record:** every triaged finding lands in the release's security report section and, if
   accepted, in the residual-risk table of `threat-model.md`.

## 5. Local run (no CI)

```bash
# From the repo root
pip install bandit pip-audit semgrep trivy   # or use uvx
bandit -r backend/app
semgrep scan --config=auto backend/ frontend/src/
pip-audit -r backend/requirements.txt
npm --prefix frontend audit --audit-level=high
```

Trivy requires a container runtime or the standalone binary; it is normally executed in CI
against the built images.
