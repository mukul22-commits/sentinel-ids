# Sentinel IDS v3 - Penetration Test Report

## 1. Report metadata

| Field | Value |
| --- | --- |
| Report ID | SENTINEL-PENTEST-<NNN> |
| Version | <X.Y> |
| Classification | INTERNAL |
| Target version / commit | <RELEASE TAG OR COMMIT SHA> |
| Penetration tester(s) | <NAME(S)> |
| Client / asset owner | <PLATFORM OWNER> |

## 2. Scope and dates

| Field | Value |
| --- | --- |
| Test start date | <YYYY-MM-DD> |
| Test end date | <YYYY-MM-DD> |
| Test type | BLACK-BOX / GRAY-BOX / WHITE-BOX |
| Authorized targets | <HOSTS / URIS, e.g. https://staging.example.com> |
| Out of scope | <E.G. EXTERNAL SIEM COLLECTOR, THIRD-PARTY IDP> |
| Authorization reference | <AUTHORIZATION TICKET / SOW REFERENCE> |

## 3. Environment

| Component | Version / config |
| --- | --- |
| Backend API | <DOCKER TAG / COMMIT> |
| Frontend SPA | <DOCKER TAG / COMMIT> |
| Database | <TIMESCALEDB VERSION> |
| Redis | <VERSION> |
| Worker | <DOCKER TAG / COMMIT> |
| Deployment topology | <COMPOSE STACK / LB / TLS TERMINATION POINT> |
| Accounts provisioned | <VIEWER / ANALYST / ADMIN / SENSOR TOKENS> |

## 4. Methodology

- OWASP ASVS 4.x Level 2 (`docs/security/pen-test-plan.md`).
- OWASP API Security Top 10 (2023).
- Tools: <ZAP / BURP / SQLMAP / CURL / CUSTOM SCRIPTS>.
- All testing was performed against the staged compose stack per the plan; no production or
  local systems were tested.

## 5. Executive summary

<SHORT PARAGRAPH: WHAT WAS TESTED, OVERALL POSTURE, NUMBER OF FINDINGS BY SEVERITY, ANY
HIGH-PROFILE RISKS, AND A READINESS OPINION FOR PRODUCTION.>

## 6. Findings summary

| ID | Severity | CVSS v3.1 | Title | Affected component | Status |
| --- | --- | --- | --- | --- | --- |
| <F-01> | <CRITICAL/HIGH/MEDIUM/LOW/INFO> | <9.8> | <TITLE> | <COMPONENT> | <OPEN/RESOLVED/ACCEPTED> |
| <F-02> | <...> | <...> | <...> | <...> | <...> |

## 7. Detailed findings

### <F-01> <SEVERITY> - <TITLE>

- **CVSS v3.1:** <AV:.. /AC:../PR:../UI:../S:../C:../I:../A:../ = 0.0>
- **OWASP mapping:** <ASVS L2 CHAPTER / API TOP 10 CATEGORY>
- **Affected component:** <ENDPOINT / MODULE / FILE:LINE IF KNOWN>
- **Affected endpoint(s):** <METHOD /api/v1/...>
- **Prerequisites:** <AUTH LEVEL, CONDITIONS>
- **Reproduction steps:**
  1. <STEP>
  2. <STEP>
  3. <STEP>
- **Evidence:** <REQUEST/RESPONSE SNIPPET, SCREENSHOT, LOG EXCERPT - REDACT AS NEEDED>
- **Impact:** <WHAT AN ATTACKER CAN ACHIEVE>
- **Recommended remediation:** <CONCRETE FIX, OPTIONALLY WITH REFERENCE TO HARDENING CHECKLIST>
- **Status:** <OPEN / IN-TRIAGE / FIXED-VERIFIED / ACCEPTED-RISK>

---

### <F-02> ... (REPEAT FOR EACH FINDING)

## 8. Positive findings

Items verified as correctly implemented and worth preserving:

- <E.G. REFRESH TOKEN REUSE DETECTION WORKS: PT-04 PASS>
- <E.G. RBAC MATRIX ENFORCED: PT-09 PASS>
- <...>

## 9. Risk summary and recommendations

| Priority | Action | Owner | Due date |
| --- | --- | --- | --- |
| P1 - <24 HOURS> | <FIX CRITICAL/HIGH FINDINGS> | <OWNER> | <YYYY-MM-DD> |
| P2 - <1 WEEK> | <FIX MEDIUM FINDINGS> | <OWNER> | <YYYY-MM-DD> |
| P3 - <30 DAYS> | <FIX LOW/INFO FINDINGS + HARDENING CHECKLIST ITEMS> | <OWNER> | <YYYY-MM-DD> |

## 10. Sign-off

| Role | Name | Signature / approval | Date |
| --- | --- | --- | --- |
| Penetration tester | <NAME> | <APPROVED> | <YYYY-MM-DD> |
| Platform owner | <NAME> | <APPROVED> | <YYYY-MM-DD> |
| Security lead | <NAME> | <APPROVED> | <YYYY-MM-DD> |
