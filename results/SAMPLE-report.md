# Security Audit — LLM-Triaged Report (SAMPLE)

> **This is a synthetic example** showing the report format. All findings,
> paths, and repo names below are fabricated (`example-app`) for illustration.
> Real audit output is git-ignored and never committed.

_Scanner findings: 312 raw → 34 deduped (27 real, 7 likely-FP). Semantic findings: 4._

## Ranked Real Findings (by exploitability)

| # | Sev | Repo | Tool | Root cause | File:Line | #inst | Rationale |
|---|-----|------|------|------------|-----------|-------|-----------|
| 1 | 5 | example-app | gitleaks | Hardcoded API token in source | `example-app/services/mailer.py:14` | 1 | Live credential committed to history; grants third-party API access if leaked. |
| 2 | 5 | example-app | Trivy | Security group opens SSH to 0.0.0.0/0 | `example-app/infra/network.tf:22` | 1 | Unrestricted SSH invites brute-force and unauthorized access. |
| 3 | 4 | example-app | OpenGrep | View missing authentication decorator | `example-app/api/reports.py:88` | 3 | Endpoint reachable without auth; risks unauthorized data access. |
| 4 | 4 | example-app | OpenGrep | Object fetched by user-supplied ID without ownership check | `example-app/api/orders.py:41` | 6 | IDOR — a guessed ID exposes another user's records. |
| 5 | 4 | example-app | Bandit | subprocess call with shell=True on request data | `example-app/jobs/convert.py:57` | 2 | User-controlled input reaches a shell; command-injection risk. |
| 6 | 3 | example-app | osv-scanner | Known CVE in transitive dependency | `example-app/requirements.txt:19` | 1 | Vulnerable version pinned; upgrade to the patched release. |

## Likely False Positives (suppressed)

| Repo | Tool | Rule | File:Line | Why FP |
|------|------|------|-----------|--------|
| example-app | Bandit | B101 assert_used | `example-app/tests/test_auth.py:12` | Assert in test code, not a runtime guard. |
| example-app | Trivy | missing resource tags | `example-app/infra/logs.tf:8` | Cost-tracking hygiene; no security impact. |

## Semantic Findings (logic / authz — scanners can't express these)

1. **Broken auth ordering** — `example-app/api/middleware.py`: rate-limit runs *after* the
   auth check short-circuits, so unauthenticated requests bypass throttling.
2. **Mass-assignment** — `example-app/api/users.py:120`: the serializer accepts an
   `is_admin` field from the request body on profile update.

---

_Token spend: in 1.2M / out 0.18M / cached 0.9M — est. $0.71 (deepseek-v4-pro, max reasoning)._
