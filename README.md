# Multi-Scanner Security Audit with LLM Triage

_A one-shot, full-codebase security audit pipeline._

A one-shot security + bug audit that scans an entire codebase (multiple repos),
runs on a single AWS EC2 instance (not a laptop — CodeQL needs the RAM), and
produces:

1. **One merged SARIF** of all deterministic-scanner findings.
2. **An LLM-triaged report** (`report.md`): deduped, false-positives filtered,
   ranked by exploitability, plus a semantic pass for logic/authz/IDOR bugs the
   scanners can't express.

This is a **periodic manual audit**, not per-PR CI. Optimized for coverage +
a usable report, not speed.

---

## Architecture — one EC2 box runs everything

```
 provision_ec2.sh  ──launch──▶  EC2 r6i.2xlarge (64 GB / 8 vCPU, x86_64, Ubuntu 24.04)
   │                                 │
   │ user-data = bootstrap.sh         │  (IAM role: read Secrets Manager, write S3)
   ▼                                 ▼
 bootstrap.sh ──installs──▶ gitleaks, OpenGrep, Bandit, Trivy, checkov,
                            osv-scanner, CodeQL, python/uv, jq, awscli
                            + pulls secrets from Secrets Manager into env
   │
   ▼
 run_scanners.sh ──sequential──▶ 8 scanners, each emits SARIF → out/sarif/<repo>/
   │   (CodeQL LAST + isolated)      │   (per-repo subdir → repo attribution)
   ▼                                 ▼
 merge_sarif.py ──────────────▶ out/merged.sarif
   │
   ▼
 triage.py ──DeepSeek V4 Pro (max reasoning)──▶ out/report.md
   │   1. bulk triage: dedupe / drop FP / rank exploitability / root-cause
   │   2. deep semantic pass: confirm top findings + hunt logic/authz/IDOR
   ▼
 finish.sh ──sync out/ to S3──▶  terminate instance (nothing persists)
   ▲
   └─ run_scanners.sh calls this automatically when RUN_ON_BOOT=1
      (non-interactive). A `shutdown -h +N` hard-kill timer is armed at
      start as a fallback so a hung/forgotten box self-terminates anyway.
```

**Ephemeral lifecycle:** launch → run → push `out/` to S3 → terminate. No
source or secret persists on the box after teardown (data governance + SOC 2).

---

## Files

| File | Runs where | Purpose |
|------|-----------|---------|
| `provision_ec2.sh` | your laptop | Launch r6i.2xlarge + IAM role + SG, write `.instance.json` |
| `bootstrap.sh` | on the instance (user-data) | Install all pinned tools, pull secrets from Secrets Manager |
| `run_scanners.sh` | on the instance | Clone repos, run 8 scanners sequentially, each → SARIF. CodeQL last |
| `merge_sarif.py` | on the instance | Merge all SARIF into `out/merged.sarif` |
| `triage.py` | on the instance | Redact → bulk triage → deep semantic pass → `out/report.md` |
| `finish.sh` | on the instance (or laptop) | Sync `out/` to S3, then terminate the instance |
| `rules/opengrep.yml` | on the instance | Codebase-specific SAST rules (Django authz/IDOR, React XSS, TF open-SG) |
| `README.md` | — | this file |

---

## Prerequisites

### Secrets in AWS Secrets Manager

Create three secrets under prefix `security-audit` (override with `SECRET_PREFIX`):

| Secret name (`${prefix}/…`) | JSON value |
|----------------------------|------------|
| `security-audit/openrouter` | `{"OPENROUTER_API_KEY": "sk-or-..."}` |
| `security-audit/github` | `{"GITHUB_TOKEN": "ghp_..."}` (PAT with `repo:read` on the target repos) |
| `security-audit/repos` | `[{"name":"repo-a","url":"https://github.com/org/repo-a.git"}, ...]` |

The instance role is scoped to `arn:aws:secretsmanager:<region>:*:secret:security-audit*` —
only these secrets are readable.

### S3 bucket

Create (or pick) a bucket for artifacts. The bucket name is the one required
env var to `provision_ec2.sh`:

```bash
export S3_BUCKET=my-audit-artifacts
export AWS_REGION=us-east-1
# optional: an EC2 keypair if you want SSH access (otherwise user-data only)
export KEY_NAME=my-key
```

### Local AWS perms

Whatever creds run `provision_ec2.sh` need: `iam:CreateRole`, `iam:PutRolePolicy`,
`iam:CreateInstanceProfile`, `iam:AddRoleToInstanceProfile`, `iam:GetRole`,
`iam:GetInstanceProfile`, `ec2:*` (run-instances, describe, terminate, create-sg),
`ssm:GetParameter`. See `provision_ec2.sh` for the exact policy attached to the
instance role (read-secrets + write-bucket + CloudWatch logs + self-terminate).

---

## Launch → run → collect → teardown

```bash
# 1. Launch (writes .instance.json with InstanceId + IP).
#    provision uploads the run scripts to S3, then boots the box with
#    RUN_ON_BOOT=1 baked into user-data → bootstrap installs tools, fetches the
#    scripts, runs the WHOLE scan, uploads to S3, and TERMINATES the instance
#    automatically. No SSH needed.
./provision_ec2.sh

# That's it for a hands-off run. The box self-terminates when done. If you'd
# rather drive it yourself (inspect mid-run, tweak rules), SSH in and run
# WITHOUT the auto-finish:
ssh -i <key> ubuntu@<PublicIp>
cd /opt/security-audit && RUN_ON_BOOT=0 bash run_scanners.sh   # no auto-finish, no hard-kill timer
# then collect + terminate manually (interactive prompt):
./finish.sh

# 2. The auto-run already pushed report.md to:
#    s3://$S3_BUCKET/security-audit/<RUN_ID>/report.md  (and merged.sarif + logs)
#    If you ran finish.sh from the laptop, it also downloads report-<RUN_ID>.md.

# 3. Rotate the GitHub PAT + OpenRouter key used (one-shot secrets — rotate).
```

**Self-termination safety net:** when `RUN_ON_BOOT=1`, `run_scanners.sh` arms
`shutdown -h +${SHUTDOWN_TIMEOUT_MIN:-360}` at start, and `provision_ec2.sh`
sets `--instance-initiated-shutdown-behavior=terminate`. So even if the scan
hangs or finish.sh never runs, the box dies within 6h (configurable) — no
zombie r6i.2xlarge bleeding cost. On a clean run, finish.sh terminates the box
outright and the timer is moot.

Tail the run from your laptop before it finishes:

```bash
IID=$(jq -r .InstanceId .instance.json)
aws ec2 get-console-output --instance-id "$IID" --region "$AWS_REGION" --output text | tail -50
```

---

## Scanners (sequential; each emits SARIF)

| # | Tool | What it catches | Notes |
|---|------|------------------|-------|
| 2 | **gitleaks** | secrets across **full git history** (not just working tree) | `--redact` + `--log-opts=--all` |
| 3 | **OpenGrep** + `rules/opengrep.yml` | SAST Python + JS/TS, codebase-specific patterns | replaces any standalone regex layer |
| 4 | **Bandit** | Python-specific SAST | excludes tests/, venv, migrations |
| 5 | **Trivy fs** | dependency CVEs + IaC misconfig + Dockerfile | `--scanners vuln,misconfig,license` |
| 6 | **checkov** | deeper Terraform/IaC rules | complements Trivy |
| 7 | **osv-scanner** | lockfile CVEs (Python + JS) | cross-checks Trivy SCA |
| 8 | **CodeQL** | taint/dataflow Python + JS | runs **last + isolated**, one DB per repo per lang |

All tool versions are **pinned** at the top of `bootstrap.sh`. Bump there;
the run is reproducible from that block (SOC 2 evidence — keep logs + artifacts
in S3).

---

## LLM triage (DeepSeek V4 Pro, max reasoning)

Both AI passes use **`deepseek/deepseek-v4-pro`** via OpenRouter at **max
reasoning** (`reasoning.effort = "xhigh"` — the largest budget DeepSeek V4 Pro
accepts on OpenRouter; maps to `max`). Cheap enough (~$0.44/$0.87 per M tokens,
cached input ~$0.0036/M) to run max-reasoning across the whole finding set.

1. **Bulk triage** (chunked by repo, ~60 findings/call): dedupe, drop false
   positives, rank by exploitability (1–5), group by root cause.
2. **Deep semantic pass** (on the high-risk shortlist, top ~40 non-FP findings):
   confirm each top finding + **hunt logic/authz/business-logic bugs** the
   scanners can't express — broken auth ordering, IDOR, missing authz on new
   endpoints, SSRF, races, mass-assignment.

Token spend (input/output/cached) + estimated cost is appended to `report.md`.

### Secret handling — the critical invariant

gitleaks output contains **real secret values**. Before anything reaches the
LLM, `triage.py`:

- For any finding whose rule/message looks secret-bearing (`secret`, `token`,
  `password`, `gitleaks`, …) — sends **only file + line + rule id**. The
  message and region text are stripped entirely.
- Runs a redaction regex over **every** string that leaves the box (AWS keys,
  private keys, Slack/GitHub/OpenAI/Google tokens, `password=…` literals).
- A **self-check** (`python3 triage.py` with no args) asserts no candidate
  secret pattern survives `redact()` and that a gitleaks-style finding's
  message is stripped before flattening. Run it before every audit.

> No live credential ever enters an LLM prompt. Verify by grepping the
> `out/logs/` for your key prefixes after a run.

---

See [`results/SAMPLE-report.md`](results/SAMPLE-report.md) for a synthetic example of
the triaged report format (fabricated findings — real output is git-ignored).

## Expected output (`out/`)

```
out/
├── report.md                 ← the deliverable: ranked + semantic report (per-repo)
├── merged.sarif              ← all scanner findings, one SARIF (repo-tagged)
├── sarif/
│   └── <repo>/               ← per-repo subdir; parent dir = repo attribution
│       ├── gitleaks.sarif
│       ├── opengrep.sarif
│       ├── bandit.sarif
│       ├── trivy.sarif
│       ├── checkov.sarif
│       ├── osv.sarif
│       └── codeql-<lang>.sarif
├── codeql-db/                ← CodeQL databases (large; not uploaded by default)
└── logs/                     ← per-scanner + clone logs (SOC 2 evidence)
    └── run.log
```

All of `out/` (minus `codeql-db/` if you want to save space) syncs to S3.

---

## Constraints & acceptance criteria

- [x] Scanners run one at a time; CodeQL isolated + last (peak RAM bounded).
- [x] Everything emits SARIF; one merged SARIF is produced.
- [x] Triage report ranks findings, marks likely FPs, lists semantic findings separately.
- [x] No secret values leave in an LLM prompt (redaction verified by self-check).
- [x] All tool versions pinned; run reproducible (logs + artifacts kept in S3).
- [x] All AI steps use DeepSeek V4 Pro with max reasoning; token spend logged.

## Out of scope

- Per-PR CI integration (this is a one-shot manual run).
- DAST / live pentest (handled separately by the AWS Security Agent pentest).
- Auto-fixing findings (report only).
