#!/usr/bin/env bash
# scanners run SEQUENTIALLY, one at a time. Peak RAM stays bounded —
# CodeQL is the only one that really wants the 64 GB, and it runs LAST + alone.
# Parallel would buy speed we explicitly don't care about (manual one-shot)
# and raise peak RAM. Keep it serial.
set -euo pipefail

AUDIT_DIR="/opt/security-audit"
OUT_DIR="$AUDIT_DIR/out"
REPO_DIR="$AUDIT_DIR/repos"
RULES_DIR="$AUDIT_DIR/rules"
SARIF_DIR="$OUT_DIR/sarif"
LOG_DIR="$OUT_DIR/logs"
mkdir -p "$SARIF_DIR" "$LOG_DIR" "$REPO_DIR"

[ -f /etc/security-audit.env ] && set -a && . /etc/security-audit.env && set +a
# GH_TOKEN is only needed for the clone path — read inside that branch below, so
# a LOCAL_SOURCE run needs no token and no /run/github_token file.

# on ANY exit (incl. a set -e crash mid-scan), ship run.log + per-scanner
# logs to S3. finish.sh only runs on the success path, so without this a scan
# crash uploads NOTHING and we're blind (exactly what bit us). AUDIT_S3_BUCKET +
# AWS_REGION are inherited from bootstrap's env.
_ship_scan_log() {
  local rc=$?
  if [ -n "${AUDIT_S3_BUCKET:-}" ]; then
    local ts; ts="$(date -u +%Y%m%dT%H%M%SZ)"
    aws s3 cp "$OUT_DIR/run.log" "s3://$AUDIT_S3_BUCKET/security-audit/debug/run-${ts}-rc${rc}.log" --region "${AWS_REGION:-us-west-2}" >/dev/null 2>&1 || true
    aws s3 cp "$LOG_DIR" "s3://$AUDIT_S3_BUCKET/security-audit/debug/scanlogs-${ts}/" --recursive --region "${AWS_REGION:-us-west-2}" >/dev/null 2>&1 || true
  fi
}
trap _ship_scan_log EXIT

# belt-and-suspenders against a forgotten/zombie box. When this run
# was auto-started (RUN_ON_BOOT=1, headless), arm a hard kill timer now — if the
# scan hangs or finish.sh never runs, the instance shuts down + terminates
# (provision sets --instance-initiated-shutdown-behavior=terminate). Normal
# completion calls finish.sh which terminates the box, so the timer is moot.
# SHUTDOWN_TIMEOUT_MIN is generous; CodeQL on big multi-repo audits can run hours.
# The fallback's job is bounding the FORGOTTEN box (a days-long zombie), not the
# normal run — so 6h gives big audits room while still capping the cost leak.
if [ "${RUN_ON_BOOT:-0}" = "1" ]; then
  SHUTDOWN_TIMEOUT_MIN="${SHUTDOWN_TIMEOUT_MIN:-360}"
  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] arming hard-kill fallback: shutdown -h +${SHUTDOWN_TIMEOUT_MIN}m"
  shutdown -h "+${SHUTDOWN_TIMEOUT_MIN}" "security-audit hard-kill fallback (scan hung)" >/dev/null 2>&1 || true
fi

stamp () { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
say    () { echo "[$(stamp)] $*"; }
faillog() { say "  (errors logged to $LOG_DIR/$1)"; }

# Repo list. Two modes:
#   LOCAL_SOURCE=1 → code already unpacked into $REPO_DIR/<name> (uploaded from a
#     downloaded zip). No GitHub token, no repos.json, no clone. gitleaks runs in
#     working-tree mode (no .git history in a zip).
#   default        → clone from repos.json using a token (the EC2 clone path).
LOCAL_SOURCE="${LOCAL_SOURCE:-0}"
REPOS_JSON="${REPOS_JSON:-$AUDIT_DIR/repos.json}"
repo_names() {
  if [ "$LOCAL_SOURCE" = "1" ]; then
    find "$REPO_DIR" -mindepth 1 -maxdepth 1 -type d -exec basename {} \;
  else
    jq -r '.[].name' "$REPOS_JSON"
  fi
}

# --------------------------------------------------------------------------
if [ "$LOCAL_SOURCE" = "1" ]; then
  # fail loudly if the source never got unpacked — otherwise every
  # scanner loops over nothing and the run "succeeds" with zero findings.
  if [ -z "$(repo_names)" ]; then
    echo "FATAL: LOCAL_SOURCE=1 but $REPO_DIR has no repo subdirs. Did bootstrap extract the uploaded source?" >&2
    exit 1
  fi
  say "=== [1/source] LOCAL_SOURCE=1 — scanning pre-supplied code (no clone, no token) ==="
  for name in $(repo_names); do mkdir -p "$SARIF_DIR/$name"; say "  found $name"; done
else
  if [ ! -f "$REPOS_JSON" ] || ! jq -e 'type == "array" and length > 0' "$REPOS_JSON" >/dev/null 2>&1; then
    echo "FATAL: $REPOS_JSON missing/empty. Set LOCAL_SOURCE=1 for pre-supplied code, or provide the 'repos' secret." >&2
    exit 1
  fi
  GH_TOKEN="$(cat "${GITHUB_TOKEN_FILE:-/run/github_token}")"; export GH_TOKEN
  say "=== [1/clone] cloning repos (full history) ==="
  for entry in $(jq -c '.[]' "$REPOS_JSON"); do
    name=$(echo "$entry" | jq -r '.name')
    url=$(echo  "$entry" | jq -r '.url' | sed "s#https://#https://x-access-token:${GH_TOKEN}@#")
    if [ -d "$REPO_DIR/$name/.git" ]; then
      say "  $name: fetch + hard reset to origin/HEAD"
      git -C "$REPO_DIR/$name" fetch --prune --tags origin '+refs/heads/*:refs/heads/*' >>"$LOG_DIR/clone-$name.log" 2>&1 || faillog "clone-$name.log"
      git -C "$REPO_DIR/$name" reset --hard origin/HEAD >>"$LOG_DIR/clone-$name.log" 2>&1 || true
    else
      say "  $name: clone (full history)"
      git clone --no-single-branch "$url" "$REPO_DIR/$name" >>"$LOG_DIR/clone-$name.log" 2>&1 || { say "  CLONE FAILED $name"; faillog "clone-$name.log"; }
    fi
    # Strip the embedded token from git config so it never appears in gitleaks/logs.
    git -C "$REPO_DIR/$name" config --local remote.origin.url "$(echo "$entry" | jq -r '.url')"
    mkdir -p "$SARIF_DIR/$name"
  done
fi

# --------------------------------------------------------------------------
# strip macOS zip cruft — .DS_Store / ._* trip osv's path handling
# and add noise. Junk in a source zip anyway.
find "$REPO_DIR" \( -name '.DS_Store' -o -name '._*' \) -delete 2>/dev/null || true

say "=== [2/gitleaks] secrets ==="
for name in $(repo_names); do
  say "  $name"
  if [ -d "$REPO_DIR/$name/.git" ]; then
    # cloned repo → scan full commit history
    gitleaks git -v --redact --report-format sarif --report-path "$SARIF_DIR/$name/gitleaks.sarif" \
      --log-opts="--all" --source "$REPO_DIR/$name" >>"$LOG_DIR/gitleaks-$name.log" 2>&1 || faillog "gitleaks-$name.log"
  else
    # uploaded zip → no .git → working-tree scan only (history not available)
    gitleaks dir -v --redact --report-format sarif --report-path "$SARIF_DIR/$name/gitleaks.sarif" \
      "$REPO_DIR/$name" >>"$LOG_DIR/gitleaks-$name.log" 2>&1 || faillog "gitleaks-$name.log"
  fi
done

# --------------------------------------------------------------------------
say "=== [3/opengrep] SAST (Python + JS/TS) with custom rules ==="
# Custom rules live in rules/opengrep.yml (codebase-specific patterns).
OG_RULES="${RULES_DIR}/opengrep.yml"
if [ -f "$OG_RULES" ]; then
  for name in $(repo_names); do
    say "  $name"
    # --json emits semgrep JSON (merge_sarif would skip it). --sarif-output
    # writes SARIF v2.1.0 directly. `scan` is the OpenGrep subcommand.
    opengrep scan --config "$OG_RULES" --sarif-output "$SARIF_DIR/$name/opengrep.sarif" \
      "$REPO_DIR/$name" >>"$LOG_DIR/opengrep-$name.log" 2>&1 || faillog "opengrep-$name.log"
  done
else
  say "  (no rules/opengrep.yml — skipping custom SAST; run p/default to use built-in rules)"
fi

# --------------------------------------------------------------------------
say "=== [4/bandit] Python SAST ==="
for name in $(repo_names); do
  py_root="$REPO_DIR/$name"
  [ -d "$py_root" ] || continue
  say "  $name"
  # -x globs match path suffixes; leading slashes don't match. Use
  # */dir/* so bandit skips tests/venv/node_modules/migrations reliably.
  bandit -r "$py_root" -f sarif -o "$SARIF_DIR/$name/bandit.sarif" \
    -x "*/tests/*,*/node_modules/*,*/.venv/*,*/venv/*,*/migrations/*,*/.git/*" \
    >>"$LOG_DIR/bandit-$name.log" 2>&1 || faillog "bandit-$name.log"
done

# --------------------------------------------------------------------------
say "=== [5/trivy] fs scan — deps CVEs + IaC + Dockerfile ==="
for name in $(repo_names); do
  say "  $name"
  trivy fs --quiet --format sarif -o "$SARIF_DIR/$name/trivy.sarif" \
    --scanners vuln,misconfig "$REPO_DIR/$name" >>"$LOG_DIR/trivy-$name.log" 2>&1 || faillog "trivy-$name.log"
done

# --------------------------------------------------------------------------
say "=== [6/checkov] deeper Terraform/IaC rules ==="
for name in $(repo_names); do
  # checkov auto-discovers *.tf, Dockerfiles, etc. across the repo.
  say "  $name"
  # --output-file-path semantics vary by version (dir → fixed
  # results_sarif.sarif name; file → IsADirectoryError in some builds). The
  # version-independent form is: single -o sarif writes SARIF to stdout; redirect
  # it to the exact file, send stderr to the log. --soft-fail keeps exit 0 on
  # real findings (so faillog only fires on actual errors).
  checkov -d "$REPO_DIR/$name" -o sarif --soft-fail \
    >"$SARIF_DIR/$name/checkov.sarif" 2>>"$LOG_DIR/checkov-$name.log" \
    || faillog "checkov-$name.log"
done

# --------------------------------------------------------------------------
say "=== [7/osv-scanner] lockfile CVEs (cross-check Trivy) ==="
for name in $(repo_names); do
  say "  $name"
  # --lockfile-dir doesn't exist; -r/--recursive walks the repo for
  # all lockfiles (package-lock.json, requirements.txt, etc.). osv exits non-zero
  # when vulns are found — that's expected, faillog keeps us going.
  # --no-ignore: skip .gitignore resolution (a zip has no .git → osv errors out
  # trying to compute relative paths and writes no SARIF).
  osv-scanner --recursive --no-ignore "$REPO_DIR/$name" --format sarif \
    --output "$SARIF_DIR/$name/osv.sarif" >>"$LOG_DIR/osv-$name.log" 2>&1 || faillog "osv-$name.log"
done

# --------------------------------------------------------------------------
# CodeQL runs LAST and ALONE. DB build is the RAM/CPU/disk heavyweight.
say "=== [8/codeql] taint/dataflow — Python + JS (isolated, last) ==="
# one DB per repo per language. Compiling all DBs first then running
# queries avoids re-slicing RAM between build+query. If a repo has no code in a
# language, codeql database create fails softly (we skip, logged).
mkdir -p "$OUT_DIR/codeql-db"   # CodeQL won't create this parent dir itself
for name in $(repo_names); do
  for lang in python javascript; do
    db="$OUT_DIR/codeql-db/${name}-${lang}"
    say "  $name / $lang: build DB"
    # --build-mode none: python/js are interpreted (no compile) — extract only.
    codeql database create "$db" --language="$lang" --build-mode none --source-root="$REPO_DIR/$name" \
      --overwrite --threads=0 >>"$LOG_DIR/codeql-$name-$lang.log" 2>&1 || { say "    (no $lang source or build failed)"; continue; }
    say "  $name / $lang: analyze (language default suite)"
    # no explicit query pack. Passing codeql/<lang>-queries directly
    # applies the pack's defaultSuiteFile filters (Trail of Bits: silent zero
    # results) AND running the wrong language's suite errors on mismatch. With
    # no query arg, CodeQL runs the default security+quality suite for the
    # DB's own language — correct and never mismatched.
    codeql database analyze "$db" \
      --format=sarif-latest --output="$SARIF_DIR/$name/codeql-$lang.sarif" \
      --threads=0 >>"$LOG_DIR/codeql-$name-$lang.log" 2>&1 || faillog "codeql-$name-$lang.log"
  done
done

# --------------------------------------------------------------------------
say "=== [9/merge] merging all SARIF ==="
cd "$AUDIT_DIR"
python3 merge_sarif.py "$SARIF_DIR" "$OUT_DIR/merged.sarif" || say "MERGE FAILED"
say "=== [10/triage] LLM triage (DeepSeek V4 Pro, max reasoning) ==="
python3 triage.py "$OUT_DIR/merged.sarif" "$OUT_DIR/report.md" || say "TRIAGE FAILED"
say "=== DONE. Artifacts in $OUT_DIR ==="

# Hands-off finish: upload to S3 + terminate. Non-interactive (no TTY on a
# headless run). finish.sh uploads FIRST, then terminates — so partial results
# survive even if triage failed above. The shutdown timer stays armed as the
# fallback if this terminate call itself fails.
if [ "${RUN_ON_BOOT:-0}" = "1" ]; then
  say "=== [11/finish] RUN_ON_BOOT=1 → upload S3 + terminate (non-interactive) ==="
  FINISH_NONINTERACTIVE=1 bash "$(dirname "$0")/finish.sh" || say "FINISH FAILED (instance may still be running; hard-kill timer will fire)"
else
  say "=== manual run: collect + terminate yourself with ./finish.sh ==="
fi
