#!/usr/bin/env bash
# Local one-repo audit (macOS/Linux). Reuses merge_sarif.py + triage.py.
# CodeQL is OPT-IN (CODEQL=1) — it's the RAM hog; skip on a 16 GB laptop.
#
#   OPENROUTER_API_KEY=... ./run_local.sh /path/to/repo
#   CODEQL=1 ./run_local.sh /path/to/repo      # include CodeQL (needs codeql CLI + RAM)
set -euo pipefail

REPO="${1:?usage: run_local.sh /path/to/repo}"
REPO="${REPO%/}"                       # strip trailing slash
NAME="$(basename "$REPO")"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out-local"
SARIF="$OUT/sarif/$NAME"
LOG="$OUT/logs"
mkdir -p "$SARIF" "$LOG"

# key: env or your secrets file
[ -z "${OPENROUTER_API_KEY:-}" ] && [ -f ~/.config/openrouter.env ] && . ~/.config/openrouter.env
export OPENROUTER_API_KEY

say(){ echo "[$(date -u +%H:%M:%SZ)] $*"; }
have(){ command -v "$1" >/dev/null 2>&1; }

say "=== auditing $NAME ($REPO) → $SARIF ==="

# 1. secrets (working tree — zip has no git history)
if have gitleaks; then
  say "gitleaks (dir)"
  gitleaks dir --redact --report-format sarif --report-path "$SARIF/gitleaks.sarif" "$REPO" \
    >>"$LOG/gitleaks.log" 2>&1 || say "  (gitleaks non-zero — see log)"
else say "  skip gitleaks (not installed)"; fi

# 2. SAST — prefer opengrep, else semgrep (same rule syntax)
SAST=""; have opengrep && SAST=opengrep; [ -z "$SAST" ] && have semgrep && SAST=semgrep
if [ -n "$SAST" ]; then
  RULES="$HERE/rules/opengrep.yml"; CFG=(--config "auto"); [ -f "$RULES" ] && CFG=(--config "$RULES" --config "auto")
  say "$SAST"
  "$SAST" scan "${CFG[@]}" --sarif-output "$SARIF/$SAST.sarif" "$REPO" >>"$LOG/$SAST.log" 2>&1 || say "  ($SAST non-zero — see log)"
else say "  skip SAST (install opengrep or: brew install semgrep)"; fi

# 3. Python SAST
if have bandit; then
  say "bandit"
  bandit -r "$REPO" -f sarif -o "$SARIF/bandit.sarif" \
    -x "*/tests/*,*/node_modules/*,*/.venv/*,*/venv/*,*/migrations/*,*/.git/*" \
    >>"$LOG/bandit.log" 2>&1 || say "  (bandit non-zero — see log)"
else say "  skip bandit"; fi

# 4. deps + IaC + Dockerfile
if have trivy; then
  say "trivy fs"
  trivy fs --quiet --format sarif -o "$SARIF/trivy.sarif" --scanners vuln,misconfig,license "$REPO" \
    >>"$LOG/trivy.log" 2>&1 || say "  (trivy non-zero — see log)"
else say "  skip trivy"; fi

# 5. deeper IaC
if have checkov; then
  say "checkov"
  checkov -d "$REPO" -o sarif --soft-fail >"$SARIF/checkov.sarif" 2>>"$LOG/checkov.log" || say "  (checkov non-zero — see log)"
else say "  skip checkov"; fi

# 6. lockfile CVEs
if have osv-scanner; then
  say "osv-scanner"
  osv-scanner --recursive "$REPO" --format sarif --output "$SARIF/osv.sarif" \
    >>"$LOG/osv.log" 2>&1 || say "  (osv non-zero — see log)"
else say "  skip osv-scanner"; fi

# 7. CodeQL — opt-in only
if [ "${CODEQL:-0}" = "1" ] && have codeql; then
  for lang in python javascript; do
    db="$OUT/codeql-db/$NAME-$lang"
    say "codeql $lang: build"
    codeql database create "$db" --language="$lang" --source-root="$REPO" --overwrite --threads=0 \
      >>"$LOG/codeql-$lang.log" 2>&1 || { say "  (no $lang or build failed)"; continue; }
    say "codeql $lang: analyze"
    codeql database analyze "$db" --format=sarif-latest --output="$SARIF/codeql-$lang.sarif" --threads=0 \
      >>"$LOG/codeql-$lang.log" 2>&1 || say "  (codeql analyze non-zero — see log)"
  done
elif [ "${CODEQL:-0}" = "1" ]; then say "  CODEQL=1 but codeql not installed"; fi

# 8. merge + triage (portable — reuse the EC2 scripts)
say "merge"
python3 "$HERE/merge_sarif.py" "$OUT/sarif" "$OUT/merged.sarif"
say "triage (DeepSeek V4 Pro, max reasoning)"
python3 "$HERE/triage.py" "$OUT/merged.sarif" "$OUT/report.md"
say "=== DONE → $OUT/report.md ==="
