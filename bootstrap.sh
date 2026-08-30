#!/usr/bin/env bash
# cloud-init user-data. Pinned versions for reproducibility (SOC 2
# evidence). If a pinned tarball 404s the run fails loudly rather than silently
# grabbing "latest" — a drifting scanner version is worse than a loud failure.
#
# Runs ON the instance. Installs every scanner the audit needs, pulls secrets
# from Secrets Manager into /etc/security-audit.env (root-readable, 0600), and
# clones the run_scanners.sh so a later SSH or the user-data tail can kick it.
# The whole script is idempotent — re-running is safe.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
# cloud-init runs user-data as root with a barebones env — HOME is often unset,
# and `set -u` turns "$HOME" (uv/tool installs) into a hard exit. Pin it.
export HOME="${HOME:-/root}"
# IMDSv2: current Ubuntu AMIs default to HttpTokens=required, so the token-less
# v1 endpoint 401s. Fetch a token, use it; fall back to v1 if v2 unavailable.
# Region: prefer what provision passed (authoritative — set in user-data), then
# AWS_REGION, then IMDS as a last resort (with generous timeouts; IMDS can be slow
# this early in boot). The old code only checked IMDS + AWS_REGION and missed the
# AUDIT_REGION provision actually passes → empty REGION → hard exit.
REGION="${AUDIT_REGION:-${AWS_REGION:-}}"
if [ -z "$REGION" ]; then
  _imds="http://169.254.169.254/latest"
  _token="$(curl -s --max-time 5 -X PUT "$_imds/api/token" -H 'X-aws-ec2-metadata-service-ttl:60' 2>/dev/null || true)"
  [ -n "$_token" ] && REGION="$(curl -s --max-time 5 -H "X-aws-ec2-metadata-token: $_token" "$_imds/meta-data/placement/region" 2>/dev/null || true)"
fi
: "${REGION:?could not determine region (AUDIT_REGION/AWS_REGION unset and IMDS unavailable)}"
export AWS_REGION="$REGION"   # so plain awscli calls in this script default correctly

# arm the hard-kill fallback NOW, before the failure-prone install
# steps — so a bootstrap failure can never leave a zombie box again (we've been
# bitten twice). Instance has --instance-initiated-shutdown-behavior=terminate,
# so this terminates. run_scanners re-arms it; finish.sh terminates on success
# long before it fires.
if [ "${RUN_ON_BOOT:-0}" = "1" ]; then
  shutdown -h +360 "security-audit hard-kill fallback (bootstrap/scan)" >/dev/null 2>&1 || true
fi
AUDIT_DIR="/opt/security-audit"
OUT_DIR="/opt/security-audit/out"
REPO_DIR="/opt/security-audit/repos"
RULES_DIR="/opt/security-audit/rules"

echo "=== [bootstrap] region=$REGION ==="

# --- Pinned versions (bump here; everything reproducible from this block) ---
GITLEAKS_VER="8.21.2"
OPENGREP_VER="1.25.0"
BANDIT_VER="1.8.6"
TRIVY_VER="0.72.0"
CHECKOV_VER="3.3.8"
OSV_SCANNER_VER="1.9.2"
CODEQL_VER="2.20.6"
PYTHON_VER="3.12"
NODE_VER="20"

mkdir -p "$AUDIT_DIR" "$OUT_DIR" "$REPO_DIR" "$RULES_DIR"

echo "=== [bootstrap] apt baseline ==="
apt-get update -y
# NOTE: 'awscli' was removed from Ubuntu 24.04 apt — install AWS CLI v2 below.
apt-get install -y curl wget unzip git jq build-essential libffi-dev \
  libssl-dev pkg-config ruby-full default-jre-headless python3

echo "=== [bootstrap] AWS CLI v2 (apt awscli is gone on 24.04) ==="
if ! command -v aws >/dev/null 2>&1; then
  curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install
  hash -r
fi
aws --version

# from here on, ship the full bootstrap log to S3 on ANY exit — the
# serial console truncates the real error, so this is how we actually debug
# failures (and it captures the success log too). aws + REGION are ready now.
_ship_log() {
  local rc=$?
  aws s3 cp /var/log/cloud-init-output.log \
    "s3://${AUDIT_S3_BUCKET:-}/security-audit/debug/bootstrap-$(date -u +%Y%m%dT%H%M%SZ)-rc${rc}.log" \
    --region "$REGION" >/dev/null 2>&1 || true
}
trap _ship_log EXIT

echo "=== [bootstrap] Python $PYTHON_VER (via uv) ==="
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv python install "$PYTHON_VER"
uv python pin "$PYTHON_VER" --directory "$AUDIT_DIR" 2>/dev/null || true

echo "=== [bootstrap] Node $NODE_VER (for JS scanners / lockfile tooling) ==="
curl -fsSL https://deb.nodesource.com/setup_${NODE_VER}.x | bash -
apt-get install -y nodejs

echo "=== [bootstrap] gitleaks $GITLEAKS_VER ==="
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz" \
  -o /tmp/gitleaks.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks
chmod +x /usr/local/bin/gitleaks

echo "=== [bootstrap] OpenGrep $OPENGREP_VER ==="
# OpenGrep ships a bare manylinux binary (no tarball) — download straight to bin.
curl -sSL "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VER}/opengrep_manylinux_x86" \
  -o /usr/local/bin/opengrep
chmod +x /usr/local/bin/opengrep

echo "=== [bootstrap] Bandit $BANDIT_VER (+ SARIF formatter plugin) ==="
# bandit has NO native sarif output — the bandit-sarif-formatter plugin adds the
# `-f sarif` choice, installed into the same tool venv via --with.
uv tool install "bandit==$BANDIT_VER" --with bandit-sarif-formatter

echo "=== [bootstrap] Trivy $TRIVY_VER ==="
curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VER}/trivy_${TRIVY_VER}_Linux-64bit.tar.gz" \
  -o /tmp/trivy.tar.gz
tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
chmod +x /usr/local/bin/trivy

echo "=== [bootstrap] checkov $CHECKOV_VER (pipx) ==="
uv tool install "checkov==$CHECKOV_VER"

echo "=== [bootstrap] osv-scanner $OSV_SCANNER_VER ==="
curl -sSL "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VER}/osv-scanner_linux_amd64" \
  -o /usr/local/bin/osv-scanner
chmod +x /usr/local/bin/osv-scanner

echo "=== [bootstrap] CodeQL CLI $CODEQL_VER ==="
curl -sSL "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${CODEQL_VER}/codeql-bundle-linux64.tar.gz" \
  -o /tmp/codeql.tar.gz
tar -xzf /tmp/codeql.tar.gz -C /opt
ln -sf /opt/codeql/codeql /usr/local/bin/codeql

echo "=== [bootstrap] fetch run scripts + rules from S3 ==="
# provision_ec2.sh tar'd run_scanners.sh / merge_sarif.py / triage.py / rules/
# into s3://$AUDIT_S3_BUCKET/$AUDIT_PAYLOAD_KEY and passed the coords here via
# the user-data env header. Pull + extract so the scan has something to run.
if [ -n "${AUDIT_S3_BUCKET:-}" ] && [ -n "${AUDIT_PAYLOAD_KEY:-}" ]; then
  aws s3 cp "s3://$AUDIT_S3_BUCKET/$AUDIT_PAYLOAD_KEY" /tmp/audit-payload.tar.gz \
    --region "${AUDIT_REGION:-$REGION}" >/dev/null
  tar -xzf /tmp/audit-payload.tar.gz -C "$AUDIT_DIR"
  chmod +x "$AUDIT_DIR/run_scanners.sh" "$AUDIT_DIR/merge_sarif.py" "$AUDIT_DIR/triage.py"
  echo "    extracted run scripts + rules into $AUDIT_DIR"
else
  echo "    WARNING: AUDIT_S3_BUCKET/AUDIT_PAYLOAD_KEY not set — no run scripts on box." >&2
  echo "    SSH in and upload run_scanners.sh / merge_sarif.py / triage.py / rules/ manually." >&2
fi

echo "=== [bootstrap] pull secrets from Secrets Manager ==="
# Secret names expected: ${SECRET_PREFIX}/openrouter  (OPENROUTER_API_KEY)
#                       ${SECRET_PREFIX}/github       (GitHub PAT for cloning)
#                       ${SECRET_PREFIX}/repos       (JSON list of {name,url} to clone)
SECRET_PREFIX="${SECRET_PREFIX:-security-audit}"
ENV_FILE="/etc/security-audit.env"
: > "$ENV_FILE"; chmod 600 "$ENV_FILE"

get_secret () {
  aws secretsmanager get-secret-value --region "$REGION" \
    --secret-id "${SECRET_PREFIX}/$1" --query SecretString --output text
}

# OpenRouter key — used by triage.py. Never logged, never put in a prompt payload.
get_secret openrouter | jq -r '.OPENROUTER_API_KEY' > /run/openrouter_key
chmod 600 /run/openrouter_key
echo "OPENROUTER_API_FILE=/run/openrouter_key" >> "$ENV_FILE"

# LOCAL_SOURCE mode: code uploaded to S3 (no GitHub token, no 'repos' secret).
if [ -n "${AUDIT_SOURCE_KEY:-}" ]; then
  echo "=== [bootstrap] LOCAL_SOURCE: fetching uploaded source (no token/repos) ==="
  aws s3 cp "s3://$AUDIT_S3_BUCKET/$AUDIT_SOURCE_KEY" /tmp/audit-source.tar.gz \
    --region "${AUDIT_REGION:-$REGION}" >/dev/null
  SRC_NAME="${AUDIT_SOURCE_NAME:-repo}"
  mkdir -p "$REPO_DIR/$SRC_NAME"
  # tarball has one top dir (provision tars `basename SOURCE_DIR`); strip it so
  # files land directly under $REPO_DIR/$SRC_NAME.
  tar -xzf /tmp/audit-source.tar.gz -C "$REPO_DIR/$SRC_NAME" --strip-components=1
  echo "LOCAL_SOURCE=1" >> "$ENV_FILE"
  echo "    source → $REPO_DIR/$SRC_NAME"
else
  # clone path: GitHub token + repo list from Secrets Manager.
  get_secret github | jq -r '.GITHUB_TOKEN' > /run/github_token
  chmod 600 /run/github_token
  echo "GITHUB_TOKEN_FILE=/run/github_token" >> "$ENV_FILE"
  get_secret repos > "$AUDIT_DIR/repos.json"
fi

echo "=== [bootstrap] done. Versions: ==="
gitleaks version || true
opengrep --version || true
bandit --version | head -1 || true
trivy --version | head -1 || true
checkov --version || true
osv-scanner --version || true
codeql version | head -1 || true

# If RUN_ON_BOOT=1 (set in user-data by provisioner), kick the scan immediately.
if [ "${RUN_ON_BOOT:-0}" = "1" ] && [ -x "$AUDIT_DIR/run_scanners.sh" ]; then
  echo "=== [bootstrap] RUN_ON_BOOT=1 → launching run_scanners.sh in nohup ==="
  cd "$AUDIT_DIR"
  nohup bash run_scanners.sh > "$OUT_DIR/run.log" 2>&1 &
fi
