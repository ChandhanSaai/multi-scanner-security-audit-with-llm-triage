#!/usr/bin/env bash
# ship artifacts to S3, then kill the box. Two distinct steps so a
# failed upload never leaves a dangling instance AND never self-terminates
# before your evidence is safely off-box. Termination is the whole point
# (ephemeral lifecycle: nothing source/secret persists after teardown).
set -euo pipefail

# Runs ON the instance (via IMDS role) OR from your laptop (with .instance.json).
AUDIT_DIR="/opt/security-audit"
OUT_DIR="${OUT_DIR:-$AUDIT_DIR/out}"
STATE_FILE="$(cd "$(dirname "$0")" && pwd)/.instance.json"

# Region + bucket: prefer env, else IMDSv2 (token), else state file.
# IMDSv2-required instances 401 the token-less v1 endpoint — use the token.
IMDS="http://169.254.169.254/latest"
_imds_token="$(curl -s --max-time 2 -X PUT "$IMDS/api/token" -H 'X-aws-ec2-metadata-service-ttl:60' 2>/dev/null || true)"
_imds_region() {
  if [ -n "$_imds_token" ]; then
    curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $_imds_token" "$IMDS/meta-data/placement/region" 2>/dev/null
  else
    curl -s --max-time 2 "$IMDS/meta-data/placement/region" 2>/dev/null  # v1 fallback
  fi
}
if [ -n "${AWS_REGION:-}" ]; then REGION="$AWS_REGION"
else
  REGION="$(_imds_region)"
  if [ -z "$REGION" ] && [ -f "$STATE_FILE" ]; then REGION="$(jq -r .Region "$STATE_FILE")"; fi
  if [ -z "$REGION" ] || [ "$REGION" = "null" ]; then
    echo "could not determine region (set AWS_REGION or run on the instance)" >&2; exit 1
  fi
fi
if [ -n "${S3_BUCKET:-}" ]; then BUCKET="$S3_BUCKET"
elif [ -n "${AUDIT_S3_BUCKET:-}" ]; then BUCKET="$AUDIT_S3_BUCKET"   # on-box: bootstrap's env var
elif [ -f "$STATE_FILE" ]; then BUCKET="$(jq -r .S3Bucket "$STATE_FILE")"
else echo "set S3_BUCKET or AUDIT_S3_BUCKET" >&2; exit 1; fi

# A stable run id so multiple audits don't clobber each other in S3.
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
S3_PREFIX="security-audit/${RUN_ID}"

echo "==> uploading $OUT_DIR → s3://$BUCKET/$S3_PREFIX/"
# Sync everything: merged SARIF, per-scanner SARIF, logs, report. Logs are the
# SOC 2 evidence of what ran at which pinned version — keep them.
if [ -d "$OUT_DIR" ]; then
  aws s3 sync "$OUT_DIR" "s3://$BUCKET/$S3_PREFIX/" --region "$REGION" --no-progress
fi
echo "    done.  s3://$BUCKET/$S3_PREFIX/report.md"

# Optional: pull report down to the laptop if we're running from there.
if [ -f "$STATE_FILE" ]; then
  echo "==> downloading report.md locally"
  aws s3 cp "s3://$BUCKET/$S3_PREFIX/report.md" "$(dirname "$0")/report-${RUN_ID}.md" \
    --region "$REGION" || echo "    (download skipped)"
fi

echo "==> WARNING: about to TERMINATE the instance. All on-box state is lost."
if [ -n "${SKIP_TERMINATE:-0}" ] && [ "${SKIP_TERMINATE}" = "1" ]; then
  echo "    SKIP_TERMINATE=1 → leaving instance running. Set SKIP_TERMINATE=0 / unset to terminate."
  exit 0
fi
# FINISH_NONINTERACTIVE=1 (set by run_scanners.sh on a RUN_ON_BOOT run) skips
# the prompt — there's no TTY on a headless box anyway.
if [ "${FINISH_NONINTERACTIVE:-0}" != "1" ]; then
  read -r -p "Terminate now? [y/N] " ans
  if [[ ! "$ans" =~ ^[Yy]$ ]]; then
    echo "    not terminating. Instance still running. Re-run to terminate later."
    exit 0
  fi
fi

# Terminate via IMDSv2 (on-box) or state file (from laptop). Reuse the token
# fetched above for region detection.
if [ -n "$_imds_token" ]; then
  IID="$(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $_imds_token" "$IMDS/meta-data/instance-id")"
  if [ -n "$IID" ]; then
    aws ec2 terminate-instances --instance-ids "$IID" --region "$REGION" >/dev/null
    echo "    terminated $IID (on-box, IMDSv2)"
  fi
fi
if [ -z "${IID:-}" ]; then
  if [ -f "$STATE_FILE" ]; then
    IID="$(jq -r .InstanceId "$STATE_FILE")"
    aws ec2 terminate-instances --instance-ids "$IID" --region "$REGION" >/dev/null
    echo "    terminated $IID (from .instance.json)"
  else
    echo "    could not determine instance id (no IMDS, no .instance.json)" >&2
    exit 1
  fi
fi
echo "==> cleanup: revoke/rotate any secrets used (GitHub PAT, OpenRouter key)."
