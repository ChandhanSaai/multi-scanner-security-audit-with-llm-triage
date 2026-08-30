#!/usr/bin/env bash
# on-demand EC2 for a one-shot audit. No ASG, no Launch Template —
# a bare run-instances is the smallest thing that gets the job done for a manual run.
# Upgrade path: wrap in a Terraform module if this runs on a schedule.
#
# Launches an r6i.2xlarge (64 GB / 8 vCPU, x86_64) Ubuntu instance with an IAM
# instance profile that can read audit secrets from Secrets Manager and write
# artifacts to S3. Prints the InstanceId + public IP and writes them to a local
# state file so finish.sh / SSH can find the box.
#
# Usage: ./provision_ec2.sh
# Requires: aws CLI configured with perms to create instance profile + SG + instance.
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-r6i.2xlarge}"   # 64 GB RAM / 8 vCPU, x86_64
# Ubuntu 24.04 AMI resolved via describe-images against Canonical's owner id
# (099720109477) — robust across regions, no fragile SSM parameter path.
KEY_NAME="${KEY_NAME:-}"                          # optional EC2 keypair for SSH; blank = user-data only
S3_BUCKET="${S3_BUCKET:?S3_BUCKET must be set, e.g. my-audit-artifacts}"
SECRET_PREFIX="${SECRET_PREFIX:-security-audit}" # Secrets Manager secret names live under this prefix
PROJECT_TAG="security-audit"
STATE_FILE="$(cd "$(dirname "$0")" && pwd)/.instance.json"

echo "==> Resolving latest Ubuntu 24.04 (amd64) AMI from Canonical..."
AMI_ID="$(aws ec2 describe-images --region "$REGION" \
  --owners 099720109477 \
  --filters 'Name=name,Values=ubuntu/images/hvm-ssd*/ubuntu-noble-24.04-amd64-server-*' \
            'Name=state,Values=available' \
  --query 'sort_by(Images,&CreationDate)[-1].ImageId' --output text)"
if [ -z "$AMI_ID" ] || [ "$AMI_ID" = "None" ]; then
  echo "FATAL: no Ubuntu 24.04 amd64 AMI found in $REGION" >&2; exit 1
fi
echo "    AMI: $AMI_ID"

echo "==> Creating / reusing IAM role + instance profile: $PROJECT_TAG-role"
if ! aws iam get-role --role-name "$PROJECT_TAG-role" >/dev/null 2>&1; then
  aws iam create-role --role-name "$PROJECT_TAG-role" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
    --region "$REGION" >/dev/null
fi
# Inline policy: read secrets, write to S3, write CloudWatch logs. Nothing else.
aws iam put-role-policy --role-name "$PROJECT_TAG-role" --policy-name audit-perms --policy-document "$(cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect":"Allow","Action":["secretsmanager:GetSecretValue"],"Resource":"arn:aws:secretsmanager:${REGION}:*:secret:${SECRET_PREFIX}*"},
    {"Effect":"Allow","Action":["s3:PutObject","s3:PutObjectAcl","s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::${S3_BUCKET}","arn:aws:s3:::${S3_BUCKET}/*"]},
    {"Effect":"Allow","Action":["logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:${REGION}:*:log-group:/security-audit/*"},
    {"Effect":"Allow","Action":["ec2:DescribeInstances","ec2:TerminateInstances"],"Resource":"*"}
  ]
}
JSON
)" --region "$REGION" >/dev/null

if ! aws iam get-instance-profile --instance-profile-name "$PROJECT_TAG-profile" >/dev/null 2>&1; then
  aws iam create-instance-profile --instance-profile-name "$PROJECT_TAG-profile" >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name "$PROJECT_TAG-profile" --role-name "$PROJECT_TAG-role" >/dev/null
fi
# IAM is eventually consistent — EC2 can't see a freshly created profile for a
# few seconds. Confirm IAM has it; the run-instances retry below rides out the
# remaining IAM→EC2 propagation lag.
aws iam wait instance-profile-exists --instance-profile-name "$PROJECT_TAG-profile" 2>/dev/null || true

echo "==> Creating / reusing security group: $PROJECT_TAG-sg"
VPC_ID="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text --region "$REGION")"
SG_ID="$(aws ec2 describe-security-groups --filters Name=group-name,Values=$PROJECT_TAG-sg --query 'SecurityGroups[0].GroupId' --output text --region "$REGION" 2>/dev/null || echo "")"
if [ -z "$SG_ID" ] || [ "$SG_ID" = "None" ]; then
  SG_ID="$(aws ec2 create-security-group --group-name $PROJECT_TAG-sg --description "security-audit runner" --vpc-id "$VPC_ID" --query 'GroupId' --output text --region "$REGION")"
  # Outbound only. No inbound rules unless a keypair is provided (then 22 from your IP).
  if [ -n "$KEY_NAME" ]; then
    MY_IP="$(curl -s https://checkip.amazonaws.com)/32"
    aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 --cidr "$MY_IP" --region "$REGION" >/dev/null
  fi
fi

echo "==> Packaging audit scripts → S3 (so bootstrap can fetch them on the box)..."
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
PAYLOAD_KEY="security-audit/payload-latest.tar.gz"
# ship only the run-time scripts + rules. bootstrap.sh travels via
# user-data (below); .instance.json / report-*.md stay local.
tar -czf /tmp/audit-payload.tar.gz -C "$SELF_DIR" run_scanners.sh merge_sarif.py triage.py finish.sh rules
aws s3 cp /tmp/audit-payload.tar.gz "s3://$S3_BUCKET/$PAYLOAD_KEY" --region "$REGION" >/dev/null
echo "    s3://$S3_BUCKET/$PAYLOAD_KEY"

# LOCAL_SOURCE: if SOURCE_DIR is set, upload that downloaded repo instead of
# cloning on the box (no GitHub token, no 'repos' secret needed).
SOURCE_DIR="${SOURCE_DIR:-}"
if [ -n "$SOURCE_DIR" ]; then
  SOURCE_DIR="${SOURCE_DIR%/}"
  SRC_NAME="$(basename "$SOURCE_DIR")"
  SOURCE_KEY="security-audit/source-latest.tar.gz"
  echo "==> LOCAL_SOURCE: packaging $SOURCE_DIR → s3://$S3_BUCKET/$SOURCE_KEY"
  tar -czf /tmp/audit-source.tar.gz -C "$(dirname "$SOURCE_DIR")" "$SRC_NAME"
  aws s3 cp /tmp/audit-source.tar.gz "s3://$S3_BUCKET/$SOURCE_KEY" --region "$REGION" >/dev/null
fi

echo "==> Launching instance ($INSTANCE_TYPE, 150 GB gp3)..."
BOOTSTRAP="$SELF_DIR/bootstrap.sh"
# Build user-data = env header (tells bootstrap where the payload lives + to
# auto-run the scan) + bootstrap.sh body. Cloud-init runs this as root on boot.
USER_DATA=/tmp/audit-user-data.sh
{
  printf '#!/usr/bin/env bash\n'
  printf 'export AUDIT_S3_BUCKET="%s"\n' "$S3_BUCKET"
  printf 'export AUDIT_PAYLOAD_KEY="%s"\n' "$PAYLOAD_KEY"
  printf 'export AUDIT_REGION="%s"\n' "$REGION"
  printf 'export AWS_REGION="%s"\n' "$REGION"   # belt-and-suspenders for awscli + bootstrap region
  printf 'export RUN_ON_BOOT="1"\n'   # hands-off: scan starts after bootstrap
  if [ -n "$SOURCE_DIR" ]; then
    printf 'export AUDIT_SOURCE_KEY="%s"\n' "$SOURCE_KEY"
    printf 'export AUDIT_SOURCE_NAME="%s"\n' "$SRC_NAME"
  fi
  cat "$BOOTSTRAP"
} > "$USER_DATA"

_launch() {
  aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --iam-instance-profile Name="$PROJECT_TAG-profile" \
    --security-group-ids "$SG_ID" \
    --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=150,VolumeType=gp3,DeleteOnTermination=true}' \
    --instance-initiated-shutdown-behavior terminate \
    --user-data file://"$USER_DATA" \
    ${KEY_NAME:+--key-name "$KEY_NAME"} \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Project,Value=$PROJECT_TAG},{Key=Name,Value=$PROJECT_TAG-runner}]" \
    --query 'Instances[0].InstanceId' --output text --region "$REGION"
}
# Retry the IAM→EC2 propagation race (Invalid IAM Instance Profile) up to ~70s.
INSTANCE_ID=""
for attempt in 1 2 3 4 5 6 7; do
  if INSTANCE_ID="$(_launch 2>/tmp/audit-launch.err)"; then break; fi
  if grep -q "Invalid IAM Instance Profile" /tmp/audit-launch.err; then
    echo "    IAM profile not visible to EC2 yet (attempt $attempt/7) — waiting 10s..."
    sleep 10; INSTANCE_ID=""; continue
  fi
  echo "    run-instances failed:" >&2; cat /tmp/audit-launch.err >&2; exit 1
done
if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "None" ]; then
  echo "FATAL: run-instances still failing after retries:" >&2; cat /tmp/audit-launch.err >&2; exit 1
fi

echo "    InstanceId: $INSTANCE_ID"
echo "==> Waiting for instance to run..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"
PUBLIC_IP="$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text --region "$REGION")"
echo "    Public IP: $PUBLIC_IP"

cat > "$STATE_FILE" <<JSON
{"InstanceId":"$INSTANCE_ID","PublicIp":"$PUBLIC_IP","Region":"$REGION","S3Bucket":"$S3_BUCKET"}
JSON
echo "==> State written to $STATE_FILE"
echo
echo "Next: the instance is running bootstrap.sh via user-data right now."
echo "Tail it:  aws ec2 get-console-output --instance-id $INSTANCE_ID --region $REGION --output text"
echo "When done, collect from S3 and terminate: ./finish.sh"
