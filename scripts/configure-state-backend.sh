#!/usr/bin/env bash
# Select local or S3 Terraform state for vulnerable-vm/aws.
#
# Terraform cannot read variables inside a backend block, so this script reads
# state_backend / state_bucket / state_key from terraform.tfvars and writes (or
# removes) backend_override.tf, which is git-ignored. Run it before `terraform init`.
#
# Usage: scripts/configure-state-backend.sh [tf-dir]   (default: vulnerable-vm/aws)
# Environment overrides: STATE_BACKEND, STATE_BUCKET, STATE_KEY, AWS_REGION
set -euo pipefail

DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)/vulnerable-vm/aws}"
TFVARS="$DIR/terraform.tfvars"
OVERRIDE="$DIR/backend_override.tf"

# Read a simple `name = "value"` entry from terraform.tfvars (empty if absent).
tfvar() {
  [ -f "$TFVARS" ] || return 0
  sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"?([^\"#]*[^\"#[:space:]])\"?[[:space:]]*(#.*)?$/\1/p" "$TFVARS" | head -n1
}

BACKEND="${STATE_BACKEND:-$(tfvar state_backend)}"
BACKEND="${BACKEND:-local}"

case "$BACKEND" in
  local)
    rm -f "$OVERRIDE"
    echo "State backend: local (terraform.tfstate in $DIR)"
    ;;
  s3)
    REGION="${AWS_REGION:-$(tfvar region)}"
    BUCKET="${STATE_BUCKET:-$(tfvar state_bucket)}"
    KEY="${STATE_KEY:-$(tfvar state_key)}"
    KEY="${KEY:-vulnerable-vm/terraform.tfstate}"
    if [ -z "$BUCKET" ]; then
      ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
      BUCKET="forticnapp-threat-tfstate-${ACCOUNT_ID}-${REGION}"
    fi
    [ -n "$REGION" ] || { echo "Error: region not set (tfvars 'region' or AWS_REGION)" >&2; exit 1; }
    cat > "$OVERRIDE" <<TF
terraform {
  backend "s3" {
    bucket       = "${BUCKET}"
    key          = "${KEY}"
    region       = "${REGION}"
    encrypt      = true
    use_lockfile = true
  }
}
TF
    echo "State backend: s3://${BUCKET}/${KEY} (${REGION})"
    echo "Create the bucket once with scripts/create-tfstate-bucket.sh ${REGION} ${BUCKET}"
    ;;
  *)
    echo "Error: state_backend must be \"local\" or \"s3\", got \"$BACKEND\"" >&2
    exit 1
    ;;
esac

echo "Now run: terraform init -reconfigure   (or -migrate-state to move existing state)"
