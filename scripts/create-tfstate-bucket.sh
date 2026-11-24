#!/usr/bin/env bash
# Create the S3 bucket that holds the Terraform state for vulnerable-vm/aws.
# Uses the AWS CLI with your current credentials. Safe to re-run.
#
# Usage: scripts/create-tfstate-bucket.sh [region] [bucket-name]
#   region       defaults to $AWS_REGION, then $AWS_DEFAULT_REGION, then the CLI profile region
#   bucket-name  defaults to multi-cve-tfstate-<account-id>-<region> (what the GitHub workflow expects)
set -euo pipefail

REGION="${1:-${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region || true)}}}"
if [ -z "$REGION" ]; then
  echo "Error: no region given. Pass it as the first argument or set AWS_REGION." >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
BUCKET="${2:-multi-cve-tfstate-${ACCOUNT_ID}-${REGION}}"

echo "Account: $ACCOUNT_ID"
echo "Region:  $REGION"
echo "Bucket:  $BUCKET"

if aws s3api head-bucket --bucket "$BUCKET" --region "$REGION" 2>/dev/null; then
  echo "Bucket already exists, only (re)applying its settings."
else
  # us-east-1 must not be given a LocationConstraint.
  if [ "$REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION"
  else
    aws s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=$REGION"
  fi
fi

aws s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

aws s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

echo "Done. State bucket ready: s3://$BUCKET"
