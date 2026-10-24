#!/usr/bin/env bash
# Fills infrastructure values into the manifests. Run after `tofu apply`,
# then review `git diff` and commit the rendered values.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

BUCKET="$(tofu -chdir=infra output -raw backup_bucket)"
REGION="$(tofu -chdir=infra output -raw aws_region)"
DOMAIN="$(tofu -chdir=infra output -raw auth_hostname)"

export BUCKET REGION DOMAIN
perl -pi -e '
  s/REPLACE_WITH_BUCKET/$ENV{BUCKET}/g;
  s/REPLACE_WITH_REGION/$ENV{REGION}/g;
  s/REPLACE_WITH_DOMAIN/$ENV{DOMAIN}/g;
' manifests/platform/*.yaml manifests/values/thunderid.yaml

echo "Rendered bucket=${BUCKET} region=${REGION} domain=${DOMAIN}."
echo "Remaining placeholders (image/repo URLs):"
grep -rn "your-org\|REPLACE_WITH" manifests gitops || true
