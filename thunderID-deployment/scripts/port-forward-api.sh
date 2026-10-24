#!/usr/bin/env bash
# Runs until stopped. In another terminal: export KUBECONFIG=$HOME/.kube/thunderid.yaml
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CP_ID="$(tofu -chdir=infra output -json nodes | jq -r '."cp-01".instance_id')"

exec aws ssm start-session \
  --target "$CP_ID" \
  --document-name AWS-StartPortForwardingSession \
  --parameters '{"portNumber":["6443"],"localPortNumber":["16443"]}'
