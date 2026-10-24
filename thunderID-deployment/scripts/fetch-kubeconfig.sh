#!/usr/bin/env bash
# Fetches admin.conf over SSM and points it at the local SSM port-forward.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CP_ID="$(tofu -chdir=infra output -json nodes | jq -r '."cp-01".instance_id')"
API_DNS="$(tofu -chdir=infra output -raw api_endpoint)"

COMMAND_ID="$(aws ssm send-command \
  --instance-ids "$CP_ID" \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["cat /etc/kubernetes/admin.conf"]' \
  --query 'Command.CommandId' --output text)"

aws ssm wait command-executed --command-id "$COMMAND_ID" --instance-id "$CP_ID"

mkdir -p "$HOME/.kube"
aws ssm get-command-invocation \
  --command-id "$COMMAND_ID" \
  --instance-id "$CP_ID" \
  --query StandardOutputContent --output text >"$HOME/.kube/thunderid.yaml"
chmod 600 "$HOME/.kube/thunderid.yaml"

kubectl --kubeconfig "$HOME/.kube/thunderid.yaml" config set-cluster kubernetes \
  --server=https://127.0.0.1:16443 \
  --tls-server-name="$API_DNS"

echo "Wrote $HOME/.kube/thunderid.yaml"
echo "Keep scripts/port-forward-api.sh running in another terminal."
