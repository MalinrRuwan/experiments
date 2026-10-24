#!/usr/bin/env bash
# Optional hardening components from the diagram: Vault PKI/secrets,
# cert-manager, and Falco runtime detection.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CERT_MANAGER_VERSION="${CERT_MANAGER_VERSION:-1.21.2}"
VAULT_CHART_VERSION="${VAULT_CHART_VERSION:-0.34.1}"
FALCO_CHART_VERSION="${FALCO_CHART_VERSION:-9.2.1}"

REGION="$(tofu -chdir=infra output -raw aws_region)"
KMS_KEY_ID="$(tofu -chdir=infra output -raw vault_kms_key_id)"
RENDERED_VALUES="$(mktemp)"
trap 'rm -f "$RENDERED_VALUES"' EXIT

sed -e "s|REPLACE_WITH_REGION|${REGION}|g" \
  -e "s|REPLACE_WITH_KMS_KEY_ID|${KMS_KEY_ID}|g" \
  manifests/values/vault.yaml >"$RENDERED_VALUES"

helm repo add jetstack https://charts.jetstack.io --force-update
helm repo add hashicorp https://helm.releases.hashicorp.com --force-update
helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update
helm repo update

helm upgrade --install cert-manager jetstack/cert-manager \
  --version "$CERT_MANAGER_VERSION" \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true \
  --wait --timeout 10m

# Vault stays uninitialised until `vault operator init`; do not use --wait.
helm upgrade --install vault hashicorp/vault \
  --version "$VAULT_CHART_VERSION" \
  --namespace vault --create-namespace \
  -f "$RENDERED_VALUES"

helm upgrade --install falco falcosecurity/falco \
  --version "$FALCO_CHART_VERSION" \
  --namespace falco --create-namespace \
  --set driver.kind=modern_ebpf \
  --set driver.modernEbpf.leastPrivileged=true \
  --wait --timeout 10m

cat <<'EOF'

Vault is deployed with AWS KMS auto-unseal, but it still needs a one-time init:

  kubectl -n vault exec -it vault-0 -- vault operator init

Store the recovery keys offline. Do not commit them.
EOF
