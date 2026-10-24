#!/usr/bin/env bash
# Installs local-path storage and CloudNativePG. Optionally installs Kyverno
# and Argo CD when INSTALL_GITOPS=true.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

LOCAL_PATH_VERSION="${LOCAL_PATH_VERSION:-v0.0.32}"
CNPG_VERSION="${CNPG_VERSION:-0.29.1}"
KYVERNO_VERSION="${KYVERNO_VERSION:-3.9.2}"
ARGO_CD_VERSION="${ARGO_CD_VERSION:-8.0.9}"
INSTALL_GITOPS="${INSTALL_GITOPS:-false}"

kubectl apply -f "https://raw.githubusercontent.com/rancher/local-path-provisioner/${LOCAL_PATH_VERSION}/deploy/local-path-storage.yaml"
kubectl -n local-path-storage rollout status deploy/local-path-provisioner --timeout=120s
kubectl get storageclass local-path

helm repo add cnpg https://cloudnative-pg.github.io/charts --force-update
helm repo update cnpg
helm upgrade --install cnpg cnpg/cloudnative-pg \
  --version "$CNPG_VERSION" \
  --namespace cnpg-system --create-namespace \
  --wait --timeout 10m

if [[ "$INSTALL_GITOPS" == "true" ]]; then
  helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
  helm repo add argo https://argoproj.github.io/argo-helm --force-update
  helm repo update
  helm upgrade --install kyverno kyverno/kyverno \
    --version "$KYVERNO_VERSION" -n kyverno --create-namespace \
    --wait --timeout 10m
  helm upgrade --install argocd argo/argo-cd \
    --version "$ARGO_CD_VERSION" -n argocd --create-namespace \
    --wait --timeout 15m
fi

kubectl -n cnpg-system get pods
