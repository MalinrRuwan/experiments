#!/usr/bin/env bash
# Installs Istio (SPIFFE identities + STRICT mTLS) and the NodePort gateway.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

ISTIO_VERSION="${ISTIO_VERSION:-1.31.3}"

helm repo add istio https://blob.istio.io/istio-release/charts --force-update
helm repo update istio

helm upgrade --install istio-base istio/base \
  --version "$ISTIO_VERSION" \
  --namespace istio-system --create-namespace \
  --wait --timeout 10m

helm upgrade --install istiod istio/istiod \
  --version "$ISTIO_VERSION" \
  --namespace istio-system \
  --set autoscaleEnabled=false \
  --set resources.requests.cpu=100m \
  --set resources.requests.memory=256Mi \
  --set resources.limits.cpu=500m \
  --set resources.limits.memory=1Gi \
  --wait --timeout 10m

helm upgrade --install istio-ingress istio/gateway \
  --version "$ISTIO_VERSION" \
  --namespace istio-ingress --create-namespace \
  -f manifests/values/istio-gateway.yaml \
  --wait --timeout 10m

kubectl apply -f manifests/platform/00-namespace.yaml
kubectl apply -f manifests/platform/10-istio.yaml

kubectl -n istio-system get pods
kubectl -n istio-ingress get svc
