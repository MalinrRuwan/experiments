#!/usr/bin/env bash
# Cilium eBPF dataplane with WireGuard node encryption and Hubble flow logs.
# This kernel's iptables NAT backend is unusable, so Cilium replaces kube-proxy.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CILIUM_VERSION="${CILIUM_VERSION:-1.20.3}"
CP1_IP="$(tofu -chdir=infra output -json nodes 2>/dev/null | jq -r '."cp-01".private_ip // empty')"
K8S_HOST="${K8S_HOST:-$CP1_IP}"
if [[ -z "$K8S_HOST" ]]; then
  echo "Set K8S_HOST to the control-plane IP or apply the infrastructure first." >&2
  exit 1
fi

helm repo add cilium https://helm.cilium.io/ --force-update
helm repo update cilium
helm upgrade --install cilium cilium/cilium \
  --version "$CILIUM_VERSION" \
  --namespace kube-system \
  --set ipam.mode=kubernetes \
  --set routingMode=tunnel \
  --set tunnelProtocol=vxlan \
  --set kubeProxyReplacement=true \
  --set k8sServiceHost="$K8S_HOST" \
  --set k8sServicePort=6443 \
  --set encryption.enabled=true \
  --set encryption.type=wireguard \
  --set hubble.enabled=true \
  --set hubble.relay.enabled=true \
  --set hubble.ui.enabled=true \
  --wait --timeout 15m

# kube-proxy cannot program this kernel's NAT table; Cilium owns service routing.
kubectl -n kube-system delete ds kube-proxy --ignore-not-found
kubectl -n kube-system rollout status ds/cilium --timeout=10m
kubectl get nodes -o wide
