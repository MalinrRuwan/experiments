#!/usr/bin/env bash
# Installs containerd and the Kubernetes packages on a fresh Ubuntu 24.04 node.
# It is embedded in EC2 user-data by OpenTofu, and can also be run by hand:
#   sudo K8S_MINOR=v1.36 bash bootstrap-node.sh cp-01
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

HOSTNAME="${1:-$(hostname)}"
K8S_MINOR="${K8S_MINOR:-v1.36}"

hostnamectl set-hostname "$HOSTNAME"

# Read the private IP from IMDSv2 so kubelet never advertises a public address.
TOKEN="$(curl -fsS -X PUT http://169.254.169.254/latest/api/token \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)"
NODE_IP="$(curl -fsS -H "X-aws-ec2-metadata-token: ${TOKEN}" \
  http://169.254.169.254/latest/meta-data/local-ipv4 2>/dev/null || true)"
if [[ -z "$NODE_IP" ]]; then
  NODE_IP="$(hostname -I | awk '{print $1}')"
fi

# Kubernetes requires swap off.
swapoff -a 2>/dev/null || true
sed -ri '/\sswap\s/s/^([^#])/#\1/' /etc/fstab

cat >/etc/modules-load.d/k8s.conf <<'EOF'
overlay
br_netfilter
EOF
modprobe overlay
modprobe br_netfilter

cat >/etc/sysctl.d/99-kubernetes-cri.conf <<'EOF'
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sysctl --system >/dev/null

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gpg apt-transport-https containerd

mkdir -p /etc/containerd
if [[ ! -f /etc/containerd/config.toml ]]; then
  containerd config default >/etc/containerd/config.toml
fi
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
systemctl enable --now containerd
systemctl restart containerd

mkdir -p -m 0755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key" |
  gpg --batch --yes --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/ /" \
  >/etc/apt/sources.list.d/kubernetes.list

apt-get update -y
apt-get install -y kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl

printf 'KUBELET_EXTRA_ARGS=--node-ip=%s\n' "$NODE_IP" >/etc/default/kubelet
systemctl daemon-reload
systemctl enable --now kubelet

echo "Node ${HOSTNAME} (${NODE_IP}) bootstrapped with ${K8S_MINOR}."
echo "kubelet will report errors until kubeadm init/join completes; that is expected."
