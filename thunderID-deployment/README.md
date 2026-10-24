# ThunderID on Kubernetes

A compact AWS lab for ThunderID: a kubeadm cluster, CloudNativePG, Istio,
and the official ThunderID Helm chart.

- 1 × `t4g.small` control plane (no HA)
- 3 × `t4g.small` workers
- 2 × `t4g.small` data nodes
- VPC `10.42.0.0/16`, internal NLB, public ALB + WAF
- Route 53 alias + ACM certificate
- Cilium eBPF (kube-proxy replacement), Istio, CloudNativePG
- ThunderID `1.0.1` from `ghcr.io/thunder-id/thunderid:1.0.1`

PostgreSQL and the ThunderID cert/secret volumes use `local-path` on the
encrypted gp3 root disks for a simple lab. For production, swap in an EBS CSI
`gp3` StorageClass and configure backups.

## Requirements

- AWS account and credentials
- A domain or subdomain, for example `auth.example.com`
- A public Route 53 hosted zone for that name. It can be a subdomain zone
  delegated from Cloudflare.
- `tofu`, `aws` CLI v2, `session-manager-plugin`, `kubectl`, `helm`, `jq`,
  `openssl`
- AWS permissions for VPC, EC2, ELB, WAF, ACM, Route 53, IAM, KMS, S3, SSM

## 1. DNS: Cloudflare → Route 53

Keep the domain registered at Cloudflare and delegate only the auth name:

1. In Route 53, create a public hosted zone named `auth.example.com`.
2. Copy its four `NS` values.
3. In Cloudflare DNS for `example.com`, remove any existing A/AAAA/CNAME for
   `auth`, then add four `NS` records for `auth` with the Route 53 values.
   Keep them DNS-only.
4. Verify:

```bash
dig +short NS auth.example.com @1.1.1.1
```

Terraform creates the ACM validation CNAME and the ALB alias record in Route 53
automatically. To move the whole domain instead, change the registrar's
nameservers; the subdomain delegation is safer.

## 2. Provision AWS

```bash
cp infra/terraform.tfvars.example infra/terraform.tfvars
$EDITOR infra/terraform.tfvars
```

Set at least:

```hcl
aws_region      = "ap-southeast-1"
domain_name     = "auth.example.com"
route53_zone_id = "Z0123456789ABCDEFGHIJ"
```

Then:

```bash
tofu -chdir=infra init
tofu -chdir=infra fmt -check
tofu -chdir=infra validate
tofu -chdir=infra plan
tofu -chdir=infra apply
```

The instances install containerd and kubeadm from user-data. Give the control
plane unlimited CPU credits so etcd/API do not throttle:

```bash
CP1_ID=$(tofu -chdir=infra output -json nodes | jq -r '."cp-01".instance_id')
aws ec2 modify-instance-credit-specification \
  --region "$(tofu -chdir=infra output -raw aws_region)" \
  --instance-credit-specification "InstanceId=$CP1_ID,CpuCredits=unlimited"
```

Read the cluster endpoints:

```bash
tofu -chdir=infra output
API_DNS=$(tofu -chdir=infra output -raw api_endpoint)
CP1_IP=$(tofu -chdir=infra output -json nodes | jq -r '."cp-01".private_ip')
```

## 3. Create the Kubernetes cluster

Open an SSM shell on `cp-01`:

```bash
aws ssm start-session --target "$CP1_ID"
```

Inside, initialize the control plane with the **internal NLB DNS**, not the
public domain. Replace the placeholders first:

```bash
sudo kubeadm init \
  --control-plane-endpoint "<API_DNS>:6443" \
  --apiserver-advertise-address "<CP1_IP>" \
  --pod-network-cidr=10.244.0.0/16 \
  --service-cidr=10.96.0.0/12
```

From your laptop, fetch the admin kubeconfig and keep the API port-forward
running in a separate terminal:

```bash
bash scripts/fetch-kubeconfig.sh
bash scripts/port-forward-api.sh
```

In another terminal:

```bash
export KUBECONFIG="$HOME/.kube/thunderid.yaml"
kubectl get nodes
```

Install Cilium. It replaces kube-proxy because this kernel's iptables NAT
backend cannot program ClusterIPs:

```bash
bash scripts/install-cilium.sh
```

On `cp-01`, print the worker join command:

```bash
sudo kubeadm token create --print-join-command
```

Join the three workers and two data nodes. Use `CP1_IP` in place of the NLB
DNS, because the NLB data path is not used in this lab. Run the command through
SSM on each node:

```bash
sudo kubeadm join "<CP1_IP>:6443" \
  --token <TOKEN> \
  --discovery-token-ca-cert-hash sha256:<HASH> \
  --cri-socket=unix:///run/containerd/containerd.sock
```

Label the nodes:

```bash
kubectl label node worker-01 worker-02 worker-03 role=worker
kubectl label node data-01 data-02 role=data
kubectl get nodes -o wide
```

All six nodes should be `Ready`.

## 4. Install the platform

```bash
bash scripts/install-istio.sh
bash scripts/install-platform.sh
```

`install-platform.sh` installs the local-path provisioner and CloudNativePG.
For optional Kyverno and Argo CD:

```bash
INSTALL_GITOPS=true bash scripts/install-platform.sh
```

Render the domain, bucket and region into the manifests:

```bash
bash scripts/render.sh
```

The ThunderID values are in `manifests/values/thunderid.yaml`. The `publicUrl`
and passkey origin are filled by `render.sh`.

## 5. Deploy PostgreSQL and ThunderID

Create the database bootstrap secret:

```bash
kubectl -n production create secret generic auth-db-app \
  --from-literal=username=auth \
  --from-literal=password="$(openssl rand -hex 24)" \
  --dry-run=client -o yaml | kubectl apply -f -
```

Apply the database and wait:

```bash
kubectl apply -f manifests/platform/00-namespace.yaml
kubectl apply -f manifests/platform/30-postgres.yaml
kubectl -n production wait \
  --for=condition=Ready clusters.postgresql.cnpg.io/auth-db --timeout=10m
```

Create the four ThunderID databases and load their schemas. The official chart
does not create the database tables:

```bash
PRIMARY=$(kubectl -n production get cluster auth-db \
  -o jsonpath='{.status.currentPrimary}')

for db in configdb entitydb runtime_persistent runtime_transient; do
  kubectl -n production exec "$PRIMARY" -- \
    psql -U postgres -c "CREATE DATABASE $db OWNER auth" || true
done

kubectl -n production run thunderid-dbinit \
  --image=ghcr.io/thunder-id/thunderid:1.0.1 \
  --restart=Never --command -- sleep 900
kubectl -n production wait --for=condition=Ready pod/thunderid-dbinit --timeout=180s

PW=$(kubectl -n production get secret auth-db-app -o jsonpath='{.data.password}' | base64 -d)
for db in configdb entitydb runtime_persistent runtime_transient; do
  kubectl -n production exec thunderid-dbinit -- \
    cat /opt/thunderid/dbscripts/$db/postgres.sql \
    | kubectl -n production exec -i "$PRIMARY" -- \
        env PGPASSWORD="$PW" psql -h 127.0.0.1 -U auth -d "$db" \
        -v ON_ERROR_STOP=1 -f -
done

kubectl -n production delete pod thunderid-dbinit
```

Deploy ThunderID with the official chart:

```bash
helm upgrade --install thunderid \
  oci://ghcr.io/thunder-id/helm-charts/thunderid \
  --version 1.0.1 \
  -n production \
  -f manifests/values/thunderid.yaml \
  --wait --timeout 12m
```

The chart runs a one-time setup Job, generates signing keys, and creates the
admin secret. Retrieve the generated password:

```bash
kubectl -n production get secret thunderid-admin-credentials \
  -o jsonpath='{.data.admin-password}' | base64 -d; echo
```

## 6. Verify

```bash
kubectl get nodes
kubectl -n production get pods,svc
curl -I "https://$(tofu -chdir=infra output -raw auth_hostname)/health/readiness"
curl -I "https://$(tofu -chdir=infra output -raw auth_hostname)/console"
```

The ALB health check path is `/health/readiness`. The console is at
`https://<domain>/console/`.

## 7. Destroy everything

Destroy the Kubernetes-created storage first, while the cluster is still
reachable:

```bash
helm uninstall thunderid -n production --ignore-not-found
kubectl -n production delete cluster auth-db --ignore-not-found
kubectl -n production delete pvc --all --ignore-not-found
kubectl get pv
kubectl delete pv --all --ignore-not-found
```

Uninstall optional platform components if installed:

```bash
helm uninstall istio-ingress -n istio-ingress --ignore-not-found
helm uninstall istiod -n istio-system --ignore-not-found
helm uninstall istio-base -n istio-system --ignore-not-found
helm uninstall cnpg -n cnpg-system --ignore-not-found
helm uninstall kyverno -n kyverno --ignore-not-found
helm uninstall argocd -n argocd --ignore-not-found
helm uninstall aws-ebs-csi-driver -n kube-system --ignore-not-found
```

Destroy the AWS infrastructure:

```bash
tofu -chdir=infra plan -destroy
tofu -chdir=infra destroy
```

Finally, clean up the resources Terraform does not own:

- **Route 53 hosted zone**: Terraform removes the ACM validation and alias
  records, but the zone itself was created manually. Delete it in Route 53
  after checking it has no other records.
- **Cloudflare**: remove the four `NS` records that delegated `auth` to
  Route 53.
- **S3 backups**: the bucket has Object Lock in COMPLIANCE mode. If you added
  backups, objects cannot be deleted before the 30-day retention expires and
  `tofu destroy` may fail. Wait out retention before removing the bucket.
- **KMS**: Terraform schedules key deletion with a 30-day window. Check
  `aws kms list-keys` / the console if you need to cancel or confirm it.
- **EBS**: local-path data lives on the instance root disks and is removed with
  the instances. If EBS CSI was used, check for orphaned volumes:

```bash
aws ec2 describe-volumes --region "$(tofu -chdir=infra output -raw aws_region)" \
  --filters Name=status,Values=available \
  --query 'Volumes[].[VolumeId,Size,CreateTime]' --output table
```

- **Local state**: after a successful destroy, remove `infra/terraform.tfstate*`
  if you do not need it. Never commit state or `terraform.tfvars`.

## Notes

- This is a **single-control-plane lab**: if `cp-01` fails, the cluster API is
  unavailable. The original design called for three control-plane nodes.
- The internal NLB is created for the API endpoint and certificate SAN; this
  lab reaches the API through the SSM port-forward to `cp-01`.
- ALB terminates public TLS 1.3. ALB → Istio → ThunderID is HTTP inside the
  VPC. WebAuthn is configured for the public HTTPS origin.
- PostgreSQL backups are not configured by default. Add the CloudNativePG
  Barman Cloud plugin before depending on the S3 bucket.
- Kyverno and Argo CD are optional (`INSTALL_GITOPS=true`). If Kyverno is
  installed, `manifests/platform/50-kyverno-images.yaml` is in `Audit` mode.
- Optional hardening not enabled by the bootstrap: Vault, cert-manager and
  Falco (`bash scripts/install-security.sh`), Cilium L7 policies
  (`manifests/platform/40-cilium-policy.yaml`), and Argo CD GitOps.
