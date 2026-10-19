# patch-pwnescape-k8s

Mitigate container escape ("pwnescape") in Kubernetes with eBPF — no LSM
required.

Three layers live in this repo:

- a **netfilter drop guard** for **CVE-2026-99999 ("PwnEscape")**, enabled by
  default: a BPF netfilter program at IPv4 PREROUTING rejects trigger packets
  *before* routing, forwarding and fragmentation, so the corrupting checksum
  completion never runs and nothing leaves the node (kernel >= 6.4);
- a **kprobe guard** for the same CVE that detects the trigger at
  `skb_checksum_help()` and, in enforce mode, kills the offending sender. It
  is the backstop for packets the PREROUTING hook cannot see (other network
  namespaces) and provides attribution;
- an optional **TC guard** that drops pod egress towards escape/pivot
  channels (node subnet, link-local metadata, host loopback). It is disabled
  in the shipped manifest (`--no-tc-guard`); see *TC guard design* below.

None of these layers is a sandbox: the netfilter hook covers IPv4 traffic that
traverses the host stack, the kprobe contains and attributes the sender, and
the TC guard only removes the network pivot surface. Pure syscall-level escapes
(`unshare`, `mount`, `core_pattern`, ...) need an LSM or a patched kernel (see
*Limitations*).

## CVE-2026-99999 ("PwnEscape") guards

The bug: a packet can be admitted with `CHECKSUM_PARTIAL` and a `csum_start`
that points *inside* the already-validated IPv4 header. When the deferred
completion runs (`skb_checksum_help()`), the kernel writes the computed
checksum at `csum_start + csum_offset` — corrupting header bytes it has already
parsed (`ihl`, addresses, ...). A subsequent `ip_do_fragment()` re-reads the
corrupted header, handing the sender control over fragmentation and output
device selection.

Upstream `6785011f8b16` ("ipv4: validate checksum_start before completing
checksum") adds `ip_check_csum_start()` at the five callers and returns
`-EINVAL` before the completion, which drops the skb. Both eBPF layers below
implement the same predicate (plus a version check, because the hooks are
generic IPv4/IPv6 entry points):

```text
ip_summed == CHECKSUM_PARTIAL
version == 4
csum_start < network_header + ihl*4   =>  reject
```

### Packet rejection: BPF netfilter at PREROUTING (default)

A kprobe cannot reject the packet: it may not abort the probed function or
override its return value (`bpf_override_return`/`fmod_ret` only work on
functions in the kernel's error-injection list, and `skb_checksum_help` is not
in it — checked on the lab node: 519 entries, none matching `checksum`).
eBPF also has no helper to write kernel memory, so it cannot neutralize the
skb in place. TC/XDP are not alternatives either: their context does not
expose `csum_start`/`ip_summed`, and TC egress runs after `ip_do_fragment()`
has already consumed the corrupted header.

The guard therefore uses `BPF_PROG_TYPE_NETFILTER` (Linux >= 6.4), whose
context exposes the `sk_buff` as a BTF pointer and whose verdict can be
`NF_DROP`. It is attached at `NF_INET_PRE_ROUTING` in the host network
namespace with priority `-450` (before conntrack and every other PREROUTING
hook), so a matching packet is dropped before routing, `ip_forward` and
`ip_do_fragment()`: `skb_checksum_help()` never runs and no fragment goes out.

- **Loading**: aya 0.14 has no typed netfilter program support, so
  `patch-pwnescape-k8s/src/netfilter.rs` emits the eBPF instructions directly
  and uses `bpf(2)` (`BPF_PROG_LOAD` + `BPF_LINK_CREATE`). The `sk_buff`
  offsets come from the same BTF parsing as the kprobe and are encoded as
  instruction immediates; no CO-RE, no map for the offsets.
- **Program**: reads `ip_summed` (bitfield), `csum_start`, `network_header`
  and `head` with `bpf_probe_read_kernel`, parses the IPv4 source (version +
  IHL) at `head + network_header`, and returns `NF_DROP` only on the exact
  upstream predicate. All other packets return `NF_ACCEPT`. Packets that are
  not `CHECKSUM_PARTIAL` pay one program call and one 2-byte read.
- **Observability**: a drop counter map is polled once per second and logged as
  `CVE-2026-99999 REJECTED <n> packet(s) at IPv4 PREROUTING`.
- **Failure mode**: if the program cannot be loaded/attached (kernel < 6.4,
  missing capabilities, verifier rejection), the agent logs a warning and
  keeps the kprobe guard active. `--no-netfilter-drop` disables this layer
  explicitly.

**Scope**: the hook is registered in the network namespace the agent runs in —
the host namespace for the DaemonSet (`hostNetwork: true`). Packets that an
attacker injects and forwards *entirely inside a pod/user network namespace*
do not traverse this hook; the kprobe guard still detects and (where the
completion runs in the sender's context) kills the sender. Attaching the drop
program in every pod netns is a possible extension, not implemented here. The
upstream kernel patch remains the only complete fix.

### Detection and attribution: kprobe on `skb_checksum_help()`

The kprobe is the backstop and reporting layer. It runs at
`skb_checksum_help+0`, reads the same fields through the `CSUM_CONFIG` map
(filled from kernel BTF; no CO-RE), and fires on the predicate above.

- **Enforce** (`--kprobe-mode=enforce`): `bpf_send_signal(SIGKILL)` to the
  sending task, but only when completion runs in *that task's process
  context*: `preempt_count & (SOFTIRQ_OFFSET | HARDIRQ_MASK | NMI_MASK) == 0`
  and `!(task->flags & PF_KTHREAD)`. `rcu_read_lock_bh()` and
  `local_bh_disable()` bits are outside the mask, so the normal tun/forwarding
  path stays killable; softirq, hardirq and kthread completions are reported
  but never killed.
- Reports go through a ringbuf and are logged as
  `CVE-2026-99999 KILLED` / `DETECTED` with the offending `comm`/pid and the
  `csum_start`/`network_header`/`ihl` numbers.

With the netfilter layer active, the kprobe normally does **not** fire for a
host-netns trigger: the packet is dropped before `skb_checksum_help()`. It
still matters for other netns paths, for packets generated inside the kernel,
and for attribution.

### What the guards do not do

The kprobe by itself cannot prevent the first corrupting write: if the packet
reaches `skb_checksum_help()`, the write happens and the skb is still
forwarded. That is why the netfilter layer exists. The netfilter layer is a
per-netns signature check, not a kernel fix, and it only covers IPv4 traffic
that traverses the stack where it is attached. The real fix is upstream
`6785011f8b16` or a patched kernel; these layers are a backstop for unpatched
kernels.

### Verified in this lab

`tools/csum-trigger.rs` injects a guest-style packet through a tun device
(`NEEDS_CSUM` virtio header + a 1400-byte UDP datagram), the packet is
forwarded to a 576-byte-MTU veth and `ip_do_fragment()` would complete the
checksum. Result on the lab node (kernel `6.8.0-117-generic`, arm64, Cilium):

| mode | trigger result | `pv1` fragments | agent log |
| --- | --- | --- | --- |
| default (netfilter drop + kprobe) | sender survives (exit 0) | **0** | `REJECTED 1 packet(s) at IPv4 PREROUTING (1 total)` |
| `--no-netfilter-drop` (kprobe only) | sender killed (exit **137**) | **+3 pkts / +1490 B** | `KILLED: csum-trigger[...] csum_start=84 ... network_header=64, ihl=6` |

The default row is the important one: the packet is dropped at PREROUTING, so
routing, forwarding, `ip_do_fragment()` and `skb_checksum_help()` never run;
the sender is not killed because there is nothing to contain. The second row is
the honest kprobe-only limitation (the corrupting write happens and the
fragments are still delivered).

Selectivity is verified with two controls on the same setup:

- no `NEEDS_CSUM` (ordinary tun packet): forwarded, **+3 pkts / +1482 B**, no
  drop and no guard event;
- valid `CHECKSUM_PARTIAL` with `csum_start=20`, `ihl=5`
  (`csum-trigger pescape0 20 6`): forwarded, **+3 pkts / +1482 B**, no drop —
  the guard only rejects the `csum_start < nh + ihl*4` case.

Two kernel gates shape the trigger (both handled in the tool):

1. `virtio_net_hdr_to_skb()` on this kernel rejects `csum_start < nh + 20`
   with `EINVAL`, but compares against the constant `sizeof(struct iphdr)`
   instead of the packet's IHL. A 24-byte header (IHL=6) with
   `csum_start = 20` passes admission and still satisfies
   `csum_start < nh + ihl*4` at completion time.
2. `__fib_validate_source()` (`accept_local=0`) drops packets whose source is
   one of the node's own addresses, so the tun takes `10.99.99.254/24` while
   the packet claims `src 10.99.99.1`.

Reproduce on the node (as root; `pv0`/`pv1` are a scratch veth pair):

```sh
ip link add pv0 type veth peer name pv1
ip link set pv0 mtu 576 up && ip link set pv1 up
ip route add 10.99.98.0/24 dev pv0
ip neigh replace 10.99.98.2 lladdr "$(cat /sys/class/net/pv1/address)" dev pv0 nud permanent

csum-trigger pescape0 none      # control: survives, 3 fragments on pv1
csum-trigger pescape0 20 6      # valid CHECKSUM_PARTIAL: 3 fragments, no drop
csum-trigger pescape0 trigger   # default: REJECTED, 0 fragments, survives
```

To reproduce the kprobe-only row, add `--no-netfilter-drop` to the DaemonSet
arguments (see *Agent flags*); the trigger then exits 137 and `pv1` receives
three fragments.

Build the trigger next to the agent build (macOS host):

```sh
rustc --target=aarch64-unknown-linux-musl -C linker=rust-lld -O \
  tools/csum-trigger.rs -o /tmp/csum-trigger
```

## TC guard design

The TC (`clsact`) classifier is attached to the *ingress* side of every
host-side pod link (`lxc*` on Cilium nodes, `veth*` on other runtimes).
Ingress on that link is exactly the traffic **originating from a pod**
(pod `eth0` egress → host-side veth ingress). It drops pod egress to the
channels a container escape typically pivots through:

| Channel | Why it matters |
| --- | --- |
| Node subnet (`192.168.49.0/24` in this lab) | kubelet API `:10250`, SSH, etcd, container-runtime frontends. On this cluster the kubelet is reachable from **every** pod and answers unauthenticated (`404/401`). |
| `169.254.0.0/16` | Cloud metadata service (`169.254.169.254`) — credentials often reachable from pods. |
| `127.0.0.0/8` | Host loopback reachable through the veth route. |

Destination matches are longest-prefix-matched against an LPM trie
(`POLICY4`), which the userspace agent populates from `--deny-cidr` flags.
Normal cluster traffic is untouched: pod CIDR (`10.244.0.0/16`), service CIDR
(`10.96.0.0/12`) and everything else fall through to the default allow.

- **eBPF** (`patch-pwnescape-k8s-ebpf`): one `SchedClassifier` program
  `tc_pwnescape_guard` parses Ethernet/IPv4/TCP/UDP, looks up the destination
  in an LPM trie, and:
  - `TC_ACT_SHOT` in **enforce** mode (packet dropped),
  - `TC_ACT_UNSPEC` on pass-through (observe mode, no match, unparseable,
    IPv6/ARP/...). `TC_ACT_UNSPEC` is the TCX "run the next program in the
    chain" verdict, which is what keeps Cilium alive (see below).
  - Every match is emitted through an `EVENTS` ringbuf (ifindex, src/dst,
    proto, ports, dropped-or-observed).
- **Maps**: `POLICY4` (LPM trie: 4-byte IPv4 prefix → `Rule {action, proto,
  port}`), `MODE` (`0` observe / `1` enforce), `EXEMPT_IFACES`
  (ifindex → exempt), `EVENTS` (ringbuf).
- **Userspace** (`patch-pwnescape-k8s`): loads the program, populates the
  policy trie and mode, then every `--scan-interval` seconds scans
  `/sys/class/net` for pod links and attaches the guard to new ones
  (`ifindex` → link name table feeds the event log). Link disappearance is
  handled by the kernel (TCX links die with their device), stale entries are
  pruned.

### Cilium coexistence (important)

This cluster runs Cilium, which also attaches TC programs to pod links. On
kernels >= 6.6 (this lab: 6.8) Cilium attaches through **TCX** links, and TCX
chains run programs in order with strict verdict semantics:

- only **`TC_ACT_UNSPEC`** continues to the next program,
- **`TC_ACT_OK` terminates the chain with "accept"**.

Therefore the guard is attached with `LinkOrder::first()` and returns
`TC_ACT_UNSPEC` on pass-through. Cilium's from-container program still runs
after us and its NetworkPolicies keep being enforced; our drops
(`TC_ACT_SHOT`) happen before Cilium sees the packet. (Attaching *after*
Cilium would make the guard silently ineffective, because Cilium's
`TC_ACT_OK` terminates the chain — this is verified in the lab.)

Kernels < 6.6 fall back to a classic clsact/netlink filter; ordering there is
best effort only (`--` see `attach_guard`).

### What this does not do

- No syscall interception (that is the LSM/kprobe layer; this kernel has no
  `bpf` LSM active).
- IPv4 only (IPv6/ARP pass). Extend `try_tc_pwnescape_guard` for IPv6.
- Host-network pods have no veth and are not filtered (they are node-level
  workloads such as Cilium itself).

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)
1. Linux kernel >= 6.4 for the netfilter drop layer (the kprobe layer works on
   older kernels); the lab runs 6.8. aarch64/arm64 in this setup.

## Build

Cross-compile on macOS (the userspace crate depends on Linux-only `aya`):

```shell
cargo build --package patch-pwnescape-k8s --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```

Cargo build scripts build the eBPF object and embed it into the binary.

## Deploy (minikube, `cilium-lab`)

```shell
# build + load the image into every node
docker build -t localhost/patch-pwnescape-k8s:latest .
minikube -p cilium-lab image load localhost/patch-pwnescape-k8s:latest

# deploy the agent (hostNetwork, privileged)
kubectl apply -f deployment/patch-pwnescape.yaml
kubectl -n kube-system logs -l k8s-app=patch-pwnescape-k8s --prefix -f
```

The DaemonSet runs with `hostNetwork: true` (it must see and attach to the
host's pod links and register the CVE netfilter hook in the host network
namespace) and `privileged: true` / `Unconfined` (BPF/TC attach).
A least-privilege profile (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`) is a
hardening TODO.

### Agent flags

```
--no-tc-guard                   disable the TC guard entirely
--no-kprobe-guard               disable the whole CVE-2026-99999 guard
                                (netfilter drop + kprobe)
--no-netfilter-drop             keep the kprobe but disable the PREROUTING drop
--kprobe-mode=observe|enforce   default: enforce (report + SIGKILL)
--mode=observe|enforce          TC guard default: enforce
--deny-cidr=<CIDR>              repeatable; replaces the default
                                (169.254.0.0/16, 127.0.0.0/8)
--pod-link-prefixes=lxc,veth    default: lxc,veth
--exempt-veth=<link>            repeatable; host-side links to never filter
--scan-interval=<secs>          default: 5
```

The shipped DaemonSet runs `--no-tc-guard --kprobe-mode=enforce`, i.e. both
CVE layers with the PREROUTING drop enabled (the default). Drop
`--no-tc-guard` (and add the `--mode`/`--deny-cidr` arguments) to enable the
TC layer as well.

Per-link exemptions are resolved on every scan, so an exempt link that
appears later is picked up. For pod-level exemptions, pass that pod's
host-side link name (visible in `ip link` on the node, e.g. `lxc1a2b3c4d5e6f`).

## TC guard demo (optional — enable the TC guard first)

The shipped manifest runs with `--no-tc-guard`. Re-enable it (see *Agent
flags*) before using this demo.

Baseline **without** the guard: every pod can reach the kubelet:

```shell
kubectl exec escape-artist -- curl -sk -m 4 -o /dev/null -w '%{http_code}\n' https://192.168.49.2:10250/
# 404  -> reachable (escape channel)
```

With `--mode=enforce`:

```shell
kubectl apply -f deployment/escape-test.yaml
kubectl exec escape-artist -- sh -c '
  curl -sk -m 4 -o /dev/null -w "kubelet: %{http_code}\n" https://192.168.49.2:10250/     # 000 + exit 28 (dropped)
  curl -sk -m 4 -o /dev/null -w "apiserver via ClusterIP: %{http_code}\n" https://10.96.0.1:443/  # 403 (still works)
  nslookup nginx                                                                           # DNS still works
'
# daemon log:
# DROPPED: pod egress via lxc89f2e70b7f7b: 10.244.2.113 -> 192.168.49.2 (tcp, dport 10250)
```

Cilium policy is unaffected (this check passes with either guard active):

```shell
kubectl exec allowed-client -- curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://nginx   # 200
kubectl exec blocked-client -- curl -s -m 5 -o /dev/null http://nginx                       # timeout (28)
```

Switch the TC guard to observe mode without redeploying the policy:

```shell
kubectl -n kube-system patch ds patch-pwnescape-k8s --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--mode=observe"}]'
# traffic passes again (kubelet -> 404) and the log says "observed: ..."
```

## CVE guard verification

The full procedure and observed output are in *Verified in this lab* above.
With the default drop layer, the DaemonSet logs rejected packets:

```
[WARN  patch_pwnescape_k8s] CVE-2026-99999 REJECTED 1 packet(s) at IPv4
PREROUTING (1 total): checksum completion never ran, nothing left the node
```

With `--no-netfilter-drop` (kprobe only), the packet is still forwarded and the
kprobe reports/kills:

```
[WARN  patch_pwnescape_k8s] CVE-2026-99999 KILLED: csum-trigger[92542] sent a
CHECKSUM_PARTIAL skb whose csum_start=84 points inside the IPv4 header
(network_header=64, ihl=6, csum_offset write would land on already-validated
header bytes)
```

Switch the kprobe to report-only (no SIGKILL; events still logged, verdict
`detected`); the netfilter drop stays active unless `--no-netfilter-drop` is
also set:

```shell
kubectl -n kube-system patch ds patch-pwnescape-k8s --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/args/1","value":"--kprobe-mode=observe"}]'
```

Disable the PREROUTING drop (kprobe detection remains):

```shell
kubectl -n kube-system patch ds patch-pwnescape-k8s --type=json \
  -p='[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--no-netfilter-drop"}]'
```

### Files

- `patch-pwnescape-k8s-ebpf/src/main.rs` — the kprobe detector and helpers.
- `patch-pwnescape-k8s/src/netfilter.rs` — raw `BPF_PROG_TYPE_NETFILTER`
  emitter/loader for the PREROUTING drop.
- `patch-pwnescape-k8s/src/btf.rs` — BTF reader that supplies the
  `sk_buff`/`task_struct` offsets to both layers.
- `deployment/patch-pwnescape.yaml` — the agent DaemonSet.
- `tools/csum-trigger.rs` — the CVE-2026-99999 trigger used by the guard test.
- `deployment/escape-test.yaml` — a pod that probes the pivot channels.
- `deployment/cilium-deployment.yaml` / `deployment/cilium-policy.yaml` —
  the pre-existing Cilium demo (nginx + allowed/blocked clients).

## Limitations / roadmap

- **The netfilter drop is the prevention; the kprobe is the backstop.** The
  drop program is attached in the host network namespace only, so a packet
  injected and forwarded entirely inside another network namespace is not
  dropped there (the kprobe still detects it). It only covers IPv4 traffic
  that traverses the attached stack, and it is a per-netns signature check,
  not a kernel fix. Patch the kernel (upstream `6785011f8b16`) for complete,
  namespace-independent prevention.
- **The kprobe cannot prevent the write.** It fires at
  `skb_checksum_help()` entry; a kprobe may not abort the function or inject
  an error, and eBPF has no helper to write arbitrary kernel memory
  (SystemTap could neutralize the packet by setting `ip_summed =
  CHECKSUM_NONE`; eBPF cannot). Without the netfilter layer the corrupting
  write happens and the fragments are still delivered
  (`--no-netfilter-drop` demonstrates this); the kprobe reports the sender
  and, in enforce mode, kills it.
- **The drop layer needs kernel >= 6.4** with BPF netfilter support and
  `CAP_BPF`/`CAP_PERFMON` (for `bpf_probe_read_kernel`) plus `CAP_NET_ADMIN`;
  the shipped DaemonSet is privileged. If the program can't be loaded or
  attached, the agent logs the verifier/attach error and keeps the kprobe
  active.
- **The kill is context-dependent.** It only fires when completion runs in the
  sender's process context (tun on arm64, synchronous forwarding). Completions
  in NET_RX softirq, hardirq or kthreads are logged only, because the task
  being killed would not be the sender.
- **Offsets come from BTF at load time** (no CO-RE): the agent parses
  `/sys/kernel/btf/vmlinux`; if the layout can't be resolved the guard refuses
  to attach rather than guess.
- **Syscall-level escapes** (`unshare(CLONE_NEWUSER)`, `mount`,
  `core_pattern`, `kcore`, `init_module`, ...) are not addressed here. BPF
  LSM would be the natural hook but is inactive on this kernel
  (`/sys/kernel/security/lsm` has no `bpf`); kprobe/tracepoint programs with
  `bpf_send_signal` are the alternative. The TC layer remains complementary:
  it contains the network pivot that usually follows an escape.
- IPv4-only policy; port/proto matching exists in `Rule` but the CLI only
  generates all-protocol rules.
- TCX ordering guarantees require kernel >= 6.6 (this lab: 6.8).

## License

With the exception of eBPF code, patch-pwnescape-k8s is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
