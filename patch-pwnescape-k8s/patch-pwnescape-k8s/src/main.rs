use std::{
    collections::{HashMap, HashSet},
    fs,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, anyhow, bail};
use aya::{
    Ebpf,
    maps::{
        Array as EbpfArray, HashMap as EbpfHashMap,
        lpm_trie::{Key, LpmTrie},
        ring_buf::RingBuf,
    },
    programs::{
        KProbe, LinkOrder, SchedClassifier, TcAttachType,
        tc::{NlOptions, TcAttachOptions},
    },
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use patch_pwnescape_k8s_common::{
    CsumEvent, CsumOffsets, MAP_CSUM_CONFIG, MAP_CVE_EVENTS, MAP_CVE_MODE, MAP_EVENTS,
    MAP_EXEMPT_IFACES, MAP_MODE, MAP_POLICY4, MODE_ENFORCE, MODE_KEY, MODE_OBSERVE,
    PROG_KPROBE_GUARD, PROG_TC_GUARD, PacketEvent, Rule,
};
use tokio::{io::unix::AsyncFd, signal, time::interval};

mod btf;
mod netfilter;

/// Mitigate container escapes:
///
/// * a TC classifier on every host-side pod link drops pod traffic that heads
///   for the node subnet (kubelet/apiserver/ssh/etcd), link-local metadata and
///   host loopback (`--no-tc-guard` disables it);
/// * a BPF netfilter program at IPv4 PREROUTING rejects CVE-2026-99999
///   ("PwnEscape") packets before routing/fragmentation: a `CHECKSUM_PARTIAL`
///   skb whose `csum_start` points inside the IPv4 header would let the
///   deferred checksum write mutate an already-validated header
///   (`--no-netfilter-drop` disables it, `--no-kprobe-guard` disables the
///   whole CVE guard);
/// * a kprobe on `skb_checksum_help()` detects the same trigger as a
///   defense-in-depth/reporting layer and can `SIGKILL` the sender when the
///   completion runs in its process context.
#[derive(Debug, Parser)]
struct Opt {
    /// `observe` only logs matches, `enforce` drops them.
    #[clap(long, default_value = "enforce")]
    mode: String,

    /// IPv4 destination CIDR to drop pod traffic to. Repeatable. Replaces the
    /// default (169.254.0.0/16, 127.0.0.0/8).
    #[clap(long = "deny-cidr", value_name = "CIDR")]
    deny_cidrs: Vec<String>,

    /// Prefixes of host-side pod links. Cilium names them `lxc*`, other
    /// runtimes `veth*`.
    #[clap(long, value_delimiter = ',', default_value = "lxc,veth")]
    pod_link_prefixes: String,

    /// Host-side pod links to exempt from enforcement, by name. Repeatable.
    #[clap(long = "exempt-veth", value_name = "LINK")]
    exempt_veths: Vec<String>,

    /// Seconds between scans of /sys/class/net for new pod links.
    #[clap(long, default_value_t = 5)]
    scan_interval: u64,

    /// Do not load or attach the TC pod-egress classifier.
    #[clap(long)]
    no_tc_guard: bool,

    /// Do not load or attach the CVE-2026-99999 checksum guard (both the
    /// netfilter drop hook and the kprobe detector).
    #[clap(long)]
    no_kprobe_guard: bool,

    /// Do not attach the CVE-2026-99999 netfilter drop hook at IPv4
    /// PREROUTING; the kprobe detector stays active.
    #[clap(long)]
    no_netfilter_drop: bool,

    /// CVE guard: `observe` only reports violations, `enforce` also sends
    /// `SIGKILL` when the checksum completion runs in the offending process
    /// context (softirq and kernel threads are always report-only).
    #[clap(long, default_value = "observe")]
    kprobe_mode: String,
}

const DEFAULT_DENY_CIDRS: &[&str] = &["169.254.0.0/16", "127.0.0.0/8"];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    let mode = match opt.mode.as_str() {
        "observe" => MODE_OBSERVE,
        "enforce" => MODE_ENFORCE,
        other => bail!("unknown mode `{other}` (expected `observe` or `enforce`)"),
    };

    // Bump the memlock rlimit. This is needed for older kernels that don't use
    // the new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/patch-pwnescape-k8s"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            // SAFETY: The logger owns its file descriptor, which stays open and unchanged
            // while the AsyncFd owns it. We only flush the logger, never replace it.
            let mut logger = unsafe {
                tokio::io::unix::AsyncFd::register_with_interest(
                    logger,
                    tokio::io::Interest::READABLE,
                )
            }?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let Opt {
        mode: _,
        deny_cidrs,
        pod_link_prefixes,
        exempt_veths,
        scan_interval,
        no_tc_guard,
        no_kprobe_guard,
        no_netfilter_drop,
        kprobe_mode,
    } = &opt;

    let tc_enabled = !no_tc_guard;
    let cve_enabled = !no_kprobe_guard;
    if !tc_enabled && !cve_enabled {
        bail!("--no-tc-guard and --no-kprobe-guard together leave nothing to do");
    }

    // --------------------------------------------------------------- TC guard
    let mut attached: HashSet<String> = HashSet::new();
    let ifnames: Arc<Mutex<HashMap<u32, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let prefixes: Vec<String> = pod_link_prefixes
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();

    if tc_enabled {
        // The deny list: CLI-provided or the defaults.
        let cidrs: Vec<&str> = if deny_cidrs.is_empty() {
            DEFAULT_DENY_CIDRS.to_vec()
        } else {
            deny_cidrs.iter().map(String::as_str).collect()
        };

        // Populate the policy trie.
        let mut policy: LpmTrie<_, [u8; 4], Rule> =
            LpmTrie::try_from(ebpf.map_mut(MAP_POLICY4).context("POLICY4 map")?)?;
        for cidr in &cidrs {
            let (prefix_len, addr) = parse_cidr(cidr)?;
            policy
                .insert(&Key::new(prefix_len, addr.octets()), Rule::drop_any(), 0)
                .with_context(|| format!("inserting deny cidr {cidr}"))?;
            info!("policy: drop pod egress to {cidr}");
        }

        // Enforcement mode.
        let mut mode_map: EbpfHashMap<_, u32, u32> =
            EbpfHashMap::try_from(ebpf.map_mut(MAP_MODE).context("MODE map")?)?;
        mode_map.insert(MODE_KEY, mode, 0)?;
        info!(
            "tc mode: {}",
            if mode == MODE_ENFORCE {
                "enforce (drop)"
            } else {
                "observe (log only)"
            }
        );

        // Load the classifier once; attach happens per pod link.
        let prog: &mut SchedClassifier = ebpf
            .program_mut(PROG_TC_GUARD)
            .with_context(|| format!("finding {PROG_TC_GUARD}"))?
            .try_into()?;
        prog.load()?;

        // Hand the events map to the reader task, together with a table to
        // translate ifindex -> link name.
        let events_map = Ebpf::take_map(&mut ebpf, MAP_EVENTS).context("EVENTS map")?;
        let events_rb: RingBuf<_> = RingBuf::try_from(events_map)?;
        // SAFETY: The ring buffer owns its file descriptor, which stays open and
        // unchanged while the AsyncFd owns it. We only consume events, never
        // replace the buffer.
        let mut events = unsafe { AsyncFd::register(events_rb) }?;
        let ifnames_for_events = Arc::clone(&ifnames);
        tokio::task::spawn(async move {
            loop {
                let mut guard = events.readable_mut().await.expect("events readable");
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    handle_event(&item, &ifnames_for_events);
                }
                guard.clear_ready();
            }
        });

        // Scan host links for pods and keep the guard attached to all of them.
        scan_and_attach(&mut ebpf, &mut attached, &prefixes, exempt_veths, &ifnames)?;
    }

    // ------------------------------------------------- CVE-2026-99999 guard
    if cve_enabled {
        // Both layers mirror upstream `ip_check_csum_start()`. TC hooks cannot
        // reach the trigger: it lives in `struct sk_buff` metadata
        // (`ip_summed`/`csum_start`), not in packet bytes. The netfilter
        // context does expose the skb, which is what makes the drop layer
        // possible. Offsets come from kernel BTF because no BPF helper exposes
        // them.
        let offsets = btf::csum_offsets()?;
        info!(
            "CVE-2026-99999 guard offsets: head={} network_header={} ({}B) csum_start={} ({}B) \
             ip_summed=bit{} ({} bits) preempt_count={} ({}B) task_flags={}",
            offsets.head,
            offsets.network_header,
            offsets.network_header_size,
            offsets.csum_start,
            offsets.csum_start_size,
            offsets.ip_summed_bit,
            offsets.ip_summed_bits,
            offsets.task_preempt_count,
            offsets.preempt_count_size,
            offsets.task_flags,
        );

        let mut cfg_map: EbpfArray<_, CsumOffsets> =
            EbpfArray::try_from(ebpf.map_mut(MAP_CSUM_CONFIG).context("CSUM_CONFIG map")?)?;
        cfg_map.set(0, offsets, 0)?;

        // The kprobe can only observe and kill: a kprobe may not abort the
        // probed function or force an error return (skb_checksum_help() is not
        // error-injectable). Reject the packet earlier, at IPv4 PREROUTING,
        // where a BPF netfilter program can read sk_buff metadata and return
        // NF_DROP before routing and fragmentation.
        if !no_netfilter_drop {
            match netfilter::NetfilterDrop::attach(&offsets) {
                Ok(guard) => {
                    info!(
                        "CVE-2026-99999 drop guard attached at IPv4 PREROUTING (priority {}): \
                         offending skbs are rejected before routing, forwarding and fragmentation",
                        netfilter::PREROUTING_PRIORITY
                    );
                    tokio::task::spawn(async move {
                        let mut last = 0u64;
                        loop {
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            match guard.drops() {
                                Ok(total) if total != last => {
                                    warn!(
                                        "CVE-2026-99999 REJECTED {} packet(s) at IPv4 PREROUTING \
                                         ({} total): checksum completion never ran, nothing left \
                                         the node",
                                        total - last,
                                        total
                                    );
                                    last = total;
                                }
                                Ok(_) => {}
                                Err(e) => warn!("CVE-2026-99999 drop counter: {e:#}"),
                            }
                        }
                    });
                }
                Err(e) => warn!(
                    "CVE-2026-99999 drop guard unavailable: {e:#}; kprobe detection remains \
                     active"
                ),
            }
        } else {
            info!("CVE-2026-99999 drop guard disabled (--no-netfilter-drop): kprobe detection only");
        }

        let cve_mode = match kprobe_mode.as_str() {
            "observe" => MODE_OBSERVE,
            "enforce" => MODE_ENFORCE,
            other => bail!("unknown kprobe mode `{other}` (expected `observe` or `enforce`)"),
        };
        let mut cve_mode_map: EbpfArray<_, u32> =
            EbpfArray::try_from(ebpf.map_mut(MAP_CVE_MODE).context("CVE_MODE map")?)?;
        cve_mode_map.set(0, cve_mode, 0)?;

        let prog: &mut KProbe = ebpf
            .program_mut(PROG_KPROBE_GUARD)
            .with_context(|| format!("finding {PROG_KPROBE_GUARD}"))?
            .try_into()?;
        prog.load()?;
        prog.attach("skb_checksum_help", 0)
            .context("attaching the CVE guard to skb_checksum_help")?;
        info!(
            "CVE-2026-99999 guard attached to skb_checksum_help: {}",
            if cve_mode == MODE_ENFORCE {
                "enforce (report + SIGKILL in process context)"
            } else {
                "observe (report only)"
            }
        );

        let events_map = Ebpf::take_map(&mut ebpf, MAP_CVE_EVENTS).context("CVE_EVENTS map")?;
        let events_rb: RingBuf<_> = RingBuf::try_from(events_map)?;
        // SAFETY: The ring buffer owns its file descriptor, which stays open and
        // unchanged while the AsyncFd owns it. We only consume events, never
        // replace the buffer.
        let mut events = unsafe { AsyncFd::register(events_rb) }?;
        tokio::task::spawn(async move {
            loop {
                let mut guard = events.readable_mut().await.expect("cve events readable");
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    handle_csum_event(&item);
                }
                guard.clear_ready();
            }
        });
    }

    // -------------------------------------------------------------- main loop
    let mut ticker = interval(Duration::from_secs(*scan_interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    println!("Watching for pod links and CVE-2026-99999 violations (Ctrl-C to exit)...");
    loop {
        tokio::select! {
            _ = &mut ctrl_c => break,
            _ = ticker.tick(), if tc_enabled => {
                if let Err(e) =
                    scan_and_attach(&mut ebpf, &mut attached, &prefixes, exempt_veths, &ifnames)
                {
                    warn!("scan: {e}");
                }
            }
        }
    }
    println!("Exiting...");
    Ok(())
}

/// Discover host-side pod links, keep the TC guard attached to each, refresh
/// the ifindex -> name table and the exemption list.
fn scan_and_attach(
    ebpf: &mut Ebpf,
    attached: &mut HashSet<String>,
    prefixes: &[String],
    exempt_veths: &[String],
    ifnames: &Arc<Mutex<HashMap<u32, String>>>,
) -> anyhow::Result<()> {
    let links = pod_links(prefixes)?;

    // Refresh ifindex -> name table.
    ifnames
        .lock()
        .expect("ifnames")
        .retain(|_, name| links.iter().any(|(_, n)| n == name));
    for (ifindex, name) in &links {
        ifnames
            .lock()
            .expect("ifnames")
            .insert(*ifindex, name.clone());
    }

    // Refresh exemptions (late-appearing exempt links get picked up here too).
    let mut exemptions: EbpfHashMap<_, u32, u8> = EbpfHashMap::try_from(
        ebpf.map_mut(MAP_EXEMPT_IFACES)
            .context("EXEMPT_IFACES map")?,
    )?;
    for (ifindex, name) in &links {
        if exempt_veths.iter().any(|ex| name == ex) {
            exemptions.insert(*ifindex, 1, 0)?;
        }
    }

    // Attach to links that appeared; forget links that disappeared (the
    // kernel tears their filters down with the link).
    attached.retain(|name| links.iter().any(|(_, n)| n == name));
    for (ifindex, name) in &links {
        if !attached.insert(name.clone()) {
            continue;
        }
        match attach_guard(ebpf, name) {
            Ok(()) => info!("attached guard to pod link {name} (ifindex {ifindex})"),
            Err(e) => {
                warn!("attaching guard to {name}: {e}");
                attached.remove(name);
            }
        }
    }
    Ok(())
}

/// Attach the guard to one pod link.
///
/// Kernels >= 6.6 use TCX links. We attach **first** in the per-device chain:
/// the pass verdict is `TC_ACT_UNSPEC`, so the chain continues into Cilium's
/// from-container program (which terminates it with `TC_ACT_OK` on allow),
/// while a drop (`TC_ACT_SHOT`) takes effect before Cilium ever runs.
/// Older kernels fall back to clsact/netlink filters, where ordering is best
/// effort only.
fn attach_guard(ebpf: &mut Ebpf, link: &str) -> anyhow::Result<()> {
    let prog: &mut SchedClassifier = ebpf
        .program_mut(PROG_TC_GUARD)
        .with_context(|| format!("finding {PROG_TC_GUARD}"))?
        .try_into()?;
    if prog
        .attach_with_options(
            link,
            TcAttachType::Ingress,
            TcAttachOptions::TcxOrder(LinkOrder::first()),
        )
        .is_ok()
    {
        return Ok(());
    }
    // Fall back: ensure a clsact qdisc exists, then attach with an explicit
    // priority.
    if let Err(e) = aya::programs::tc::qdisc_add_clsact(link) {
        debug!("qdisc_add_clsact({link}): {e} (fine if it exists)");
    }
    prog.attach_with_options(
        link,
        TcAttachType::Ingress,
        TcAttachOptions::Netlink(NlOptions {
            priority: 50,
            ..Default::default()
        }),
    )
    .with_context(|| format!("netlink attach to {link}"))?;
    Ok(())
}

/// Find host-side pod links: name + ifindex of every link matching the
/// configured prefixes. For the `lxc` (Cilium) prefix we additionally require
/// a hex suffix so Cilium's own `lxc_health` is not mistaken for a pod.
fn pod_links(prefixes: &[String]) -> anyhow::Result<Vec<(u32, String)>> {
    let mut links = Vec::new();
    let entries = fs::read_dir("/sys/class/net").context("reading /sys/class/net")?;
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().into_string().ok() else {
            continue;
        };
        let is_pod_link = prefixes.iter().any(|prefix| {
            if prefix == "lxc" {
                name.len() > 3
                    && name.starts_with("lxc")
                    && name[3..].bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                name.len() > prefix.len() && name.starts_with(prefix)
            }
        });
        if !is_pod_link {
            continue;
        }
        let ifindex: u32 = fs::read_to_string(entry.path().join("ifindex"))
            .with_context(|| format!("reading ifindex of {name}"))?
            .trim()
            .parse()
            .with_context(|| format!("parsing ifindex of {name}"))?;
        links.push((ifindex, name));
    }
    links.sort();
    Ok(links)
}

/// Parse an IPv4 CIDR into (prefix length, network address).
fn parse_cidr(cidr: &str) -> anyhow::Result<(u32, Ipv4Addr)> {
    let (addr, len) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("`{cidr}`: expected a.b.c.d/len"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("`{cidr}`: bad address"))?;
    let len: u32 = len
        .parse()
        .with_context(|| format!("`{cidr}`: bad prefix length"))?;
    if len > 32 {
        bail!("`{cidr}`: prefix length > 32");
    }
    Ok((len, addr))
}

/// Log one policy match reported by the eBPF program.
fn handle_event(buf: &[u8], ifnames: &Mutex<HashMap<u32, String>>) {
    let Some(event) = PacketEvent::from_bytes(buf) else {
        return;
    };
    let name = ifnames
        .lock()
        .expect("ifnames")
        .get(&event.ifindex)
        .cloned()
        .unwrap_or_else(|| format!("ifindex {}", event.ifindex));
    let src = Ipv4Addr::from(event.src_ip);
    let dst = Ipv4Addr::from(event.dst_ip);
    let proto = match event.proto {
        patch_pwnescape_k8s_common::IPPROTO_TCP => "tcp",
        patch_pwnescape_k8s_common::IPPROTO_UDP => "udp",
        patch_pwnescape_k8s_common::IPPROTO_ICMP => "icmp",
        _ => "other",
    };
    let verdict = if event.dropped == 1 {
        "DROPPED"
    } else {
        "observed"
    };
    info!(
        "{verdict}: pod egress via {name}: {src} -> {dst} ({}, dport {})",
        proto,
        u16::from_be(event.dst_port)
    );
}

/// Log one CVE-2026-99999 trigger reported by the `skb_checksum_help` guard.
fn handle_csum_event(buf: &[u8]) {
    let Some(event) = CsumEvent::from_bytes(buf) else {
        return;
    };
    let comm = String::from_utf8_lossy(&event.comm)
        .trim_end_matches('\0')
        .to_string();
    let verdict = if event.killed == 1 {
        "KILLED"
    } else {
        "detected"
    };
    warn!(
        "CVE-2026-99999 {verdict}: {comm}[{}] sent a CHECKSUM_PARTIAL skb whose \
         csum_start={} points inside the IPv4 header (network_header={}, ihl={}, \
         csum_offset write would land on already-validated header bytes)",
        event.tgid, event.csum_start, event.network_header, event.ihl
    );
}
