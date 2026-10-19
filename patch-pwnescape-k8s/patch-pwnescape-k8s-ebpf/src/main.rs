#![no_std]
#![no_main]

//! `tc_pwnescape_guard` - a TC (traffic control) classifier attached to the
//! *ingress* of every host-side pod link (`lxc*` on Cilium nodes, `veth*`
//! elsewhere). Traffic received there is traffic **originating from a pod**,
//! i.e. pod egress. Packets whose destination matches a drop rule in the
//! `POLICY4` LPM trie are shot (enforce mode) and reported through the
//! `EVENTS` ringbuf.
//!
//! This blocks the network channels a container escape typically pivots
//! through: the node subnet (kubelet 10250, apiserver 6443, ssh, etcd),
//! link-local metadata (169.254.169.254) and host loopback.
//!
//! It deliberately coexists with Cilium: on kernels >= 6.6 both attach via
//! TCX links, and this program is attached *first* in the per-device chain.
//! Pass-through (no policy match, observe mode, unparseable packets) returns
//! `TC_ACT_UNSPEC` (TCX "run the next program in the chain"), so Cilium's
//! from-container program still runs and enforces its NetworkPolicies.
//! A match in enforce mode returns `TC_ACT_SHOT`, which drops the packet
//! before any later program sees it. Note that returning `TC_ACT_OK` here
//! would *terminate* the TCX chain with "accept" and silently disable Cilium
//! policy for that device - hence `TC_ACT_UNSPEC` everywhere on the pass path.
//!
//! `kprobe_pwnescape_csum_guard` - a kprobe on `skb_checksum_help()` that
//! detects CVE-2026-99999 ("PwnEscape"): a `CHECKSUM_PARTIAL` skb whose
//! `csum_start` points inside the IPv4 header, so the deferred checksum
//! write mutates an already-validated header. The kprobe is the *detection*
//! layer: by the time it runs, the skb has already been routed and queued for
//! fragmentation, and a kprobe cannot abort the function or force an error
//! return (`skb_checksum_help()` is not error-injectable). The userspace agent
//! therefore also attaches a `BPF_PROG_TYPE_NETFILTER` program at IPv4
//! PREROUTING, which can read the same `sk_buff` metadata and return
//! `NF_DROP` before routing/fragmentation: that is the layer that actually
//! rejects the trigger packet. This guard mirrors upstream commit
//! `6785011f8b16` (`csum_start < network_header + ip_hdrlen`) using field
//! offsets read from kernel BTF, reports violations through the `CVE_EVENTS`
//! ringbuf, and in enforce mode sends `SIGKILL` to the current task when the
//! completion runs in its process context (softirq/kernel-thread contexts are
//! only reported).

use aya_ebpf::{
    bindings::{TC_ACT_SHOT, TC_ACT_UNSPEC},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_probe_read_kernel, bpf_send_signal_thread,
    },
    macros::{classifier, kprobe, map},
    maps::{
        array::Array,
        hash_map::LruHashMap,
        lpm_trie::{Key, LpmTrie},
        ring_buf::RingBuf,
    },
    programs::{ProbeContext, TcContext},
};
use aya_log_ebpf::info;
use patch_pwnescape_k8s_common::{
    CHECKSUM_PARTIAL, CsumEvent, CsumOffsets, ETH_P_IPV4, IPPROTO_TCP, IPPROTO_UDP,
    KILLABLE_PREEMPT_MASK, MODE_ENFORCE, MODE_KEY, MODE_OBSERVE, PF_KTHREAD, PacketEvent, Rule,
};

/// `SIGKILL`.
const SIGKILL: u32 = 9;

/// Destination-based policy trie, written by the userspace loader.
#[map(name = "POLICY4")]
static POLICY4: LpmTrie<[u8; 4], Rule> = LpmTrie::with_max_entries(1024, 0);

/// Enforcement mode: `MODE_OBSERVE` (default) or `MODE_ENFORCE`.
#[map(name = "MODE")]
static MODE: LruHashMap<u32, u32> = LruHashMap::with_max_entries(8, 0);

/// Pod links (ifindex) exempt from enforcement.
#[map(name = "EXEMPT_IFACES")]
static EXEMPT_IFACES: LruHashMap<u32, u8> = LruHashMap::with_max_entries(8192, 0);

/// Event stream consumed by the userspace loader.
#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// `struct sk_buff` / `struct task_struct` offsets for the CVE guard,
/// discovered from kernel BTF by the userspace loader.
#[map(name = "CSUM_CONFIG")]
static CSUM_CONFIG: Array<CsumOffsets> = Array::with_max_entries(1, 0);

/// CVE guard mode: `MODE_OBSERVE` (report only) or `MODE_ENFORCE`
/// (report + SIGKILL when the completion runs in process context).
#[map(name = "CVE_MODE")]
static CVE_MODE: Array<u32> = Array::with_max_entries(1, 0);

/// CVE guard event stream.
#[map(name = "CVE_EVENTS")]
static CVE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

const ETH_HLEN: usize = 14;
const IPV4_MIN_HLEN: usize = 20;

#[classifier]
pub fn tc_pwnescape_guard(ctx: TcContext) -> i32 {
    match try_tc_pwnescape_guard(ctx) {
        Ok(action) => action,
        // Fail open on unparseable/short packets; the policy is IPv4-only for
        // now and everything else (IPv6, ARP, ...) passes untouched.
        Err(_) => TC_ACT_UNSPEC as i32,
    }
}

fn try_tc_pwnescape_guard(ctx: TcContext) -> Result<i32, i64> {
    if ctx.len() < (ETH_HLEN + IPV4_MIN_HLEN) as u32 {
        return Ok(TC_ACT_UNSPEC as i32);
    }

    // Ethernet header: we only care about the ethertype.
    if u16::from_be(ctx.load::<u16>(12)?) != ETH_P_IPV4 {
        return Ok(TC_ACT_UNSPEC as i32);
    }

    // IPv4 header: IHL, protocol, source and destination addresses.
    let ihl = ((ctx.load::<u8>(ETH_HLEN)? & 0x0f) as usize) * 4;
    if ihl < IPV4_MIN_HLEN {
        return Ok(TC_ACT_UNSPEC as i32);
    }
    let proto: u8 = ctx.load(ETH_HLEN + 9)?;
    let src_ip: [u8; 4] = ctx.load(ETH_HLEN + 12)?;
    let dst_ip: [u8; 4] = ctx.load(ETH_HLEN + 16)?;

    // Transport ports (TCP and UDP share the source/dest port offsets).
    let (src_port, dst_port): (u16, u16) = match proto {
        IPPROTO_TCP | IPPROTO_UDP => (
            ctx.load::<u16>(ETH_HLEN + ihl)?,
            ctx.load::<u16>(ETH_HLEN + ihl + 2)?,
        ),
        _ => (0, 0),
    };

    // The pod link this packet arrived on. Exempt links pass untouched.
    let ifindex = unsafe { (*ctx.skb.skb).ingress_ifindex };
    if unsafe { EXEMPT_IFACES.get(&ifindex) }.is_some() {
        return Ok(TC_ACT_UNSPEC as i32);
    }

    // Longest-prefix match the destination against the policy trie. A miss or
    // a rule that doesn't match the protocol/port passes.
    let matches = POLICY4
        .get(&Key::new(32, dst_ip))
        .is_some_and(|rule| rule.matches(proto, dst_port));
    if !matches {
        return Ok(TC_ACT_UNSPEC as i32);
    }

    let enforce = unsafe { MODE.get(&MODE_KEY) }
        .copied()
        .unwrap_or(MODE_OBSERVE)
        == MODE_ENFORCE;

    // Report the match to userspace.
    if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
        entry.write(PacketEvent {
            ifindex,
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
            dropped: u8::from(enforce),
            _pad: 0,
        });
        entry.submit(0);
    }

    if enforce {
        info!(
            &ctx,
            "pwnescape: dropped pod egress ifindex={} proto={} dport={}",
            ifindex,
            proto,
            u16::from_be(dst_port)
        );
        return Ok(TC_ACT_SHOT as i32);
    }

    Ok(TC_ACT_UNSPEC as i32)
}

/// CVE-2026-99999 guard: kprobe on `skb_checksum_help()`.
///
/// The deferred checksum write is about to happen with `skb->ip_summed ==
/// CHECKSUM_PARTIAL`. If `csum_start` points before the end of the IPv4
/// header, the write can mutate bytes the kernel has already validated
/// (`ihl` `0x45 -> 0x4f`), which the fragmenter then re-reads. Report it,
/// and in enforce mode kill the current task when we can prove the
/// completion is running on its behalf.
#[kprobe]
pub fn kprobe_pwnescape_csum_guard(ctx: ProbeContext) -> u32 {
    let _ = try_csum_guard(ctx);
    0
}

fn try_csum_guard(ctx: ProbeContext) -> Result<(), i64> {
    let cfg = CSUM_CONFIG.get(0).ok_or(1i64)?;
    if cfg.valid != 1 || cfg.ip_summed_bits == 0 || cfg.ip_summed_bits > 8 {
        return Ok(());
    }

    let skb: *const u8 = ctx.arg(0).ok_or(2i64)?;
    if skb.is_null() {
        return Ok(());
    }

    // `skb->ip_summed` is a bitfield: read the 16 bits containing it.
    let byte = (cfg.ip_summed_bit / 8) as usize;
    let shift = cfg.ip_summed_bit % 8;
    let pool: u16 =
        unsafe { bpf_probe_read_kernel(skb.add(byte).cast::<u16>()) }.map_err(|e| e as i64)?;
    let mask = (1u16 << cfg.ip_summed_bits) - 1;
    let ip_summed = ((pool >> shift) & mask) as u8;
    if ip_summed != CHECKSUM_PARTIAL {
        return Ok(());
    }

    // `head` is the base all header offsets are relative to.
    let head: u64 = unsafe { bpf_probe_read_kernel(skb.add(cfg.head as usize).cast::<u64>()) }
        .map_err(|e| e as i64)?;
    let network_header = read_offset(skb, cfg.network_header, cfg.network_header_size)?;
    let csum_start = read_offset(skb, cfg.csum_start, cfg.csum_start_size)?;

    // First IPv4 header byte at `head + network_header`.
    let iph: u8 =
        unsafe { bpf_probe_read_kernel((head.wrapping_add(network_header as u64)) as *const u8) }
            .map_err(|e| e as i64)?;
    let version = iph >> 4;
    let ihl = iph & 0x0f;
    if version != 4 {
        return Ok(());
    }

    // The upstream invariant: the completion write must not land inside the
    // parsed IPv4 header (`skb->csum_start < network_header + ip_hdrlen`).
    let hlen = (ihl as u32) * 4;
    if csum_start >= network_header.wrapping_add(hlen) {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);

    let enforce = CVE_MODE.get(0).copied().unwrap_or(MODE_OBSERVE) == MODE_ENFORCE;
    let mut killed = 0u8;
    if enforce && safe_to_kill(cfg) {
        // On violation, stop the sender rather than let it keep probing.
        unsafe { bpf_send_signal_thread(SIGKILL) };
        killed = 1;
    }

    if let Some(mut entry) = CVE_EVENTS.reserve::<CsumEvent>(0) {
        entry.write(CsumEvent {
            pid: pid_tgid as u32,
            tgid: (pid_tgid >> 32) as u32,
            csum_start,
            network_header,
            comm,
            ihl,
            ip_summed,
            version,
            killed,
        });
        entry.submit(0);
    }

    Ok(())
}

/// Read a `sk_buff` offset whose width is 2 or 4 bytes.
#[inline(always)]
fn read_offset(skb: *const u8, off: u32, size: u32) -> Result<u32, i64> {
    let ptr = unsafe { skb.add(off as usize) };
    if size == 4 {
        unsafe { bpf_probe_read_kernel(ptr.cast::<u32>()) }.map_err(|e| e as i64)
    } else {
        unsafe { bpf_probe_read_kernel(ptr.cast::<u16>()) }
            .map(u32::from)
            .map_err(|e| e as i64)
    }
}

/// SIGKILL only makes sense when the completion is running on behalf of a
/// user task. Hardirq/NMI and softirq-serving contexts may be completing for
/// an unrelated task, and kernel threads are never the sender. A user task
/// with bottom halves merely disabled (`rcu_read_lock_bh()` in the transmit
/// path) is still the sender, so only the interrupt bits block the kill.
#[inline(always)]
fn safe_to_kill(cfg: &CsumOffsets) -> bool {
    let task = unsafe { bpf_get_current_task() };
    if task == 0 {
        return false;
    }
    let task = task as *const u8;

    let preempt_count = if cfg.preempt_count_size == 8 {
        match unsafe {
            bpf_probe_read_kernel(task.add(cfg.task_preempt_count as usize).cast::<u64>())
        } {
            Ok(v) => v,
            Err(_) => return false,
        }
    } else {
        match unsafe {
            bpf_probe_read_kernel(task.add(cfg.task_preempt_count as usize).cast::<u32>())
        } {
            Ok(v) => u64::from(v),
            Err(_) => return false,
        }
    };
    if preempt_count as u32 & KILLABLE_PREEMPT_MASK != 0 {
        return false;
    }

    match unsafe { bpf_probe_read_kernel(task.add(cfg.task_flags as usize).cast::<u32>()) } {
        Ok(flags) => flags & PF_KTHREAD == 0,
        Err(_) => false,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
