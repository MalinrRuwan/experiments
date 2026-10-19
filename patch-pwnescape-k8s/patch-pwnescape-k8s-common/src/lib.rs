#![no_std]

//! Types shared between the userspace loader and the eBPF programs.

/// eBPF program names (single source of truth for `Ebpf::program_mut`).
pub const PROG_TC_GUARD: &str = "tc_pwnescape_guard";
pub const PROG_KPROBE_GUARD: &str = "kprobe_pwnescape_csum_guard";

/// eBPF map names (single source of truth for `Ebpf::map_mut`).
pub const MAP_POLICY4: &str = "POLICY4";
pub const MAP_MODE: &str = "MODE";
pub const MAP_EXEMPT_IFACES: &str = "EXEMPT_IFACES";
pub const MAP_EVENTS: &str = "EVENTS";
pub const MAP_CSUM_CONFIG: &str = "CSUM_CONFIG";
pub const MAP_CVE_MODE: &str = "CVE_MODE";
pub const MAP_CVE_EVENTS: &str = "CVE_EVENTS";

/// `skb->ip_summed` state that defers checksum completion (`CHECKSUM_PARTIAL`).
pub const CHECKSUM_PARTIAL: u8 = 3;

/// `PF_KTHREAD`.
pub const PF_KTHREAD: u32 = 0x0020_0000;

/// `preempt_count` bits that mean "not a killable context": softirq-serving
/// (`SOFTIRQ_OFFSET`), hardirq (`HARDIRQ_MASK`) and NMI (`NMI_MASK`), per
/// `include/linux/preempt.h`. Bottom halves merely *disabled* by the sender
/// (`SOFTIRQ_DISABLE_OFFSET`, e.g. `rcu_read_lock_bh()` around the transmit
/// path) do not set any of these: that is still the sender's process context.
pub const SOFTIRQ_OFFSET: u32 = 1 << 8;
pub const HARDIRQ_MASK: u32 = 0x0f << 16;
pub const NMI_MASK: u32 = 0x03 << 20;
pub const KILLABLE_PREEMPT_MASK: u32 = SOFTIRQ_OFFSET | HARDIRQ_MASK | NMI_MASK;

/// Key into the MODE map plus its two values.
pub const MODE_KEY: u32 = 0;
pub const MODE_OBSERVE: u32 = 0;
pub const MODE_ENFORCE: u32 = 1;

/// Ethertype for IPv4.
pub const ETH_P_IPV4: u16 = 0x0800;

/// L3 protocols we parse (subset).
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Rule actions stored in the [`MAP_POLICY4`] lpm trie.
pub const RULE_PASS: u8 = 0;
pub const RULE_DROP: u8 = 1;

/// A policy rule attached to a destination CIDR in the [`MAP_POLICY4`] trie.
///
/// `proto` `0` and `port` `0` are wildcards. `port` is stored **big endian**
/// (network byte order) so that the eBPF program can compare it against the
/// raw value loaded from the packet.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    pub action: u8,
    pub proto: u8,
    pub port: u16,
}

// SAFETY: `Rule` is a `repr(C)` struct of integer fields with no implicit
// padding (u8, u8, u16 = 4 contiguous bytes), so its in-memory bit pattern is
// byte-identical on the eBPF and userspace targets (both little-endian
// aarch64). The `port` field is big endian by construction on both sides.
#[cfg(feature = "user")]
unsafe impl aya::Pod for Rule {}

impl Rule {
    /// A drop rule matching any protocol and port.
    pub const fn drop_any() -> Self {
        Self {
            action: RULE_DROP,
            proto: 0,
            port: 0,
        }
    }

    /// Whether the rule matches (and drops) `proto`/`port_be` traffic.
    pub fn matches(&self, proto: u8, port_be: u16) -> bool {
        self.action == RULE_DROP
            && (self.proto == 0 || self.proto == proto)
            && (self.port == 0 || self.port == port_be)
    }
}

/// Event emitted through the [`MAP_EVENTS`] ringbuf whenever a packet from a
/// pod link matches a policy rule.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    /// `ifindex` of the host-side pod link (e.g. `lxc*`/`veth*`) the packet
    /// was received on; the userspace maps it back to a link name.
    pub ifindex: u32,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub proto: u8,
    /// Big endian.
    pub src_port: u16,
    /// Big endian.
    pub dst_port: u16,
    /// `0` = observe (rule matched, packet passed), `1` = enforce (dropped).
    pub dropped: u8,
    pub _pad: u8,
}

#[cfg(feature = "user")]
impl PacketEvent {
    /// Size of the event as laid out in the ring buffer.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Interpret ring buffer bytes as an event, or `None` if too short.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        // Use read_unaligned so we never depend on the record's alignment.
        Some(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Self) })
    }
}

/// Kernel struct offsets used by the CVE-2026-99999 ("PwnEscape") guards.
///
/// Both guards apply the check added by upstream commit `6785011f8b16`:
///
/// ```text
/// skb->csum_start < skb->network_header + ip_hdrlen(skb)  =>  violation
/// ```
///
/// The kprobe guard on `skb_checksum_help()` reads these fields to detect and
/// attribute the trigger; the userspace agent also encodes the same offsets
/// into a raw `BPF_PROG_TYPE_NETFILTER` program at IPv4 PREROUTING, which can
/// reject the packet before routing/fragmentation. `csum_start`,
/// `network_header` and `ip_summed` are read straight out of `struct sk_buff`;
/// the offsets are discovered from `/sys/kernel/btf/vmlinux` at startup,
/// because nothing exposes them to BPF programs otherwise.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CsumOffsets {
    /// Byte offset of `sk_buff.head` (pointer).
    pub head: u32,
    /// Byte offset of `sk_buff.network_header`.
    pub network_header: u32,
    /// Byte size of `network_header` (2 or 4).
    pub network_header_size: u32,
    /// Byte offset of `sk_buff.csum_start`.
    pub csum_start: u32,
    /// Byte size of `csum_start` (2 or 4).
    pub csum_start_size: u32,
    /// Bit offset of the `sk_buff.ip_summed` bitfield.
    pub ip_summed_bit: u32,
    /// Bit width of `ip_summed`.
    pub ip_summed_bits: u32,
    /// Byte offset of `task_struct.thread_info.preempt_count` inside
    /// `task_struct` (used to keep SIGKILL away from softirq context).
    pub task_preempt_count: u32,
    /// Byte size of `preempt_count` (4 or 8).
    pub preempt_count_size: u32,
    /// Byte offset of `task_struct.flags` (PF_KTHREAD check).
    pub task_flags: u32,
    /// `1` once userspace has filled in valid offsets; the guard is a no-op
    /// until then.
    pub valid: u32,
}

// SAFETY: `CsumOffsets` is a `repr(C)` struct of eleven contiguous `u32`
// fields (44 bytes, no padding), byte-identical on the eBPF and userspace
// targets.
#[cfg(feature = "user")]
unsafe impl aya::Pod for CsumOffsets {}

/// Event emitted through the [`MAP_CVE_EVENTS`] ringbuf when a packet with
/// `CHECKSUM_PARTIAL` metadata carries a `csum_start` that points inside the
/// IPv4 header (the CVE-2026-99999 trigger condition).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CsumEvent {
    /// Thread id (`current` at `skb_checksum_help` entry).
    pub pid: u32,
    /// Process id.
    pub tgid: u32,
    pub csum_start: u32,
    pub network_header: u32,
    /// `current->comm`, NUL padded.
    pub comm: [u8; 16],
    /// IPv4 header length in 32-bit words.
    pub ihl: u8,
    /// `skb->ip_summed` (always `CHECKSUM_PARTIAL` for a report).
    pub ip_summed: u8,
    /// IPv4 version nibble.
    pub version: u8,
    /// `1` if enforce mode sent `SIGKILL` to the current task.
    pub killed: u8,
}

// `CsumEvent` is 36 bytes of `repr(C)` integers, `comm` included.
#[cfg(feature = "user")]
unsafe impl aya::Pod for CsumEvent {}

#[cfg(feature = "user")]
impl CsumEvent {
    /// Size of the event as laid out in the ring buffer.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Interpret ring buffer bytes as an event, or `None` if too short.
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < Self::SIZE {
            return None;
        }
        Some(unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const Self) })
    }
}
