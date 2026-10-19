//! CVE-2026-99999 packet rejection at IPv4 PREROUTING.
//!
//! The kprobe guard runs *inside* `skb_checksum_help()`, when the corrupt skb
//! has already been routed and queued for fragmentation. A kprobe cannot abort
//! the probed function nor override its return value (`skb_checksum_help()` is
//! not in the kernel's error-injection list), so the completion still runs and
//! the packet still leaves the node.
//!
//! A `BPF_PROG_TYPE_NETFILTER` program (Linux >= 6.4) runs at
//! `NF_INET_PRE_ROUTING` *before* routing and fragmentation. Its context
//! exposes the `sk_buff` as a BTF pointer, so it can read the same metadata as
//! the kprobe (`ip_summed`, `csum_start`, `network_header`, `head`) and return
//! `NF_DROP`: the corrupting checksum completion never happens and nothing is
//! forwarded.
//!
//! aya 0.14 has no typed netfilter program support, so the program is emitted
//! as raw eBPF instructions and loaded with `bpf(2)`. The `sk_buff` offsets
//! come from kernel BTF (the same [`CsumOffsets`] used by the kprobe) and are
//! encoded as instruction immediates.
//!
//! Scope: the hook is registered in the network namespace the agent runs in
//! (the host namespace for the DaemonSet). Packets injected into a *pod*
//! netns and forwarded inside that namespace do not traverse this hook; the
//! kprobe guard remains the cross-netns detection layer.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Context as _, bail};
use patch_pwnescape_k8s_common::{CHECKSUM_PARTIAL, CsumOffsets};

// bpf(2) commands, from include/uapi/linux/bpf.h.
const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_LOOKUP_ELEM: libc::c_int = 1;
const BPF_PROG_LOAD: libc::c_int = 5;
const BPF_LINK_CREATE: libc::c_int = 28;

// `BPF_PROG_TYPE_NETFILTER` and `BPF_NETFILTER` (the program type requires the
// attach type as `expected_attach_type` at load time).
const BPF_PROG_TYPE_NETFILTER: u32 = 32;
const BPF_NETFILTER: u32 = 45;

// include/uapi/linux/netfilter.h and include/uapi/linux/netfilter_ipv4.h.
const NFPROTO_IPV4: u32 = 2;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_DROP: i32 = 0;
const NF_ACCEPT: i32 = 1;

// include/uapi/linux/bpf.h: map type and helper ids.
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_FUNC_PROBE_READ_KERNEL: i32 = 113;

/// Run before conntrack (and every other PREROUTING hook): a dropped packet
/// never reaches routing, forwarding, or fragmentation.
pub const PREROUTING_PRIORITY: i32 = -450;

/// `union bpf_attr` is 128 bytes; only the leading fields are used here.
const BPF_ATTR_LEN: usize = 128;

// ---------------------------------------------------------------- instructions

/// One eBPF instruction. `regs` packs `src_reg << 4 | dst_reg`.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug)]
struct Insn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

const fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Insn {
    Insn {
        code,
        regs: (src << 4) | dst,
        off,
        imm,
    }
}

fn ldx_mem_b(dst: u8, src: u8, off: i16) -> Insn {
    insn(0x71, dst, src, off, 0)
}

fn ldx_mem_h(dst: u8, src: u8, off: i16) -> Insn {
    insn(0x69, dst, src, off, 0)
}

fn ldx_mem_w(dst: u8, src: u8, off: i16) -> Insn {
    insn(0x61, dst, src, off, 0)
}

fn ldx_mem_dw(dst: u8, src: u8, off: i16) -> Insn {
    insn(0x79, dst, src, off, 0)
}

fn st_mem_w(dst: u8, off: i16, imm: i32) -> Insn {
    insn(0x62, dst, 0, off, imm)
}

fn stx_xadd_dw(dst: u8, src: u8) -> Insn {
    insn(0xdb, dst, src, 0, 0)
}

fn mov64_imm(dst: u8, imm: i32) -> Insn {
    insn(0xb7, dst, 0, 0, imm)
}

fn mov64_reg(dst: u8, src: u8) -> Insn {
    insn(0xbf, dst, src, 0, 0)
}

fn add64_imm(dst: u8, imm: i32) -> Insn {
    insn(0x07, dst, 0, 0, imm)
}

fn add64_reg(dst: u8, src: u8) -> Insn {
    insn(0x0f, dst, src, 0, 0)
}

fn lsh64_imm(dst: u8, imm: i32) -> Insn {
    insn(0x67, dst, 0, 0, imm)
}

fn rsh64_imm(dst: u8, imm: i32) -> Insn {
    insn(0x77, dst, 0, 0, imm)
}

fn and64_imm(dst: u8, imm: i32) -> Insn {
    insn(0x57, dst, 0, 0, imm)
}

fn jeq_imm(dst: u8, imm: i32) -> Insn {
    insn(0x15, dst, 0, 0, imm)
}

fn jne_imm(dst: u8, imm: i32) -> Insn {
    insn(0x55, dst, 0, 0, imm)
}

fn jge_reg(dst: u8, src: u8) -> Insn {
    insn(0x3d, dst, src, 0, 0)
}

fn call_imm(func: i32) -> Insn {
    insn(0x85, 0, 0, 0, func)
}

fn exit_insn() -> Insn {
    insn(0x95, 0, 0, 0, 0)
}

/// `ld_imm64 dst, map_fd` (two instructions: `BPF_PSEUDO_MAP_FD`).
fn ld_map_fd(dst: u8, fd: RawFd) -> [Insn; 2] {
    [insn(0x18, dst, 1, 0, fd), insn(0, 0, 0, 0, 0)]
}

/// Tiny assembler with forward jump fixups.
#[derive(Default)]
struct Asm {
    insns: Vec<Insn>,
    labels: Vec<(&'static str, usize)>,
    fixups: Vec<(usize, &'static str)>,
}

impl Asm {
    fn emit(&mut self, insn: Insn) {
        self.insns.push(insn);
    }

    fn label(&mut self, name: &'static str) {
        self.labels.push((name, self.insns.len()));
    }

    fn jump(&mut self, insn: Insn, target: &'static str) {
        let idx = self.insns.len();
        self.insns.push(insn);
        self.fixups.push((idx, target));
    }

    fn finish(mut self) -> Vec<Insn> {
        for (idx, target) in std::mem::take(&mut self.fixups) {
            let dest = self
                .labels
                .iter()
                .find(|(name, _)| *name == target)
                .map(|(_, pos)| *pos)
                .unwrap_or_else(|| panic!("unknown label {target}"));
            let off = dest as isize - (idx as isize + 1);
            assert!(
                (-32768..=32767).contains(&off),
                "jump offset out of range"
            );
            self.insns[idx].off = off as i16;
        }
        self.insns
    }
}

/// Emit the drop program.
///
/// ```text
/// skb = ctx->skb
/// if skb == NULL: accept
/// if skb->ip_summed != CHECKSUM_PARTIAL: accept
/// if skb->csum_start >= skb->network_header + ip_hdrlen(skb): accept
/// else: counter++, drop
/// ```
///
/// All `sk_buff` reads go through `bpf_probe_read_kernel`, so the verifier
/// never has to type-check bitfields or pointer fields (`ip_summed` is a
/// bitfield, `head` is a pointer).
fn emit_program(offsets: &CsumOffsets, counter_fd: RawFd) -> Vec<Insn> {
    let ip_summed_byte = (offsets.ip_summed_bit / 8) as i32;
    let ip_summed_shift = (offsets.ip_summed_bit % 8) as i32;
    let ip_summed_mask = ((1u32 << offsets.ip_summed_bits) - 1) as i32;
    let csum_load = if offsets.csum_start_size == 4 {
        ldx_mem_w(8, 10, -16)
    } else {
        ldx_mem_h(8, 10, -16)
    };
    let nh_load = if offsets.network_header_size == 4 {
        ldx_mem_w(9, 10, -24)
    } else {
        ldx_mem_h(9, 10, -24)
    };

    let mut a = Asm::default();

    // r6 = ctx->skb (`struct bpf_nf_ctx` = { state, skb }).
    a.emit(ldx_mem_dw(6, 1, 8));
    a.jump(jeq_imm(6, 0), "accept");

    // ip_summed = (u16 at skb + byte) >> shift & mask.
    a.emit(mov64_reg(1, 10));
    a.emit(add64_imm(1, -8));
    a.emit(mov64_imm(2, 2));
    a.emit(mov64_reg(3, 6));
    a.emit(add64_imm(3, ip_summed_byte));
    a.emit(call_imm(BPF_FUNC_PROBE_READ_KERNEL));
    a.jump(jne_imm(0, 0), "accept");
    a.emit(ldx_mem_h(7, 10, -8));
    a.emit(rsh64_imm(7, ip_summed_shift));
    a.emit(and64_imm(7, ip_summed_mask));
    a.jump(jne_imm(7, CHECKSUM_PARTIAL as i32), "accept");

    // r8 = csum_start.
    a.emit(mov64_reg(1, 10));
    a.emit(add64_imm(1, -16));
    a.emit(mov64_imm(2, offsets.csum_start_size as i32));
    a.emit(mov64_reg(3, 6));
    a.emit(add64_imm(3, offsets.csum_start as i32));
    a.emit(call_imm(BPF_FUNC_PROBE_READ_KERNEL));
    a.jump(jne_imm(0, 0), "accept");
    a.emit(csum_load);

    // r9 = network_header.
    a.emit(mov64_reg(1, 10));
    a.emit(add64_imm(1, -24));
    a.emit(mov64_imm(2, offsets.network_header_size as i32));
    a.emit(mov64_reg(3, 6));
    a.emit(add64_imm(3, offsets.network_header as i32));
    a.emit(call_imm(BPF_FUNC_PROBE_READ_KERNEL));
    a.jump(jne_imm(0, 0), "accept");
    a.emit(nh_load);

    // r7 = head.
    a.emit(mov64_reg(1, 10));
    a.emit(add64_imm(1, -32));
    a.emit(mov64_imm(2, 8));
    a.emit(mov64_reg(3, 6));
    a.emit(add64_imm(3, offsets.head as i32));
    a.emit(call_imm(BPF_FUNC_PROBE_READ_KERNEL));
    a.jump(jne_imm(0, 0), "accept");
    a.emit(ldx_mem_dw(7, 10, -32));

    // First IPv4 byte at head + network_header.
    a.emit(mov64_reg(1, 10));
    a.emit(add64_imm(1, -40));
    a.emit(mov64_imm(2, 1));
    a.emit(mov64_reg(3, 7));
    a.emit(add64_reg(3, 9));
    a.emit(call_imm(BPF_FUNC_PROBE_READ_KERNEL));
    a.jump(jne_imm(0, 0), "accept");
    a.emit(ldx_mem_b(7, 10, -40));

    // version must be 4.
    a.emit(rsh64_imm(7, 4));
    a.jump(jne_imm(7, 4), "accept");

    // r7 = network_header + ip_hdrlen.
    a.emit(ldx_mem_b(7, 10, -40));
    a.emit(and64_imm(7, 0x0f));
    a.emit(lsh64_imm(7, 2));
    a.emit(add64_reg(7, 9));

    // No violation when csum_start >= network_header + ip_hdrlen.
    a.jump(jge_reg(8, 7), "accept");

    // Violation: count it (best effort) and drop.
    let [map0, map1] = ld_map_fd(1, counter_fd);
    a.emit(map0);
    a.emit(map1);
    a.emit(st_mem_w(10, -48, 0));
    a.emit(mov64_reg(2, 10));
    a.emit(add64_imm(2, -48));
    a.emit(call_imm(BPF_FUNC_MAP_LOOKUP_ELEM));
    a.jump(jeq_imm(0, 0), "drop");
    a.emit(mov64_imm(1, 1));
    a.emit(stx_xadd_dw(0, 1));
    a.label("drop");
    a.emit(mov64_imm(0, NF_DROP));
    a.emit(exit_insn());

    a.label("accept");
    a.emit(mov64_imm(0, NF_ACCEPT));
    a.emit(exit_insn());

    a.finish()
}

// -------------------------------------------------------------------- syscalls

fn bpf(cmd: libc::c_int, attr: &mut [u8]) -> io::Result<libc::c_long> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as libc::c_long,
            attr.as_mut_ptr(),
            attr.len(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn put_u32(buf: &mut [u8; BPF_ATTR_LEN], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_i32(buf: &mut [u8; BPF_ATTR_LEN], off: usize, value: i32) {
    buf[off..off + 4].copy_from_slice(&value.to_ne_bytes());
}

fn put_u64(buf: &mut [u8; BPF_ATTR_LEN], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_ne_bytes());
}

fn create_counter_map() -> anyhow::Result<OwnedFd> {
    let mut attr = [0u8; BPF_ATTR_LEN];
    put_u32(&mut attr, 0, BPF_MAP_TYPE_ARRAY);
    put_u32(&mut attr, 4, 4); // key_size
    put_u32(&mut attr, 8, 8); // value_size
    put_u32(&mut attr, 12, 1); // max_entries
    let fd = bpf(BPF_MAP_CREATE, &mut attr).context("bpf(BPF_MAP_CREATE)")? as RawFd;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn load_program(insns: &[Insn]) -> anyhow::Result<OwnedFd> {
    let mut log = vec![0u8; 64 * 1024];
    let license = b"GPL\0";
    let mut attr = [0u8; BPF_ATTR_LEN];
    put_u32(&mut attr, 0, BPF_PROG_TYPE_NETFILTER);
    put_u32(&mut attr, 4, insns.len() as u32);
    put_u64(&mut attr, 8, insns.as_ptr() as u64);
    put_u64(&mut attr, 16, license.as_ptr() as u64);
    put_u32(&mut attr, 24, 1); // log_level
    put_u32(&mut attr, 28, log.len() as u32);
    put_u64(&mut attr, 32, log.as_mut_ptr() as u64);
    let name = b"pwnescape_nf\0";
    attr[48..48 + name.len()].copy_from_slice(name);
    put_u32(&mut attr, 68, BPF_NETFILTER); // expected_attach_type

    match bpf(BPF_PROG_LOAD, &mut attr) {
        Ok(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }),
        Err(e) => {
            let end = log.iter().position(|&b| b == 0).unwrap_or(log.len());
            let log = String::from_utf8_lossy(&log[..end]);
            bail!(
                "bpf(BPF_PROG_LOAD) failed: {e}; verifier log: {}",
                log.trim()
            );
        }
    }
}

fn create_link(prog_fd: RawFd) -> anyhow::Result<OwnedFd> {
    let mut attr = [0u8; BPF_ATTR_LEN];
    put_u32(&mut attr, 0, prog_fd as u32);
    put_u32(&mut attr, 8, BPF_NETFILTER);
    put_u32(&mut attr, 16, NFPROTO_IPV4);
    put_u32(&mut attr, 20, NF_INET_PRE_ROUTING);
    put_i32(&mut attr, 24, PREROUTING_PRIORITY);
    let fd = bpf(BPF_LINK_CREATE, &mut attr).context("bpf(BPF_LINK_CREATE)")? as RawFd;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_counter(map_fd: RawFd) -> io::Result<u64> {
    let key: u32 = 0;
    let mut value: u64 = 0;
    let mut attr = [0u8; BPF_ATTR_LEN];
    put_u32(&mut attr, 0, map_fd as u32);
    put_u64(&mut attr, 8, (&key as *const u32) as u64);
    put_u64(&mut attr, 16, (&mut value as *mut u64) as u64);
    bpf(BPF_MAP_LOOKUP_ELEM, &mut attr)?;
    Ok(value)
}

// ----------------------------------------------------------------------- guard

/// Keeps the netfilter program/link alive; dropping it detaches the hook.
pub struct NetfilterDrop {
    _prog: OwnedFd,
    _link: OwnedFd,
    counter: OwnedFd,
}

impl NetfilterDrop {
    /// Load and attach the drop program to `NF_INET_PRE_ROUTING` of the
    /// current network namespace.
    pub fn attach(offsets: &CsumOffsets) -> anyhow::Result<Self> {
        let counter = create_counter_map().context("creating the drop counter map")?;
        let insns = emit_program(offsets, counter.as_raw_fd());
        let prog = load_program(&insns).context("loading the netfilter program")?;
        let link = create_link(prog.as_raw_fd()).context("attaching at IPv4 PREROUTING")?;
        Ok(Self {
            _prog: prog,
            _link: link,
            counter,
        })
    }

    /// Number of packets rejected so far.
    pub fn drops(&self) -> anyhow::Result<u64> {
        read_counter(self.counter.as_raw_fd()).context("reading the drop counter")
    }
}
