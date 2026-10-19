//! Minimal BTF reader for the CVE-2026-99999 guard.
//!
//! The guard needs field offsets that no BPF helper exposes:
//! `sk_buff.{head,network_header,csum_start,ip_summed}` and
//! `task_struct.{thread_info.preempt_count,flags}`. CO-RE relocations are not
//! used (the eBPF side reads with `bpf_probe_read_kernel`), so we parse the
//! kernel's BTF blob ourselves. The offsets go into the `CSUM_CONFIG` map and
//! the guard stays a no-op until they are filled in.

use std::fs;

use anyhow::{Context as _, bail};
use patch_pwnescape_k8s_common::CsumOffsets;

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_VERSION: u8 = 1;
const BTF_HEADER_LEN: usize = 24;

const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

fn le_u16(data: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(off..off + 2)?.try_into().ok()?))
}

fn le_u32(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(off..off + 4)?.try_into().ok()?))
}

#[derive(Debug)]
struct Member {
    name: String,
    type_id: u32,
    bit_offset: u32,
    bit_size: u32,
}

#[derive(Debug)]
struct Type {
    kind: u32,
    name: String,
    /// `size` for int/struct/union/enum, otherwise the referenced type id.
    size_or_type: u32,
    members: Vec<Member>,
}

struct Btf {
    types: Vec<Type>,
}

impl Btf {
    fn parse(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < BTF_HEADER_LEN {
            bail!("BTF blob is truncated");
        }
        let magic = le_u16(data, 0).unwrap();
        if magic != BTF_MAGIC {
            bail!("bad BTF magic {magic:#x}");
        }
        if data[2] != BTF_VERSION {
            bail!("unsupported BTF version {}", data[2]);
        }
        let hdr_len = le_u32(data, 4).unwrap() as usize;
        let type_off = le_u32(data, 8).unwrap() as usize;
        let type_len = le_u32(data, 12).unwrap() as usize;
        let str_off = le_u32(data, 16).unwrap() as usize;
        let str_len = le_u32(data, 20).unwrap() as usize;

        let type_start = hdr_len
            .checked_add(type_off)
            .context("BTF type offset overflow")?;
        let types_data = data
            .get(
                type_start
                    ..type_start
                        .checked_add(type_len)
                        .context("BTF type length overflow")?,
            )
            .context("BTF type section out of bounds")?;
        let str_start = hdr_len
            .checked_add(str_off)
            .context("BTF string offset overflow")?;
        let strings = data
            .get(
                str_start
                    ..str_start
                        .checked_add(str_len)
                        .context("BTF string length overflow")?,
            )
            .context("BTF string section out of bounds")?
            .to_vec();

        let name_of = |off: u32| -> String {
            let off = off as usize;
            if off == 0 || off >= strings.len() {
                return String::new();
            }
            let end = strings[off..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| off + i)
                .unwrap_or(strings.len());
            String::from_utf8_lossy(&strings[off..end]).into_owned()
        };

        // Type id 0 is the implicit void.
        let mut types = vec![Type {
            kind: 0,
            name: String::new(),
            size_or_type: 0,
            members: Vec::new(),
        }];

        let mut off = 0usize;
        while off + 12 <= types_data.len() {
            let name_off = le_u32(types_data, off).unwrap();
            let info = le_u32(types_data, off + 4).unwrap();
            let size_or_type = le_u32(types_data, off + 8).unwrap();
            off += 12;

            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let kind_flag = (info >> 31) == 1;
            let name = name_of(name_off);

            let mut members = Vec::new();
            match kind {
                KIND_INT => off += 4,
                KIND_ARRAY => off += 12,
                KIND_STRUCT | KIND_UNION => {
                    for _ in 0..vlen {
                        let m_name = le_u32(types_data, off).context("truncated BTF member")?;
                        let m_type = le_u32(types_data, off + 4).context("truncated BTF member")?;
                        let m_off = le_u32(types_data, off + 8).context("truncated BTF member")?;
                        off += 12;
                        let (bit_offset, bit_size) = if kind_flag {
                            (m_off & 0x00ff_ffff, m_off >> 24)
                        } else {
                            (m_off, 0)
                        };
                        members.push(Member {
                            name: name_of(m_name),
                            type_id: m_type,
                            bit_offset,
                            bit_size,
                        });
                    }
                }
                KIND_ENUM => off += 8 * vlen,
                KIND_FUNC_PROTO => off += 8 * vlen,
                KIND_VAR => off += 4,
                KIND_DATASEC => off += 12 * vlen,
                KIND_DECL_TAG => off += 4,
                KIND_ENUM64 => off += 12 * vlen,
                _ => {}
            }

            types.push(Type {
                kind,
                name,
                size_or_type,
                members,
            });
        }

        Ok(Self { types })
    }

    /// Resolve typedefs/qualifiers to the underlying type id.
    fn resolve(&self, mut id: u32) -> u32 {
        loop {
            match self.types.get(id as usize) {
                Some(t)
                    if matches!(
                        t.kind,
                        KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG
                    ) =>
                {
                    id = t.size_or_type;
                }
                _ => return id,
            }
        }
    }

    fn type_size(&self, id: u32) -> Option<u32> {
        let t = self.types.get(self.resolve(id) as usize)?;
        match t.kind {
            KIND_INT | KIND_STRUCT | KIND_UNION | KIND_ENUM => Some(t.size_or_type),
            KIND_PTR => Some(8),
            _ => None,
        }
    }

    fn find_struct(&self, name: &str) -> Option<u32> {
        self.types
            .iter()
            .position(|t| t.kind == KIND_STRUCT && t.name == name)
            .map(|i| i as u32)
    }

    /// Find a member, descending into anonymous struct/union members.
    /// Returns `(absolute bit offset, bit size, member type id)`.
    fn find_member(&self, type_id: u32, name: &str, base_bits: u32) -> Option<(u32, u32, u32)> {
        let t = self.types.get(type_id as usize)?;
        if !matches!(t.kind, KIND_STRUCT | KIND_UNION) {
            return None;
        }
        for m in &t.members {
            let bits = base_bits.checked_add(m.bit_offset)?;
            if m.name == name {
                return Some((bits, m.bit_size, m.type_id));
            }
            if m.name.is_empty() {
                if let Some(found) = self.find_member(m.type_id, name, bits) {
                    return Some(found);
                }
            }
        }
        None
    }
}

/// Discover the struct offsets the CVE guard needs from the kernel's BTF.
pub fn csum_offsets() -> anyhow::Result<CsumOffsets> {
    let data = fs::read("/sys/kernel/btf/vmlinux").context(
        "reading /sys/kernel/btf/vmlinux (kernel BTF is required for the CVE guard; \
         disable it with --no-kprobe-guard)",
    )?;
    let btf = Btf::parse(&data).context("parsing kernel BTF")?;

    let sk_buff = btf
        .find_struct("sk_buff")
        .context("struct sk_buff not found in kernel BTF")?;
    let (head_bit, _, head_type) = btf
        .find_member(sk_buff, "head", 0)
        .context("sk_buff.head not found")?;
    if btf.type_size(head_type) != Some(8) {
        bail!("sk_buff.head is not a 64-bit pointer; the CVE guard only supports 64-bit kernels");
    }

    let (network_header_bit, _, nh_type) = btf
        .find_member(sk_buff, "network_header", 0)
        .context("sk_buff.network_header not found")?;
    let nh_size = btf.type_size(nh_type).unwrap_or(0);
    if nh_size != 2 && nh_size != 4 {
        bail!("unexpected sk_buff.network_header size {nh_size}");
    }

    let (csum_start_bit, _, cs_type) = btf
        .find_member(sk_buff, "csum_start", 0)
        .context("sk_buff.csum_start not found")?;
    let cs_size = btf.type_size(cs_type).unwrap_or(0);
    if cs_size != 2 && cs_size != 4 {
        bail!("unexpected sk_buff.csum_start size {cs_size}");
    }

    let (ip_summed_bit, ip_summed_bits, _) = btf
        .find_member(sk_buff, "ip_summed", 0)
        .context("sk_buff.ip_summed not found")?;
    if ip_summed_bits == 0 || ip_summed_bits > 8 {
        bail!("unexpected sk_buff.ip_summed bit width {ip_summed_bits}");
    }

    let task = btf
        .find_struct("task_struct")
        .context("struct task_struct not found in kernel BTF")?;
    let (thread_info_bit, _, thread_info_type) = btf
        .find_member(task, "thread_info", 0)
        .context("task_struct.thread_info not found")?;
    let (preempt_count_bit, _, preempt_count_type) = btf
        .find_member(thread_info_type, "preempt_count", thread_info_bit)
        .context("thread_info.preempt_count not found")?;
    let preempt_count_size = btf.type_size(preempt_count_type).unwrap_or(0);
    if preempt_count_size != 4 && preempt_count_size != 8 {
        bail!("unexpected preempt_count size {preempt_count_size}");
    }
    let (flags_bit, _, flags_type) = btf
        .find_member(task, "flags", 0)
        .context("task_struct.flags not found")?;
    let flags_size = btf.type_size(flags_type).unwrap_or(0);
    if flags_size != 4 {
        bail!("unexpected task_struct.flags size {flags_size}");
    }

    Ok(CsumOffsets {
        head: (head_bit / 8) as u32,
        network_header: (network_header_bit / 8) as u32,
        network_header_size: nh_size,
        csum_start: (csum_start_bit / 8) as u32,
        csum_start_size: cs_size,
        ip_summed_bit,
        ip_summed_bits,
        task_preempt_count: (preempt_count_bit / 8) as u32,
        preempt_count_size,
        task_flags: (flags_bit / 8) as u32,
        valid: 1,
    })
}
