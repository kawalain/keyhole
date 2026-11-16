//! The kernel packet filter that feeds the observer (ADR 0010), and the
//! FreeBSD `/dev/bpf` capture that runs it.
//!
//! The filter passes, for IPv4 TCP on ports 443 and 80 in either direction:
//! resets from the server, TLS handshake records whose first message is a
//! ClientHello or ServerHello, and segments starting with `GET `, `HEAD`,
//! `POST` or `HTTP`. Everything else stays in the kernel.

#[cfg(target_os = "freebsd")]
pub use freebsd::Capture;

/// One classic BPF instruction: `(code, jt, jf, k)`.
pub type Insn = (u16, u8, u8, u32);

/// Bytes copied per accepted frame; a full Ethernet frame fits.
pub const SNAPLEN: u32 = 2048;

const LDH: u16 = 0x28; // A = halfword at k
const LDB: u16 = 0x30; // A = byte at k
const LD_IND: u16 = 0x40; // A = word at X + k
const LDH_IND: u16 = 0x48; // A = halfword at X + k
const LDB_IND: u16 = 0x50; // A = byte at X + k
const LDX_MSH: u16 = 0xb1; // X = 4 * (byte at k & 0x0f)
const AND: u16 = 0x54; // A &= k
const RSH: u16 = 0x74; // A >>= k
const ADD_X: u16 = 0x0c; // A += X
const TAX: u16 = 0x07; // X = A
const JEQ: u16 = 0x15; // A == k
const JSET: u16 = 0x45; // A & k != 0
const RET: u16 = 0x06; // accept k bytes

/// Offsets are from the start of the Ethernet frame; after instruction 6,
/// X holds the IPv4 header length and `X + 14` is the TCP header. Jump
/// targets are relative: the next instruction is 0.
pub const FILTER: [Insn; 32] = [
    (LDH, 0, 0, 12),                           // 0: ethertype
    (JEQ, 0, 29, 0x0800),                      // 1: IPv4, else reject
    (LDB, 0, 0, 23),                           // 2: IP protocol
    (JEQ, 0, 27, 6),                           // 3: TCP, else reject
    (LDH, 0, 0, 20),                           // 4: flags and fragment offset
    (JSET, 25, 0, 0x1fff),                     // 5: later fragments: reject
    (LDX_MSH, 0, 0, 14),                       // 6: X = IP header length
    (LDH_IND, 0, 0, 14),                       // 7: source port
    (JEQ, 4, 0, 443),                          // 8: from 443 -> 13
    (JEQ, 3, 0, 80),                           // 9: from 80 -> 13
    (LDH_IND, 0, 0, 16),                       // 10: destination port
    (JEQ, 3, 0, 443),                          // 11: to 443 -> 15
    (JEQ, 2, 18, 80),                          // 12: to 80 -> 15, else reject
    (LDB_IND, 0, 0, 27),                       // 13: TCP flags
    (JSET, 15, 0, 0x04),                       // 14: RST: accept
    (LDB_IND, 0, 0, 26),                       // 15: TCP data offset
    (AND, 0, 0, 0xf0),                         // 16
    (RSH, 0, 0, 2),                            // 17: TCP header length
    (ADD_X, 0, 0, 0),                          // 18
    (TAX, 0, 0, 0),                            // 19: X + 14 = payload
    (LDH_IND, 0, 0, 14),                       // 20: payload bytes 0-1
    (JEQ, 0, 3, 0x1603),                       // 21: TLS handshake record, else -> 25
    (LDB_IND, 0, 0, 19),                       // 22: first handshake message type
    (JEQ, 6, 0, 1),                            // 23: ClientHello: accept
    (JEQ, 5, 6, 2),                            // 24: ServerHello: accept, else reject
    (LD_IND, 0, 0, 14),                        // 25: payload bytes 0-3
    (JEQ, 3, 0, u32::from_be_bytes(*b"GET ")), // 26
    (JEQ, 2, 0, u32::from_be_bytes(*b"HEAD")), // 27
    (JEQ, 1, 0, u32::from_be_bytes(*b"POST")), // 28
    (JEQ, 0, 1, u32::from_be_bytes(*b"HTTP")), // 29
    (RET, 0, 0, SNAPLEN),                      // 30: accept
    (RET, 0, 0, 0),                            // 31: reject
];

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::fs::File;
    use std::io::{self, Read};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

    use super::FILTER;

    const BUFFER: libc::c_uint = 64 * 1024;

    /// Captures the frames the filter passes on one interface.
    pub struct Capture {
        dev: File,
        buf: Vec<u8>,
    }

    impl Capture {
        pub fn open(interface: &str) -> io::Result<Self> {
            let dev = File::open("/dev/bpf")?;
            let fd = dev.as_raw_fd();
            let check = |rc: libc::c_int| {
                if rc == -1 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            };
            let mut len = BUFFER;
            // SAFETY: each call passes the argument type its request
            // encodes; the kernel only reads or writes that object.
            unsafe {
                check(libc::ioctl(fd, libc::BIOCSBLEN, &raw mut len))?;
                let mut ifr: libc::ifreq = std::mem::zeroed();
                if interface.len() >= ifr.ifr_name.len() {
                    return Err(io::ErrorKind::InvalidInput.into());
                }
                for (dst, src) in ifr.ifr_name.iter_mut().zip(interface.bytes()) {
                    *dst = src as libc::c_char;
                }
                check(libc::ioctl(fd, libc::BIOCSETIF, &raw const ifr))?;
                let on: libc::c_uint = 1;
                check(libc::ioctl(fd, libc::BIOCIMMEDIATE, &raw const on))?;
                let mut insns: Vec<libc::bpf_insn> = FILTER
                    .iter()
                    .map(|&(code, jt, jf, k)| libc::bpf_insn { code, jt, jf, k })
                    .collect();
                let program = libc::bpf_program {
                    bf_len: insns.len() as libc::c_uint,
                    bf_insns: insns.as_mut_ptr(),
                };
                check(libc::ioctl(fd, libc::BIOCSETF, &raw const program))?;
            }
            Ok(Self {
                dev,
                buf: vec![0; len as usize],
            })
        }

        /// Blocks until frames arrive, then hands each one to `f`. Poll the
        /// descriptor ([`AsFd`]) first to wait with a timeout.
        pub fn read(&mut self, mut f: impl FnMut(&[u8])) -> io::Result<()> {
            let n = self.dev.read(&mut self.buf)?;
            let header = size_of::<libc::bpf_hdr>();
            let mut pos = 0;
            while pos + header <= n {
                // SAFETY: the kernel wrote a bpf_hdr at every record start;
                // records are only word-aligned, hence the unaligned read.
                let hdr: libc::bpf_hdr =
                    unsafe { std::ptr::read_unaligned(self.buf[pos..].as_ptr().cast()) };
                let start = pos + usize::from(hdr.bh_hdrlen);
                let end = start + hdr.bh_caplen as usize;
                if end > n {
                    break;
                }
                f(&self.buf[start..end]);
                pos = libc::BPF_WORDALIGN(end - pos) + pos;
            }
            Ok(())
        }
    }

    impl AsFd for Capture {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.dev.as_fd()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observer::Observer;
    use crate::observer::tests::{LAN_PCAP, frame};
    use crate::testutil::pcap_frames;
    use std::time::{Duration, Instant};

    /// A classic BPF interpreter for the instructions FILTER uses. Loads
    /// beyond the frame reject it, as the kernel does.
    fn run(program: &[Insn], pkt: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let at = |off: usize, n: usize| pkt.get(off..off + n);
        loop {
            let (code, jt, jf, k) = program[pc];
            pc += 1;
            let ind = x as usize + k as usize;
            let load = match code {
                LDH => at(k as usize, 2).map(|b| u32::from(u16::from_be_bytes([b[0], b[1]]))),
                LDB => at(k as usize, 1).map(|b| u32::from(b[0])),
                LD_IND => at(ind, 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]])),
                LDH_IND => at(ind, 2).map(|b| u32::from(u16::from_be_bytes([b[0], b[1]]))),
                LDB_IND => at(ind, 1).map(|b| u32::from(b[0])),
                _ => Some(a),
            };
            let Some(loaded) = load else { return 0 };
            a = loaded;
            match code {
                LDX_MSH => match at(k as usize, 1) {
                    Some(b) => x = u32::from(b[0] & 0x0f) * 4,
                    None => return 0,
                },
                AND => a &= k,
                RSH => a >>= k,
                ADD_X => a = a.wrapping_add(x),
                TAX => x = a,
                JEQ => pc += usize::from(if a == k { jt } else { jf }),
                JSET => pc += usize::from(if a & k != 0 { jt } else { jf }),
                RET => return k,
                _ => {}
            }
        }
    }

    fn accepts(pkt: &[u8]) -> bool {
        run(&FILTER, pkt) == SNAPLEN
    }

    #[test]
    fn jumps_stay_inside_the_program() {
        for (i, &(code, jt, jf, _)) in FILTER.iter().enumerate() {
            if code == JEQ || code == JSET {
                assert!(i + 1 + usize::from(jt.max(jf)) < FILTER.len(), "insn {i}");
            }
        }
        assert_eq!(FILTER[30], (RET, 0, 0, SNAPLEN));
        assert_eq!(FILTER[31], (RET, 0, 0, 0));
    }

    #[test]
    fn passes_exactly_what_the_observer_needs_from_a_real_capture() {
        let frames = pcap_frames(LAN_PCAP);
        let passed: Vec<_> = frames.iter().copied().filter(|f| accepts(f)).collect();
        // ClientHello, reset, GET, HTTP response, ClientHello, ServerHello,
        // and the reset closing the normal connection (the observer ignores
        // it: that flow was answered). Client resets stay in the kernel.
        assert_eq!(passed.len(), 7, "{} of {}", passed.len(), frames.len());

        let t0 = Instant::now();
        let mut all = Observer::new(Duration::from_secs(5), 64);
        let mut filtered = Observer::new(Duration::from_secs(5), 64);
        let from_all: Vec<_> = frames.iter().filter_map(|f| all.on_frame(f, t0)).collect();
        let from_filtered: Vec<_> = passed
            .iter()
            .filter_map(|f| filtered.on_frame(f, t0))
            .collect();
        assert_eq!(from_all, from_filtered);
        assert_eq!(from_all.len(), 2);
    }

    #[test]
    fn rejects_bulk_data_and_bare_acks() {
        assert!(!accepts(&frame(
            false,
            443,
            0x18,
            &[0x17, 3, 3, 0, 9, 1, 2, 3]
        )));
        assert!(!accepts(&frame(
            false,
            443,
            0x18,
            &[0x16, 3, 3, 0, 9, 0x0b, 0]
        )));
        assert!(!accepts(&frame(true, 443, 0x10, &[])));
        assert!(!accepts(&frame(false, 80, 0x18, b"<html>")));
        assert!(!accepts(&frame(true, 22, 0x18, b"GET / HTTP/1.1")));
        assert!(accepts(&frame(true, 80, 0x18, b"HEAD / HTTP/1.1")));
        assert!(accepts(&frame(false, 443, 0x14, &[])));
    }
}
