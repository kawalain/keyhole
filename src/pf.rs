//! FreeBSD pf integration (ADR 0007): recovering a redirected connection's
//! original destination.

#[cfg(target_os = "freebsd")]
pub use freebsd::NatLook;

/// `struct pf_addr` from `netpfil/pf/pf.h`: 16 bytes, aligned like the
/// `u_int32_t addr32[4]` member of its union.
#[cfg(any(target_os = "freebsd", test))]
#[repr(C, align(4))]
#[derive(Clone, Copy, Default)]
struct PfAddr([u8; 16]);

/// `struct pfioc_natlook` from `net/pfvar.h` (FreeBSD 15.1).
#[cfg(any(target_os = "freebsd", test))]
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PfiocNatlook {
    saddr: PfAddr,
    daddr: PfAddr,
    rsaddr: PfAddr,
    rdaddr: PfAddr,
    sport: u16,
    dport: u16,
    rsport: u16,
    rdport: u16,
    af: u8,
    proto: u8,
    direction: u8,
}

/// `_IOWR('D', 23, struct pfioc_natlook)`.
#[cfg(any(target_os = "freebsd", test))]
const DIOCNATLOOK: u64 =
    0xc000_0000 | ((size_of::<PfiocNatlook>() as u64) << 16) | ((b'D' as u64) << 8) | 23;

#[cfg(target_os = "freebsd")]
mod freebsd {
    use std::fs::File;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
    use std::os::fd::AsRawFd;

    use super::{DIOCNATLOOK, PfAddr, PfiocNatlook};

    const AF_INET: u8 = 2;
    const AF_INET6: u8 = 28;
    const IPPROTO_TCP: u8 = 6;
    const PF_OUT: u8 = 2;

    /// Looks up pf state to find where a redirected client meant to go.
    pub struct NatLook {
        dev: File,
    }

    impl NatLook {
        pub fn open() -> io::Result<Self> {
            Ok(Self {
                dev: File::open("/dev/pf")?,
            })
        }

        /// The destination the client of `stream` connected to before pf
        /// redirected it to this host.
        pub fn original_dst(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
            let (client, local) = (stream.peer_addr()?, stream.local_addr()?);
            // Same query as squid's pf interception: the state from the
            // client to the redirect target, looked up outbound.
            let mut nl = PfiocNatlook {
                saddr: pf_addr(client.ip()),
                daddr: pf_addr(local.ip()),
                sport: client.port().to_be(),
                dport: local.port().to_be(),
                af: if client.is_ipv4() { AF_INET } else { AF_INET6 },
                proto: IPPROTO_TCP,
                direction: PF_OUT,
                ..PfiocNatlook::default()
            };
            // SAFETY: `nl` is a live `pfioc_natlook` whose size is encoded in
            // the request number; the kernel reads and writes it in place.
            let rc = unsafe {
                libc::ioctl(
                    self.dev.as_raw_fd(),
                    DIOCNATLOOK as libc::c_ulong,
                    &raw mut nl,
                )
            };
            if rc == -1 {
                return Err(io::Error::last_os_error());
            }
            let b = nl.rdaddr.0;
            let ip = if client.is_ipv4() {
                IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            } else {
                IpAddr::V6(Ipv6Addr::from(b))
            };
            Ok(SocketAddr::new(ip, u16::from_be(nl.rdport)))
        }
    }

    fn pf_addr(ip: IpAddr) -> PfAddr {
        let mut addr = PfAddr::default();
        match ip {
            IpAddr::V4(v4) => addr.0[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => addr.0 = v6.octets(),
        }
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natlook_layout_matches_freebsd() {
        assert_eq!(size_of::<PfiocNatlook>(), 76);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, rdaddr), 48);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, sport), 64);
        assert_eq!(std::mem::offset_of!(PfiocNatlook, af), 72);
        assert_eq!(DIOCNATLOOK, 0xc04c_4417);
    }
}
