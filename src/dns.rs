//! Just enough DNS to forward messages and read the addresses in answers.
//! keyhole never builds DNS messages; it relays the bytes it receives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::domain::Domain;

const HEADER: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
pub const RCODE_NXDOMAIN: u8 = 3;

/// What a response says about the name it answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The question name, when it is a usable host name.
    pub domain: Option<Domain>,
    pub rcode: u8,
    /// A and AAAA addresses anywhere in the answer section, so addresses
    /// behind a CNAME chain are attributed to the question name.
    pub addrs: Vec<IpAddr>,
    /// The smallest TTL of those address records.
    pub ttl: Option<u32>,
}

/// The message ID.
pub fn id(msg: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.first()?, *msg.get(1)?]))
}

pub fn set_id(msg: &mut [u8], id: u16) {
    if msg.len() >= 2 {
        msg[..2].copy_from_slice(&id.to_be_bytes());
    }
}

/// The raw question section of a message with exactly one question, used
/// to match a response to its query.
pub fn question(msg: &[u8]) -> Option<&[u8]> {
    if msg.get(4..6)? != [0, 1] {
        return None;
    }
    let end = skip_name(msg, HEADER)? + 4;
    msg.get(HEADER..end)
}

/// Reads the answer of a response. Returns `None` for queries and for
/// messages that are malformed.
pub fn parse_response(msg: &[u8]) -> Option<Answer> {
    if msg.get(2)? & 0x80 == 0 {
        return None; // a query
    }
    let rcode = msg.get(3)? & 0x0f;
    question(msg)?;
    let (name, mut pos) = read_name(msg, HEADER)?;
    pos += 4;
    let ancount = u16::from_be_bytes([*msg.get(6)?, *msg.get(7)?]);
    let mut addrs = Vec::new();
    let mut ttl: Option<u32> = None;
    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        let rr = msg.get(pos..pos + 10)?;
        let kind = u16::from_be_bytes([rr[0], rr[1]]);
        let rr_ttl = u32::from_be_bytes([rr[4], rr[5], rr[6], rr[7]]);
        let len = usize::from(u16::from_be_bytes([rr[8], rr[9]]));
        let data = msg.get(pos + 10..pos + 10 + len)?;
        let addr = match (kind, data.len()) {
            (TYPE_A, 4) => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?))),
            (TYPE_AAAA, 16) => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?))),
            _ => None,
        };
        if let Some(addr) = addr {
            addrs.push(addr);
            ttl = Some(ttl.map_or(rr_ttl, |t| t.min(rr_ttl)));
        }
        pos += 10 + len;
    }
    Some(Answer {
        domain: Domain::parse(&name),
        rcode,
        addrs,
        ttl,
    })
}

/// Returns the position after the (possibly compressed) name at `pos`.
fn skip_name(msg: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some(pos + 1),
            l if l & 0xc0 == 0xc0 => {
                msg.get(pos + 1)?;
                return Some(pos + 2);
            }
            l if l & 0xc0 == 0 => pos += 1 + usize::from(l),
            _ => return None,
        }
    }
}

/// Reads the name at `pos`, following compression pointers. Returns the
/// dotted name and the position after the name's first encoding.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut pos = start;
    let mut end = None;
    for _ in 0..128 {
        let len = *msg.get(pos)?;
        match len {
            0 => return Some((name, end.unwrap_or(pos + 1))),
            l if l & 0xc0 == 0xc0 => {
                let target = usize::from(u16::from_be_bytes([l & 0x3f, *msg.get(pos + 1)?]));
                end.get_or_insert(pos + 2);
                pos = target;
            }
            l if l & 0xc0 == 0 => {
                let label = msg.get(pos + 1..pos + 1 + usize::from(l))?;
                if !name.is_empty() {
                    name.push('.');
                }
                name.push_str(std::str::from_utf8(label).ok()?);
                if name.len() > 255 {
                    return None;
                }
                pos += 1 + usize::from(l);
            }
            _ => return None,
        }
    }
    None // pointer loop
}

#[cfg(test)]
mod tests {
    use super::*;

    const CNAME_A: &[u8] = include_bytes!("../testdata/dns-cname-a.bin");
    const AAAA: &[u8] = include_bytes!("../testdata/dns-aaaa.bin");
    const NXDOMAIN: &[u8] = include_bytes!("../testdata/dns-nxdomain.bin");

    #[test]
    fn addresses_behind_a_cname_belong_to_the_question_name() {
        let a = parse_response(CNAME_A).unwrap();
        assert_eq!(a.domain, Domain::parse("www.github.com"));
        assert_eq!(a.rcode, 0);
        assert_eq!(a.addrs.len(), 1);
        assert!(a.addrs[0].is_ipv4());
        assert!(a.ttl.is_some());
    }

    #[test]
    fn reads_aaaa_records() {
        let a = parse_response(AAAA).unwrap();
        assert_eq!(a.domain, Domain::parse("www.google.com"));
        assert!(!a.addrs.is_empty());
        assert!(a.addrs.iter().all(IpAddr::is_ipv6));
    }

    #[test]
    fn nxdomain_has_no_addresses() {
        let a = parse_response(NXDOMAIN).unwrap();
        assert_eq!(a.rcode, RCODE_NXDOMAIN);
        assert!(a.addrs.is_empty());
        assert_eq!(a.ttl, None);
    }

    #[test]
    fn ttl_is_the_smallest_address_ttl() {
        let mut msg = CNAME_A.to_vec();
        let a = parse_response(&msg).unwrap();
        // The A record is last: its TTL sits 10 bytes before the end.
        let at = msg.len() - 10;
        msg[at..at + 4].copy_from_slice(&7u32.to_be_bytes());
        assert_ne!(a.ttl, Some(7));
        assert_eq!(parse_response(&msg).unwrap().ttl, Some(7));
    }

    #[test]
    fn question_and_id_round_trip() {
        let mut msg = CNAME_A.to_vec();
        assert_eq!(id(&msg), Some(0x1234));
        set_id(&mut msg, 0xbeef);
        assert_eq!(id(&msg), Some(0xbeef));
        let q = question(&msg).unwrap();
        assert!(q.starts_with(b"\x03www\x06github\x03com\x00"));
        assert_eq!(q.len(), 16 + 4);
    }

    #[test]
    fn queries_are_not_responses() {
        let mut msg = CNAME_A.to_vec();
        msg[2] &= 0x7f;
        assert_eq!(parse_response(&msg), None);
    }

    #[test]
    fn pointer_loops_and_damage_never_panic() {
        let mut looped = CNAME_A.to_vec();
        looped[HEADER] = 0xc0;
        looped[HEADER + 1] = HEADER as u8;
        assert_eq!(parse_response(&looped), None);

        for msg in [CNAME_A, AAAA, NXDOMAIN] {
            for cut in 0..msg.len() {
                let _ = parse_response(&msg[..cut]);
            }
            let mut buf = msg.to_vec();
            for i in 0..buf.len() {
                for v in [0x00, 0x3f, 0xc0, 0xff] {
                    let old = std::mem::replace(&mut buf[i], v);
                    let _ = parse_response(&buf);
                    let _ = question(&buf);
                    buf[i] = old;
                }
            }
        }
    }
}
