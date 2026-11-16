//! Just enough TLS to find, build and split a ClientHello. Nothing here
//! performs a handshake or touches the network.

use std::ops::Range;

const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const SERVER_NAME: u16 = 0x0000;

/// The result of looking at the start of a client's first flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hello {
    /// A complete first TLS record holding a ClientHello. `len` is the
    /// record's length including its header; `sni` is the byte range of the
    /// server name within the buffer, when one was found.
    Complete {
        len: usize,
        sni: Option<Range<usize>>,
    },
    /// Looks like a ClientHello, but the first record is not complete yet.
    Incomplete,
    /// Not a TLS ClientHello.
    NotClientHello,
}

/// Looks at the start of `buf` for a ClientHello.
pub fn parse_client_hello(buf: &[u8]) -> Hello {
    if buf.first().is_some_and(|&b| b != HANDSHAKE) || buf.get(1).is_some_and(|&b| b != 0x03) {
        return Hello::NotClientHello;
    }
    let Some(record_len) = buf
        .get(3..5)
        .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
    else {
        return Hello::Incomplete;
    };
    let len = 5 + record_len;
    let Some(payload) = buf.get(5..len) else {
        return Hello::Incomplete;
    };
    if payload.first() != Some(&CLIENT_HELLO) {
        return Hello::NotClientHello;
    }
    let sni = find_sni(payload).map(|r| r.start + 5..r.end + 5);
    Hello::Complete { len, sni }
}

/// Finds the host name in a ClientHello handshake message. The message may
/// be cut off at the record boundary; a name beyond it is not found.
fn find_sni(handshake: &[u8]) -> Option<Range<usize>> {
    let mut r = Reader {
        buf: handshake,
        pos: 4,
    };
    r.skip(2 + 32)?; // legacy_version, random
    let n = r.u8()?;
    r.skip(n.into())?; // session id
    let n = r.u16()?;
    r.skip(n.into())?; // cipher suites
    let n = r.u8()?;
    r.skip(n.into())?; // compression methods
    let ext_end = r.pos + usize::from(r.u16()?);
    while r.pos + 4 <= ext_end {
        let kind = r.u16()?;
        let len = usize::from(r.u16()?);
        if kind != SERVER_NAME {
            r.skip(len)?;
            continue;
        }
        r.u16()?; // server name list length
        if r.u8()? != 0 {
            return None; // not a host name
        }
        let name_len = usize::from(r.u16()?);
        let start = r.pos;
        r.skip(name_len)?;
        return Some(start..r.pos);
    }
    None
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn skip(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        (end <= self.buf.len()).then(|| self.pos = end)
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from(self.u8()?) << 8 | u16::from(self.u8()?))
    }
}

/// Rewrites a first flight so the ClientHello's first TLS record ends inside
/// the host name (ADR 0003). Returns `None` when `buf` does not start with a
/// complete ClientHello carrying a host name.
pub fn split_in_sni(buf: &[u8]) -> Option<Vec<u8>> {
    let Hello::Complete {
        len,
        sni: Some(sni),
    } = parse_client_hello(buf)
    else {
        return None;
    };
    if sni.len() < 2 {
        return None;
    }
    // Two bytes into the name was measured to work; stay inside short names.
    let at = sni.start + 2.min(sni.len() - 1);
    let mut out = Vec::with_capacity(buf.len() + 5);
    for part in [&buf[5..at], &buf[at..len]] {
        out.extend_from_slice(&buf[..3]);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&buf[len..]);
    Some(out)
}

/// Builds a ClientHello for `server_name` that any TLS 1.2 or 1.3 server
/// answers. `entropy` fills the random, the session id and the X25519 key
/// share; the key does not need to be a real key because the handshake is
/// never completed.
pub fn client_hello(server_name: &str, entropy: &[u8; 96]) -> Vec<u8> {
    let name = server_name.as_bytes();
    let mut ext = Vec::with_capacity(160 + name.len());
    let mut push_ext = |kind: u16, data: &[u8]| {
        ext.extend_from_slice(&kind.to_be_bytes());
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(data);
    };
    let mut sni = Vec::with_capacity(5 + name.len());
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    push_ext(SERVER_NAME, &sni);
    push_ext(0x000a, &[0, 6, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]); // groups
    push_ext(0x000b, &[1, 0]); // ec point formats
    push_ext(
        0x000d, // signature algorithms
        &[
            0, 16, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
            0x06, 0x06, 0x01,
        ],
    );
    push_ext(0x0010, b"\x00\x09\x08http/1.1"); // ALPN
    push_ext(0x0017, &[]); // extended master secret
    push_ext(0x002b, &[4, 0x03, 0x04, 0x03, 0x03]); // supported versions
    push_ext(0x002d, &[1, 1]); // psk key exchange modes
    let mut share = vec![0, 36, 0x00, 0x1d, 0, 32];
    share.extend_from_slice(&entropy[64..96]);
    push_ext(0x0033, &share); // key share
    push_ext(0xff01, &[0]); // renegotiation info

    let suites: &[u8] = &[
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc,
        0xa9, 0xcc, 0xa8,
    ];
    let mut body = Vec::with_capacity(128 + ext.len());
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&entropy[..32]);
    body.push(32);
    body.extend_from_slice(&entropy[32..64]);
    body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    body.extend_from_slice(suites);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(&[HANDSHAKE, 0x03, 0x01]);
    out.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    out.push(CLIENT_HELLO);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHROMIUM: &[u8] = include_bytes!("../testdata/client-hello-chromium.bin");
    const OPENSSL: &[u8] = include_bytes!("../testdata/client-hello-openssl.bin");

    fn sni_of(buf: &[u8]) -> Option<&[u8]> {
        match parse_client_hello(buf) {
            Hello::Complete { sni, .. } => sni.map(|r| &buf[r]),
            _ => None,
        }
    }

    #[test]
    fn finds_the_host_name_in_real_client_hellos() {
        for hello in [CHROMIUM, OPENSSL] {
            assert_eq!(sni_of(hello), Some(&b"womenhelp.org"[..]));
            assert!(
                matches!(parse_client_hello(hello), Hello::Complete { len, .. } if len == hello.len())
            );
        }
    }

    #[test]
    fn every_truncation_is_incomplete() {
        for cut in 0..CHROMIUM.len() {
            assert_eq!(
                parse_client_hello(&CHROMIUM[..cut]),
                Hello::Incomplete,
                "{cut}"
            );
        }
    }

    #[test]
    fn rejects_other_protocols() {
        assert_eq!(
            parse_client_hello(b"GET / HTTP/1.1\r\n"),
            Hello::NotClientHello
        );
        assert_eq!(
            parse_client_hello(&[0x16, 0x03, 0x01, 0, 1, 0x02]),
            Hello::NotClientHello
        );
    }

    #[test]
    fn corrupted_bytes_never_panic_or_leave_the_buffer() {
        let mut buf = CHROMIUM.to_vec();
        for i in 0..buf.len() {
            for v in [0x00, 0xff] {
                let old = std::mem::replace(&mut buf[i], v);
                if let Hello::Complete { len, sni } = parse_client_hello(&buf) {
                    assert!(len <= buf.len());
                    assert!(sni.is_none_or(|r| r.end <= len));
                }
                buf[i] = old;
            }
        }
    }

    #[test]
    fn built_hello_is_well_formed() {
        let hello = client_hello("womenhelp.org", &[7; 96]);
        assert_eq!(sni_of(&hello), Some(&b"womenhelp.org"[..]));
        let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        assert_eq!(hs_len + 9, hello.len());
    }

    #[test]
    fn split_puts_a_record_boundary_inside_the_host_name() {
        for hello in [CHROMIUM, OPENSSL] {
            let mut flight = hello.to_vec();
            flight.extend_from_slice(b"tail");
            let split = split_in_sni(&flight).unwrap();

            let first_len = 5 + usize::from(u16::from_be_bytes([split[3], split[4]]));
            let second = &split[first_len..];
            let second_len = usize::from(u16::from_be_bytes([second[3], second[4]]));
            assert_eq!(&split[..3], &hello[..3]);
            assert_eq!(&second[..3], &hello[..3]);
            assert!(split[..first_len].ends_with(b"wo"));
            assert!(second[5..].starts_with(b"menhelp.org"));

            let mut joined = split[5..first_len].to_vec();
            joined.extend_from_slice(&second[5..5 + second_len]);
            assert_eq!(joined, &hello[5..]);
            assert_eq!(&second[5 + second_len..], b"tail");
        }
    }

    #[test]
    fn split_refuses_what_it_cannot_split() {
        assert_eq!(split_in_sni(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(split_in_sni(&CHROMIUM[..100]), None);
    }
}
