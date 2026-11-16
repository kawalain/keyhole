//! Turns the few LAN packets the BPF filter passes into block signals
//! (ADR 0010). Pure: frames and the time go in, signals come out.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::domain::Domain;
use crate::http::BLOCK_PAGE_HOST as BLOCK_PAGE;
use crate::tls;

const TLS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;
const RST: u8 = 0x04;

/// A connection that ended the way a censor ends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signal {
    /// The server side reset a TLS connection before answering its
    /// ClientHello. `sni` is the name when the first segment carried it.
    TlsReset { server: IpAddr, sni: Option<Domain> },
    /// A plain-HTTP response redirected to the block page. `host` is the
    /// request's `Host` when it was seen.
    HttpBlock {
        server: IpAddr,
        host: Option<Domain>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    client: IpAddr,
    client_port: u16,
    server: IpAddr,
    server_port: u16,
}

struct Flow {
    name: Option<Domain>,
    at: Instant,
}

pub struct Observer {
    window: Duration,
    max_flows: usize,
    flows: HashMap<FlowKey, Flow>,
}

impl Observer {
    /// `window` bounds how long after the client's first segment an answer
    /// still counts; at most `max_flows` connections are tracked at once.
    pub fn new(window: Duration, max_flows: usize) -> Self {
        Self {
            window,
            max_flows,
            flows: HashMap::new(),
        }
    }

    /// Feeds one Ethernet frame seen on the LAN.
    pub fn on_frame(&mut self, frame: &[u8], now: Instant) -> Option<Signal> {
        let seg = Segment::parse(frame)?;
        if seg.dst_port == TLS_PORT || seg.dst_port == HTTP_PORT {
            self.on_request(&seg, now);
            None
        } else if seg.src_port == TLS_PORT || seg.src_port == HTTP_PORT {
            self.on_response(&seg, now)
        } else {
            None
        }
    }

    fn on_request(&mut self, seg: &Segment, now: Instant) {
        let name = match seg.dst_port {
            TLS_PORT if starts_client_hello(seg.payload) => tls::sni_in_prefix(seg.payload),
            HTTP_PORT if is_http_request(seg.payload) => http_host(seg.payload),
            _ => return,
        };
        if self.flows.len() >= self.max_flows {
            let window = self.window;
            self.flows.retain(|_, f| now.duration_since(f.at) <= window);
            if self.flows.len() >= self.max_flows {
                return;
            }
        }
        let name = name
            .and_then(|n| std::str::from_utf8(n).ok())
            .and_then(Domain::parse);
        self.flows.insert(seg.request_key(), Flow { name, at: now });
    }

    fn on_response(&mut self, seg: &Segment, now: Instant) -> Option<Signal> {
        if seg.payload.is_empty() && seg.flags & RST == 0 {
            return None; // bare ACKs and FINs neither answer nor reset
        }
        let flow = self.flows.remove(&seg.response_key());
        let name = flow
            .filter(|f| now.duration_since(f.at) <= self.window)
            .map(|f| f.name);
        let server = seg.src;
        if seg.src_port == TLS_PORT {
            // Any answer ends the flow; only a reset before one is a signal.
            (seg.flags & RST != 0 && seg.payload.is_empty())
                .then_some(())
                .and(name)
                .map(|sni| Signal::TlsReset { server, sni })
        } else {
            let head = &seg.payload[..seg.payload.len().min(512)];
            let redirect = head.starts_with(b"HTTP/1.")
                && head.windows(BLOCK_PAGE.len()).any(|w| w == BLOCK_PAGE);
            redirect.then(|| Signal::HttpBlock {
                server,
                host: name.flatten(),
            })
        }
    }
}

/// A TLS handshake record whose first message is a ClientHello.
fn starts_client_hello(payload: &[u8]) -> bool {
    payload.len() > 5 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01
}

fn is_http_request(payload: &[u8]) -> bool {
    [&b"GET "[..], b"HEAD ", b"POST "]
        .iter()
        .any(|m| payload.starts_with(m))
}

/// The value of the `Host` header, without a port.
fn http_host(request: &[u8]) -> Option<&[u8]> {
    let head = &request[..request.len().min(2048)];
    head.split(|&b| b == b'\n').skip(1).find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let colon = line.iter().position(|&b| b == b':')?;
        if !line[..colon].eq_ignore_ascii_case(b"host") {
            return None;
        }
        let value = line[colon + 1..].trim_ascii();
        Some(value.split(|&b| b == b':').next().unwrap_or(value))
    })
}

struct Segment<'a> {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    payload: &'a [u8],
}

impl<'a> Segment<'a> {
    /// Parses an Ethernet frame carrying an unfragmented IPv4 or IPv6 TCP
    /// segment (VLAN tags are skipped).
    fn parse(frame: &'a [u8]) -> Option<Self> {
        let mut ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
        let mut pos = 14;
        if ethertype == 0x8100 {
            ethertype = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
            pos = 18;
        }
        let ip = frame.get(pos..)?;
        let (src, dst, tcp) = match ethertype {
            0x0800 => {
                let ihl = usize::from(ip.first()? & 0x0f) * 4;
                let total = usize::from(u16::from_be_bytes([*ip.get(2)?, *ip.get(3)?]));
                let fragmented = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x3fff != 0;
                if *ip.get(9)? != 6 || fragmented || ihl < 20 {
                    return None;
                }
                let src: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
                let dst: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
                let end = total.min(ip.len());
                (
                    IpAddr::V4(Ipv4Addr::from(src)),
                    IpAddr::V4(Ipv4Addr::from(dst)),
                    ip.get(ihl..end)?,
                )
            }
            0x86dd => {
                if *ip.get(6)? != 6 {
                    return None; // extension headers are not followed
                }
                let len = usize::from(u16::from_be_bytes([*ip.get(4)?, *ip.get(5)?]));
                let src: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
                let dst: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
                let end = (40 + len).min(ip.len());
                (
                    IpAddr::V6(Ipv6Addr::from(src)),
                    IpAddr::V6(Ipv6Addr::from(dst)),
                    ip.get(40..end)?,
                )
            }
            _ => return None,
        };
        let offset = usize::from(tcp.get(12)? >> 4) * 4;
        Some(Self {
            src,
            dst,
            src_port: u16::from_be_bytes([*tcp.first()?, *tcp.get(1)?]),
            dst_port: u16::from_be_bytes([*tcp.get(2)?, *tcp.get(3)?]),
            flags: *tcp.get(13)?,
            payload: tcp.get(offset.max(20)..)?,
        })
    }

    fn request_key(&self) -> FlowKey {
        FlowKey {
            client: self.src,
            client_port: self.src_port,
            server: self.dst,
            server_port: self.dst_port,
        }
    }

    fn response_key(&self) -> FlowKey {
        FlowKey {
            client: self.dst,
            client_port: self.dst_port,
            server: self.src,
            server_port: self.src_port,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::pcap_frames;

    pub const LAN_PCAP: &[u8] = include_bytes!("../testdata/lan-blocked-and-normal.pcap");
    const CHROMIUM: &[u8] = include_bytes!("../testdata/client-hello-chromium.bin");
    const SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(199, 58, 81, 252));

    fn observer() -> Observer {
        Observer::new(Duration::from_secs(5), 16)
    }

    fn d(name: &str) -> Option<Domain> {
        Domain::parse(name)
    }

    /// An Ethernet/IPv4/TCP frame between 192.168.1.135:50000 and SERVER.
    pub fn frame(to_server: bool, port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let client = [192, 168, 1, 135];
        let server = [199, 58, 81, 252];
        let (src, dst) = if to_server {
            (client, server)
        } else {
            (server, client)
        };
        let (sport, dport) = if to_server {
            (50000, port)
        } else {
            (port, 50000)
        };
        let mut f = vec![0; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let total = (20 + 20 + payload.len()) as u16;
        f.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0]);
        f[16..18].copy_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&src);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&u16::to_be_bytes(sport));
        f.extend_from_slice(&u16::to_be_bytes(dport));
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn real_capture_yields_one_tls_and_one_http_signal() {
        let t0 = Instant::now();
        let mut o = observer();
        let signals: Vec<_> = pcap_frames(LAN_PCAP)
            .into_iter()
            .filter_map(|f| o.on_frame(f, t0))
            .collect();
        assert_eq!(
            signals,
            [
                Signal::TlsReset {
                    server: SERVER,
                    sni: d("womenhelp.org")
                },
                Signal::HttpBlock {
                    server: SERVER,
                    host: d("womenhelp.org")
                },
            ]
        );
    }

    #[test]
    fn name_beyond_the_first_segment_leaves_the_signal_unnamed() {
        let t0 = Instant::now();
        let mut o = observer();
        assert_eq!(
            o.on_frame(&frame(true, 443, 0x10, &CHROMIUM[..1460]), t0),
            None
        );
        assert_eq!(
            o.on_frame(&frame(false, 443, RST | 0x10, &[]), t0),
            Some(Signal::TlsReset {
                server: SERVER,
                sni: None
            })
        );
    }

    #[test]
    fn answered_or_late_or_unknown_resets_are_not_signals() {
        let t0 = Instant::now();
        let mut o = observer();
        let hello = frame(true, 443, 0x18, &CHROMIUM[..1460]);
        let reset = frame(false, 443, RST, &[]);

        o.on_frame(&hello, t0);
        o.on_frame(&frame(false, 443, 0x10, &[]), t0);
        o.on_frame(&frame(false, 443, 0x18, &[0x16, 3, 3, 0, 1, 2]), t0);
        assert_eq!(o.on_frame(&reset, t0), None, "server answered first");

        o.on_frame(&hello, t0);
        assert_eq!(
            o.on_frame(&reset, t0 + Duration::from_secs(6)),
            None,
            "too late"
        );

        assert_eq!(o.on_frame(&reset, t0), None, "no ClientHello seen");
    }

    #[test]
    fn http_host_header_is_read_without_port_and_case() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\nhOsT: WomenHelp.org:80\r\n\r\n";
        assert_eq!(http_host(req), Some(&b"WomenHelp.org"[..]));
        assert_eq!(http_host(b"GET / HTTP/1.1\r\n\r\n"), None);
    }

    #[test]
    fn ordinary_http_redirects_are_not_signals() {
        let t0 = Instant::now();
        let mut o = observer();
        o.on_frame(
            &frame(
                true,
                80,
                0x18,
                b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            ),
            t0,
        );
        let reply = b"HTTP/1.1 301 Moved\r\nLocation: https://example.com/\r\n\r\n";
        assert_eq!(o.on_frame(&frame(false, 80, 0x18, reply), t0), None);
    }

    #[test]
    fn flow_table_is_bounded() {
        let t0 = Instant::now();
        let mut o = Observer::new(Duration::from_secs(5), 1);
        o.on_frame(&frame(true, 443, 0x18, &CHROMIUM[..1460]), t0);
        let mut other = frame(true, 443, 0x18, &CHROMIUM[..1460]);
        other[34] = 0xbe; // another client port
        o.on_frame(&other, t0);
        assert_eq!(o.flows.len(), 1);
    }

    #[test]
    fn damaged_frames_never_panic() {
        let mut o = observer();
        let t0 = Instant::now();
        for f in pcap_frames(LAN_PCAP) {
            for cut in (0..f.len()).step_by(7) {
                o.on_frame(&f[..cut], t0);
            }
        }
    }
}
