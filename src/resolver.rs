//! DNS forwarder between Unbound and the ISP resolver (ADR 0004, 0009).
//!
//! Every query is relayed unchanged except for its message ID, which is
//! replaced with an unpredictable one on the way upstream. Before a response
//! goes back, the caller's hook sees the parsed [`Answer`], so a bypassed
//! domain's addresses can be registered before any client connects to them.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::dns::{self, Answer};
use crate::entropy;

const MAX_UDP: usize = 4096;
const THREAD_STACK: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    /// The ISP resolver.
    pub upstream: SocketAddr,
    /// How long a query may wait for its answer; Unbound retries on its own.
    pub timeout: Duration,
    /// Upper bound on outstanding UDP queries; queries beyond it are dropped.
    pub max_pending: usize,
}

impl Config {
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            timeout: Duration::from_secs(5),
            max_pending: 1024,
        }
    }
}

struct Pending {
    client: SocketAddr,
    id: u16,
    question: Vec<u8>,
    deadline: Instant,
}

/// Relays UDP queries arriving on `downstream` forever.
pub fn serve_udp<H>(downstream: UdpSocket, config: Config, hook: H) -> io::Result<()>
where
    H: Fn(&Answer) + Send + 'static,
{
    let bind: SocketAddr = match config.upstream {
        SocketAddr::V4(_) => ([0, 0, 0, 0], 0).into(),
        SocketAddr::V6(_) => ([0u16; 8], 0).into(),
    };
    let upstream = UdpSocket::bind(bind)?;
    upstream.connect(config.upstream)?;
    let pending: Arc<Mutex<HashMap<u16, Pending>>> = Arc::default();

    let (up, down, table) = (
        upstream.try_clone()?,
        downstream.try_clone()?,
        pending.clone(),
    );
    thread::Builder::new()
        .stack_size(THREAD_STACK)
        .spawn(move || relay_answers(&up, &down, &table, &hook))?;

    let mut buf = [0; MAX_UDP];
    let mut ids = IdSource::default();
    loop {
        let Ok((n, client)) = downstream.recv_from(&mut buf) else {
            continue;
        };
        let msg = &mut buf[..n];
        let (Some(id), Some(question)) = (dns::id(msg), dns::question(msg).map(<[u8]>::to_vec))
        else {
            continue;
        };
        let now = Instant::now();
        let new_id = {
            let mut table = pending.lock().unwrap_or_else(PoisonError::into_inner);
            if table.len() >= config.max_pending {
                table.retain(|_, p| p.deadline > now);
                if table.len() >= config.max_pending {
                    continue;
                }
            }
            let new_id = ids.unused(|id| table.contains_key(&id));
            table.insert(
                new_id,
                Pending {
                    client,
                    id,
                    question,
                    deadline: now + config.timeout,
                },
            );
            new_id
        };
        dns::set_id(msg, new_id);
        let _ = upstream.send(msg);
    }
}

fn relay_answers<H: Fn(&Answer)>(
    upstream: &UdpSocket,
    downstream: &UdpSocket,
    pending: &Mutex<HashMap<u16, Pending>>,
    hook: &H,
) {
    let mut buf = [0; MAX_UDP];
    loop {
        let Ok(n) = upstream.recv(&mut buf) else {
            continue;
        };
        let msg = &mut buf[..n];
        let Some(id) = dns::id(msg) else { continue };
        let entry = {
            let mut table = pending.lock().unwrap_or_else(PoisonError::into_inner);
            match table.get(&id) {
                Some(p) if dns::question(msg) == Some(&p.question[..]) => table.remove(&id),
                _ => None,
            }
        };
        let Some(entry) = entry else { continue };
        if entry.deadline < Instant::now() {
            continue;
        }
        if let Some(answer) = dns::parse_response(msg) {
            hook(&answer);
        }
        dns::set_id(msg, entry.id);
        let _ = downstream.send_to(msg, entry.client);
    }
}

/// Unpredictable message IDs, drawn from a refilled buffer of random bytes.
#[derive(Default)]
struct IdSource {
    buf: Vec<u8>,
}

impl IdSource {
    fn unused(&mut self, taken: impl Fn(u16) -> bool) -> u16 {
        loop {
            if self.buf.len() < 2 {
                self.buf.resize(512, 0);
                entropy::fill(&mut self.buf);
            }
            let id =
                u16::from_be_bytes([self.buf[self.buf.len() - 2], self.buf[self.buf.len() - 1]]);
            self.buf.truncate(self.buf.len() - 2);
            if !taken(id) {
                return id;
            }
        }
    }
}

/// Relays DNS-over-TCP connections arriving on `listener` forever; Unbound
/// uses TCP when a UDP answer was truncated.
pub fn serve_tcp<H>(listener: TcpListener, config: Config, hook: H) -> io::Result<()>
where
    H: Fn(&Answer) + Send + Sync + 'static,
{
    let hook = Arc::new(hook);
    for client in listener.incoming() {
        let Ok(client) = client else { continue };
        let (config, hook) = (config.clone(), hook.clone());
        let _ = thread::Builder::new()
            .stack_size(THREAD_STACK)
            .spawn(move || relay_tcp(client, &config, &*hook));
    }
    Ok(())
}

fn relay_tcp<H: Fn(&Answer)>(mut client: TcpStream, config: &Config, hook: &H) -> io::Result<()> {
    client.set_read_timeout(Some(config.timeout * 2))?;
    let mut upstream = TcpStream::connect_timeout(&config.upstream, config.timeout)?;
    upstream.set_read_timeout(Some(config.timeout))?;
    upstream.set_nodelay(true)?;
    while let Some(query) = read_framed(&mut client)? {
        write_framed(&mut upstream, &query)?;
        let Some(response) = read_framed(&mut upstream)? else {
            break;
        };
        if dns::id(&response) != dns::id(&query)
            || dns::question(&response) != dns::question(&query)
        {
            break;
        }
        if let Some(answer) = dns::parse_response(&response) {
            hook(&answer);
        }
        write_framed(&mut client, &response)?;
    }
    Ok(())
}

/// Reads one length-prefixed message; `None` on a clean close.
fn read_framed(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0; 2];
    match stream.read_exact(&mut len) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        other => other?,
    }
    let mut msg = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut msg)?;
    Ok(Some(msg))
}

fn write_framed(stream: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    let len = u16::try_from(msg.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut framed = Vec::with_capacity(2 + msg.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(msg);
    stream.write_all(&framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::mpsc;

    use crate::domain::Domain;

    fn query(id: u16, name: &str) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        m
    }

    /// Answers `query` with one A record whose last octet is the name length.
    fn answer(query: &[u8]) -> Vec<u8> {
        let mut m = query.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = 1;
        let octet = query.len() as u8;
        m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, octet]);
        m
    }

    fn addr_for(name: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, query(0, name).len() as u8))
    }

    fn local_udp() -> UdpSocket {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap()
    }

    /// A UDP upstream that collects `batch` queries, then answers them in
    /// reverse order, forever. Every query it saw goes to the channel.
    fn udp_upstream(batch: usize) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
        let socket = local_udp();
        let addr = socket.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            loop {
                let mut got = Vec::new();
                while got.len() < batch {
                    let mut buf = [0; 512];
                    let (n, from) = socket.recv_from(&mut buf).unwrap();
                    let _ = tx.send(buf[..n].to_vec());
                    got.push((buf[..n].to_vec(), from));
                }
                for (q, from) in got.into_iter().rev() {
                    socket.send_to(&answer(&q), from).unwrap();
                }
            }
        });
        (addr, rx)
    }

    type Seen = Arc<Mutex<Vec<Answer>>>;

    fn start_udp(upstream: SocketAddr, timeout: Duration) -> (SocketAddr, Seen) {
        let socket = local_udp();
        let addr = socket.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let sink = seen.clone();
        let config = Config {
            timeout,
            ..Config::new(upstream)
        };
        thread::spawn(move || {
            serve_udp(socket, config, move |a| {
                sink.lock().unwrap().push(a.clone())
            })
        });
        (addr, seen)
    }

    fn recv(client: &UdpSocket) -> Option<Vec<u8>> {
        let mut buf = [0; 512];
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        client.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
    }

    #[test]
    fn answers_return_to_their_queries_with_the_original_ids() {
        let (upstream, upstream_saw) = udp_upstream(2);
        let (server, _) = start_udp(upstream, Duration::from_secs(5));
        let client = local_udp();
        client.connect(server).unwrap();
        client.send(&query(0x1111, "womenhelp.org")).unwrap();
        client.send(&query(0x2222, "example.com")).unwrap();

        let mut replies = [recv(&client).unwrap(), recv(&client).unwrap()];
        replies.sort();
        assert_eq!(replies[0], answer(&query(0x1111, "womenhelp.org")));
        assert_eq!(replies[1], answer(&query(0x2222, "example.com")));

        let sent: Vec<_> = upstream_saw.try_iter().collect();
        assert_eq!(sent.len(), 2);
        assert!(
            sent.iter().all(|q| q[2..] == query(0, "womenhelp.org")[2..]
                || q[2..] == query(0, "example.com")[2..])
        );
    }

    #[test]
    fn hook_sees_the_answer_before_the_client_does() {
        let (upstream, _) = udp_upstream(1);
        let (server, seen) = start_udp(upstream, Duration::from_secs(5));
        let client = local_udp();
        client.connect(server).unwrap();
        client.send(&query(7, "womenhelp.org")).unwrap();
        recv(&client).unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].domain, Domain::parse("womenhelp.org"));
        assert_eq!(seen[0].addrs, [addr_for("womenhelp.org")]);
        assert_eq!(seen[0].ttl, Some(60));
    }

    #[test]
    fn answers_with_the_wrong_question_are_dropped() {
        // An upstream that answers with a different question.
        let socket = local_udp();
        let upstream = socket.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = [0; 512];
            let (n, from) = socket.recv_from(&mut buf).unwrap();
            let mut forged = answer(&query(0, "evil.example"));
            forged[..2].copy_from_slice(&buf[..2]);
            socket.send_to(&forged, from).unwrap();
            let _ = n;
        });
        let (server, seen) = start_udp(upstream, Duration::from_secs(5));
        let client = local_udp();
        client.connect(server).unwrap();
        client.send(&query(7, "womenhelp.org")).unwrap();
        assert_eq!(recv(&client), None);
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn tcp_queries_are_relayed_in_order() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream = upstream_listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut s, _) = upstream_listener.accept().unwrap();
            while let Some(q) = read_framed(&mut s).unwrap() {
                write_framed(&mut s, &answer(&q)).unwrap();
            }
        });
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server = listener.local_addr().unwrap();
        let seen: Seen = Arc::default();
        let sink = seen.clone();
        thread::spawn(move || {
            serve_tcp(listener, Config::new(upstream), move |a| {
                sink.lock().unwrap().push(a.clone())
            })
        });

        let mut client = TcpStream::connect(server).unwrap();
        for (id, name) in [(1, "womenhelp.org"), (2, "example.com")] {
            write_framed(&mut client, &query(id, name)).unwrap();
            assert_eq!(
                read_framed(&mut client).unwrap().unwrap(),
                answer(&query(id, name))
            );
        }
        assert_eq!(seen.lock().unwrap().len(), 2);
    }
}
