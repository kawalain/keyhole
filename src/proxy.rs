//! Transparent TCP proxy for bypassed connections (ADR 0003).
//!
//! Only connections the enforcer redirects reach the proxy. It reads the
//! client's ClientHello, splits it into two TLS records inside the host name,
//! sends it to the original destination and then relays bytes both ways.
//! Anything that is not a ClientHello is relayed unchanged.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use crate::tls::{self, Hello};

/// Largest first flight the proxy buffers: one maximum-size TLS record.
const MAX_FIRST_FLIGHT: usize = 5 + (1 << 14);
const THREAD_STACK: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct Config {
    /// How long to wait for the client's complete ClientHello before
    /// relaying whatever has arrived.
    pub first_flight_timeout: Duration,
    pub connect_timeout: Duration,
    /// Connections beyond this many are refused.
    pub max_connections: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            first_flight_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            max_connections: 512,
        }
    }
}

/// Accepts connections forever. `original_dst` recovers the address a
/// redirected client meant to reach; it is the seam to the OS redirect.
pub fn serve<F>(listener: TcpListener, original_dst: F, config: Config) -> io::Result<()>
where
    F: Fn(&TcpStream) -> io::Result<SocketAddr> + Send + Sync + 'static,
{
    let original_dst = Arc::new(original_dst);
    let active = Arc::new(AtomicUsize::new(0));
    for client in listener.incoming() {
        let Ok(client) = client else { continue };
        if active.fetch_add(1, Ordering::Relaxed) >= config.max_connections {
            active.fetch_sub(1, Ordering::Relaxed);
            continue;
        }
        let (original_dst, slot, config) = (original_dst.clone(), active.clone(), config.clone());
        let spawned = thread::Builder::new()
            .stack_size(THREAD_STACK)
            .spawn(move || {
                match original_dst(&client) {
                    Ok(dst) => {
                        if let Err(e) = handle(client, dst, &config) {
                            crate::log!("proxy: {dst}: {e}");
                        }
                    }
                    Err(e) => crate::log!("proxy: no original destination: {e}"),
                }
                slot.fetch_sub(1, Ordering::Relaxed);
            });
        if spawned.is_err() {
            active.fetch_sub(1, Ordering::Relaxed);
        }
    }
    Ok(())
}

/// Proxies one client connection to `upstream` until both sides close.
pub fn handle(mut client: TcpStream, upstream: SocketAddr, config: &Config) -> io::Result<()> {
    let flight = read_first_flight(&mut client, config.first_flight_timeout)?;
    let flight = tls::split_in_sni(&flight).unwrap_or(flight);

    let mut server = TcpStream::connect_timeout(&upstream, config.connect_timeout)?;
    server.set_nodelay(true)?;
    server.write_all(&flight)?;
    server.set_nodelay(false)?;

    let (mut client_r, mut server_w) = (client.try_clone()?, server.try_clone()?);
    let upload = thread::Builder::new()
        .stack_size(THREAD_STACK)
        .spawn(move || pipe(&mut client_r, &mut server_w))?;
    pipe(&mut server, &mut client);
    let _ = upload.join();
    Ok(())
}

/// Reads until the buffer holds a complete ClientHello record, something
/// that is not one, or the timeout passes.
fn read_first_flight(client: &mut TcpStream, timeout: Duration) -> io::Result<Vec<u8>> {
    client.set_read_timeout(Some(timeout))?;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = [0; 4096];
    while buf.len() < MAX_FIRST_FLIGHT && tls::parse_client_hello(&buf) == Hello::Incomplete {
        match client.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    client.set_read_timeout(None)?;
    Ok(buf)
}

/// Copies until EOF or error, then half-closes the destination so the
/// other direction can finish.
fn pipe(from: &mut TcpStream, to: &mut TcpStream) {
    let _ = io::copy(from, to);
    let _ = to.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const CHROMIUM: &[u8] = include_bytes!("../testdata/client-hello-chromium.bin");

    /// An upstream that records everything it receives until EOF, replying
    /// `reply` after the first read.
    fn upstream(reply: &'static [u8]) -> (SocketAddr, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut got = vec![0; 65536];
            let n = s.read(&mut got).unwrap();
            got.truncate(n);
            s.write_all(reply).unwrap();
            s.read_to_end(&mut got).unwrap();
            got
        });
        (addr, handle)
    }

    /// Starts a proxy that sends every connection to `dst`.
    fn proxy(dst: SocketAddr, config: Config) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || serve(listener, move |_| Ok(dst), config));
        addr
    }

    fn client_exchange(proxy: SocketAddr, chunks: &[&[u8]]) -> Vec<u8> {
        let mut c = TcpStream::connect(proxy).unwrap();
        c.set_nodelay(true).unwrap();
        for chunk in chunks {
            c.write_all(chunk).unwrap();
            thread::sleep(Duration::from_millis(20));
        }
        c.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        c.read_to_end(&mut reply).unwrap();
        reply
    }

    #[test]
    fn client_hello_arriving_in_pieces_reaches_upstream_split() {
        let (dst, server) = upstream(b"server hello");
        let p = proxy(dst, Config::default());
        let (a, b) = CHROMIUM.split_at(700);
        let reply = client_exchange(p, &[a, b, b"app data"]);

        assert_eq!(reply, b"server hello");
        let mut expected = tls::split_in_sni(CHROMIUM).unwrap();
        expected.extend_from_slice(b"app data");
        assert_eq!(server.join().unwrap(), expected);
    }

    #[test]
    fn other_protocols_pass_through_unchanged() {
        let (dst, server) = upstream(b"HTTP/1.1 200 OK\r\n\r\n");
        let p = proxy(dst, Config::default());
        let reply = client_exchange(p, &[b"GET / HTTP/1.1\r\n\r\n"]);
        assert_eq!(reply, b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(server.join().unwrap(), b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn silent_client_is_relayed_after_the_timeout() {
        let (dst, server) = upstream(b"banner");
        let config = Config {
            first_flight_timeout: Duration::from_millis(100),
            ..Config::default()
        };
        let p = proxy(dst, config);
        let mut c = TcpStream::connect(p).unwrap();
        thread::sleep(Duration::from_millis(300));
        c.write_all(b"late").unwrap();
        c.shutdown(Shutdown::Write).unwrap();
        let mut reply = Vec::new();
        c.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, b"banner");
        assert_eq!(server.join().unwrap(), b"late");
    }

    #[test]
    fn connections_beyond_the_limit_are_refused() {
        let (dst, _server) = upstream(b"");
        let config = Config {
            max_connections: 1,
            ..Config::default()
        };
        let p = proxy(dst, config);
        let _held = TcpStream::connect(p).unwrap();
        thread::sleep(Duration::from_millis(50));
        let mut refused = TcpStream::connect(p).unwrap();
        refused
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0];
        // An accepted connection would wait for its first flight and time
        // out with an error instead.
        assert_eq!(refused.read(&mut buf).unwrap(), 0);
    }
}
