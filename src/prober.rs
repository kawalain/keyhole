//! Active probes that turn suspicion into a [`Verdict`] (ADR 0002).
//!
//! A TLS probe sends a ClientHello for the real name, a control ClientHello
//! for a harmless name to the same address, and then each bypass strategy.
//! A domain is blocked only when the control gets through and the real name
//! does not, twice.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::classifier::{Strategy, Verdict};
use crate::domain::Domain;
use crate::tls;

/// How one connection attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The server answered with at least one byte.
    Reached,
    /// The connection was reset before any answer.
    Reset,
    /// The connection was closed before any answer.
    Closed,
    /// No answer arrived in time.
    TimedOut,
    /// No connection could be made.
    Unreachable,
}

/// Opens a connection, sends a first flight and reports what came back.
pub trait Dialer {
    fn attempt(&self, addr: SocketAddr, first_flight: &[u8]) -> Attempt;
}

/// Bypass strategies, in the order they are tried.
const TLS_STRATEGIES: [Strategy; 1] = [Strategy::TlsRecordSplit];

pub struct Prober<D> {
    dialer: D,
    control: Domain,
}

impl<D: Dialer> Prober<D> {
    /// `control` must be a name no censor blocks.
    pub fn new(dialer: D, control: Domain) -> Self {
        Self { dialer, control }
    }

    /// Probes `domain` on port 443 of `addr`.
    pub fn tls(&self, domain: &Domain, addr: IpAddr) -> Verdict {
        let addr = SocketAddr::new(addr, 443);
        let real = || tls::client_hello(domain.as_str(), &entropy());
        if self.dialer.attempt(addr, &real()) == Attempt::Reached {
            return Verdict::NotBlocked;
        }
        let control = tls::client_hello(self.control.as_str(), &entropy());
        if self.dialer.attempt(addr, &control) != Attempt::Reached {
            return Verdict::Inconclusive;
        }
        for strategy in TLS_STRATEGIES {
            let flight = match strategy {
                Strategy::TlsRecordSplit => tls::split_in_sni(&real()),
            };
            if flight.is_some_and(|f| self.dialer.attempt(addr, &f) == Attempt::Reached) {
                // Rule out a transient failure of the first real attempt.
                return match self.dialer.attempt(addr, &real()) {
                    Attempt::Reached => Verdict::NotBlocked,
                    _ => Verdict::Blocked(Some(strategy)),
                };
            }
        }
        Verdict::Blocked(None)
    }
}

/// Bytes for ClientHello randoms and key shares.
fn entropy() -> [u8; 96] {
    let mut buf = [0; 96];
    crate::entropy::fill(&mut buf);
    buf
}

/// A [`Dialer`] over real TCP connections.
pub struct TcpDialer {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Default for TcpDialer {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        }
    }
}

impl Dialer for TcpDialer {
    fn attempt(&self, addr: SocketAddr, first_flight: &[u8]) -> Attempt {
        let Ok(mut stream) = TcpStream::connect_timeout(&addr, self.connect_timeout) else {
            return Attempt::Unreachable;
        };
        let sent = stream
            .set_nodelay(true)
            .and_then(|()| stream.set_read_timeout(Some(self.read_timeout)))
            .and_then(|()| stream.write_all(first_flight));
        let mut byte = [0];
        match sent.and_then(|()| stream.read(&mut byte)) {
            Ok(0) => Attempt::Closed,
            Ok(_) => Attempt::Reached,
            Err(e) => match e.kind() {
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => Attempt::Reset,
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Attempt::TimedOut,
                _ => Attempt::Closed,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    /// Behaves like the measured Korean DPI: it reassembles TCP but not TLS
    /// records, and resets when the first record carries a blocked name.
    struct FakeDpi {
        blocked: &'static [&'static str],
        server_up: bool,
        /// Outcomes forced on the next attempts, before the DPI model.
        forced: RefCell<VecDeque<Attempt>>,
        sent: RefCell<Vec<Vec<u8>>>,
    }

    impl FakeDpi {
        fn new(blocked: &'static [&'static str]) -> Self {
            Self {
                blocked,
                server_up: true,
                forced: RefCell::default(),
                sent: RefCell::default(),
            }
        }
    }

    impl Dialer for FakeDpi {
        fn attempt(&self, addr: SocketAddr, flight: &[u8]) -> Attempt {
            assert_eq!(addr.port(), 443);
            self.sent.borrow_mut().push(flight.to_vec());
            if let Some(a) = self.forced.borrow_mut().pop_front() {
                return a;
            }
            if !self.server_up {
                return Attempt::TimedOut;
            }
            let first_record = match tls::parse_client_hello(flight) {
                tls::Hello::Complete { len, .. } => &flight[..len],
                _ => flight,
            };
            let hit = self.blocked.iter().any(|name| {
                first_record
                    .windows(name.len())
                    .any(|w| w == name.as_bytes())
            });
            if hit {
                Attempt::Reset
            } else {
                Attempt::Reached
            }
        }
    }

    const ADDR: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(199, 58, 81, 252));

    fn d(name: &str) -> Domain {
        Domain::parse(name).unwrap()
    }

    fn prober(dpi: FakeDpi) -> Prober<FakeDpi> {
        Prober::new(dpi, d("example.com"))
    }

    #[test]
    fn unblocked_domain_is_not_blocked_after_one_attempt() {
        let p = prober(FakeDpi::new(&["womenhelp.org"]));
        assert_eq!(p.tls(&d("example.org"), ADDR), Verdict::NotBlocked);
        assert_eq!(p.dialer.sent.borrow().len(), 1);
    }

    #[test]
    fn sni_blocked_domain_is_bypassed_by_record_split() {
        let p = prober(FakeDpi::new(&["womenhelp.org"]));
        assert_eq!(
            p.tls(&d("womenhelp.org"), ADDR),
            Verdict::Blocked(Some(Strategy::TlsRecordSplit))
        );
    }

    #[test]
    fn blocked_with_no_working_strategy() {
        // A censor that matches a prefix still sees it in the first record.
        let p = prober(FakeDpi::new(&["womenhelp.org", "wo"]));
        assert_eq!(p.tls(&d("womenhelp.org"), ADDR), Verdict::Blocked(None));
    }

    #[test]
    fn unreachable_server_is_inconclusive() {
        let mut dpi = FakeDpi::new(&[]);
        dpi.server_up = false;
        assert_eq!(
            prober(dpi).tls(&d("womenhelp.org"), ADDR),
            Verdict::Inconclusive
        );
    }

    #[test]
    fn transient_failure_of_the_real_name_is_not_a_block() {
        let dpi = FakeDpi::new(&[]);
        dpi.forced.borrow_mut().push_back(Attempt::Reset);
        assert_eq!(
            prober(dpi).tls(&d("womenhelp.org"), ADDR),
            Verdict::NotBlocked
        );
    }

    #[test]
    fn control_uses_the_control_name_on_the_same_address() {
        let p = prober(FakeDpi::new(&["womenhelp.org"]));
        p.tls(&d("womenhelp.org"), ADDR);
        let sent = p.dialer.sent.borrow();
        let sni = |f: &[u8]| match tls::parse_client_hello(f) {
            tls::Hello::Complete { sni: Some(r), .. } => f[r].to_vec(),
            _ => Vec::new(),
        };
        assert_eq!(sni(&sent[0]), b"womenhelp.org");
        assert_eq!(sni(&sent[1]), b"example.com");
    }
}
