//! Probes against the real network. They need a Korean ISP connection and
//! are ignored by default: `cargo test -- --ignored`.

use std::net::{IpAddr, ToSocketAddrs};

use keyhole::classifier::{Strategy, Verdict};
use keyhole::domain::Domain;
use keyhole::prober::{Prober, TcpDialer};

fn prober() -> Prober<TcpDialer> {
    Prober::new(TcpDialer::default(), Domain::parse("example.com").unwrap())
}

fn resolve(name: &str) -> IpAddr {
    (name, 443).to_socket_addrs().unwrap().next().unwrap().ip()
}

#[test]
#[ignore = "needs a Korean ISP connection"]
fn sni_blocked_domain_is_bypassed_by_record_split() {
    let domain = Domain::parse("womenhelp.org").unwrap();
    assert_eq!(
        prober().tls(&domain, resolve("womenhelp.org")),
        Verdict::Blocked(Some(Strategy::TlsRecordSplit))
    );
}

#[test]
#[ignore = "needs network access"]
fn unblocked_domain_is_not_blocked() {
    let domain = Domain::parse("www.rust-lang.org").unwrap();
    assert_eq!(
        prober().tls(&domain, resolve("www.rust-lang.org")),
        Verdict::NotBlocked
    );
}
