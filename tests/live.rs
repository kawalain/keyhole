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
#[ignore = "needs a Korean ISP connection and curl"]
fn curl_reaches_blocked_domain_through_the_proxy() {
    let upstream = (resolve("womenhelp.org"), 443).into();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        keyhole::proxy::serve(listener, move |_| Ok(upstream), Default::default())
    });
    let out = std::process::Command::new("curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "15",
        ])
        .arg("--resolve")
        .arg(format!("womenhelp.org:{port}:127.0.0.1"))
        .arg(format!("https://womenhelp.org:{port}/"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "curl failed: {stderr}");
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

#[test]
#[ignore = "needs a Korean ISP connection"]
fn forwarder_relays_to_the_isp_resolver_and_reports_addresses() {
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::time::Duration;

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let server = socket.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let config = keyhole::resolver::Config::new("168.126.63.1:53".parse().unwrap());
    std::thread::spawn(move || {
        keyhole::resolver::serve_udp(socket, config, move |a| {
            let _ = tx.send(a.clone());
        })
    });

    let mut query = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x09womenhelp\x03org\x00\x00\x01\x00\x01");
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.send_to(&query, server).unwrap();
    let mut buf = [0; 512];
    let n = client.recv(&mut buf).unwrap();
    assert_eq!(&buf[..2], &[0xab, 0xcd]);

    let answer = rx.try_recv().expect("hook ran before the reply");
    assert_eq!(answer.domain, Domain::parse("womenhelp.org"));
    assert_eq!(answer.addrs, [resolve("womenhelp.org")]);
    assert!(n > query.len());
}
