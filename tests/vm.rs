//! Checks that need the OPNsense test VM (`vm/`), run inside the router VM
//! while the client VM connects. Ignored by default.
#![cfg(target_os = "freebsd")]

use std::net::{SocketAddr, TcpListener};

/// Needs `<keyhole>` = 199.58.81.252 with the anchor's rdr to
/// 127.0.0.1:8443, and the client VM connecting to https://womenhelp.org.
#[test]
#[ignore = "needs the OPNsense test VM and a client connection"]
fn natlook_recovers_the_original_destination() {
    let listener = TcpListener::bind("127.0.0.1:8443").unwrap();
    let natlook = keyhole::pf::NatLook::open().unwrap();
    let (stream, _) = listener.accept().unwrap();
    let expected: SocketAddr = "199.58.81.252:443".parse().unwrap();
    assert_eq!(natlook.original_dst(&stream).unwrap(), expected);
}

/// Captures on the LAN until `stop` says so or `secs` pass; returns the
/// number of frames the filter passed and the observer's signals.
fn capture(
    secs: u64,
    stop: impl Fn(&[keyhole::observer::Signal]) -> bool,
) -> (usize, Vec<keyhole::observer::Signal>) {
    use std::os::fd::{AsFd, AsRawFd};
    use std::time::{Duration, Instant};

    let mut capture = keyhole::bpf::Capture::open("vtnet0").unwrap();
    let mut observer = keyhole::observer::Observer::new(Duration::from_secs(5), 1024);
    let deadline = Instant::now() + Duration::from_secs(secs);
    let (mut frames, mut signals) = (0, Vec::new());
    while Instant::now() < deadline && !stop(&signals) {
        let mut pfd = libc::pollfd {
            fd: capture.as_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the duration of the call.
        if unsafe { libc::poll(&raw mut pfd, 1, 500) } <= 0 {
            continue;
        }
        capture
            .read(|f| {
                frames += 1;
                signals.extend(observer.on_frame(f, Instant::now()));
            })
            .unwrap();
    }
    (frames, signals)
}

/// Needs an empty `<keyhole>` table and the client VM running
/// `curl https://womenhelp.org` (blocked).
#[test]
#[ignore = "needs the OPNsense test VM and a client connection"]
fn bpf_capture_feeds_the_observer() {
    use keyhole::observer::Signal;
    let want = Signal::TlsReset {
        server: "199.58.81.252".parse().unwrap(),
        sni: keyhole::domain::Domain::parse("womenhelp.org"),
    };
    let (frames, signals) = capture(30, |s| s.contains(&want));
    eprintln!("frames passed: {frames}");
    assert!(signals.contains(&want), "{signals:?}");
}

/// Needs the client VM downloading a large file over HTTPS meanwhile.
#[test]
#[ignore = "needs the OPNsense test VM and a client download"]
fn bpf_filter_keeps_bulk_data_in_the_kernel() {
    let (frames, signals) = capture(20, |_| false);
    eprintln!("frames passed during the download: {frames}");
    assert!(frames < 20, "{frames}");
    assert!(signals.is_empty(), "{signals:?}");
}
