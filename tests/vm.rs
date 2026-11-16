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
