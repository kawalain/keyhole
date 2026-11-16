# Test data

Raw bytes as received on the wire, captured 2026-11-17.

- `client-hello-chromium.bin`: the first TLS record headless Chromium sent
  for `https://womenhelp.org/`, with `--host-resolver-rules` pointing the
  name at a local listener (Chromium on Arch Linux; includes an ML-KEM key
  share).
- `client-hello-openssl.bin`: the same from Python's `ssl` module (OpenSSL).
- `dns-cname-a.bin`, `dns-aaaa.bin`, `dns-nxdomain.bin`: UDP responses from
  the KT resolver (168.126.63.1) for `www.github.com` A (CNAME then A),
  `www.google.com` AAAA, and a nonexistent `.com` name.
- `lan-blocked-and-normal.pcap`: the router VM's LAN (`vtnet0`) while the
  client VM ran curl against `https://womenhelp.org` (reset),
  `http://womenhelp.org` (302 to `warning.or.kr`) and
  `https://www.rust-lang.org` (normal). The VM's WAN is QEMU user-mode NAT,
  so TCP options and TTLs on the server side come from QEMU, not the ISP.
