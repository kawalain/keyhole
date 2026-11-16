"""Characterise the ISP's SNI/Host filter from a LAN host, without root.

Usage: python3 -I kt_filter_probe.py [trials]

Every probe opens a fresh TCP connection, sends one first flight and
classifies the first reaction: answer (any byte), reset, eof or timeout.
"""
import os, socket, struct, sys, time

TRIALS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
BLOCKED, CONTROL = "womenhelp.org", "example.com"
WOMENHELP_IP = "199.58.81.252"


def client_hello(name: str) -> bytes:
    """Minimal TLS 1.2/1.3 ClientHello, same shape as keyhole's tls.rs."""
    n = name.encode()
    ext = b""

    def add(kind, data):
        nonlocal ext
        ext += struct.pack(">HH", kind, len(data)) + data

    add(0, struct.pack(">HBH", len(n) + 3, 0, len(n)) + n)
    add(0x0A, bytes([0, 6, 0, 0x1D, 0, 0x17, 0, 0x18]))
    add(0x0B, bytes([1, 0]))
    add(0x0D, bytes([0, 8, 4, 3, 8, 4, 4, 1, 5, 3]))
    add(0x2B, bytes([4, 3, 4, 3, 3]))
    add(0x2D, bytes([1, 1]))
    add(0x33, bytes([0, 36, 0, 0x1D, 0, 32]) + os.urandom(32))
    suites = bytes([0x13, 1, 0x13, 2, 0x13, 3, 0xC0, 0x2B, 0xC0, 0x2F])
    body = (b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
            + struct.pack(">H", len(suites)) + suites + b"\x01\x00"
            + struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def probe(ip, port, payload, timeout=5.0):
    """Returns (outcome, connect_ms, reaction_ms)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.connect((ip, port))
    except OSError as e:
        s.close()
        return f"noconnect:{e.__class__.__name__}", None, None
    t1 = time.monotonic()
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        s.sendall(payload)
        t2 = time.monotonic()
        data = s.recv(4096)
        t3 = time.monotonic()
        outcome = "answer" if data else "eof"
        if data.startswith(b"HTTP/") and b"warning.or.kr" in data:
            outcome = "blockpage"
    except ConnectionResetError:
        t3 = time.monotonic()
        outcome = "reset"
    except socket.timeout:
        t3 = time.monotonic()
        outcome = "timeout"
    finally:
        s.close()
    return outcome, (t1 - t0) * 1000, (t3 - t2) * 1000


def summary(results):
    outcomes = sorted({r[0] for r in results})
    return "/".join(outcomes)


def section(title):
    print(f"\n## {title}", flush=True)


# 1. Where is the filter? Compare connect RTT with the reset delay.
section("timing at the blocked server (ms)")
for name in [CONTROL, BLOCKED]:
    for _ in range(TRIALS):
        o, rtt, react = probe(WOMENHELP_IP, 443, client_hello(name))
        print(f"{name:16} {o:8} rtt={rtt:6.1f} reaction={react:6.1f}")
req = f"GET / HTTP/1.1\r\nHost: {BLOCKED}\r\nConnection: close\r\n\r\n".encode()
ctl = f"GET / HTTP/1.1\r\nHost: {CONTROL}\r\nConnection: close\r\n\r\n".encode()
for label, payload in [("http control", ctl), ("http blocked", req)]:
    for _ in range(TRIALS):
        o, rtt, react = probe(WOMENHELP_IP, 80, payload)
        print(f"{label:16} {o:9} rtt={rtt:6.1f} reaction={react:6.1f}")

# 2. Does the destination matter?
section("blocked SNI to other destinations (control / blocked)")
targets = ["www.naver.com", "www.daum.net", "www.google.com", "dns.google",
           "one.one.one.one", "www.cloudflare.com", "example.com",
           "www.fastly.com", "www.microsoft.com", "www.amazon.com",
           "github.com", "www.akamai.com"]
for host in targets:
    try:
        ip = socket.getaddrinfo(host, 443, socket.AF_INET)[0][4][0]
    except OSError:
        print(f"{host:20} unresolved")
        continue
    c = [probe(ip, 443, client_hello(CONTROL)) for _ in range(TRIALS)]
    b = [probe(ip, 443, client_hello(BLOCKED)) for _ in range(TRIALS)]
    print(f"{host:20} {ip:16} control={summary(c):10} blocked={summary(b)}", flush=True)

# 3. How is the name matched?
section(f"SNI variants at {WOMENHELP_IP}")
variants = ["womenhelp.org", "WOMENHELP.ORG", "WomenHelp.org", "www.womenhelp.org",
            "a.b.womenhelp.org", "xwomenhelp.org", "womenhelp.org.example.com",
            "womenhelp.or", "omenhelp.org", "womenhelp.org.", "womenhelp.net",
            "womenhelp", "abortionpillinfo.org"]
for v in variants:
    r = [probe(WOMENHELP_IP, 443, client_hello(v)) for _ in range(TRIALS)]
    print(f"{v:28} {summary(r)}", flush=True)

# 4. Which ports?  Cloudflare serves HTTPS on several ports.
section("blocked SNI on other ports of a Cloudflare address")
cf = socket.getaddrinfo("www.cloudflare.com", 443, socket.AF_INET)[0][4][0]
for port in [443, 8443, 2053, 2083, 2087, 2096]:
    c = [probe(cf, port, client_hello(CONTROL)) for _ in range(TRIALS)]
    b = [probe(cf, port, client_hello(BLOCKED)) for _ in range(TRIALS)]
    print(f"{cf}:{port:<5} control={summary(c):10} blocked={summary(b)}", flush=True)
