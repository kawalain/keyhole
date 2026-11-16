"""Measure which plain-HTTP request rewrites get past Korean Host filtering.

Usage: python3 -I http_probe.py <host> <ip> [runs]

Each variant is sent `runs` times, interleaved, on fresh connections. A
run passes when the response is not a redirect to warning.or.kr.
"""
import socket, sys, time

host, ip = sys.argv[1], sys.argv[2]
runs = int(sys.argv[3]) if len(sys.argv) > 3 else 5
H = host

VARIANTS = {
    "plain": [f"GET / HTTP/1.1\r\nHost: {H}\r\nConnection: close\r\n\r\n"],
    "host-mixed-case": [f"GET / HTTP/1.1\r\nHoSt: {H}\r\nConnection: close\r\n\r\n"],
    "host-no-space": [f"GET / HTTP/1.1\r\nHost:{H}\r\nConnection: close\r\n\r\n"],
    "host-tab": [f"GET / HTTP/1.1\r\nHost:\t{H}\r\nConnection: close\r\n\r\n"],
    "host-upper-value": [f"GET / HTTP/1.1\r\nHost: {H.upper()}\r\nConnection: close\r\n\r\n"],
    "absolute-uri-other-host": [
        f"GET http://{H}/ HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    ],
    "host-last-header": [
        f"GET / HTTP/1.1\r\nConnection: close\r\nAccept: */*\r\nHost: {H}\r\n\r\n"
    ],
    "padding-before-host": [
        f"GET / HTTP/1.1\r\nX-Pad: {'a' * 1600}\r\nHost: {H}\r\nConnection: close\r\n\r\n"
    ],
    "lf-only": [f"GET / HTTP/1.1\nHost: {H}\nConnection: close\n\n"],
    "split-host-delay-1s": [
        f"GET / HTTP/1.1\r\nHost: {H[:2]}",
        f"{H[2:]}\r\nConnection: close\r\n\r\n",
    ],
    "method-separate-segment": [
        "GET / HTTP/1.1\r\n",
        f"Host: {H}\r\nConnection: close\r\n\r\n",
    ],
}


def attempt(parts):
    s = socket.create_connection((ip, 80), timeout=8)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        for i, p in enumerate(parts):
            if i:
                time.sleep(1.0)
            s.sendall(p.encode())
        resp = b""
        while len(resp) < 2048:
            c = s.recv(2048)
            if not c:
                break
            resp += c
    except OSError as e:
        return f"ERR {e.__class__.__name__}"
    finally:
        s.close()
    line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    if b"warning.or.kr" in resp:
        return "BLOCKED"
    return line or "EMPTY"


results = {k: [] for k in VARIANTS}
for r in range(runs):
    for name, parts in VARIANTS.items():
        results[name].append(attempt(parts))
for name, rs in results.items():
    passed = sum(1 for x in rs if x != "BLOCKED" and not x.startswith(("ERR", "EMPTY")))
    print(f"{name:26} {passed}/{runs}  {sorted(set(rs))}")
