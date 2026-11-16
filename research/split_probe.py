"""Measure which first-payload transformations defeat Korean SNI/Host filtering.

Usage: python3 -I split_probe.py <host> <ip>
"""
import socket, ssl, sys, time

host, ip = sys.argv[1], sys.argv[2]
H = host.encode()


def tcp_split(data):
    pos = data.find(H) + 2
    return [data[:pos], data[pos:]]


def record_split(data):
    # One TLS record -> two records, split inside the SNI host name.
    ctype, ver, body = data[0:1], data[1:3], data[5:]
    pos = body.find(H) + 2
    a, b = body[:pos], body[pos:]
    rec = lambda p: ctype + ver + len(p).to_bytes(2, "big") + p
    return [rec(a) + rec(b)]


def record_and_tcp_split(data):
    one = record_split(data)[0]
    first_len = 5 + int.from_bytes(one[3:5], "big")
    return [one[:first_len], one[first_len:]]


def tls(transform):
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=host)
    s = socket.create_connection((ip, 443), timeout=8)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    first = True
    try:
        while True:
            try:
                obj.do_handshake()
                return f"OK {obj.version()}"
            except ssl.SSLWantReadError:
                data = out.read()
                if data:
                    parts = transform(data) if (first and transform) else [data]
                    for i, p in enumerate(parts):
                        if i:
                            time.sleep(0.05)
                        s.sendall(p)
                    first = False
                chunk = s.recv(65536)
                if not chunk:
                    return "EOF"
                inc.write(chunk)
    except Exception as e:
        return f"FAIL {type(e).__name__}: {e}"
    finally:
        s.close()


def http(req_tmpl, split=False):
    req = req_tmpl.format(host=host).encode()
    s = socket.create_connection((ip, 80), timeout=8)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    parts = tcp_split(req) if split else [req]
    for i, p in enumerate(parts):
        if i:
            time.sleep(0.05)
        s.sendall(p)
    resp = b""
    try:
        while len(resp) < 4096:
            c = s.recv(4096)
            if not c:
                break
            resp += c
    except Exception as e:
        return f"FAIL {e}"
    lines = resp.split(b"\r\n")
    loc = next((l for l in lines if l.lower().startswith(b"location")), b"")
    return f"{lines[0].decode(errors='replace')} {loc.decode(errors='replace')}"


print("TLS plain              :", tls(None))
print("TLS tcp split in SNI   :", tls(tcp_split))
print("TLS record split       :", tls(record_split))
print("TLS record + tcp split :", tls(record_and_tcp_split))
base = "GET / HTTP/1.1\r\n{hdr}\r\nConnection: close\r\n\r\n"
for name, hdr in [("Host:", "Host: {host}"), ("host: lower", "host: {host}"),
                  ("HoSt: mixed", "HoSt: {host}"), ("Host:<no sp>", "Host:{host}"),
                  ("Host: trailing dot", "Host: {host}.")]:
    print(f"HTTP {name:20}:", http(base.replace("{hdr}", hdr)))
print(f"HTTP {'tcp split Host':20}:", http(base.replace("{hdr}", "Host: {host}"), split=True))
