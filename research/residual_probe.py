"""Measure residual blocking: after a blocked ClientHello triggers a reset,
how long do bypassed (record-split) ClientHellos to the same server fail?

Usage: python3 -I residual_probe.py <host> <ip> [rounds]
"""
import socket, ssl, sys, time

host, ip = sys.argv[1], sys.argv[2]
rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 3
H = host.encode()


def hello(split):
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    data = out.read()
    if not split:
        return data
    body = data[5:]
    pos = body.find(H) + 2
    rec = lambda p: data[:3] + len(p).to_bytes(2, "big") + p
    return rec(body[:pos]) + rec(body[pos:])


def attempt(split):
    s = socket.create_connection((ip, 443), timeout=5)
    try:
        s.sendall(hello(split))
        return "ok" if s.recv(1) else "eof"
    except ConnectionResetError:
        return "reset"
    except socket.timeout:
        return "timeout"
    finally:
        s.close()


for r in range(rounds):
    time.sleep(20)  # let any earlier residual state expire
    trigger = attempt(False)
    start = time.monotonic()
    line = [f"trigger={trigger}"]
    for delay in [0.2, 0.5, 1, 2, 3, 4, 6, 8, 12]:
        time.sleep(max(0, start + delay - time.monotonic()))
        line.append(f"{delay}s={attempt(True)}")
    print(" ".join(line), flush=True)

time.sleep(20)
print("baseline split without trigger:", [attempt(True) for _ in range(3)])
