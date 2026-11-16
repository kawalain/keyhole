"""Minimal A query over UDP. Usage: python3 -I dnsq.py <server> <name>..."""
import random, socket, struct, sys

server = sys.argv[1]
for name in sys.argv[2:]:
    qid = random.randrange(65536)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"
    q += struct.pack(">HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(4)
    try:
        s.sendto(q, (server, 53))
        r, _ = s.recvfrom(4096)
    except Exception as e:
        print(f"{name:28} {e}")
        continue
    rcode = r[3] & 0xF
    an = struct.unpack(">H", r[6:8])[0]
    pos = len(q)
    ips = []
    for _ in range(an):
        if r[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while r[pos]:
                pos += r[pos] + 1
            pos += 1
        typ, _, ttl, ln = struct.unpack(">HHIH", r[pos:pos + 10])
        pos += 10
        if typ == 1:
            ips.append(f"{socket.inet_ntoa(r[pos:pos + 4])} ttl={ttl}")
        pos += ln
    print(f"{name:28} rcode={rcode} {ips}")
