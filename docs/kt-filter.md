# KT's SNI/Host filter as measured

Measured on 2026-11-17 from a LAN host on a KT line (AS4766), without root,
with `research/kt_filter_probe.py`, `research/split_probe.py`,
`research/http_probe.py`, `research/residual_probe.py` and curl's HTTP/3
support. Blocked test name: `womenhelp.org` (also `pornhub.com`,
`xvideos.com`). Control name: `example.com`. Each row is three or more
fresh connections unless noted.

## Where it sits and what it sends

| Probe at 199.58.81.252 | Connect RTT | First reaction |
|---|---|---|
| TLS, control SNI | 173 ms | ServerHello after 174 ms |
| TLS, blocked SNI | 175 ms | TCP reset after 8–9 ms |
| HTTP, control `Host` | 174 ms | origin response after 175 ms |
| HTTP, blocked `Host` | 175 ms | `HTTP/1.0 302` to `http://warning.or.kr/i6.html` after 7.5–9 ms |

The reset and the block page arrive about 20 times sooner than anything
from the server could: they are injected by a box a few milliseconds away,
inside the domestic network. The client receives the injected packet; the
filter is on-path, not in the DNS (ISP resolvers answer truthfully, ADR
0002).

## What it parses

| First flight | Port | Result |
|---|---|---|
| TLS ClientHello with the blocked SNI | 443 | reset |
| TLS ClientHello with the blocked SNI | 80 | reset |
| TLS ClientHello with the blocked SNI | 8443, 2053, 2083, 2087, 2096 | HTTP block page |
| HTTP `GET` with the blocked `Host` | 80, 8443 | block page |
| HTTP `GET` with the blocked `Host` | 443 | block page (2 of 3) |
| Arbitrary bytes containing `womenhelp.org` | 80, 443, 8443 | passes |
| QUIC (HTTP/3) with the blocked SNI, to a Google address whose TLS-over-TCP is filtered | UDP 443 | passes (server's 404) |

The filter recognises TLS and HTTP by content on any TCP port and reads
the SNI or `Host`; it does not search raw bytes. It does not inspect QUIC.

## How it matches names

At 199.58.81.252, TLS:

| SNI | Result |
|---|---|
| `womenhelp.org`, `WOMENHELP.ORG`, `WomenHelp.org` | reset |
| `womenhelp.org.` (trailing dot) | reset |
| `www.womenhelp.org` | reset |
| `a.b.womenhelp.org`, `xwomenhelp.org`, `omenhelp.org`, `womenhelp.or`, `womenhelp.net`, `womenhelp`, `womenhelp.org.example.com` | passes |

Matching is exact after lower-casing and dropping a trailing dot, with the
`www.` form also listed (or stripped). It is neither a suffix nor a
substring match: deeper subdomains of a blocked name pass.

## What it reassembles

- TCP: yes. A ClientHello or request split across segments, even with a
  1 s pause, is still caught (ADR 0003, 0011).
- TLS records: no. A ClientHello split into two records inside the name
  passes (ADR 0003).
- HTTP: only the first request in a segment is inspected; a harmless
  request in front hides the real one (ADR 0011). A later request on the
  same connection, in its own segment, is inspected again.
- No residual blocking: right after a reset, a bypassed ClientHello to the
  same server passes from 0.2 s on.

## Where it applies

Not every destination is inspected. With the blocked SNI:

| Destination | Result |
|---|---|
| 199.58.81.252 (womenhelp.org), 142.251.x (Google), 172.66.147.243 (Cloudflare, example.com) | reset |
| 8.8.8.8 | reset in 20 of 20 in one run, mixed in another |
| 223.130.192.247 (Naver), 121.53.105.193 (Daum), 1.1.1.1, 104.16.124.96 (Cloudflare), 151.101.x (Fastly), Microsoft, Amazon, GitHub, Akamai addresses | passes |

Even an inspected destination is not inspected every time (172.66.147.243
on 443: reset in one run, mixed in the next). The filter looks like boxes
on some routes only, possibly not on every parallel path or not under all
load. A domain's verdict can therefore depend on which address it resolves
to, which is why keyhole probes the address the client actually used and
re-verifies verdicts.
