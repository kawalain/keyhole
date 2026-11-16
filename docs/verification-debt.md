# Verification debt

Behaviour that tests cannot reach yet. Each entry says what was seen and what
still needs a real router, a real ISP path or a real service.

- **ISP resolver tampering** ([0002](adr/0002-korean-blocking-model.md),
  [0005](adr/0005-dns-upstream-policy.md)): seen only through an encrypted
  resolver, which answered correctly. Needs a query to the ISP resolver
  directly from the router for a known DNS-blocked domain.
- **Path-dependent SNI blocking** ([0002](adr/0002-korean-blocking-model.md)):
  the blocked SNI passed to 1.1.1.1 and a Fastly address but failed to a
  Cloudflare address and 8.8.8.8; the failure type was not captured. Needs a
  repeat that records reset vs. timeout vs. TLS alert.
- **Plain-HTTP bypass** ([0003](adr/0003-bypass-tls-record-fragmentation.md)):
  header-case tricks passed in 1 of 3 runs. Needs a reliable transformation
  if HTTP-only blocked sites turn up.
- **pf interception on OPNsense** ([0007](adr/0007-freebsd-interception.md)):
  `rdr-to`, `DIOCNATLOOK` and the BPF filter are unverified. Needs the real
  router or an OPNsense VM.
- **Resource budget** ([0006](adr/0006-language-rust.md)): no numbers yet.
  Needs a prototype measured on OPNsense.
