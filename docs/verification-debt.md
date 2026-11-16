# Verification debt

Behaviour that tests cannot reach yet. Each entry says what was seen and what
still needs a real router, a real ISP path or a real service.

- **Path-dependent SNI blocking** ([0002](adr/0002-korean-blocking-model.md)):
  the blocked SNI passed to 1.1.1.1 and a Fastly address but failed to a
  Cloudflare address and 8.8.8.8; the failure type was not captured. Needs a
  repeat that records reset vs. timeout vs. TLS alert.
- **Plain-HTTP bypass** ([0003](adr/0003-bypass-tls-record-fragmentation.md)):
  header-case tricks passed in 1 of 3 runs. Needs a reliable transformation
  if HTTP-only blocked sites turn up.
- **QEMU in front of the WAN** ([0007](adr/0007-freebsd-interception.md)):
  the test VM's WAN is QEMU user-mode NAT, which terminates TCP itself. pf,
  BPF and the bypass were seen working there, but not on a router whose WAN
  faces the ISP directly. Needs the real router.
- **Resource budget on real hardware** ([0006](adr/0006-language-rust.md)):
  measured only in the KVM test VM with light load. Needs numbers from the
  real router under a household's normal browsing.
- **Reaction time**: in the test VM a block was detected, probed and
  bypassed about 1.1 s after the first reset; a connection started in that
  second was still reset. Not measured on the real router.
