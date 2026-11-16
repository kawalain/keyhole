# Test data

- `client-hello-chromium.bin`: the first TLS record headless Chromium sent
  for `https://womenhelp.org/`, with `--host-resolver-rules` pointing the
  name at a local listener (2026-11-17, Chromium on Arch Linux; includes an
  ML-KEM key share).
- `client-hello-openssl.bin`: the same from Python's `ssl` module (OpenSSL).

Both are raw bytes as received by the listener, one complete record each.
