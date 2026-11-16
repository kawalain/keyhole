//! Plain-HTTP bypass (ADR 0011): the censor inspects only the first request
//! in a segment, so the proxy puts a harmless `HEAD` for the server's own
//! address in front of the client's request and drops its response.

use std::net::IpAddr;

/// Where Korean block pages redirect to (ADR 0002).
pub const BLOCK_PAGE_HOST: &[u8] = b"warning.or.kr";

/// Whether `buf` starts like an HTTP/1 request.
pub fn is_request(buf: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"TRACE ",
        b"CONNECT ",
    ];
    METHODS.iter().any(|m| buf.starts_with(m))
}

/// The request sent ahead of the client's, in the same segment.
pub fn decoy(server: IpAddr) -> Vec<u8> {
    let host = match server {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    format!("HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

/// Drops the decoy's response from the start of the server's byte stream.
/// A response to `HEAD` is a status line and headers without a body.
#[derive(Default)]
pub struct DecoyResponse {
    /// The last bytes seen, to find a terminator split across reads.
    tail: Vec<u8>,
    done: bool,
    seen: usize,
}

/// Longest decoy response head accepted before giving up and passing the
/// stream through unchanged.
const MAX_HEAD: usize = 16 * 1024;

impl DecoyResponse {
    /// Whether the decoy's response has been dropped completely.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Returns the part of `chunk` that belongs to the client.
    pub fn strip<'a>(&mut self, chunk: &'a [u8]) -> &'a [u8] {
        if self.done {
            return chunk;
        }
        let keep = self.tail.len();
        let mut window = std::mem::take(&mut self.tail);
        window.extend_from_slice(chunk);
        if let Some(end) = window.windows(4).position(|w| w == b"\r\n\r\n") {
            self.done = true;
            return &chunk[end + 4 - keep..];
        }
        self.seen += chunk.len();
        if self.seen > MAX_HEAD {
            self.done = true;
            return chunk;
        }
        let from = window.len().saturating_sub(3);
        self.tail = window[from..].to_vec();
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECOY_REPLY: &[u8] = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://a.example/\r\nContent-Length: 162\r\n\r\n";
    const REAL: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

    #[test]
    fn recognises_requests() {
        assert!(is_request(b"GET / HTTP/1.1\r\n"));
        assert!(is_request(b"POST /x HTTP/1.1\r\n"));
        assert!(!is_request(b"\x16\x03\x01"));
        assert!(!is_request(b"GETX"));
    }

    #[test]
    fn decoy_targets_the_server_address() {
        assert_eq!(
            decoy("199.58.81.252".parse().unwrap()),
            b"HEAD / HTTP/1.1\r\nHost: 199.58.81.252\r\n\r\n"
        );
    }

    #[test]
    fn strips_the_decoy_response_however_it_is_cut() {
        let mut stream = DECOY_REPLY.to_vec();
        stream.extend_from_slice(REAL);
        for cut1 in 0..stream.len() {
            for cut2 in [cut1, (cut1 + 3).min(stream.len()), stream.len()] {
                let mut d = DecoyResponse::default();
                let mut out = Vec::new();
                for part in [&stream[..cut1], &stream[cut1..cut2], &stream[cut2..]] {
                    out.extend_from_slice(d.strip(part));
                }
                assert_eq!(out, REAL, "cuts at {cut1} and {cut2}");
            }
        }
    }

    #[test]
    fn oversized_heads_pass_through() {
        let mut d = DecoyResponse::default();
        let junk = vec![b'a'; MAX_HEAD + 1];
        assert_eq!(d.strip(&junk), &junk[..]);
        assert_eq!(d.strip(b"more"), b"more");
    }
}
