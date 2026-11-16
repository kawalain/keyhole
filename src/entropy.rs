//! Unpredictable bytes for ClientHello randoms and DNS message IDs.

use std::io::Read;

/// Fills `buf` from the kernel's random source, falling back to the
/// standard library's randomly keyed hasher if it cannot be read.
pub fn fill(buf: &mut [u8]) {
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .is_ok()
    {
        return;
    }
    use std::hash::{BuildHasher, RandomState};
    for (i, chunk) in buf.chunks_mut(8).enumerate() {
        let word = RandomState::new().hash_one(i).to_ne_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
}
