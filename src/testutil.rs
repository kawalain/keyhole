//! Helpers shared by unit tests.

/// The frames of a little-endian, microsecond pcap file.
pub fn pcap_frames(file: &[u8]) -> Vec<&[u8]> {
    assert_eq!(&file[..4], &[0xd4, 0xc3, 0xb2, 0xa1], "little-endian pcap");
    let mut frames = Vec::new();
    let mut pos = 24;
    while pos + 16 <= file.len() {
        let len = u32::from_le_bytes(file[pos + 8..pos + 12].try_into().unwrap()) as usize;
        pos += 16;
        frames.push(&file[pos..pos + len]);
        pos += len;
    }
    frames
}
