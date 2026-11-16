//! keyhole: detects Korean ISP censorship and bypasses it only where needed.
//!
//! See `docs/adr/` for the architecture.

pub mod classifier;
pub mod domain;
pub mod tls;
