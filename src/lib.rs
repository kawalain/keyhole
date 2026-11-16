//! keyhole: detects Korean ISP censorship and bypasses it only where needed.
//!
//! See `docs/adr/` for the architecture.

pub mod classifier;
pub mod dns;
pub mod domain;
pub mod entropy;
pub mod pf;
pub mod prober;
pub mod proxy;
pub mod resolver;
pub mod tls;
