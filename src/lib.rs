//! keyhole: detects Korean ISP censorship and bypasses it only where needed.
//!
//! See `docs/adr/` for the architecture.

pub mod bpf;
pub mod classifier;
pub mod dns;
pub mod domain;
pub mod engine;
pub mod entropy;
pub mod http;
pub mod log;
pub mod observer;
pub mod pf;
pub mod prober;
pub mod proxy;
pub mod resolver;
#[cfg(test)]
mod testutil;
pub mod tls;
