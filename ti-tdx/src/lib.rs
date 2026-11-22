//! Shared TDX attestation logic for the T19c confidential gateway (docs/T19c-spec.md).
//!
//! Everything here is pure: no network, no clock reads, no randomness. Callers pass
//! the time, the nonce and the collateral, so every decision is testable offline.

pub mod backend;
pub mod binding;
pub mod ccel;
pub mod policy;
pub mod reason;
pub mod release;
pub mod td;

pub use reason::Reason;
