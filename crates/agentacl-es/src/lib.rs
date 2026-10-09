//! AgentACL's Endpoint Security backend: identity and enforcement for every
//! agent on the Mac, however it was started (docs/design/endpoint-security.md).
//!
//! The engine (`model`, `tracker`, `engine`) is plain Rust and fully tested
//! without Endpoint Security. `adapter` maps ES messages onto it; it needs the
//! ES entitlement (or a development Mac with SIP and AMFI off) to run.

pub mod adapter;
pub mod creds;
pub mod engine;
pub mod journal;
pub mod model;
pub mod provider;
pub mod tracker;
