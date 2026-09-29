//! AgentFence policy language. Pure: no I/O beyond what callers pass in, no
//! clocks, no randomness. Every decision is a deterministic function of
//! (policy set, request).

pub mod error;
pub mod model;
pub mod raw;

pub use error::PolicyError;
pub use model::*;
pub use raw::{parse_doc, RawDoc, RawRule, RuleKind};
pub mod expand;
pub mod pathpat;
