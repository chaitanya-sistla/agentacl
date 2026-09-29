//! AgentFence core: macOS process facts, agent identity, sessions, enforcement
//! backends, observers and the audit store.

pub mod config;
pub mod escape;
pub mod audit;
pub mod proc;
pub mod agents;
pub mod enforce;
pub mod identity;
pub mod session;
