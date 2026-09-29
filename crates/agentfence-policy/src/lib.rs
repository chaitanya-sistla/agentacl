//! AgentFence policy language. Pure: no I/O beyond what callers pass in, no
//! clocks, no randomness. Every decision is a deterministic function of
//! (policy set, request).
