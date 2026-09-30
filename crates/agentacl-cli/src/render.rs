//! Human-readable output. Every attacker-influenced string goes through
//! `term_safe` (threat T15b).

use agentacl_core::audit::{Enforcement, Event};
use agentacl_core::escape::term_safe;
use agentacl_policy::Effect;

pub fn tilde(path: &str, home: &str) -> String {
    match path.strip_prefix(home) {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_string(),
    }
}

/// Left-aligned table with a header row; cells are escaped.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = rows.iter().map(|r| r.iter().map(|c| term_safe(c)).collect()).collect();
    let mut w: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let line = |cells: Vec<&str>| -> String {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                s.push_str(&format!("{:<width$}  ", c, width = w[i]));
            }
        }
        s.trim_end().to_string()
    };
    let mut out = line(headers.to_vec());
    out.push('\n');
    for r in &rows {
        out.push_str(&line(r.iter().map(String::as_str).collect()));
        out.push('\n');
    }
    out
}

pub fn action_word(action: &str) -> String {
    match action {
        "filesystem.read" => "Read".into(),
        "filesystem.write" => "Write".into(),
        "process.exec" => "Execute".into(),
        "network.connect" => "Connect".into(),
        "network.listen" => "Listen".into(),
        "ipc.mach-lookup" => "System service (IPC)".into(),
        other => other.into(),
    }
}

pub fn decision_label(e: &Event) -> &'static str {
    match (e.decision, e.enforcement) {
        (Some(Effect::Deny), Some(Enforcement::Enforced)) => "BLOCKED",
        (Some(Effect::Ask), Some(Enforcement::Enforced)) => "BLOCKED (approval required)",
        (Some(Effect::Allow), Some(Enforcement::Enforced)) => "allowed",
        (Some(Effect::Deny | Effect::Ask), Some(Enforcement::Observed)) => "OBSERVED — NOT BLOCKED",
        (Some(Effect::Allow), _) => "allowed",
        _ => "",
    }
}

/// The `AGENTACL DENIED` card (only for decisions that actually took effect).
pub fn card(e: &Event, agent_display: &str) -> String {
    let title = match (e.decision, e.enforcement) {
        (Some(Effect::Deny), Some(Enforcement::Enforced)) => "AGENTACL DENIED",
        (Some(Effect::Ask), Some(Enforcement::Enforced)) => "AGENTACL DENIED (approval required)",
        (Some(_), Some(Enforcement::Observed)) => "AGENTACL OBSERVED — NOT BLOCKED",
        _ => "AGENTACL",
    };
    let mut s = format!("{title}\n\n");
    let mut row = |k: &str, v: &str| s.push_str(&format!("{:<12}{}\n", format!("{k}:"), term_safe(v)));
    row("Agent", agent_display);
    row("Action", &action_word(&e.action));
    row("Resource", &e.resource);
    if !e.delegation_chain.is_empty() {
        row("Chain", &e.delegation_chain.join(" → "));
    }
    row("Policy", &format!("{}{}", e.policy.as_deref().unwrap_or("-"), e.rule_id.as_deref().map(|r| format!(" ({r})")).unwrap_or_default()));
    row("Reason", e.reason.as_deref().unwrap_or("-"));
    if e.count > 1 {
        row("Count", &e.count.to_string());
    }
    row("Session", &e.session);
    row("Time", &e.timestamp);
    s
}

pub fn agent_display(id: &str) -> String {
    agentacl_core::agents::provider(id).map(|p| p.display_name().to_string()).unwrap_or_else(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_escapes() {
        let t = table(&["A", "B"], &[vec!["x\x1b]52;c;evil\x07".into(), "y".into()]]);
        assert!(!t.contains('\x1b'));
        assert!(t.contains("\\x1b]52"));
    }

    #[test]
    fn tilde_paths() {
        assert_eq!(tilde("/Users/u/src/p", "/Users/u"), "~/src/p");
        assert_eq!(tilde("/Users/uu/x", "/Users/u"), "/Users/uu/x");
    }
}
