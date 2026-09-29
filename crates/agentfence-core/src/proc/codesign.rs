//! Code-signing identity via `/usr/bin/codesign -dv`. Used for agent
//! identification (evidence), never as an authorization input on its own.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeSignature {
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub authority: Vec<String>,
}

pub fn code_signature(path: &Path) -> Option<CodeSignature> {
    let out = Command::new("/usr/bin/codesign").arg("-dv").arg("--verbose=2").arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_codesign(&String::from_utf8_lossy(&out.stderr)))
}

pub fn parse_codesign(text: &str) -> CodeSignature {
    let mut sig = CodeSignature::default();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("Identifier=") {
            sig.signing_id = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("TeamIdentifier=") {
            let v = v.trim();
            if v != "not set" {
                sig.team_id = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("Authority=") {
            sig.authority.push(v.trim().to_string());
        }
    }
    sig
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_binary() {
        let s = code_signature(Path::new("/usr/bin/true")).unwrap();
        assert_eq!(s.signing_id.as_deref(), Some("com.apple.true"));
    }

    #[test]
    fn parses_developer_id() {
        let s = parse_codesign("Executable=/x\nIdentifier=com.anthropic.claude-code\nAuthority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\nTeamIdentifier=Q6L2SF6YDW\n");
        assert_eq!(s.team_id.as_deref(), Some("Q6L2SF6YDW"));
        assert_eq!(s.signing_id.as_deref(), Some("com.anthropic.claude-code"));
        assert_eq!(s.authority.len(), 1);
        assert_eq!(parse_codesign("TeamIdentifier=not set\n").team_id, None);
    }
}
