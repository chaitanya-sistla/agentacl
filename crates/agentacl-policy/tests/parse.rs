use agentacl_policy::{parse_doc, Layer, PolicyError, RuleKind};

const EXAMPLE: &str = r#"
version: v1
name: default
match:
  agents: ["claude-code", "codex"]
  projects: ["${HOME}/src/**"]
defaults:
  filesystem: deny
  network: deny
  process: allow
filesystem:
  allow_read:
    - "${PROJECT}/**"
  allow_write:
    - "${PROJECT}/**"
  deny_read:
    - "${HOME}/.ssh/**"
    - path: "${PROJECT}/**/.env.*"
      except: ["**/.env.example", "**/.env.sample", "**/.env.template", "**/.env.dist"]
      id: env-variants
      reason: "Environment secret files are protected"
  deny_write:
    - "${PROJECT}/.git/hooks/**"
process:
  deny:
    - "sudo *"
  require_approval:
    - "terraform apply *"
    - "terraform destroy *"
    - "kubectl delete *"
    - "git push *"
network:
  allow:
    - "api.anthropic.com"
    - "*.githubusercontent.com"
    - "github.com:443"
  deny:
    - "169.254.169.254"
"#;

#[test]
fn full_example_parses() {
    let d = parse_doc(EXAMPLE, Layer::User, "user").unwrap();
    assert_eq!(d.name, "default");
    assert_eq!(d.filesystem.allow_read.len(), 1);
    assert_eq!(d.filesystem.deny_read.len(), 2);
    assert_eq!(d.filesystem.deny_write.len(), 1);
    assert_eq!(d.process.deny.len(), 1);
    assert_eq!(d.process.require_approval.len(), 4);
    assert_eq!(d.network.allow.len(), 3);
    let env = &d.filesystem.deny_read[1];
    assert_eq!(env.id.as_deref(), Some("env-variants"));
    assert_eq!(env.except.len(), 4);
    assert_eq!(env.kind, RuleKind::Path);
    assert_eq!(d.match_.unwrap().agents, vec!["claude-code", "codex"]);
}

#[test]
fn name_defaults_to_source() {
    let d = parse_doc("version: v1\n", Layer::User, "policy").unwrap();
    assert_eq!(d.name, "policy");
}

#[test]
fn wrong_version() {
    let e = parse_doc("version: v2\n", Layer::User, "u").unwrap_err();
    assert!(matches!(e, PolicyError::Version { .. }));
}

#[test]
fn unknown_key_rejected() {
    let e = parse_doc("version: v1\nfilesytem: {}\n", Layer::User, "u").unwrap_err();
    assert!(e.to_string().contains("filesytem"), "{e}"); // spellchecker:disable-line
    let e = parse_doc("version: v1\nfilesystem:\n  alow_read: []\n", Layer::User, "u").unwrap_err(); // spellchecker:disable-line
    assert!(e.to_string().contains("alow_read"), "{e}"); // spellchecker:disable-line
}

#[test]
fn project_restrict_only() {
    for (yaml, key) in [
        ("filesystem:\n  allow_read: [\"/x\"]", "filesystem.allow_read"),
        ("filesystem:\n  allow_write: [\"/x\"]", "filesystem.allow_write"),
        ("process:\n  allow: [\"ls\"]", "process.allow"),
        ("network:\n  allow: [\"a.com\"]", "network.allow"),
        ("network:\n  listen: [\"localhost:3000\"]", "network.listen"),
        ("builtin:\n  disable: [keys]", "builtin"),
    ] {
        let e = parse_doc(&format!("version: v1\n{yaml}\n"), Layer::Project, "p").unwrap_err();
        assert_eq!(e, PolicyError::ProjectForbidden { doc: "p".into(), key: key.into() }, "{yaml}");
    }
    let ok = "version: v1\ndefaults:\n  network: deny\nfilesystem:\n  deny_read: [\"${PROJECT}/secret/**\"]\nprocess:\n  deny: [\"rm *\"]\n  require_approval: [\"git push *\"]\nnetwork:\n  deny: [\"evil.com\"]\n";
    parse_doc(ok, Layer::Project, "p").unwrap();
}

#[test]
fn rule_object_needs_exactly_one_kind() {
    let y = "version: v1\nfilesystem:\n  deny_read:\n    - path: /a\n      host: b\n";
    assert!(matches!(parse_doc(y, Layer::User, "u").unwrap_err(), PolicyError::BadRule { .. }));
    let y = "version: v1\nfilesystem:\n  deny_read:\n    - host: b\n";
    assert!(matches!(parse_doc(y, Layer::User, "u").unwrap_err(), PolicyError::BadRule { .. }));
    let y = "version: v1\nnetwork:\n  deny:\n    - host: b\n      except: [c]\n";
    assert!(matches!(parse_doc(y, Layer::User, "u").unwrap_err(), PolicyError::BadRule { .. }));
}
