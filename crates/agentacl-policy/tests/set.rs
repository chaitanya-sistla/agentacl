mod common;
use agentacl_policy::set::{protect_secrets_groups, sha256_hex, GeneratedDoc, LoadOptions};
use agentacl_policy::{Effect, Layer, PolicyError};
use common::*;

#[test]
fn builtins_load_with_all_groups() {
    let set = load(vec![]);
    let mut groups = protect_secrets_groups();
    groups.sort();
    groups.dedup();
    let want = ["aws", "azure", "browsers", "env-files", "gcp", "git-creds", "gpg", "keys", "kube", "package-creds", "ssh", "terraform"];
    assert_eq!(groups, want);
    let names: Vec<&str> = set.docs.iter().map(|d| d.name.as_str()).collect();
    for n in ["protect-secrets", "exec-persistence", "agentacl-self", "runtime", "default"] {
        assert!(names.contains(&n), "{n}");
    }
    // deny_read is mirrored into deny_write for every group
    let r = set.rules_for("claude-code", "/p");
    let reads = r.iter().filter(|r| r.policy == "protect-secrets" && r.section == agentacl_policy::set::Section::FsRead).count();
    let writes = r.iter().filter(|r| r.policy == "protect-secrets" && r.section == agentacl_policy::set::Section::FsWrite).count();
    assert_eq!(reads, writes);
    assert!(reads > 30);
}

#[test]
fn default_only_without_user_policy() {
    let with_user = load(vec![user("version: v1\n")]);
    assert!(!with_user.docs.iter().any(|d| d.name == "default"));
}

#[test]
fn builtin_disable() {
    let set = load(vec![user("version: v1\nbuiltin:\n  disable: [keys]\n")]);
    assert!(!set.rules_for("claude-code", "/p").iter().any(|r| r.id == "keys"));
    assert!(set.rules_for("claude-code", "/p").iter().any(|r| r.id == "ssh"));
    for g in ["agentacl-self", "exec-persistence", "nope"] {
        let e = try_load(vec![user(&format!("version: v1\nbuiltin:\n  disable: [{g}]\n"))], LoadOptions::default()).unwrap_err();
        assert!(matches!(e, PolicyError::Invalid { .. }), "{g}");
    }
}

#[test]
fn match_selects_documents() {
    let set = load(vec![user("version: v1\nmatch:\n  agents: [codex, \"custom:*\"]\nfilesystem:\n  allow_read: [\"/opt/x/**\"]\n")]);
    let has = |agent: &str| set.rules_for(agent, "/p").iter().any(|r| r.written == "/opt/x/**");
    assert!(!has("claude-code"));
    assert!(has("codex"));
    assert!(has("custom:mytool"));
    // builtins apply regardless of match
    assert!(set.rules_for("anything", "/p").iter().any(|r| r.id == "ssh"));
}

#[test]
fn defaults_most_restrictive_and_fallback() {
    let set = load(vec![user("version: v1\ndefaults:\n  filesystem: allow\n")]);
    // no default doc now; user says allow; nothing else sets fs → allow
    assert_eq!(set.effective_defaults("claude-code", "/p").filesystem, Effect::Allow);
    // network and process unset anywhere → fallback
    assert_eq!(set.effective_defaults("claude-code", "/p").network, Effect::Deny);
    assert_eq!(set.effective_defaults("claude-code", "/p").process, Effect::Allow);
    let two = load(vec![
        user("version: v1\ndefaults:\n  filesystem: allow\n"),
        agentacl_policy::set::PolicySource { layer: Layer::User, name: "user2".into(), yaml: "version: v1\ndefaults:\n  filesystem: ask\n".into() },
    ]);
    assert_eq!(two.effective_defaults("claude-code", "/p").filesystem, Effect::Ask);
}

#[test]
fn project_defaults_only_tighten_and_trust() {
    let loose = "version: v1\ndefaults:\n  filesystem: allow\n";
    let e = try_load(vec![project(loose)], LoadOptions::default()).unwrap_err();
    assert_eq!(e, PolicyError::ProjectForbidden { doc: "project".into(), key: "defaults.filesystem".into() });
    let opts = LoadOptions { trusted_project_sha256: vec![sha256_hex(loose.as_bytes())], ..Default::default() };
    let set = try_load(vec![project(loose)], opts).unwrap();
    assert!(set.docs.iter().any(|d| d.name == "project" && d.layer == Layer::User));
    // a trusted file that changes is no longer trusted
    let changed = "version: v1\ndefaults:\n  filesystem: allow\n# edit\n";
    let opts = LoadOptions { trusted_project_sha256: vec![sha256_hex(loose.as_bytes())], ..Default::default() };
    assert!(try_load(vec![project(changed)], opts).is_err());
    // tightening is fine
    load(vec![project("version: v1\ndefaults:\n  process: deny\n")]);
}

#[test]
fn sha_is_stable_and_sensitive() {
    let a = load(vec![user("version: v1\nfilesystem:\n  allow_read: [\"/a/**\"]\n")]);
    let b = load(vec![user("version: v1\nfilesystem:\n  allow_read: [\"/a/**\"]\n")]);
    let c = load(vec![user("version: v1\nfilesystem:\n  allow_read: [\"/b/**\"]\n")]);
    assert_eq!(a.sha256, b.sha256);
    assert_ne!(a.sha256, c.sha256);
}

#[test]
fn generated_docs_are_builtin_layer() {
    let g = GeneratedDoc {
        name: "provider:claude-code".into(),
        allow_write: vec!["${HOME}/.claude/**".into()],
        deny_write: vec!["${HOME}/.claude/settings.json".into()],
        net_allow: vec!["api.anthropic.com".into()],
        reason: "Claude Code runtime requirement".into(),
        ..Default::default()
    };
    let set = try_load(vec![], LoadOptions { generated: vec![g], ..Default::default() }).unwrap();
    let d = set.docs.iter().find(|d| d.name == "provider:claude-code").unwrap();
    assert_eq!(d.layer, Layer::Builtin);
    assert_eq!(d.rules.len(), 4); // read+write for the write path, deny_write, net allow
}

#[test]
fn listen_must_be_loopback() {
    assert!(try_load(vec![user("version: v1\nnetwork:\n  listen: [\"0.0.0.0:3000\"]\n")], LoadOptions::default()).is_err());
    load(vec![user("version: v1\nnetwork:\n  listen: [\"localhost:3000\"]\n")]);
}

#[test]
fn relative_except_rejected() {
    let y = "version: v1\nfilesystem:\n  deny_read:\n    - path: \"/p/**/.env.*\"\n      except: [\".env.example\"]\n";
    assert!(try_load(vec![user(y)], LoadOptions::default()).is_err());
}

#[test]
fn rule_id_default_is_reserved() {
    let y = "version: v1\nnetwork:\n  deny:\n    - { host: \"x.example.com\", id: default }\n";
    assert!(try_load(vec![user(y)], LoadOptions::default()).is_err());
}
