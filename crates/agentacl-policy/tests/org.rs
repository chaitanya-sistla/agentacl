//! Company rules (the `org` layer, docs/design/fleet.md): explicit denies
//! that nothing on the Mac can lift.
mod common;
use agentacl_policy::set::{sha256_hex, GeneratedDoc, LoadOptions, PolicySet, PolicySource};
use agentacl_policy::{Action, Effect, Layer, PolicyEngine, PolicyError, Request, Resource, Subject, WriteOp};
use common::*;

fn org(yaml: &str) -> PolicySource {
    PolicySource { layer: Layer::Org, name: "managed/policy.yaml".into(), yaml: yaml.into() }
}

const ORG: &str = "version: v1
name: anything
filesystem:
  deny_read: [\"/u/company/**\"]
  deny_write: [\"/p/infra/**\"]
process:
  deny: [\"terraform apply *\"]
network:
  deny: [\"*.pastebin.com\"]
";

fn ev(set: &PolicySet, agent: &str, project: &str, action: Action, resource: Resource) -> Effect {
    let subject = Subject { agent_id: agent.into(), project: project.into(), ..Default::default() };
    set.evaluate(&Request { subject, action, resource }).effect
}

fn read(set: &PolicySet, p: &str) -> Effect {
    ev(set, "claude-code", "/p", Action::FsRead, Resource::Path(p.into()))
}

#[test]
fn company_rules_may_only_forbid() {
    for (yaml, key) in [
        ("filesystem:\n  allow_read: [\"/x/**\"]\n", "filesystem.allow_read"),
        ("filesystem:\n  allow_write: [\"/x/**\"]\n", "filesystem.allow_write"),
        ("process:\n  allow: [\"git *\"]\n", "process.allow"),
        ("process:\n  require_approval: [\"git push *\"]\n", "process.require_approval"),
        ("network:\n  allow: [\"example.com\"]\n", "network.allow"),
        ("network:\n  listen: [\"127.0.0.1:8080\"]\n", "network.listen"),
        ("builtin:\n  disable: [keys]\n", "builtin"),
        ("match:\n  agents: [codex]\n", "match"),
        ("defaults:\n  network: allow\n", "defaults"),
        ("defaults:\n  filesystem: deny\n", "defaults"),
        ("filesystem:\n  deny_write: [\"${PROJECT}/infra/**\"]\n", "${PROJECT}"),
        ("filesystem:\n  deny_read: [{path: \"/x/**\", except: [\"${TMPDIR}/**\"]}]\n", "${TMPDIR}"),
    ] {
        let e = try_load(vec![org(&format!("version: v1\n{yaml}"))], LoadOptions::default()).unwrap_err();
        assert_eq!(e, PolicyError::OrgForbidden { doc: "managed/policy.yaml".into(), key: key.into() }, "{yaml}");
    }
    // Explicit denies, and an empty document, load.
    load(vec![org(ORG)]);
    load(vec![org("version: v1\n")]);
}

#[test]
fn nothing_on_the_mac_lifts_a_company_deny() {
    let user_allow = user("version: v1\nfilesystem:\n  allow_read: [\"/u/**\"]\n  allow_write: [\"/p/**\"]\nprocess:\n  allow: [\"terraform *\"]\nnetwork:\n  allow: [\"*.pastebin.com\"]\n");
    let project_doc = "version: v1\nfilesystem:\n  allow_read: [\"/u/company/**\"]\n";
    let trusted = LoadOptions {
        trusted_project_sha256: vec![sha256_hex(project_doc.as_bytes())],
        generated: vec![GeneratedDoc { name: "session".into(), allow_read: vec!["/u/company/**".into()], allow_write: vec!["/p/infra/**".into()], ..Default::default() }],
    };
    let set = try_load(vec![org(ORG), user_allow, project(project_doc)], trusted).unwrap();
    assert_eq!(read(&set, "/u/company/plan.md"), Effect::Deny, "user, trusted project and session allows");
    assert_eq!(ev(&set, "claude-code", "/p", Action::FsWrite(WriteOp::Write), Resource::Path("/p/infra/main.tf".into())), Effect::Deny);
    assert_eq!(ev(&set, "claude-code", "/p", Action::FsWrite(WriteOp::Write), Resource::Path("/p/src/main.rs".into())), Effect::Allow, "the rest of the project");
    let tf = |argv: &[&str]| ev(&set, "claude-code", "/p", Action::Exec, Resource::Exec { exe: "/opt/homebrew/bin/terraform".into(), argv: argv.iter().map(|s| s.to_string()).collect() });
    assert_eq!(tf(&["terraform", "apply", "-auto-approve"]), Effect::Deny);
    assert_eq!(tf(&["terraform", "plan"]), Effect::Allow);
    assert_eq!(ev(&set, "claude-code", "/p", Action::NetConnect, Resource::Host { host: "x.pastebin.com".into(), port: 443 }), Effect::Deny);
    // Every agent and project: the user picks both (--agent, --project).
    assert_eq!(ev(&set, "my-own-agent", "/elsewhere", Action::FsRead, Resource::Path("/u/company/plan.md".into())), Effect::Deny);
    let d = set.evaluate(&Request {
        subject: Subject { agent_id: "claude-code".into(), project: "/p".into(), ..Default::default() },
        action: Action::FsRead,
        resource: Resource::Path("/u/company/plan.md".into()),
    });
    assert_eq!(d.policy, "org", "named org whatever the file says");
}

#[test]
fn built_in_protections_cant_be_disabled_under_company_rules() {
    let disable = user("version: v1\nbuiltin:\n  disable: [keys, ssh]\nfilesystem:\n  allow_read: [\"/u/**\"]\n");
    let without = load(vec![disable.clone()]);
    assert_eq!(read(&without, "/u/.ssh/id_ed25519"), Effect::Allow, "disabled without company rules");
    let with = load(vec![org("version: v1\n"), disable]);
    assert_eq!(read(&with, "/u/.ssh/id_ed25519"), Effect::Deny, "kept with company rules");
    assert!(with.disabled_groups("claude-code", "/p").is_empty());
}
