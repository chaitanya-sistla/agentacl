mod common;
use agentacl_policy::set::PolicySet;
use agentacl_policy::{Action, Decision, Effect, PolicyEngine, Request, Resource, Subject, WriteOp};
use common::*;

fn subj() -> Subject {
    Subject { agent_id: "claude-code".into(), project: "/p".into(), ..Default::default() }
}

fn ev(set: &PolicySet, action: Action, resource: Resource) -> Decision {
    set.evaluate(&Request { subject: subj(), action, resource })
}
fn read(set: &PolicySet, p: &str) -> Decision {
    ev(set, Action::FsRead, Resource::Path(p.into()))
}
fn write(set: &PolicySet, op: WriteOp, p: &str) -> Decision {
    ev(set, Action::FsWrite(op), Resource::Path(p.into()))
}
fn exec(set: &PolicySet, exe: &str, argv: &[&str]) -> Decision {
    ev(set, Action::Exec, Resource::Exec { exe: exe.into(), argv: argv.iter().map(|s| s.to_string()).collect() })
}
fn host(set: &PolicySet, h: &str, port: u16) -> Decision {
    ev(set, Action::NetConnect, Resource::Host { host: h.into(), port })
}
fn is(d: &Decision, effect: Effect, rule: &str) {
    assert_eq!((d.effect, d.rule_id.as_str()), (effect, rule), "{d:?}");
}

#[test]
fn filesystem_reads() {
    let s = load(vec![]);
    is(&read(&s, "/p/src/main.rs"), Effect::Allow, "default/filesystem.allow_read/0");
    is(&read(&s, "/p/.env"), Effect::Deny, "env-files");
    is(&read(&s, "/p/sub/.ENV"), Effect::Deny, "env-files");
    is(&read(&s, "/p/.env.example"), Effect::Allow, "default/filesystem.allow_read/0");
    is(&read(&s, "/p/.env.production"), Effect::Deny, "env-files");
    is(&read(&s, "/u/.ssh/id_ed25519"), Effect::Deny, "ssh");
    is(&read(&s, "/u/Documents/x"), Effect::Deny, "default");
    is(&read(&s, "/usr/lib/libSystem.B.dylib"), Effect::Allow, "runtime/filesystem.allow_read/1");
    let d = read(&s, "/p/.env");
    assert_eq!(d.policy, "protect-secrets");
    assert_eq!(d.reason, "Environment secret files are protected");
}

#[test]
fn filesystem_writes_and_git() {
    let s = load(vec![]);
    is(&write(&s, WriteOp::Write, "/p/a.txt"), Effect::Allow, "default/filesystem.allow_write/0");
    is(&write(&s, WriteOp::Write, "/p/.git/config"), Effect::Deny, "exec-persistence");
    is(&write(&s, WriteOp::Create, "/p/.git/commondir"), Effect::Deny, "exec-persistence");
    is(&write(&s, WriteOp::Write, "/p/.git/hooks/pre-commit"), Effect::Deny, "exec-persistence");
    is(&write(&s, WriteOp::Rename, "/p/.git"), Effect::Deny, "exec-persistence");
    is(&write(&s, WriteOp::Create, "/p/sub/.git"), Effect::Deny, "exec-persistence");
    is(&write(&s, WriteOp::Write, "/p/.git/objects/ab/cd"), Effect::Allow, "default/filesystem.allow_write/0");
    is(&write(&s, WriteOp::Create, "/p/.git/index.lock"), Effect::Allow, "default/filesystem.allow_write/0");
    is(&write(&s, WriteOp::Write, "/p/.git/refs/heads/main"), Effect::Allow, "default/filesystem.allow_write/0");
    is(&write(&s, WriteOp::Write, "/p/.mcp.json"), Effect::Deny, "exec-persistence");
    is(&write(&s, WriteOp::Write, "/p/.agentacl/policy.yaml"), Effect::Deny, "agentacl-self");
    is(&write(&s, WriteOp::Write, "/u/.config/agentacl/policy.yaml"), Effect::Deny, "agentacl-self");
}

#[test]
fn implied_location_protection() {
    let s = load(vec![]);
    is(&write(&s, WriteOp::Rename, "/u/.aws"), Effect::Deny, "aws");
    is(&write(&s, WriteOp::Rename, "/p/.env.production"), Effect::Deny, "env-files");
    // plain write to the ancestor dir is only default-denied (outside project)
    is(&write(&s, WriteOp::Write, "/u/.aws"), Effect::Deny, "default");
    // user doc with deny_read only, home writable
    let u = load(vec![user("version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_write: [\"${HOME}/**\"]\n  deny_read: [\"${HOME}/secret/inner/**\"]\n")]);
    is(&write(&u, WriteOp::Rename, "/u/secret/inner/a"), Effect::Deny, "user/filesystem.deny_read/0");
    is(&write(&u, WriteOp::Rename, "/u/secret"), Effect::Deny, "user/filesystem.deny_read/0");
    is(&write(&u, WriteOp::Link, "/u/secret/inner/a"), Effect::Deny, "user/filesystem.deny_read/0");
    is(&write(&u, WriteOp::Write, "/u/secret/inner/a"), Effect::Allow, "user/filesystem.allow_write/0");
    is(&write(&u, WriteOp::Rename, "/u/other"), Effect::Allow, "user/filesystem.allow_write/0");
}

#[test]
fn move_out_and_back_is_denied() {
    use agentacl_policy::set::{GeneratedDoc, LoadOptions};
    let g = GeneratedDoc {
        name: "provider:claude-code".into(),
        allow_write: vec!["${HOME}/.claude/**".into()],
        deny_write: vec!["${HOME}/.claude/settings.json".into()],
        reason: "r".into(),
        ..Default::default()
    };
    let s = try_load(vec![], LoadOptions { generated: vec![g], ..Default::default() }).unwrap();
    // the directory holding a write-denied file cannot be moved away
    assert_eq!(write(&s, WriteOp::Rename, "/u/.claude").effect, Effect::Deny);
    // the project itself and the config dir's parent cannot be moved
    assert_eq!(write(&s, WriteOp::Rename, "/p").effect, Effect::Deny);
    assert_eq!(write(&s, WriteOp::Rename, "/u/.config").effect, Effect::Deny);
    assert_eq!(write(&s, WriteOp::Unlink, "/u").effect, Effect::Deny);
    // ordinary files in the project remain renamable
    assert_eq!(write(&s, WriteOp::Rename, "/p/src").effect, Effect::Allow);
}

#[test]
fn explicit_deny_shadows_allow() {
    let s = load(vec![user("version: v1\ndefaults: {filesystem: deny}\nfilesystem:\n  allow_write: [\"${PROJECT}/**\"]\n  deny_write: [\"${HOME}/**\"]\n")]);
    // project /p is not under /u here, so use a project-under-home subject
    let sub = Subject { agent_id: "claude-code".into(), project: "/u/src/p".into(), ..Default::default() };
    let d = s.evaluate(&Request { subject: sub, action: Action::FsWrite(WriteOp::Write), resource: Resource::Path("/u/src/p/x".into()) });
    assert_eq!(d.effect, Effect::Deny);
}

#[test]
fn process_rules() {
    let s = load(vec![user("version: v1\nprocess:\n  deny: [\"sudo *\"]\n  require_approval: [\"git push *\"]\n")]);
    is(&exec(&s, "/usr/bin/sudo", &["sudo"]), Effect::Deny, "user/process.deny/0");
    is(&exec(&s, "/usr/bin/git", &["git", "push", "origin"]), Effect::Ask, "user/process.require_approval/0");
    is(&exec(&s, "/usr/bin/git", &["git", "status"]), Effect::Allow, "default");
}

#[test]
fn network_two_phase() {
    let s = load(vec![user("version: v1\ndefaults: {network: deny}\nnetwork:\n  allow: [\"api.anthropic.com\", \"*.corp.com\", \"localhost:3000\"]\n")]);
    is(&host(&s, "api.anthropic.com", 443), Effect::Allow, "user/network.allow/0");
    is(&host(&s, "evil.com", 443), Effect::Deny, "default");
    // phase 2: host allow never re-allows reserved ranges
    let sj = subj();
    is(&s.evaluate_address(&sj, "169.254.169.254".parse().unwrap(), 443), Effect::Deny, "reserved-range:link-local");
    is(&s.evaluate_address(&sj, "10.0.0.5".parse().unwrap(), 443), Effect::Deny, "reserved-range:rfc1918");
    is(&s.evaluate_address(&sj, "140.82.112.3".parse().unwrap(), 443), Effect::Allow, "resolved-address");
    is(&s.evaluate_address(&sj, "127.0.0.1".parse().unwrap(), 3000), Effect::Allow, "user/network.allow/2");
    is(&s.evaluate_address(&sj, "127.0.0.1".parse().unwrap(), 3001), Effect::Deny, "reserved-range:loopback");
    // IP literal targets go through phase 1 (default) first
    is(&host(&s, "8.8.8.8", 443), Effect::Deny, "default");
    is(&host(&s, "127.0.0.1", 3000), Effect::Allow, "user/network.allow/2");
    is(&host(&s, "localhost", 3000), Effect::Allow, "user/network.allow/2");
    is(&host(&s, "LOCALHOST", 3001), Effect::Deny, "default");
    let m = load(vec![user("version: v1\nnetwork:\n  allow: [\"169.254.169.254\", \"8.8.8.8\"]\n")]);
    is(&m.evaluate_address(&sj, "169.254.169.254".parse().unwrap(), 80), Effect::Allow, "user/network.allow/0");
    is(&host(&m, "8.8.8.8", 443), Effect::Allow, "user/network.allow/1");
    // defaults allow still keeps reserved ranges closed
    let open = load(vec![user("version: v1\ndefaults: {network: allow}\n")]);
    is(&host(&open, "example.com", 443), Effect::Allow, "default");
    is(&open.evaluate_address(&sj, "169.254.169.254".parse().unwrap(), 80), Effect::Deny, "reserved-range:link-local");
    is(&host(&open, "127.0.0.1", 22), Effect::Deny, "reserved-range:loopback");
}

#[test]
fn listen_defaults_to_deny() {
    let s = load(vec![user("version: v1\nnetwork:\n  listen: [\"localhost:3000\"]\n")]);
    let l = |ip: &str, port| s.evaluate(&Request { subject: subj(), action: Action::NetListen, resource: Resource::Addr { ip: ip.parse().unwrap(), port } });
    assert_eq!(l("127.0.0.1", 3000).effect, Effect::Allow);
    assert_eq!(l("127.0.0.1", 3001).effect, Effect::Deny);
    assert_eq!(l("0.0.0.0", 3000).effect, Effect::Deny);
}

#[test]
fn provider_generated_doc_participates() {
    use agentacl_policy::set::{GeneratedDoc, LoadOptions};
    let g = GeneratedDoc {
        name: "provider:claude-code".into(),
        allow_write: vec!["${HOME}/.claude/**".into()],
        deny_write: vec!["${HOME}/.claude/settings.json".into()],
        reason: "Claude Code runtime requirement".into(),
        ..Default::default()
    };
    let s = try_load(vec![], LoadOptions { generated: vec![g], ..Default::default() }).unwrap();
    let d = write(&s, WriteOp::Write, "/u/.claude/projects/x");
    assert_eq!((d.effect, d.policy.as_str()), (Effect::Allow, "provider:claude-code"));
    assert_eq!(write(&s, WriteOp::Write, "/u/.claude/settings.json").effect, Effect::Deny);
}

#[test]
fn deterministic() {
    let s = load(vec![]);
    assert_eq!(read(&s, "/p/.env"), read(&s, "/p/.env"));
}
