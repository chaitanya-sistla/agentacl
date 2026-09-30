//! Property tests for the evaluator's core invariants (threat-model §5.2).
mod common;
use agentacl_policy::set::PolicySource;
use agentacl_policy::{Action, Effect, Layer, PolicyEngine, Request, Resource, Subject, WriteOp};
use common::*;
use proptest::prelude::*;

const PATTERNS: &[&str] = &["/a/**", "/a/b", "/**/.env", "/a/*", "/a/b/**", "/c/**", "/**/x*", "/p/**"];
const PATHS: &[&str] = &["/a", "/a/b", "/a/b/.env", "/a/x1", "/c/d", "/p/.env", "/p/q", "/a/b/c"];
const SECTIONS: &[&str] = &["allow_read", "allow_write", "deny_read", "deny_write"];

#[derive(Debug, Clone)]
struct R {
    section: usize,
    pattern: usize,
}

fn rule() -> impl Strategy<Value = R> {
    (0..SECTIONS.len(), 0..PATTERNS.len()).prop_map(|(section, pattern)| R { section, pattern })
}

fn doc(name: &str, rules: &[R], default: Option<&str>) -> PolicySource {
    let mut y = String::from("version: v1\n");
    if let Some(d) = default {
        y.push_str(&format!("defaults: {{filesystem: {d}}}\n"));
    }
    y.push_str("filesystem:\n");
    for (i, s) in SECTIONS.iter().enumerate() {
        let items: Vec<String> = rules.iter().filter(|r| r.section == i).map(|r| format!("\"{}\"", PATTERNS[r.pattern])).collect();
        y.push_str(&format!("  {s}: [{}]\n", items.join(", ")));
    }
    PolicySource { layer: Layer::User, name: name.into(), yaml: y }
}

fn eval(docs: Vec<PolicySource>, action: Action, path: &str) -> agentacl_policy::Decision {
    let set = load(docs);
    let subject = Subject { agent_id: "claude-code".into(), project: "/p".into(), ..Default::default() };
    set.evaluate(&Request { subject, action, resource: Resource::Path(path.into()) })
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![Just(Action::FsRead), Just(Action::FsWrite(WriteOp::Write)), Just(Action::FsWrite(WriteOp::Rename)), Just(Action::FsWrite(WriteOp::Unlink)),]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn allow_never_flips_explicit_deny(
        base in prop::collection::vec(rule(), 0..6),
        extra in prop::collection::vec(rule(), 1..4),
        default in prop::option::of(prop_oneof![Just("allow"), Just("deny"), Just("ask")]),
        path in 0..PATHS.len(),
        act in action(),
    ) {
        let before = eval(vec![doc("u", &base, default)], act, PATHS[path]);
        prop_assume!(before.effect == Effect::Deny && before.rule_id != "default");
        let allows: Vec<R> = extra.into_iter().map(|r| R { section: r.section % 2, ..r }).collect();
        let mut more = base.clone();
        more.extend(allows.iter().cloned());
        let after = eval(vec![doc("u", &more, default), doc("u2", &allows, None)], act, PATHS[path]);
        prop_assert_eq!(after.effect, Effect::Deny);
    }

    #[test]
    fn deny_never_produces_allow(
        base in prop::collection::vec(rule(), 0..6),
        extra in prop::collection::vec(rule(), 1..4),
        default in prop::option::of(prop_oneof![Just("allow"), Just("deny"), Just("ask")]),
        path in 0..PATHS.len(),
        act in action(),
    ) {
        let before = eval(vec![doc("u", &base, default)], act, PATHS[path]);
        let denies: Vec<R> = extra.into_iter().map(|r| R { section: 2 + r.section % 2, ..r }).collect();
        let mut more = base.clone();
        more.extend(denies);
        let after = eval(vec![doc("u", &more, default)], act, PATHS[path]);
        if after.effect == Effect::Allow {
            prop_assert_eq!(before.effect, Effect::Allow);
        }
    }

    #[test]
    fn evaluation_is_deterministic(
        base in prop::collection::vec(rule(), 0..6),
        path in 0..PATHS.len(),
        act in action(),
    ) {
        let a = eval(vec![doc("u", &base, None)], act, PATHS[path]);
        let b = eval(vec![doc("u", &base, None)], act, PATHS[path]);
        prop_assert_eq!(a, b);
    }
}
