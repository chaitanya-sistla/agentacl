//! Deterministic evaluation (policy-model §4, §4.2).

use crate::model::{Action, Category, Decision, Effect, PolicyEngine, Request, Resource, Subject, WriteOp};
use crate::netpat::{reserved_range, NetPattern};
use crate::pathpat::PathPattern;
use crate::set::{Matcher, PolicySet, Rule, Section};
use std::net::IpAddr;

fn from_rule(r: &Rule, trace: Vec<String>) -> Decision {
    Decision { effect: r.effect, policy: r.policy.clone(), rule_id: r.id.clone(), reason: r.reason.clone(), trace }
}

/// deny > ask > allow; first match in load order within an effect.
fn decide<'a>(matched: &[&'a Rule]) -> Option<&'a Rule> {
    [Effect::Deny, Effect::Ask, Effect::Allow]
        .into_iter()
        .find_map(|e| matched.iter().copied().find(|r| r.effect == e))
}

fn is_protected_ancestor(p: &PathPattern, path: &str) -> bool {
    p.protected_ancestors().iter().any(|a| a.eq_ignore_ascii_case(path))
}

impl PolicySet {
    fn default_decision(&self, subj: &Subject, cat: Category, trace: Vec<String>) -> Decision {
        let docs = self.applicable(&subj.agent_id, &subj.project);
        let pick = |f: fn(&crate::raw::RawDefaults) -> Option<Effect>| {
            docs.iter()
                .filter_map(|d| f(&d.defaults).map(|e| (e, d.name.clone())))
                .max_by_key(|(e, _)| e.restrictiveness())
        };
        let (effect, policy) = match cat {
            Category::Filesystem => pick(|d| d.filesystem),
            Category::Network => pick(|d| d.network),
            Category::Process => pick(|d| d.process),
        }
        .unwrap_or_else(|| {
            let f = crate::set::FALLBACK_DEFAULTS;
            let e = match cat {
                Category::Filesystem => f.filesystem,
                Category::Network => f.network,
                Category::Process => f.process,
            };
            (e, "fallback".to_string())
        });
        let cat_name = match cat {
            Category::Filesystem => "filesystem",
            Category::Network => "network",
            Category::Process => "process",
        };
        let reason = match effect {
            Effect::Allow => format!("No rule matched; the {cat_name} default is allow"),
            Effect::Deny => format!("No rule allows this; the {cat_name} default is deny"),
            Effect::Ask => format!("No rule matched; the {cat_name} default requires approval"),
        };
        Decision { effect, policy, rule_id: "default".into(), reason, trace }
    }

    fn finish(&self, subj: &Subject, cat: Category, matched: Vec<&Rule>) -> Decision {
        let trace: Vec<String> = matched.iter().map(|r| format!("{} {} ({})", r.effect.as_str(), r.id, r.policy)).collect();
        match decide(&matched) {
            Some(r) => from_rule(r, trace),
            None => self.default_decision(subj, cat, trace),
        }
    }

    fn eval_path(&self, subj: &Subject, action: Action, path: &str) -> Decision {
        let rules = self.rules_for(&subj.agent_id, &subj.project);
        let implied = matches!(action, Action::FsWrite(WriteOp::Unlink | WriteOp::Rename | WriteOp::Link));
        let section = if action == Action::FsRead { Section::FsRead } else { Section::FsWrite };
        let matched: Vec<&Rule> = rules
            .into_iter()
            .filter(|r| {
                if r.section == section && r.matches_path(path) {
                    return true;
                }
                // A deny (read or write) also protects the location of what it
                // protects: no unlink/rename/link of the path or its ancestors
                // (policy-model §4).
                implied
                    && r.effect == Effect::Deny
                    && matches!(r.section, Section::FsRead | Section::FsWrite)
                    && match &r.matcher {
                        Matcher::Path(p) => r.matches_path(path) || is_protected_ancestor(p, path),
                        _ => false,
                    }
            })
            .collect();
        self.finish(subj, Category::Filesystem, matched)
    }

    fn net_rules(&self, subj: &Subject, section: Section) -> Vec<&Rule> {
        self.rules_for(&subj.agent_id, &subj.project).into_iter().filter(|r| r.section == section).collect()
    }

    fn eval_host(&self, subj: &Subject, host: &str, port: u16) -> Decision {
        // The hostname `localhost` is the loopback address: `localhost[:port]`
        // entries (address patterns) must apply to it.
        let literal = if host.eq_ignore_ascii_case("localhost") {
            Ok(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
        } else {
            host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>()
        };
        if let Ok(ip) = literal {
            // IP literal: phase 1 on address patterns + default, then the reserved-range phase.
            let matched: Vec<&Rule> = self
                .net_rules(subj, Section::Net)
                .into_iter()
                .filter(|r| matches!(&r.matcher, Matcher::Net(n) if n.matches_addr(ip, port)))
                .collect();
            let d = self.finish(subj, Category::Network, matched);
            if d.effect != Effect::Allow {
                return d;
            }
            let d2 = self.evaluate_address(subj, ip, port);
            return if d2.effect == Effect::Allow { d } else { d2 };
        }
        let matched: Vec<&Rule> = self
            .net_rules(subj, Section::Net)
            .into_iter()
            .filter(|r| matches!(&r.matcher, Matcher::Net(n) if n.matches_host(host, port)))
            .collect();
        self.finish(subj, Category::Network, matched)
    }

    /// Network phase 2 (policy-model §4.2): run on every resolved address of a
    /// host that phase 1 allowed.
    pub fn evaluate_address(&self, subj: &Subject, ip: IpAddr, port: u16) -> Decision {
        let rules: Vec<&Rule> = self
            .net_rules(subj, Section::Net)
            .into_iter()
            .filter(|r| matches!(&r.matcher, Matcher::Net(n) if n.is_addr() && n.matches_addr(ip, port)))
            .collect();
        let trace: Vec<String> = rules.iter().map(|r| format!("{} {} ({})", r.effect.as_str(), r.id, r.policy)).collect();
        if let Some(r) = rules.iter().find(|r| r.effect == Effect::Deny) {
            return from_rule(r, trace);
        }
        let addr_allow = rules.iter().find(|r| r.effect == Effect::Allow);
        if let Some(kind) = reserved_range(ip) {
            if addr_allow.is_none() {
                return Decision {
                    effect: Effect::Deny,
                    policy: "builtin".into(),
                    rule_id: format!("reserved-range:{kind}"),
                    reason: format!("{ip} is in a reserved {kind} range; only an allow naming this address can permit it"),
                    trace,
                };
            }
        }
        match addr_allow {
            Some(r) => from_rule(r, trace),
            None => Decision {
                effect: Effect::Allow,
                policy: "network".into(),
                rule_id: "resolved-address".into(),
                reason: "Host allowed; resolved address is not restricted".into(),
                trace,
            },
        }
    }

    fn eval_listen(&self, subj: &Subject, ip: Option<IpAddr>, port: u16) -> Decision {
        let r = self.net_rules(subj, Section::Listen).into_iter().find(|r| match (&r.matcher, ip) {
            (Matcher::Net(n @ NetPattern::Addr { .. }), Some(ip)) => n.matches_addr(ip, port),
            (Matcher::Net(n), None) => n.port().is_none_or(|p| p == port),
            _ => false,
        });
        match r {
            Some(r) => from_rule(r, vec![]),
            None => Decision {
                effect: Effect::Deny,
                policy: "builtin".into(),
                rule_id: "listen".into(),
                reason: "Listening is denied unless network.listen names the loopback port".into(),
                trace: vec![],
            },
        }
    }
}

impl PolicyEngine for PolicySet {
    fn evaluate(&self, req: &Request) -> Decision {
        let subj = &req.subject;
        match (&req.action, &req.resource) {
            (Action::FsRead | Action::FsWrite(_), Resource::Path(p)) => {
                self.eval_path(subj, req.action, &crate::expand::canonical_prefix_map(p))
            }
            (Action::Exec, Resource::Exec { exe, argv }) => {
                let matched: Vec<&Rule> = self
                    .rules_for(&subj.agent_id, &subj.project)
                    .into_iter()
                    .filter(|r| r.section == Section::Exec && matches!(&r.matcher, Matcher::Cmd(c) if c.matches(exe, argv)))
                    .collect();
                self.finish(subj, Category::Process, matched)
            }
            (Action::NetConnect, Resource::Host { host, port }) => self.eval_host(subj, host, *port),
            (Action::NetConnect, Resource::Addr { ip, port }) => self.evaluate_address(subj, *ip, *port),
            (Action::NetListen, Resource::Addr { ip, port }) => self.eval_listen(subj, Some(*ip), *port),
            (Action::NetListen, Resource::Host { port, .. }) => self.eval_listen(subj, None, *port),
            (action, resource) => Decision {
                effect: Effect::Deny,
                policy: "builtin".into(),
                rule_id: "malformed-request".into(),
                reason: format!("action {action:?} does not apply to resource {resource:?}"),
                trace: vec![],
            },
        }
    }
}
