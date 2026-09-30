//! Canonical YAML emitter for policy documents (used by the local UI).
//! `parse_doc(to_yaml(d)) == d`. Strings are always double-quoted with JSON
//! escaping, which is valid YAML, so no value can change the document shape.

use crate::raw::{RawDoc, RawRule, RuleKind};

fn q(s: &str) -> String {
    serde_json::to_string(s).expect("string serializes")
}

fn rule(out: &mut String, r: &RawRule) {
    if r.except.is_empty() && r.id.is_none() && r.reason.is_none() {
        out.push_str(&format!("    - {}\n", q(&r.pattern)));
        return;
    }
    let key = match r.kind {
        RuleKind::Path => "path",
        RuleKind::Command => "command",
        RuleKind::Host => "host",
    };
    out.push_str(&format!("    - {key}: {}\n", q(&r.pattern)));
    if !r.except.is_empty() {
        out.push_str(&format!("      except: [{}]\n", r.except.iter().map(|e| q(e)).collect::<Vec<_>>().join(", ")));
    }
    if let Some(id) = &r.id {
        out.push_str(&format!("      id: {}\n", q(id)));
    }
    if let Some(reason) = &r.reason {
        out.push_str(&format!("      reason: {}\n", q(reason)));
    }
}

fn section(out: &mut String, name: &str, lists: &[(&str, &[RawRule])]) {
    if lists.iter().all(|(_, l)| l.is_empty()) {
        return;
    }
    out.push_str(&format!("{name}:\n"));
    for (k, l) in lists {
        if l.is_empty() {
            continue;
        }
        out.push_str(&format!("  {k}:\n"));
        for r in *l {
            rule(out, r);
        }
    }
}

pub fn to_yaml(d: &RawDoc) -> String {
    let mut out = String::from("version: v1\n");
    out.push_str(&format!("name: {}\n", q(&d.name)));
    if let Some(m) = &d.match_ {
        if !m.agents.is_empty() || !m.projects.is_empty() {
            out.push_str("match:\n");
            if !m.agents.is_empty() {
                out.push_str(&format!("  agents: [{}]\n", m.agents.iter().map(|a| q(a)).collect::<Vec<_>>().join(", ")));
            }
            if !m.projects.is_empty() {
                out.push_str(&format!("  projects: [{}]\n", m.projects.iter().map(|a| q(a)).collect::<Vec<_>>().join(", ")));
            }
        }
    }
    let df = &d.defaults;
    if df.filesystem.is_some() || df.network.is_some() || df.process.is_some() {
        out.push_str("defaults:\n");
        for (k, v) in [("filesystem", df.filesystem), ("network", df.network), ("process", df.process)] {
            if let Some(v) = v {
                out.push_str(&format!("  {k}: {}\n", v.as_str()));
            }
        }
    }
    let f = &d.filesystem;
    section(&mut out, "filesystem", &[("allow_read", &f.allow_read), ("allow_write", &f.allow_write), ("deny_read", &f.deny_read), ("deny_write", &f.deny_write)]);
    let p = &d.process;
    section(&mut out, "process", &[("allow", &p.allow), ("deny", &p.deny), ("require_approval", &p.require_approval)]);
    let n = &d.network;
    section(&mut out, "network", &[("allow", &n.allow), ("deny", &n.deny), ("listen", &n.listen)]);
    if let Some(b) = &d.builtin {
        if !b.disable.is_empty() {
            out.push_str(&format!("builtin:\n  disable: [{}]\n", b.disable.iter().map(|x| q(x)).collect::<Vec<_>>().join(", ")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raw::parse_doc;
    use crate::Layer;

    fn roundtrip(yaml: &str, layer: Layer) {
        let d = parse_doc(yaml, layer, "t").unwrap();
        let y2 = to_yaml(&d);
        let d2 = parse_doc(&y2, layer, "t").unwrap();
        assert_eq!(d, d2, "{y2}");
        assert_eq!(to_yaml(&d2), y2, "emitter is not stable");
    }

    #[test]
    fn roundtrips_builtins_and_examples() {
        for (_, y) in crate::set::builtin_sources(true).iter().map(|s| (s.name.clone(), s.yaml.clone())) {
            roundtrip(&y, Layer::Builtin);
        }
        roundtrip(
            "version: v1\nname: x\nmatch:\n  agents: [\"custom:*\"]\ndefaults: {filesystem: deny, process: ask}\nfilesystem:\n  deny_read:\n    - path: \"${PROJECT}/**/.env.*\"\n      except: [\"**/.env.example\"]\n      id: env\n      reason: \"it's \\\"secret\\\"\\n\"\nprocess:\n  require_approval: [\"git push *\"]\nnetwork:\n  allow: [\"a.com:443\"]\n  listen: [\"localhost:3000\"]\nbuiltin:\n  disable: [keys]\n",
            Layer::User,
        );
    }

    #[test]
    fn hostile_strings_cannot_change_shape() {
        let y = "version: v1\nfilesystem:\n  allow_read: [\"/a\\nfilesystem:\\n  allow_read: [/]\"]\n";
        let d = parse_doc(y, Layer::User, "t").unwrap();
        let out = to_yaml(&d);
        let d2 = parse_doc(&out, Layer::User, "t").unwrap();
        assert_eq!(d2.filesystem.allow_read.len(), 1);
        assert_eq!(d, d2);
    }
}
