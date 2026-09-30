//! The supervised agent's descendant tree, built by polling (architecture §4.1).
//! Observational: short-lived processes can be missed. Enforcement never
//! depends on it.

use super::ProcessFacts;
use std::collections::HashMap;

pub type Key = (i32, u64);

#[derive(Debug, Clone)]
pub struct Node {
    pub facts: ProcessFacts,
    pub parent: Option<Key>,
    pub exited: bool,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeChange {
    New(ProcessFacts),
    /// Same (pid, start time), new executable or argv: an exec in place.
    Exec(ProcessFacts),
}

#[derive(Debug, Clone)]
pub struct ProcessTree {
    root: Key,
    nodes: HashMap<Key, Node>,
}

fn key(f: &ProcessFacts) -> Key {
    (f.pid, f.start_time_us)
}

fn label(f: &ProcessFacts) -> String {
    f.exe.as_deref().and_then(|e| e.rsplit('/').next()).filter(|s| !s.is_empty()).map(str::to_string).unwrap_or_else(|| f.name.clone())
}

impl ProcessTree {
    pub fn new(root: ProcessFacts, root_label: String) -> Self {
        let k = key(&root);
        let mut nodes = HashMap::new();
        nodes.insert(k, Node { facts: root, parent: None, exited: false, label: root_label });
        ProcessTree { root: k, nodes }
    }

    pub fn root_pid(&self) -> i32 {
        self.root.0
    }

    fn live_by_pid(&self, pid: i32) -> Option<Key> {
        self.nodes.iter().find(|(k, n)| k.0 == pid && !n.exited).map(|(k, _)| *k)
    }

    /// Updates the tree from a process-table snapshot and returns what changed.
    pub fn refresh(&mut self, snap: &[ProcessFacts]) -> Vec<TreeChange> {
        let mut changes = Vec::new();
        let present: std::collections::HashSet<Key> = snap.iter().map(key).collect();
        for n in self.nodes.values_mut() {
            if !present.contains(&key(&n.facts)) {
                n.exited = true;
            }
        }
        // Exec-in-place on known members.
        for f in snap {
            if let Some(n) = self.nodes.get_mut(&key(f)) {
                if n.facts.exe != f.exe || n.facts.argv != f.argv {
                    n.facts = f.clone();
                    if key(f) != self.root {
                        n.label = label(f);
                    }
                    changes.push(TreeChange::Exec(f.clone()));
                }
            }
        }
        // Adopt children of live members until fixpoint (parents may appear later in the snapshot).
        loop {
            let mut adopted = false;
            for f in snap {
                if self.nodes.contains_key(&key(f)) {
                    continue;
                }
                if let Some(pk) = self.live_by_pid(f.ppid) {
                    let parent_start = self.nodes[&pk].facts.start_time_us;
                    // A reused pid cannot be older than its supposed parent.
                    if f.start_time_us >= parent_start {
                        self.nodes.insert(key(f), Node { facts: f.clone(), parent: Some(pk), exited: false, label: label(f) });
                        changes.push(TreeChange::New(f.clone()));
                        adopted = true;
                    }
                }
            }
            if !adopted {
                break;
            }
        }
        changes
    }

    /// Adopts a process discovered out of band (e.g. via ancestry resolution).
    pub fn adopt(&mut self, f: ProcessFacts, parent_pid: i32) -> bool {
        match self.live_by_pid(parent_pid).or_else(|| self.nodes.keys().find(|k| k.0 == parent_pid).copied()) {
            Some(pk) if !self.nodes.contains_key(&key(&f)) => {
                let l = label(&f);
                self.nodes.insert(key(&f), Node { facts: f, parent: Some(pk), exited: false, label: l });
                true
            }
            _ => false,
        }
    }

    /// Whether `pid` is (or was, while alive) a member. Prefers live nodes.
    pub fn contains_pid(&self, pid: i32) -> bool {
        self.nodes.keys().any(|k| k.0 == pid)
    }

    /// Labels from the root to `pid`, e.g. `["claude-code", "bash", "terraform"]`.
    pub fn chain(&self, pid: i32) -> Option<Vec<String>> {
        let mut k = self.live_by_pid(pid).or_else(|| self.nodes.keys().filter(|k| k.0 == pid).max_by_key(|k| k.1).copied())?;
        let mut out = vec![];
        loop {
            let n = &self.nodes[&k];
            out.push(n.label.clone());
            match n.parent {
                Some(p) => k = p,
                None => break,
            }
        }
        out.reverse();
        Some(out)
    }

    pub fn live_members(&self) -> Vec<i32> {
        self.nodes.iter().filter(|(_, n)| !n.exited).map(|(k, _)| k.0).collect()
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(pid: i32, ppid: i32, start: u64, exe: &str) -> ProcessFacts {
        ProcessFacts { pid, ppid, pgid: 0, uid: 501, start_time_us: start, exe: Some(exe.into()), argv: vec![exe.rsplit('/').next().unwrap().into()], name: String::new() }
    }

    #[test]
    fn builds_chain_and_rejects_reused_pid() {
        let mut t = ProcessTree::new(f(100, 1, 10, "/opt/claude"), "claude-code".into());
        let snap = vec![f(100, 1, 10, "/opt/claude"), f(102, 101, 30, "/opt/homebrew/bin/terraform"), f(101, 100, 20, "/bin/bash")];
        let ch = t.refresh(&snap);
        assert_eq!(ch.len(), 2);
        assert_eq!(t.chain(102).unwrap(), vec!["claude-code", "bash", "terraform"]);
        // pid 200 claims parent 100 but started before it: pid reuse, not adopted
        let ch = t.refresh(&[f(100, 1, 10, "/opt/claude"), f(200, 100, 5, "/bin/x")]);
        assert!(ch.is_empty());
        assert!(!t.contains_pid(200));
        // exited 102 still resolves
        assert_eq!(t.chain(102).unwrap(), vec!["claude-code", "bash", "terraform"]);
        assert!(!t.live_members().contains(&102));
    }

    #[test]
    fn exec_in_place_is_reported() {
        let mut t = ProcessTree::new(f(100, 1, 10, "/opt/claude"), "claude-code".into());
        t.refresh(&[f(100, 1, 10, "/opt/claude"), f(101, 100, 20, "/bin/sh")]);
        let mut git = f(101, 100, 20, "/usr/bin/git");
        git.argv = vec!["git".into(), "push".into()];
        let ch = t.refresh(&[f(100, 1, 10, "/opt/claude"), git.clone()]);
        assert_eq!(ch, vec![TreeChange::Exec(git)]);
        assert_eq!(t.chain(101).unwrap(), vec!["claude-code", "git"]);
    }
}
