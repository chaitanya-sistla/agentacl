//! macOS process introspection: facts, the supervised tree, code signatures,
//! file hashes and the machine id.

pub mod codesign;
pub mod libproc;
pub mod machine;
pub mod tree;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

pub use codesign::{code_signature, CodeSignature};
pub use libproc::{cwd, facts, list_pids, resolve_ancestry, session_members, snapshot};
pub use machine::machine_id;
pub use tree::{ProcessTree, TreeChange};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessFacts {
    pub pid: i32,
    pub ppid: i32,
    #[serde(default)]
    pub pgid: i32,
    #[serde(default)]
    pub uid: u32,
    #[serde(default)]
    pub start_time_us: u64,
    pub exe: Option<String>,
    pub argv: Vec<String>,
    #[serde(default)]
    pub name: String,
}

pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_of_self_and_child() {
        let me = facts(std::process::id() as i32).unwrap();
        assert!(me.exe.as_deref().unwrap().contains("agentfence_core"), "{:?}", me.exe);
        assert!(!me.argv.is_empty());
        let mut child = std::process::Command::new("/bin/sleep").arg("5").spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let c = facts(child.id() as i32).unwrap();
        child.kill().ok();
        child.wait().ok();
        assert_eq!(c.argv, vec!["/bin/sleep", "5"]);
        assert_eq!(c.ppid, std::process::id() as i32);
        assert_eq!(c.exe.as_deref(), Some("/bin/sleep"));
    }

    #[test]
    fn cwd_of_self() {
        let me = std::env::current_dir().unwrap();
        assert_eq!(cwd(std::process::id() as i32).map(std::path::PathBuf::from), Some(std::fs::canonicalize(me).unwrap()));
    }

    #[test]
    fn list_contains_self() {
        assert!(list_pids().contains(&(std::process::id() as i32)));
    }

    #[test]
    fn procargs2_parser() {
        let mut b = 2i32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/bin/echo\0\0\0echo\0hi\0PATH=/bin\0");
        assert_eq!(libproc::parse_procargs2(&b).unwrap(), vec!["echo", "hi"]);
    }

    #[test]
    fn sha256_known() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(sha256_file(&p).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
