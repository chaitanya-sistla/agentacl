//! The daemon side of `agentacl_core::es_journal`: appends records to the
//! user's journal, owned by the user (mode 0600), so the console can ingest
//! them. Runs on its own thread: disk I/O never delays an ES answer.

use crate::creds::become_user;
use agentacl_core::es_journal::{EsRecord, DIR, FILE};
use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Rotated at this size (the console ingests well before that).
const MAX_BYTES: u64 = 50 * 1024 * 1024;

pub struct Journal {
    dir: PathBuf,
    file: std::fs::File,
}

impl Journal {
    /// `state_dir` is the user's AgentACL state folder. Call on the thread
    /// that writes, after [`become_user`] (as [`spawn`] does).
    fn open(state_dir: &Path) -> Result<Journal> {
        let dir = state_dir.join(DIR);
        for d in [state_dir, dir.as_path()] {
            match std::fs::DirBuilder::new().mode(0o700).create(d) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("mkdir {}", d.display())),
            }
        }
        let file = Self::open_file(&dir)?;
        Ok(Journal { dir, file })
    }

    fn open_file(dir: &Path) -> Result<std::fs::File> {
        let p = dir.join(FILE);
        std::fs::OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&p).with_context(|| format!("open {}", p.display()))
    }

    pub fn write(&mut self, r: &EsRecord) -> Result<()> {
        let mut line = serde_json::to_vec(r)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        if self.file.metadata()?.len() > MAX_BYTES {
            let p = self.dir.join(FILE);
            std::fs::rename(&p, self.dir.join(format!("{FILE}.1")))?;
            self.file = Self::open_file(&self.dir)?;
        }
        Ok(())
    }
}

/// Starts the writer thread: it acts as the user, opens the journal, and
/// writes every record it receives until the channel closes. Returns once
/// the journal is open, with the error if it couldn't be.
pub fn spawn(state_dir: PathBuf, uid: u32, gid: u32, rx: std::sync::mpsc::Receiver<EsRecord>) -> Result<std::thread::JoinHandle<()>> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let h = std::thread::spawn(move || {
        let j = become_user(uid, gid).and_then(|()| Journal::open(&state_dir));
        let mut j = match j {
            Ok(j) => {
                let _ = ready_tx.send(Ok(()));
                j
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        for r in rx {
            if let Err(e) = j.write(&r) {
                eprintln!("agentacl-esd: journal: {e:#}");
            }
        }
    });
    ready_rx.recv().context("journal thread")??;
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentacl_core::config::Paths;
    use agentacl_core::es_journal::{ingest, Kind};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn writes_what_the_console_ingests() {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let paths = Paths::with_dirs(root.join("home"), root.join("state"), root.join("config"));
        let mut j = Journal::open(&paths.state_dir).unwrap();
        let r = EsRecord {
            ts: "2026-10-09T10:00:00.000Z".into(),
            kind: Kind::SessionStart,
            session: "agt_J".into(),
            agent: "codex".into(),
            agent_name: "Codex".into(),
            project: "/p".into(),
            pid: Some(7),
            chain: vec![],
            action: String::new(),
            resource: String::new(),
            decision: None,
        };
        j.write(&r).unwrap();
        let mode = std::fs::metadata(paths.state_dir.join("es").join(FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let store = agentacl_core::audit::Store::open(&paths.db_path).unwrap();
        assert_eq!(ingest(&paths, &store).unwrap(), 1);
        assert!(store.active_sessions().unwrap().iter().any(|s| s.session_id == "agt_J"));
    }
}
