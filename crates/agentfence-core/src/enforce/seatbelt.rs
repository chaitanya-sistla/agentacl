//! MVP backend: kernel-enforced Seatbelt profiles via `/usr/bin/sandbox-exec`.

use super::{classify_seatbelt, sbpl, CompileInput, EnforcementBackend, Enforceability, LaunchPlan};
use agentfence_policy::set::{PolicySet, Rule};
use anyhow::{Context, Result};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

pub struct SeatbeltBackend;

impl EnforcementBackend for SeatbeltBackend {
    fn name(&self) -> &'static str {
        "seatbelt"
    }

    fn available(&self) -> Result<(), String> {
        if Path::new(SANDBOX_EXEC).is_file() {
            Ok(())
        } else {
            Err(format!("{SANDBOX_EXEC} not found"))
        }
    }

    fn classify(&self, rule: &Rule) -> Enforceability {
        classify_seatbelt(rule)
    }

    fn prepare(&self, policy: &PolicySet, input: &CompileInput, profile_path: PathBuf, argv: &[String]) -> Result<LaunchPlan> {
        let text = sbpl::compile_profile(policy, input)?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&profile_path)
            .with_context(|| format!("writing profile {}", profile_path.display()))?;
        f.write_all(text.as_bytes())?;
        let mut args = vec!["-f".to_string(), profile_path.to_string_lossy().into_owned(), "--".to_string()];
        args.extend(argv.iter().cloned());
        Ok(LaunchPlan { program: SANDBOX_EXEC.into(), args, profile_path, profile_text: text })
    }
}
