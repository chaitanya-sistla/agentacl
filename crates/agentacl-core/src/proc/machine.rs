//! Machine identity: a hash of IOPlatformUUID (the raw UUID is never stored).

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::process::Command;

pub fn machine_id() -> Result<String> {
    let out = Command::new("/usr/sbin/ioreg").args(["-rd1", "-c", "IOPlatformExpertDevice"]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(uuid) = parse_platform_uuid(&text) else { bail!("IOPlatformUUID not found in ioreg output") };
    Ok(machine_id_from_uuid(&uuid))
}

pub fn parse_platform_uuid(ioreg: &str) -> Option<String> {
    let line = ioreg.lines().find(|l| l.contains("\"IOPlatformUUID\""))?;
    let v = line.split('=').nth(1)?.trim().trim_matches('"');
    (!v.is_empty()).then(|| v.to_string())
}

pub fn machine_id_from_uuid(uuid: &str) -> String {
    let h = hex::encode(Sha256::digest(uuid.as_bytes()));
    format!("mch_{}", &h[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_machine_id_shape() {
        let id = machine_id().unwrap();
        assert!(regex::Regex::new(r"^mch_[0-9a-f]{16}$").unwrap().is_match(&id), "{id}");
    }

    #[test]
    fn parses_ioreg() {
        let t = "  | \"IOPlatformSerialNumber\" = \"X\"\n    \"IOPlatformUUID\" = \"ABCD-1234\"\n";
        assert_eq!(parse_platform_uuid(t).as_deref(), Some("ABCD-1234"));
        assert_eq!(machine_id_from_uuid("ABCD-1234").len(), 20);
    }
}
