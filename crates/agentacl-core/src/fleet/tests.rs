use super::*;
use std::os::unix::fs::PermissionsExt;

fn managed() -> (tempfile::TempDir, Managed) {
    let t = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(t.path()).unwrap().join("AgentACL");
    (t, Managed { root, owner: unsafe { libc::getuid() } })
}

fn policy(version: u64, yaml: &str) -> PolicyResponse {
    PolicyResponse { version, yaml: yaml.into() }
}

#[test]
fn company_policies_are_checked_then_written_root_owned() {
    let (_t, m) = managed();
    m.apply_policy(&policy(0, ""), None).unwrap();
    assert_eq!(std::fs::read_to_string(m.policy()).unwrap(), "version: v1\n", "none: an empty document");
    let loaded = m.org_source().unwrap().unwrap();
    assert_eq!(loaded.layer, agentacl_policy::Layer::Org);
    let mode = std::fs::metadata(m.policy()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
    let mode = std::fs::metadata(m.root.join("managed")).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755);

    m.apply_policy(&policy(3, "version: v1\nfilesystem:\n  deny_read: [\"${HOME}/Company/**\"]\n"), Some(0)).unwrap();
    // Refused: an allow, a user-chosen variable, an older version. The last
    // good policy stays.
    for (p, cur) in [
        (policy(4, "version: v1\nnetwork:\n  allow: [\"x.com\"]\n"), Some(3)),
        (policy(5, "version: v1\nfilesystem:\n  deny_read: [\"${PROJECT}/x\"]\n"), Some(3)),
        (policy(2, "version: v1\n"), Some(3)),
    ] {
        assert!(m.apply_policy(&p, cur).is_err(), "{p:?}");
    }
    assert!(std::fs::read_to_string(m.policy()).unwrap().contains("Company"));
}

#[test]
fn enrollment_sources() {
    let (_t, m) = managed();
    std::fs::create_dir_all(&m.root).unwrap();
    std::fs::write(m.enroll_file(), r#"{"server":"https://fleet.example.com","token":"aet_x"}"#).unwrap();
    let s = enroll_source(&m).unwrap();
    assert_eq!((s.server.as_str(), s.token.as_str()), ("https://fleet.example.com", "aet_x"));
    assert!(enroll(&m, &EnrollSource { server: "http://fleet.example.com".into(), token: "t".into(), proxy: None }).is_err(), "HTTPS only");
}
