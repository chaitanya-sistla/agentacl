use agentfence_policy::expand::{expand, Expanded, Vars};
use agentfence_policy::pathpat::{PatKind, PathPattern};

fn vars() -> Vars {
    Vars {
        home: "/u".into(),
        project: "/p".into(),
        tmpdir: "/private/var/t".into(),
        agent_state: None,
        agentfence_state: "/u/state".into(),
        agentfence_config: "/u/.config/agentfence".into(),
    }
}

fn pat(s: &str) -> PathPattern {
    PathPattern::parse(&expand(s, &vars(), "t").unwrap()).unwrap()
}

#[test]
fn subpath_matches_dir_and_below() {
    let p = pat("${HOME}/.ssh/**");
    assert_eq!(p.kind(), &PatKind::Subpath("/u/.ssh".into()));
    for yes in ["/u/.ssh", "/u/.ssh/id_rsa", "/u/.ssh/a/b"] {
        assert!(p.matches(yes), "{yes}");
    }
    assert!(!p.matches("/u/.sshx"));
    assert!(!p.matches("/u"));
}

#[test]
fn anywhere_env() {
    let p = pat("/**/.env");
    for yes in ["/p/.env", "/.env", "/p/a/b/.env", "/P/A/.ENV"] {
        assert!(p.matches(yes), "{yes}");
    }
    for no in ["/p/.env.local", "/p/x.env", "/p/.envrc"] {
        assert!(!p.matches(no), "{no}");
    }
    assert_eq!(p.kind(), &PatKind::Glob);
    assert_eq!(p.anchor(), "/");
}

#[test]
fn env_variants_with_except() {
    let p = pat("${PROJECT}/**/.env.*");
    assert!(p.matches("/p/.env.production"));
    assert!(p.matches("/p/a/.env.local"));
    assert!(!p.matches("/p/.env"));
    assert_eq!(p.anchor(), "/p");
    let ex = PathPattern::parse_except("**/.env.example", p.anchor()).unwrap();
    assert!(ex.matches("/p/a/.env.example"));
    assert!(ex.matches("/p/.env.example"));
    assert!(!ex.matches("/q/.env.example"));
}

#[test]
fn single_and_double_star() {
    let one = pat("/u/*.pem");
    assert!(one.matches("/u/a.pem"));
    assert!(!one.matches("/u/a/b.pem"));
    let two = pat("/u/**/*.pem");
    assert!(two.matches("/u/a.pem"));
    assert!(two.matches("/u/a/b.pem"));
    let q = pat("/u/id_?sa");
    assert!(q.matches("/u/id_rsa"));
    assert!(!q.matches("/u/id_/sa"));
}

#[test]
fn kinds_and_anchors() {
    assert_eq!(pat("${HOME}/.aws/credentials").kind(), &PatKind::Literal("/u/.aws/credentials".into()));
    let g = pat("${PROJECT}/**/.env");
    assert_eq!(g.kind(), &PatKind::Glob);
    assert_eq!(g.anchor(), "/p");
    // /tmp is canonicalized
    assert_eq!(pat("/tmp/x/**").kind(), &PatKind::Subpath("/private/tmp/x".into()));
}

#[test]
fn sbpl_regex_is_folded_and_anchored() {
    assert_eq!(pat("/p/**/.env").sbpl_regex(), r"^/[pP](/.*)?/\.[eE][nN][vV]$");
    assert_eq!(pat("/u/*.pem").sbpl_regex(), r"^/[uU]/[^/]*\.[pP][eE][mM]$");
}

#[test]
fn rejects_bad_patterns() {
    let rel = Expanded { text: "foo/**".into(), var_root: None };
    assert!(PathPattern::parse(&rel).is_err());
    let dotdot = Expanded { text: "/a/../b".into(), var_root: None };
    assert!(PathPattern::parse(&dotdot).is_err());
    let midstar = Expanded { text: "/a/x**y".into(), var_root: None };
    assert!(PathPattern::parse(&midstar).is_err());
}

#[test]
fn protected_ancestors() {
    assert_eq!(pat("${HOME}/.aws/sso/cache/**").protected_ancestors(), vec!["/u", "/u/.aws", "/u/.aws/sso"]);
    assert_eq!(pat("${HOME}/.aws/credentials").protected_ancestors(), vec!["/u", "/u/.aws"]);
    assert_eq!(pat("${HOME}/.ssh/**").protected_ancestors(), vec!["/u"]);
    assert!(pat("/**/.env").protected_ancestors().is_empty());
    assert_eq!(pat("${HOME}/.kube/**/config").protected_ancestors(), vec!["/u", "/u/.kube"]);
    assert_eq!(pat("${PROJECT}/**/.env.*").protected_ancestors(), vec!["/p"]);
    assert_eq!(pat("/opt/secrets/key").protected_ancestors(), vec!["/opt", "/opt/secrets"]);
}
