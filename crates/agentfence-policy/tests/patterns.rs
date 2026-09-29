use agentfence_policy::netpat::{reserved_range, NetPattern};
use agentfence_policy::procpat::CommandPattern;
use std::net::IpAddr;

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn sudo_any_args() {
    let p = CommandPattern::parse("sudo *").unwrap();
    assert!(p.matches("/usr/bin/sudo", &argv(&["sudo"])));
    assert!(p.matches("/usr/bin/sudo", &argv(&["sudo", "-n", "true"])));
    assert!(p.matches("/usr/bin/SUDO", &argv(&["x"])));
    assert!(!p.matches("/usr/bin/sudoedit", &argv(&["sudoedit"])));
    assert!(p.is_executable_only());
    assert_eq!(p.exe_basename(), Some("sudo"));
}

#[test]
fn git_push_positional() {
    let p = CommandPattern::parse("git push *").unwrap();
    assert!(p.matches("/usr/bin/git", &argv(&["git", "push"])));
    assert!(p.matches("/usr/bin/git", &argv(&["git", "push", "origin", "main"])));
    assert!(!p.matches("/usr/bin/git", &argv(&["git", "-C", "x", "push"])));
    assert!(!p.matches("/usr/bin/git", &argv(&["git", "pull"])));
    assert!(!p.is_executable_only());
}

#[test]
fn exact_args_without_star() {
    let p = CommandPattern::parse("terraform apply").unwrap();
    assert!(p.matches("/opt/homebrew/bin/terraform", &argv(&["terraform", "apply"])));
    assert!(!p.matches("/opt/homebrew/bin/terraform", &argv(&["terraform", "apply", "-auto-approve"])));
    let bare = CommandPattern::parse("ls").unwrap();
    assert!(bare.matches("/bin/ls", &argv(&["ls"])));
    assert!(!bare.matches("/bin/ls", &argv(&["ls", "-l"])));
    assert!(bare.is_executable_only());
}

#[test]
fn absolute_exe() {
    let p = CommandPattern::parse("/usr/local/bin/tf *").unwrap();
    assert!(p.matches("/usr/local/bin/tf", &argv(&["tf", "plan"])));
    assert!(!p.matches("/opt/tf", &argv(&["tf"])));
    assert_eq!(p.exe_abs(), Some("/usr/local/bin/tf"));
    assert!(CommandPattern::parse("bin/tf").is_err());
    assert!(CommandPattern::parse("").is_err());
}

#[test]
fn host_patterns() {
    let w = NetPattern::parse("*.github.com").unwrap();
    assert!(w.matches_host("api.github.com", 443));
    assert!(w.matches_host("API.GitHub.com.", 80));
    assert!(!w.matches_host("github.com", 443));
    assert!(!w.matches_host("evilgithub.com", 443));
    let p = NetPattern::parse("github.com:443").unwrap();
    assert!(p.matches_host("github.com", 443));
    assert!(!p.matches_host("github.com", 80));
    assert!(NetPattern::parse("bad host").is_err());
}

#[test]
fn addr_patterns() {
    let n = NetPattern::parse("10.0.0.0/8").unwrap();
    assert!(n.matches_addr("10.1.2.3".parse().unwrap(), 1));
    assert!(n.matches_addr("::ffff:10.1.2.3".parse().unwrap(), 1));
    assert!(!n.matches_host("10.1.2.3", 1));
    let l = NetPattern::parse("localhost:3000").unwrap();
    assert!(l.matches_addr("127.0.0.1".parse().unwrap(), 3000));
    assert!(l.matches_addr("::1".parse().unwrap(), 3000));
    assert!(!l.matches_addr("127.0.0.1".parse().unwrap(), 3001));
    assert!(l.is_loopback_only());
    let v6 = NetPattern::parse("[::1]:8080").unwrap();
    assert!(v6.matches_addr("::1".parse().unwrap(), 8080));
    let meta = NetPattern::parse("169.254.169.254").unwrap();
    assert!(meta.matches_addr("169.254.169.254".parse().unwrap(), 80));
    assert!(!NetPattern::parse("0.0.0.0:3000").unwrap().is_loopback_only());
}

#[test]
fn reserved_ranges() {
    let r = |s: &str| reserved_range(s.parse::<IpAddr>().unwrap());
    assert_eq!(r("169.254.169.254"), Some("link-local"));
    assert_eq!(r("::ffff:10.0.0.1"), Some("rfc1918"));
    assert_eq!(r("100.64.0.1"), Some("cgnat"));
    assert_eq!(r("fd00::1"), Some("ula"));
    assert_eq!(r("127.0.0.1"), Some("loopback"));
    assert_eq!(r("::1"), Some("loopback"));
    assert_eq!(r("0.0.0.0"), Some("unspecified"));
    assert_eq!(r("8.8.8.8"), None);
    assert_eq!(r("2606:4700::1111"), None);
}
