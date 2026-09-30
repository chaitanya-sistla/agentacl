use super::*;
use agentacl_policy::expand::Vars;
use agentacl_policy::set::{builtin_sources, LoadOptions, PolicySource};
use agentacl_policy::Layer;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

fn allow(r: &str) -> Decision {
    Decision { effect: Effect::Allow, policy: "t".into(), rule_id: r.into(), reason: "ok".into(), trace: vec![] }
}
fn deny(r: &str) -> Decision {
    Decision { effect: Effect::Deny, policy: "t".into(), rule_id: r.into(), reason: "no".into(), trace: vec![] }
}

struct Fake {
    allow_host: &'static str,
    addr_calls: AtomicUsize,
}
impl NetDecider for Fake {
    fn host(&self, host: &str, _: u16) -> Decision {
        if host == self.allow_host {
            allow("h")
        } else {
            deny("h")
        }
    }
    fn addr(&self, _: IpAddr, _: u16) -> Decision {
        self.addr_calls.fetch_add(1, Ordering::SeqCst);
        allow("a")
    }
}

fn echo_server() -> u16 {
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for c in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut r = c.try_clone().unwrap();
                let mut w = c;
                let _ = std::io::copy(&mut r, &mut w);
            });
        }
    });
    port
}

fn collect() -> (EventFn, Arc<Mutex<Vec<EnforcedEvent>>>) {
    let v = Arc::new(Mutex::new(vec![]));
    let v2 = v.clone();
    (Arc::new(move |e| v2.lock().unwrap().push(e)), v)
}

fn send(port: u16, req: &str) -> (TcpStream, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut got = Vec::new();
    let mut b = [0u8; 1];
    while !got.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).unwrap() == 0 {
            break;
        }
        got.push(b[0]);
    }
    (s, String::from_utf8_lossy(&got).into_owned())
}

#[test]
fn connect_tunnel_allowed() {
    let up = echo_server();
    let (on, events) = collect();
    let p = NetProxy::start(Arc::new(Fake { allow_host: "localhost", addr_calls: AtomicUsize::new(0) }), on).unwrap();
    let (mut s, head) = send(p.port, &format!("CONNECT localhost:{up} HTTP/1.1\r\nHost: localhost:{up}\r\n\r\n"));
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    s.write_all(b"ping").unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"ping");
    let ev = events.lock().unwrap();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].decision().effect, Effect::Allow);
    assert_eq!(ev[0].resource(), format!("localhost:{up}"));
}

#[test]
fn denied_host_never_resolves() {
    let (on, events) = collect();
    let fake = Arc::new(Fake { allow_host: "localhost", addr_calls: AtomicUsize::new(0) });
    let p = NetProxy::start(fake.clone(), on).unwrap();
    let (_s, head) = send(p.port, "CONNECT secret-data.evil.test:443 HTTP/1.1\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(head.contains("X-AgentACL-Reason"));
    assert_eq!(fake.addr_calls.load(Ordering::SeqCst), 0);
    assert_eq!(events.lock().unwrap()[0].decision().effect, Effect::Deny);
}

#[test]
fn host_header_mismatch() {
    let (on, _) = collect();
    let p = NetProxy::start(Arc::new(Fake { allow_host: "a.test", addr_calls: AtomicUsize::new(0) }), on).unwrap();
    let (_s, head) = send(p.port, "GET http://a.test/ HTTP/1.1\r\nHost: b.test\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    let (_s, head) = send(p.port, "GET /relative HTTP/1.1\r\nHost: a.test\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 405"), "{head}");
}

fn policy(user: &str) -> Arc<PolicySet> {
    let vars = Vars { home: "/u".into(), project: "/p".into(), tmpdir: "/private/tmp/t".into(), agent_state: None, agentacl_state: "/u/s".into(), agentacl_config: "/u/c".into() };
    let mut src = builtin_sources(false);
    src.push(PolicySource { layer: Layer::User, name: "user".into(), yaml: user.into() });
    Arc::new(PolicySet::load(src, &vars, &LoadOptions::default()).unwrap())
}

fn real(user: &str) -> Arc<dyn NetDecider> {
    Arc::new(PolicyNetDecider { policy: policy(user), subject: Subject { agent_id: "claude-code".into(), project: "/p".into(), ..Default::default() } })
}

#[test]
fn reserved_range_blocked_even_when_host_allowed() {
    let up = echo_server();
    let (on, events) = collect();
    let p = NetProxy::start(real("version: v1\nnetwork:\n  allow: [\"localhost\"]\n"), on).unwrap();
    // "localhost" as a host pattern is an address pattern (127/8) — allowed explicitly: tunnel works
    let (_s, head) = send(p.port, &format!("CONNECT localhost:{up} HTTP/1.1\r\n\r\n"));
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // a hostname allow that resolves to loopback is refused by phase 2
    let p2 = NetProxy::start(real("version: v1\nnetwork:\n  allow: [\"*.localtest.me\", \"localtest.me\"]\n"), collect().0).unwrap();
    let (_s, head) = send(p2.port, &format!("CONNECT localtest.me:{up} HTTP/1.1\r\n\r\n"));
    // localtest.me resolves to 127.0.0.1 (public DNS); if DNS is unavailable we still must not connect
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(head.contains("reserved-range") || head.contains("resolve"), "{head}");
    drop(events);
}

#[test]
fn ip_literal_default_deny_and_ask_fail_closed() {
    let (on, _) = collect();
    let p = NetProxy::start(real("version: v1\n"), on).unwrap();
    let (_s, head) = send(p.port, "CONNECT 8.8.8.8:443 HTTP/1.1\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 403") && head.contains("/default"), "{head}");
    let p = NetProxy::start(real("version: v1\ndefaults: {network: ask}\n"), collect().0).unwrap();
    let (_s, head) = send(p.port, "CONNECT example.com:443 HTTP/1.1\r\n\r\n");
    assert!(head.starts_with("HTTP/1.1 403"), "ask must be refused: {head}");
}

#[test]
fn ui_port_is_always_refused() {
    let up = echo_server();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(format!("ui-{}.json", std::process::id())), format!("{{\"pid\":{},\"port\":{up}}}", std::process::id())).unwrap();
    let guard = Arc::new(UiPortGuard { state_dir: dir.path().to_path_buf() });
    let p = NetProxy::start_guarded(real("version: v1\nnetwork:\n  allow: [\"localhost\", \"0.0.0.0\", \"::ffff:127.0.0.1\"]\n"), collect().0, Some(guard.clone())).unwrap();
    for target in [format!("localhost:{up}"), format!("127.0.0.1:{up}"), format!("0.0.0.0:{up}"), format!("[::ffff:127.0.0.1]:{up}")] {
        let (_s, head) = send(p.port, &format!("CONNECT {target} HTTP/1.1\r\n\r\n"));
        assert!(head.starts_with("HTTP/1.1 403") && head.contains("agentacl-ui"), "{target}: {head}");
    }
    // other local ports stay governed by policy
    let other = echo_server();
    let (_s, head) = send(p.port, &format!("CONNECT 127.0.0.1:{other} HTTP/1.1\r\n\r\n"));
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // unreadable state dir fails closed for loopback
    let g2 = UiPortGuard { state_dir: "/private/var/root/nope".into() };
    assert!(g2.check("127.0.0.1".parse().unwrap(), 1).is_some());
    assert!(g2.check("93.184.216.34".parse().unwrap(), 443).is_none());
}
