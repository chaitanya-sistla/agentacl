//! Local HTTP CONNECT / HTTP proxy that enforces `network.*` policy
//! (macos-enforcement §2.4, policy-model §4.2). The sandbox allows the agent
//! to reach only this proxy, so every decision here takes effect.
//!
//! Two-phase: the host is decided before any DNS lookup (a denied name never
//! reaches DNS); then every resolved address is decided, and the proxy
//! connects to exactly the address it checked. Anything but `allow` is refused.

use crate::audit::EnforcedEvent;
use agentacl_policy::set::PolicySet;
use agentacl_policy::{Action, Decision, Effect, PolicyEngine, Request, Resource, Subject};
use anyhow::Result;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub trait NetDecider: Send + Sync {
    fn host(&self, host: &str, port: u16) -> Decision;
    fn addr(&self, ip: IpAddr, port: u16) -> Decision;
}

pub struct PolicyNetDecider {
    pub policy: Arc<PolicySet>,
    pub subject: Subject,
}

impl NetDecider for PolicyNetDecider {
    fn host(&self, host: &str, port: u16) -> Decision {
        self.policy.evaluate(&Request { subject: self.subject.clone(), action: Action::NetConnect, resource: Resource::Host { host: host.to_string(), port } })
    }
    fn addr(&self, ip: IpAddr, port: u16) -> Decision {
        self.policy.evaluate_address(&self.subject, ip, port)
    }
}

pub type EventFn = Arc<dyn Fn(EnforcedEvent) + Send + Sync>;

/// Refuses connections to a running `agentacl ui` (ui.md §5): any loopback or
/// unspecified destination on a port listed in a live `ui-<pid>.json` in the
/// state dir, whatever the policy says. If the state dir cannot be read, all
/// loopback/unspecified destinations are refused (fail closed).
pub struct UiPortGuard {
    pub state_dir: std::path::PathBuf,
}

impl UiPortGuard {
    fn is_local(ip: IpAddr) -> bool {
        let ip = agentacl_policy::netpat::normalize(ip);
        ip.is_loopback() || ip.is_unspecified()
    }

    /// `Some(refusal)` if this destination must be refused.
    pub fn check(&self, ip: IpAddr, port: u16) -> Option<Decision> {
        if !Self::is_local(ip) {
            return None;
        }
        let refuse = |why: String| Some(Decision { effect: Effect::Deny, policy: "builtin".into(), rule_id: "agentacl-ui".into(), reason: why, trace: vec![] });
        let rd = match std::fs::read_dir(&self.state_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(_) => return refuse("AgentACL state is unreadable; local connections are refused".into()),
        };
        for ent in rd.flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            if !(name.starts_with("ui-") && name.ends_with(".json")) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(ent.path()) else { return refuse("AgentACL UI lock is unreadable; local connections are refused".into()) };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            let (Some(pid), Some(p)) = (v["pid"].as_i64(), v["port"].as_u64()) else { continue };
            // SAFETY: kill(pid, 0) only checks existence.
            let alive = unsafe { libc::kill(pid as i32, 0) } == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
            if alive && p == port as u64 {
                return refuse("Connections to the AgentACL policy UI are never permitted to agents".into());
            }
        }
        None
    }
}

pub struct NetProxy {
    pub port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

const MAX_HEAD: usize = 32 * 1024;

impl NetProxy {
    pub fn start(decider: Arc<dyn NetDecider>, on_event: EventFn) -> Result<NetProxy> {
        Self::start_guarded(decider, on_event, None)
    }

    pub fn start_guarded(decider: Arc<dyn NetDecider>, on_event: EventFn, guard: Option<Arc<UiPortGuard>>) -> Result<NetProxy> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let handle = std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop2.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(conn) = conn else { continue };
                let (d, e, g) = (decider.clone(), on_event.clone(), guard.clone());
                std::thread::spawn(move || {
                    let _ = handle_conn(conn, d.as_ref(), e.as_ref(), g.as_deref());
                });
            }
        });
        Ok(NetProxy { port, stop, handle: Some(handle) })
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for NetProxy {
    fn drop(&mut self) {
        if self.handle.is_some() {
            self.shutdown();
        }
    }
}

struct Head {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    rest: Vec<u8>,
}

fn read_head(c: &mut TcpStream) -> std::io::Result<Option<Head>> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }
        let n = c.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let text = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, target, version) = (first.next().unwrap_or("").to_string(), first.next().unwrap_or("").to_string(), first.next().unwrap_or("HTTP/1.1").to_string());
    let headers = lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))).collect();
    Ok(Some(Head { method, target, version, headers, rest: buf[end + 4..].to_vec() }))
}

fn respond(c: &mut TcpStream, status: &str, reason: &str) {
    let body = format!("AgentACL: {reason}\n");
    let clean: String = reason.chars().filter(|ch| !ch.is_control()).collect();
    let msg = format!("HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-AgentACL-Reason: {clean}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = c.write_all(msg.as_bytes());
}

/// `host:port` / `[v6]:port` → (host, port).
fn split_authority(a: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = a.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        return Some((h.to_string(), port));
    }
    match a.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => Some((h.to_string(), p.parse().ok()?)),
        _ => Some((a.to_string(), default_port)),
    }
}

fn norm_host(h: &str) -> String {
    h.trim_end_matches('.').to_ascii_lowercase()
}

/// Two-phase decision. Returns the checked addresses to connect to, or the refusing decision.
fn decide(d: &dyn NetDecider, guard: Option<&UiPortGuard>, host: &str, port: u16) -> std::result::Result<(Vec<SocketAddr>, Decision), Decision> {
    let host_decision = d.host(host, port);
    if host_decision.effect != Effect::Allow {
        return Err(host_decision);
    }
    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(e) => return Err(Decision { effect: Effect::Deny, policy: "proxy".into(), rule_id: "resolve-failed".into(), reason: format!("could not resolve {host}: {e}"), trace: vec![] }),
    };
    if addrs.is_empty() {
        return Err(Decision { effect: Effect::Deny, policy: "proxy".into(), rule_id: "resolve-failed".into(), reason: format!("{host} has no addresses"), trace: vec![] });
    }
    for a in &addrs {
        if let Some(refusal) = guard.and_then(|g| g.check(a.ip(), port)) {
            return Err(refusal);
        }
        let ad = d.addr(a.ip(), port);
        if ad.effect != Effect::Allow {
            return Err(ad);
        }
    }
    Ok((addrs, host_decision))
}

/// Connects to the first reachable address among those already checked.
fn connect_checked(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::other("no addresses");
    for a in addrs {
        match TcpStream::connect_timeout(a, Duration::from_secs(10)) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn splice(a: TcpStream, b: TcpStream) {
    let (mut a2, mut b2) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    let (mut a1, mut b1) = (a, b);
    let t = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a1, &mut b1);
        let _ = b1.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut b2, &mut a2);
    let _ = a2.shutdown(Shutdown::Write);
    let _ = t.join();
}

fn handle_conn(mut c: TcpStream, d: &dyn NetDecider, on_event: &(dyn Fn(EnforcedEvent) + Send + Sync), guard: Option<&UiPortGuard>) -> std::io::Result<()> {
    c.set_read_timeout(Some(Duration::from_secs(30)))?;
    let Some(head) = read_head(&mut c)? else { return Ok(()) };
    let event = |host: &str, port: u16, dec: Decision| on_event(EnforcedEvent::proxy("network.connect".into(), format!("{host}:{port}"), dec));

    if head.method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = split_authority(&head.target, 443) else {
            respond(&mut c, "400 Bad Request", "malformed CONNECT target");
            return Ok(());
        };
        let host = norm_host(&host);
        match decide(d, guard, &host, port) {
            Err(dec) => {
                respond(&mut c, "403 Forbidden", &format!("{} ({}/{})", dec.reason, dec.policy, dec.rule_id));
                event(&host, port, dec);
            }
            Ok((addrs, dec)) => match connect_checked(&addrs) {
                Ok(mut up) => {
                    event(&host, port, dec);
                    c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
                    if !head.rest.is_empty() {
                        up.write_all(&head.rest)?;
                    }
                    c.set_read_timeout(None)?;
                    splice(c, up);
                }
                Err(e) => {
                    event(&host, port, dec);
                    respond(&mut c, "502 Bad Gateway", &format!("connect to {host}:{port} failed: {e}"));
                }
            },
        }
        return Ok(());
    }

    // Absolute-form HTTP request: decide on the request-URI host only.
    let Some(after) = head.target.strip_prefix("http://") else {
        respond(&mut c, "405 Method Not Allowed", "only CONNECT and absolute-form http:// requests are proxied");
        return Ok(());
    };
    let (authority, path) = match after.find('/') {
        Some(i) => (&after[..i], &after[i..]),
        None => (after, "/"),
    };
    let Some((host, port)) = split_authority(authority, 80) else {
        respond(&mut c, "400 Bad Request", "malformed request target");
        return Ok(());
    };
    let host = norm_host(&host);
    if let Some((_, hv)) = head.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")) {
        let hh = split_authority(hv, 80).map(|(h, p)| (norm_host(&h), p));
        if hh != Some((host.clone(), port)) {
            respond(&mut c, "400 Bad Request", "Host header does not match the request target");
            return Ok(());
        }
    }
    match decide(d, guard, &host, port) {
        Err(dec) => {
            respond(&mut c, "403 Forbidden", &format!("{} ({}/{})", dec.reason, dec.policy, dec.rule_id));
            event(&host, port, dec);
        }
        Ok((addrs, dec)) => match connect_checked(&addrs) {
            Ok(mut up) => {
                event(&host, port, dec);
                let mut out = format!("{} {} {}\r\n", head.method, path, head.version);
                for (k, v) in &head.headers {
                    let kl = k.to_ascii_lowercase();
                    if kl == "proxy-connection" || kl == "proxy-authorization" || kl == "connection" {
                        continue;
                    }
                    out.push_str(&format!("{k}: {v}\r\n"));
                }
                out.push_str("Connection: close\r\n\r\n");
                up.write_all(out.as_bytes())?;
                up.write_all(&head.rest)?;
                c.set_read_timeout(None)?;
                splice(c, up);
            }
            Err(e) => {
                event(&host, port, dec);
                respond(&mut c, "502 Bad Gateway", &format!("connect to {host}:{port} failed: {e}"));
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests;
