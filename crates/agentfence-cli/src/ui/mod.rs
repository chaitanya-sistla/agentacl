//! `agentfence ui`: local policy UI (docs/ui.md). Security model, §5:
//! - loopback only; `Host` must be exactly `127.0.0.1:PORT`
//! - the URL carries a single-use 60 s bootstrap code; the page exchanges it
//!   for a session token set as an HttpOnly SameSite=Strict cookie named per
//!   port; API calls also need the `X-AgentFence: 1` header (a cross-site
//!   page can't send it without a refused CORS preflight); a replayed code
//!   revokes all tokens and stops the server
//! - every POST needs `Origin: http://127.0.0.1:PORT` and a JSON body; no CORS
//! - strict CSP; all dynamic text is inserted with textContent

mod api;
mod files;

use agentfence_core::audit::{EventContext, Store};
use agentfence_core::config::Paths;
use anyhow::{Context, Result};
use std::io::{BufRead, Read};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server};

// Built from `crates/agentfence-cli/web` (`npm run build`); committed so a
// plain `cargo build` needs no Node toolchain.
const INDEX_HTML: &str = include_str!("dist/index.html");
const APP_JS: &str = include_str!("dist/assets/app.js");
const APP_CSS: &str = include_str!("dist/assets/app.css");
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
const CODE_TTL: Duration = Duration::from_secs(60);

pub struct UiState {
    pub paths: Paths,
    pub port: u16,
    pub ctx: EventContext,
    pub store: Mutex<Store>,
    auth: Mutex<Auth>,
    /// Cached agent discovery (hashing binaries takes a moment).
    pub discover_cache: Mutex<Option<(Instant, serde_json::Value)>>,
    /// Stop the process when a bootstrap code is replayed (off in tests).
    exit_on_replay: bool,
}

#[derive(Default)]
struct Auth {
    /// (code, minted at, used)
    codes: Vec<(String, Instant, bool)>,
    token: Option<String>,
}

fn random_hex(n: usize) -> Result<String> {
    let mut b = vec![0u8; n];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(hex::encode(b))
}

impl UiState {
    /// Mints a single-use bootstrap code (valid 60 s).
    pub fn mint_code(&self) -> Result<String> {
        let code = random_hex(16)?;
        self.auth.lock().unwrap().codes.push((code.clone(), Instant::now(), false));
        Ok(code)
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub struct UiOptions {
    pub port: u16,
    pub open: bool,
}

pub fn run(paths: Paths, opts: UiOptions) -> Result<i32> {
    let server = Server::http(("127.0.0.1", opts.port)).map_err(|e| anyhow::anyhow!("binding 127.0.0.1:{}: {e}", opts.port))?;
    let port = server.server_addr().to_ip().context("server address")?.port();
    let human = agentfence_core::identity::human()?;
    let ctx = EventContext {
        human: human.user.clone(),
        machine: agentfence_core::proc::machine_id().unwrap_or_else(|_| "mch_unknown".into()),
        agent: "agentfence-ui".into(),
        agent_version: Some(env!("CARGO_PKG_VERSION").into()),
        session: format!("ui_{}", random_hex(8)?),
        backend: "seatbelt".into(),
    };
    agentfence_core::config::ensure_private_dir(&paths.state_dir)?;
    let store = Store::open(&paths.db_path)?;
    let state = Arc::new(UiState { paths: paths.clone(), port, ctx, store: Mutex::new(store), auth: Mutex::new(Auth::default()), discover_cache: Mutex::new(None), exit_on_replay: true });

    // Tell supervisors' proxies which port to refuse (ui.md §5).
    let lock = paths.state_dir.join(format!("ui-{}.json", std::process::id()));
    std::fs::write(&lock, serde_json::json!({ "pid": std::process::id(), "port": port, "started": agentfence_core::audit::now_rfc3339() }).to_string())?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600))?;
    }
    let _cleanup = LockGuard(lock);

    let open_new_tab = {
        let state = state.clone();
        move |open: bool| -> Result<()> {
            let code = state.mint_code()?;
            let url = format!("http://127.0.0.1:{}/#code={code}", state.port);
            // Always print the link too, in case the browser can't be opened.
            eprintln!("  {url}");
            if open {
                let _ = std::process::Command::new("/usr/bin/open").arg(&url).status();
            }
            Ok(())
        }
    };
    eprintln!("AgentFence console running at http://127.0.0.1:{port}  —  press Enter to open it again, Ctrl-C to stop.");
    open_new_tab(opts.open)?;
    {
        let open_new_tab = open_new_tab.clone();
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            for _ in stdin.lock().lines().map_while(Result::ok) {
                let _ = open_new_tab(true);
            }
        });
    }
    // Ctrl-C: remove the lock file via the guard.
    install_sigint_exit();

    for req in server.incoming_requests() {
        let st = state.clone();
        std::thread::spawn(move || handle(&st, req));
        if SHOULD_EXIT.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
    }
    Ok(0)
}

static SHOULD_EXIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

struct LockGuard(std::path::PathBuf);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

static LOCK_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
extern "C" fn on_sigint(_: libc::c_int) {
    // Async-signal-safe enough for our purpose: best-effort unlink, then exit.
    if let Ok(g) = LOCK_PATH.try_lock() {
        if let Some(p) = g.as_ref() {
            if let Ok(c) = std::ffi::CString::new(p.to_string_lossy().as_bytes()) {
                unsafe { libc::unlink(c.as_ptr()) };
            }
        }
    }
    unsafe { libc::_exit(0) };
}

fn install_sigint_exit() {
    *LOCK_PATH.lock().unwrap() = Some(std::path::PathBuf::from(format!(
        "{}/ui-{}.json",
        Paths::from_env().map(|p| p.state_dir.to_string_lossy().into_owned()).unwrap_or_default(),
        std::process::id()
    )));
    // SAFETY: handler only unlinks and _exits.
    unsafe {
        let h = on_sigint as extern "C" fn(libc::c_int) as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, h);
        libc::signal(libc::SIGTERM, h);
    }
}

/// Live sessions whose supervisor predates the UI-port block (shown in the UI).
pub fn old_supervisor_sessions(state: &UiState) -> Vec<String> {
    let Ok(sessions) = state.store.lock().unwrap().active_sessions() else { return vec![] };
    sessions
        .into_iter()
        .filter(|s| {
            let v: serde_json::Value = serde_json::from_str(&s.identity_json).unwrap_or_default();
            !v["features"].as_array().is_some_and(|f| f.iter().any(|x| x == "ui-port-deny")) && agentfence_core::proc::facts(s.supervisor_pid).is_some()
        })
        .map(|s| s.session_id)
        .collect()
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

fn security_headers<R: Read>(mut r: Response<R>) -> Response<R> {
    for (k, v) in [
        ("Content-Security-Policy", CSP),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
        ("X-Frame-Options", "DENY"),
    ] {
        r.add_header(header(k, v));
    }
    r
}

pub fn json_response(status: u16, v: &serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let r = Response::from_string(v.to_string()).with_status_code(status).with_header(header("Content-Type", "application/json"));
    security_headers(r)
}

fn text(status: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(status, &serde_json::json!({ "error": msg }))
}

fn get_header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers().iter().find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name)).map(|h| h.value.as_str())
}

fn handle(state: &Arc<UiState>, mut req: Request) {
    let resp = route(state, &mut req);
    let _ = req.respond(resp);
}

fn route(state: &Arc<UiState>, req: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let origin_self = format!("http://127.0.0.1:{}", state.port);
    // DNS rebinding: the Host must be exactly our loopback authority.
    if get_header(req, "Host") != Some(&format!("127.0.0.1:{}", state.port)) {
        return text(421, "misdirected request");
    }
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let method = req.method().clone();
    if method == Method::Options {
        return text(405, "method not allowed");
    }
    // Static assets (no secrets in them).
    if method == Method::Get {
        let asset = match path {
            "/" | "/index.html" => Some((INDEX_HTML, "text/html; charset=utf-8")),
            "/assets/app.js" => Some((APP_JS, "text/javascript; charset=utf-8")),
            "/assets/app.css" => Some((APP_CSS, "text/css; charset=utf-8")),
            _ => None,
        };
        if let Some((body, ct)) = asset {
            return security_headers(Response::from_string(body).with_header(header("Content-Type", ct)));
        }
    }
    if !path.starts_with("/api/") {
        return text(404, "not found");
    }
    if method == Method::Post {
        if get_header(req, "Origin") != Some(origin_self.as_str()) {
            return text(403, "cross-origin request refused");
        }
        if !get_header(req, "Content-Type").is_some_and(|c| c.starts_with("application/json")) {
            return text(415, "JSON body required");
        }
    }
    let mut body = String::new();
    if method == Method::Post && req.as_reader().take(4 * 1024 * 1024).read_to_string(&mut body).is_err() {
        return text(400, "unreadable body");
    }
    let body: serde_json::Value = if body.is_empty() { serde_json::Value::Null } else {
        match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(_) => return text(400, "invalid JSON"),
        }
    };

    if method == Method::Post && path == "/api/session" {
        return exchange_code(state, &body);
    }
    // Session: an HttpOnly SameSite=Strict cookie plus a custom header that a
    // cross-origin page can't send without a (refused) CORS preflight; or a
    // bearer token (tests, scripts). A present Origin must be our own.
    if let Some(o) = get_header(req, "Origin") {
        if o != origin_self {
            return text(403, "cross-origin request refused");
        }
    }
    let cookie_name = session_cookie(state.port);
    let authed = {
        let a = state.auth.lock().unwrap();
        let Some(tok) = &a.token else { return text(401, "unauthorized") };
        let bearer = get_header(req, "Authorization").and_then(|h| h.strip_prefix("Bearer ")).is_some_and(|t| ct_eq(t, tok));
        let cookie = get_header(req, "Cookie")
            .and_then(|c| c.split(';').map(str::trim).find_map(|kv| kv.strip_prefix(&cookie_name).and_then(|v| v.strip_prefix('='))))
            .is_some_and(|t| ct_eq(t, tok));
        bearer || (cookie && get_header(req, "X-AgentFence") == Some("1"))
    };
    if !authed {
        return text(401, "unauthorized");
    }
    let q: std::collections::HashMap<String, String> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), percent_decode(v)))
        .collect();
    match api::dispatch(state, &method, path, &q, &body) {
        Ok((status, v)) => json_response(status, &v),
        Err(e) => text(400, &format!("{e:#}")),
    }
}

fn exchange_code(state: &Arc<UiState>, body: &serde_json::Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let Some(code) = body["code"].as_str() else { return text(400, "code required") };
    let mut a = state.auth.lock().unwrap();
    let pos = a.codes.iter().position(|(c, _, _)| ct_eq(c, code));
    match pos {
        Some(i) if a.codes[i].2 => {
            // Replay: someone else redeemed or is replaying this link.
            a.token = None;
            a.codes.clear();
            drop(a);
            if let Ok(s) = state.store.lock() {
                let _ = s.record_ui(&state.ctx, "ui.code_replay", "bootstrap code", "a UI link was used twice; tokens revoked and the UI stopped");
            }
            eprintln!("A console link was used twice (possible interception). All access revoked; the console stopped.");
            if state.exit_on_replay {
            SHOULD_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                std::process::exit(3);
            });
            }
            text(401, "this link was already used — possible interception; the UI has stopped")
        }
        Some(i) if a.codes[i].1.elapsed() <= CODE_TTL => {
            a.codes[i].2 = true;
            let token = match random_hex(32) {
                Ok(t) => t,
                Err(_) => return text(500, "no randomness"),
            };
            a.token = Some(token.clone());
            // The token only travels in the cookie, never to page script.
            let mut r = json_response(200, &serde_json::json!({ "ok": true }));
            r.add_header(header("Set-Cookie", &format!("{}={token}; HttpOnly; SameSite=Strict; Path=/", session_cookie(state.port))));
            r
        }
        _ => text(401, "link expired; press Enter in the agentfence ui terminal for a new one"),
    }
}

/// Browsers send cookies to every port of a host, so the name carries ours.
fn session_cookie(port: u16) -> String {
    format!("af_session_{port}")
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Starts a server on an ephemeral port without the browser, lock file or
/// signal handlers (tests).
#[cfg(test)]
pub fn start_for_test(paths: Paths) -> Result<Arc<UiState>> {
    let server = Server::http(("127.0.0.1", 0)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let port = server.server_addr().to_ip().context("addr")?.port();
    let ctx = EventContext { human: "t".into(), machine: "m".into(), agent: "agentfence-ui".into(), agent_version: None, session: "ui_test".into(), backend: "seatbelt".into() };
    agentfence_core::config::ensure_private_dir(&paths.state_dir)?;
    let store = Store::open(&paths.db_path)?;
    let state = Arc::new(UiState { paths, port, ctx, store: Mutex::new(store), auth: Mutex::new(Auth::default()), discover_cache: Mutex::new(None), exit_on_replay: false });
    let st = state.clone();
    std::thread::spawn(move || {
        for req in server.incoming_requests() {
            let st = st.clone();
            std::thread::spawn(move || handle(&st, req));
        }
    });
    Ok(state)
}

#[cfg(test)]
mod tests;
