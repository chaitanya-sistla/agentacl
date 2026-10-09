//! `agentacl-server`: the AgentACL fleet server (docs/design/fleet.md).
//!
//! ```text
//! agentacl-server init  --db PATH                 set the admin password
//! agentacl-server token --db PATH --name NAME [--days 30] [--max 50]
//!                                                 print a new enrollment token
//! agentacl-server policy --db PATH --file FILE    validate and publish a
//!                                                 company policy
//! agentacl-server serve --db PATH [--listen 127.0.0.1:8080]
//!                       [--public-url https://fleet.example.com]
//!                       [--trusted-proxy 127.0.0.1]... [--retention-days 90]
//!                       [--insecure-cookies]      (plain-HTTP testing only)
//! ```
//!
//! Serve it behind a TLS reverse proxy (deploy/fleet/docker-compose.yml).

mod api;
mod auth;
mod db;
mod html;
mod web;

use anyhow::{bail, Context, Result};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Response, Server};

/// The largest body of any request but a device's report.
const SMALL_BODY: usize = 64 * 1024;
/// Requests handled at once; more get 503.
const MAX_CONNECTIONS: usize = 256;

pub struct Config {
    /// The URL Macs use to reach the server (shown in enrollment commands).
    pub public_url: String,
    /// Proxies whose `X-Forwarded-For` is trusted for the client address.
    pub trusted_proxies: Vec<String>,
    pub insecure_cookies: bool,
    pub retention_days: i64,
}

pub struct App {
    pub db: Mutex<db::Db>,
    pub throttle: Mutex<auth::Throttle>,
    pub rates: Mutex<api::Rates>,
    /// One password check at a time.
    pub password_check: Mutex<()>,
    pub config: Config,
}

struct Args {
    cmd: String,
    db: PathBuf,
    listen: String,
    config: Config,
    name: String,
    days: i64,
    max: i64,
    file: Option<PathBuf>,
}

fn parse_args() -> Result<Args> {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_default();
    let mut a = Args {
        cmd,
        db: PathBuf::from("agentacl-server.db"),
        listen: "127.0.0.1:8080".into(),
        config: Config { public_url: "https://fleet.example.com".into(), trusted_proxies: vec![], insecure_cookies: false, retention_days: 90 },
        name: "Macs".into(),
        days: 30,
        max: 50,
        file: None,
    };
    while let Some(k) = it.next() {
        let mut v = || it.next().with_context(|| format!("{k} needs a value"));
        match k.as_str() {
            "--db" => a.db = PathBuf::from(v()?),
            "--listen" => a.listen = v()?,
            "--public-url" => a.config.public_url = v()?.trim_end_matches('/').to_string(),
            "--trusted-proxy" => a.config.trusted_proxies.push(v()?),
            "--retention-days" => a.config.retention_days = v()?.parse().context("--retention-days")?,
            "--insecure-cookies" => a.config.insecure_cookies = true,
            "--name" => a.name = v()?,
            "--file" => a.file = Some(PathBuf::from(v()?)),
            "--days" => a.days = v()?.parse::<i64>().context("--days")?.clamp(1, 365),
            "--max" => a.max = v()?.parse::<i64>().context("--max")?.clamp(1, 100_000),
            _ => bail!("unknown argument {k}"),
        }
    }
    Ok(a)
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

/// The client's address: the connection's, or, from a trusted proxy, the
/// last address in `X-Forwarded-For` (the one the proxy added).
fn client(config: &Config, remote: Option<std::net::SocketAddr>, xff: Option<&str>) -> String {
    let ip = remote.map(|r| r.ip().to_string()).unwrap_or_default();
    let addr = if config.trusted_proxies.contains(&ip) { xff.and_then(|x| x.rsplit(',').next()).map(str::trim).filter(|s| !s.is_empty()).unwrap_or(&ip).to_string() } else { ip };
    network_of(&addr)
}

/// An IPv6 client is limited by its /64 (one user gets a whole /64).
fn network_of(addr: &str) -> String {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Ok(std::net::IpAddr::V6(v6)) => v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_default(),
        _ => addr.to_string(),
    }
}

fn serve_one(app: &App, mut req: tiny_http::Request) {
    let method = req.method().as_str().to_uppercase();
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let path = path.to_string();
    let get = |name: &str| req.headers().iter().find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name)).map(|h| h.value.as_str().to_string());
    let (auth, cookie_h, xff, ctype) = (get("Authorization"), get("Cookie"), get("X-Forwarded-For"), get("Content-Type"));
    let client = client(&app.config, req.remote_addr().copied(), xff.as_deref());
    // Bodies are capped: a larger one is refused, not truncated. Only a
    // known device may send a large one (a report); anything else, 64 KiB.
    let limit = if path == agentacl_fleet::REPORT && api::known_device(app, auth.as_deref()) { agentacl_fleet::MAX_BODY } else { SMALL_BODY };
    let mut body = Vec::new();
    if req.as_reader().take(limit as u64 + 1).read_to_end(&mut body).is_err() || body.len() > limit {
        let _ = req.respond(Response::from_string("request too large").with_status_code(413));
        return;
    }
    if path.starts_with("/api/") {
        let (status, v) = api::handle(app, &method, &path, auth.as_deref(), &body, &client);
        let r = Response::from_string(v.to_string()).with_status_code(status).with_header(header("Content-Type", "application/json")).with_header(header("Cache-Control", "no-store"));
        let _ = req.respond(r);
        return;
    }
    let form =
        if method == "POST" && ctype.as_deref().is_some_and(|c| c.starts_with("application/x-www-form-urlencoded")) { html::parse_form(&String::from_utf8_lossy(&body)) } else { Default::default() };
    let cookie = cookie_h.and_then(|c| c.split(';').map(str::trim).find_map(|kv| kv.strip_prefix(&format!("{}=", web::COOKIE)).map(str::to_string))).filter(|v| !v.is_empty());
    let r = web::Req { method: &method, path: &path, query: html::parse_form(query), form, cookie, client };
    let out = web::handle(app, &r);
    let mut resp = Response::from_string(out.body)
        .with_status_code(out.status)
        .with_header(header("Content-Type", out.content_type))
        .with_header(header("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header("Referrer-Policy", "no-referrer"))
        .with_header(header("Cache-Control", "no-store"));
    for (k, v) in out.headers {
        resp.add_header(header(&k, &v));
    }
    let _ = req.respond(resp);
}

fn main() {
    if let Err(e) = run() {
        eprintln!("agentacl-server: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let a = parse_args()?;
    match a.cmd.as_str() {
        "init" => {
            let d = db::Db::open(&a.db)?;
            let pw = auth::read_password()?;
            d.set_meta("admin_password", &auth::hash_password(&pw))?;
            // A new password ends every admin session.
            d.conn.execute("DELETE FROM admin_sessions", [])?;
            println!("Admin password set in {}.", a.db.display());
            Ok(())
        }
        "token" => {
            let d = db::Db::open(&a.db)?;
            let token = format!("aet_{}", auth::random_hex());
            let now = auth::now();
            d.add_token(&a.name, &auth::sha256_hex(&token), now, now + a.days * 86_400, a.max)?;
            eprintln!("Enrollment token \"{}\": valid {} days, for up to {} Macs. It is shown only now.", a.name, a.days, a.max);
            println!("{token}");
            Ok(())
        }
        "policy" => {
            let file = a.file.context("--file is required")?;
            let yaml = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            agentacl_fleet::validate_company_policy(&yaml).map_err(|e| anyhow::anyhow!("not published: {e}"))?;
            for w in agentacl_fleet::company_policy_warnings(&yaml) {
                eprintln!("note: {w}");
            }
            let v = db::Db::open(&a.db)?.save_policy(&yaml, auth::now())?;
            println!("Published company policy version {v}.");
            Ok(())
        }
        "serve" => {
            let d = db::Db::open(&a.db)?;
            if d.meta("admin_password")?.is_none() {
                // First start of a container: the password file is a secret.
                if std::env::var_os("AGENTACL_SERVER_ADMIN_PASSWORD_FILE").is_none() {
                    bail!("no admin password yet: run `agentacl-server init --db {}` first, or set AGENTACL_SERVER_ADMIN_PASSWORD_FILE", a.db.display());
                }
                d.set_meta("admin_password", &auth::hash_password(&auth::read_password()?))?;
                eprintln!("agentacl-server: admin password set from AGENTACL_SERVER_ADMIN_PASSWORD_FILE");
            }
            let server = Arc::new(Server::http(&a.listen).map_err(|e| anyhow::anyhow!("listening on {}: {e}", a.listen))?);
            let app = Arc::new(App { db: Mutex::new(d), throttle: Mutex::default(), rates: Mutex::default(), password_check: Mutex::default(), config: a.config });
            eprintln!("agentacl-server: listening on {} (public URL {})", a.listen, app.config.public_url);
            // Daily pruning of old events.
            let pruner = app.clone();
            std::thread::spawn(move || loop {
                let before = auth::now() - pruner.config.retention_days * 86_400;
                if let Err(e) = pruner.db.lock().unwrap_or_else(|p| p.into_inner()).prune_events(before) {
                    eprintln!("agentacl-server: pruning: {e:#}");
                }
                std::thread::sleep(std::time::Duration::from_secs(86_400));
            });
            // A thread per request (bounded): a client that sends its body
            // slowly holds only its own thread, never the others'. Behind
            // Caddy, its timeouts bound that too (deploy/fleet/Caddyfile).
            let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            for req in server.incoming_requests() {
                use std::sync::atomic::Ordering::SeqCst;
                if active.fetch_add(1, SeqCst) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, SeqCst);
                    let _ = req.respond(Response::from_string("busy").with_status_code(503));
                    continue;
                }
                let (app, active) = (app.clone(), active.clone());
                std::thread::spawn(move || {
                    serve_one(&app, req);
                    active.fetch_sub(1, SeqCst);
                });
            }
            Ok(())
        }
        _ => bail!("usage: agentacl-server init|token|policy|serve --db PATH [options]; see docs/fleet.md"),
    }
}

#[cfg(test)]
mod tests;
