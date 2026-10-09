//! HTTPS to the fleet server with `/usr/bin/curl` (docs/design/fleet.md):
//! the system's TLS, no TLS library in AgentACL. The device key and the URL
//! go in a curl config on standard input, never on the command line; the
//! request body is in a root-only temporary file.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

pub struct Http {
    pub server: String,
    /// An HTTP(S) proxy the network needs, if any.
    pub proxy: Option<String>,
    /// Folder for request bodies (root-only).
    pub tmp: std::path::PathBuf,
}

/// Whether `/usr/bin/curl` can use the system trust store (a company CA
/// installed on the Mac); curl silently falls back to its own CA list.
pub fn system_trust() -> bool {
    Command::new("/usr/bin/curl").arg("-V").output().is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("SecureTransport"))
}

/// Plain HTTP only to this Mac (tests); everything else is HTTPS.
pub fn check_url(server: &str) -> Result<()> {
    let ok = server.starts_with("https://") || server.starts_with("http://127.0.0.1:") || server.starts_with("http://localhost:");
    if !ok || server.contains(['"', '\\', '\n', '\r', ' ']) {
        bail!("the server URL must start with https:// (got {server:?})");
    }
    Ok(())
}

/// A proxy URL: http(s), no spaces, quotes or control characters (it goes
/// into curl's config).
pub fn check_proxy(proxy: &str) -> Result<()> {
    let ok = (proxy.starts_with("http://") || proxy.starts_with("https://")) && !proxy.chars().any(|c| c.is_control() || c.is_whitespace() || c == '"' || c == '\\');
    if !ok {
        bail!("the proxy must be an http:// or https:// URL (got {proxy:?})");
    }
    Ok(())
}

/// A curl config line value: quoted, with `\` and `"` escaped.
fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

impl Http {
    /// `method` to `path` on the server; returns the status and the body
    /// (at most [`agentacl_fleet::MAX_BODY`] bytes).
    pub fn request(&self, method: &str, path: &str, key: Option<&str>, body: Option<&[u8]>) -> Result<(u16, Vec<u8>)> {
        check_url(&self.server)?;
        let mut cfg = String::new();
        cfg.push_str(&format!("url = {}\n", quote(&format!("{}{path}", self.server.trim_end_matches('/')))));
        cfg.push_str(&format!("request = {}\n", quote(method)));
        cfg.push_str("header = \"Content-Type: application/json\"\n");
        if let Some(k) = key {
            if !k.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("malformed device key");
            }
            cfg.push_str(&format!("header = \"Authorization: Bearer {k}\"\n"));
        }
        if let Some(p) = &self.proxy {
            check_proxy(p)?;
            cfg.push_str(&format!("proxy = {}\n", quote(p)));
        }
        let body_file = match body {
            Some(b) => {
                std::fs::create_dir_all(&self.tmp)?;
                let p = self.tmp.join(format!("req-{}.json", std::process::id()));
                let _ = std::fs::remove_file(&p);
                let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&p).with_context(|| format!("writing {}", p.display()))?;
                f.write_all(b)?;
                cfg.push_str(&format!("data-binary = {}\n", quote(&format!("@{}", p.display()))));
                Some(p)
            }
            None => None,
        };
        let result = self.run(&cfg);
        if let Some(p) = body_file {
            let _ = std::fs::remove_file(p);
        }
        result
    }

    fn run(&self, cfg: &str) -> Result<(u16, Vec<u8>)> {
        let mut cmd = Command::new("/usr/bin/curl");
        // -q first: no ~/.curlrc. No redirects, HTTPS only (or local HTTP).
        let proto = if self.server.starts_with("https://") { "=https" } else { "=http" };
        cmd.args(["-q", "-sS", "--proto", proto, "--max-redirs", "0", "--connect-timeout", "15", "--max-time", "120", "-w", "\n%{http_code}", "-K", "-"]);
        cmd.env_clear().env("PATH", "/usr/bin:/bin");
        if system_trust() {
            cmd.env("CURL_SSL_BACKEND", "secure-transport");
        }
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().context("running /usr/bin/curl")?;
        child.stdin.take().context("curl stdin")?.write_all(cfg.as_bytes())?;
        let mut out = Vec::new();
        child.stdout.take().context("curl stdout")?.take(agentacl_fleet::MAX_BODY as u64 + 16).read_to_end(&mut out)?;
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.by_ref().take(4096).read_to_string(&mut err);
        }
        let status = child.wait()?;
        if out.len() > agentacl_fleet::MAX_BODY + 8 {
            let _ = child.kill();
            bail!("the server's response is too large");
        }
        if !status.success() {
            bail!("connecting to {}: {}", self.server, err.trim());
        }
        let split = out.iter().rposition(|b| *b == b'\n').context("no status from curl")?;
        let code: u16 = String::from_utf8_lossy(&out[split + 1..]).trim().parse().context("no status from curl")?;
        out.truncate(split);
        Ok((code, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_quoting() {
        assert!(check_url("https://fleet.example.com").is_ok());
        assert!(check_url("http://127.0.0.1:8080").is_ok());
        assert!(check_url("http://fleet.example.com").is_err(), "plain HTTP elsewhere");
        assert!(check_url("https://x\"\nheader = \"Evil: 1").is_err());
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert!(check_proxy("http://proxy.corp:3128").is_ok());
        assert!(check_proxy("http://p:1\noutput = /etc/x").is_err(), "no config injection");
    }

    #[test]
    fn talks_to_a_local_server() {
        let server = tiny_http_like_server();
        let tmp = tempfile::tempdir().unwrap();
        let h = Http { server: format!("http://127.0.0.1:{}", server.0), proxy: None, tmp: tmp.path().to_path_buf() };
        let (code, body) = h.request("POST", "/api/v1/report", Some("abc123"), Some(b"{\"x\":1}")).unwrap();
        assert_eq!(code, 201);
        let seen = server.1.join().unwrap();
        assert!(seen.contains("Authorization: Bearer abc123") && seen.ends_with("{\"x\":1}"), "{seen}");
        assert_eq!(body, b"ok");
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0, "the body file is removed");
    }

    /// One HTTP exchange on a local port: returns (port, what it received).
    fn tiny_http_like_server() -> (u16, std::thread::JoinHandle<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_millis(500))).unwrap();
            let mut buf = vec![0u8; 8192];
            let mut got = Vec::new();
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&got).contains("{\"x\":1}") {
                    break;
                }
            }
            s.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").unwrap();
            String::from_utf8_lossy(&got).into_owned()
        });
        (port, h)
    }
}
