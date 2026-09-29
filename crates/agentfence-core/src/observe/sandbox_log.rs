//! Kernel Seatbelt denials, read from the unified log (macos-enforcement §2.3).
//!
//! Only lines emitted by the kernel (`processID == 0`) whose message starts
//! with `Sandbox: ` are accepted; any process can `os_log` a lookalike line
//! (threat T15a). [`KernelDenial`] can only be constructed by the parser, and
//! it is the only input to an enforced kernel event.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};

pub const LOG_PREDICATE: &str = "processIdentifier == 0 AND sender == \"Sandbox\"";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelDenial {
    proc_name: String,
    pid: i32,
    op: String,
    target: String,
}

impl KernelDenial {
    pub fn proc_name(&self) -> &str {
        &self.proc_name
    }
    pub fn pid(&self) -> i32 {
        self.pid
    }
    pub fn op(&self) -> &str {
        &self.op
    }
    /// The operation's target: a path, `local:*:port`, a Mach service name…
    pub fn target(&self) -> &str {
        &self.target
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLine {
    Denial(KernelDenial),
    Duplicate { n: u32, of: KernelDenial },
    /// A kernel Sandbox line we could not parse (reported as backend_warning).
    Unparsed(String),
    Ignored,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(rename = "processID")]
    process_id: Option<i64>,
    #[serde(rename = "eventMessage")]
    event_message: Option<String>,
}

/// `cat(22304) deny(1) file-read-data /x` → denial.
fn parse_body(body: &str) -> Option<KernelDenial> {
    let di = body.find(") deny(")?;
    let head = &body[..di]; // "cat(22304" — the name itself may contain parens
    let open = head.rfind('(')?;
    let proc_name = head[..open].to_string();
    let pid: i32 = head[open + 1..].parse().ok()?;
    let rest = &body[di + ") deny(".len()..];
    let close = rest.find(") ")?;
    let rest = &rest[close + 2..];
    let (op, target) = match rest.split_once(' ') {
        Some((op, t)) => (op.to_string(), t.to_string()),
        None => (rest.to_string(), String::new()),
    };
    if op.is_empty() || !op.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '*') {
        return None;
    }
    Some(KernelDenial { proc_name, pid, op, target })
}

pub fn parse_ndjson_line(line: &str) -> LogLine {
    let Ok(raw) = serde_json::from_str::<Raw>(line) else { return LogLine::Ignored };
    if raw.process_id != Some(0) {
        return LogLine::Ignored;
    }
    let Some(msg) = raw.event_message else { return LogLine::Ignored };
    if let Some(body) = msg.strip_prefix("Sandbox: ") {
        return parse_body(body).map(LogLine::Denial).unwrap_or(LogLine::Unparsed(msg.clone()));
    }
    // "N duplicate report(s) for Sandbox: …"
    if let Some((n, rest)) = msg.split_once(" duplicate report") {
        if let (Ok(n), Some(body)) = (n.parse::<u32>(), rest.split_once("for Sandbox: ").map(|x| x.1)) {
            return parse_body(body).map(|of| LogLine::Duplicate { n, of }).unwrap_or(LogLine::Unparsed(msg.clone()));
        }
    }
    LogLine::Ignored
}

/// Event vocabulary for a kernel operation: (action, resource).
pub fn describe(d: &KernelDenial) -> (String, String) {
    let op = d.op();
    let t = d.target();
    let action = if op.starts_with("file-read") {
        "filesystem.read".to_string()
    } else if op.starts_with("file-write") || op == "file-link" {
        "filesystem.write".to_string()
    } else if op.starts_with("process-exec") {
        "process.exec".to_string()
    } else if op == "network-outbound" {
        "network.connect".to_string()
    } else if op == "network-bind" || op == "network-inbound" {
        "network.listen".to_string()
    } else if op == "mach-lookup" {
        "ipc.mach-lookup".to_string()
    } else {
        format!("sandbox.{op}")
    };
    let resource = t.strip_prefix("path:").map(|s| s.split(' ').next().unwrap_or(s)).unwrap_or(t).to_string();
    (action, resource)
}

/// Maps a kernel file operation to the policy write-op it corresponds to.
pub fn write_op(op: &str) -> agentfence_policy::WriteOp {
    use agentfence_policy::WriteOp::*;
    match op {
        "file-write-unlink" => Unlink,
        "file-write-create" => Create,
        "file-link" => Link,
        "file-write-mode" | "file-write-owner" | "file-write-flags" | "file-write-times" | "file-write-xattr" | "file-write-setugid" => Meta,
        _ => Write,
    }
}

pub struct SandboxLogObserver {
    child: Child,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl SandboxLogObserver {
    pub fn start(on_line: impl Fn(LogLine) + Send + 'static) -> Result<Self> {
        let mut child = Command::new("/usr/bin/log")
            .args(["stream", "--style", "ndjson", "--level", "default", "--predicate", LOG_PREDICATE])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("starting `log stream` for sandbox denials")?;
        let out = child.stdout.take().expect("piped");
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let parsed = parse_ndjson_line(&line);
                if parsed != LogLine::Ignored {
                    on_line(parsed);
                }
            }
        });
        Ok(SandboxLogObserver { child, reader: Some(reader) })
    }

    pub fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }
}

impl Drop for SandboxLogObserver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Produces one kernel denial of a read of `path` (which must exist; denials
/// of missing files are not reported). Used to know the log stream is live
/// and drained (plan review 2 §2).
pub fn trigger_sentinel(path: &Path) -> Result<()> {
    let p = path.to_string_lossy();
    anyhow::ensure!(!p.contains('"') && !p.contains('\\'), "unsafe sentinel path");
    let profile = format!("(version 1)(allow default)(deny file-read-data (literal \"{p}\"))");
    let _ = Command::new("/usr/bin/sandbox-exec").args(["-p", &profile, "/bin/cat"]).arg(path).stdout(Stdio::null()).stderr(Stdio::null()).status()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REAL: &str = r#"{"processImagePath":"\/kernel","senderImagePath":"\/System\/Library\/Extensions\/Sandbox.kext\/Contents\/MacOS\/Sandbox","eventMessage":"Sandbox: cat(22304) deny(1) file-read-data \/private\/tmp\/a b\/.env","processID":0}"#;

    #[test]
    fn parses_real_kernel_line() {
        let LogLine::Denial(d) = parse_ndjson_line(REAL) else { panic!() };
        assert_eq!((d.proc_name(), d.pid(), d.op(), d.target()), ("cat", 22304, "file-read-data", "/private/tmp/a b/.env"));
        assert_eq!(describe(&d), ("filesystem.read".into(), "/private/tmp/a b/.env".into()));
    }

    #[test]
    fn forged_line_from_userspace_is_ignored() {
        let forged = REAL.replace("\"processID\":0", "\"processID\":24017");
        assert_eq!(parse_ndjson_line(&forged), LogLine::Ignored);
        let nopid = REAL.replace(",\"processID\":0", "");
        assert_eq!(parse_ndjson_line(&nopid), LogLine::Ignored);
    }

    #[test]
    fn other_lines() {
        let sp = r#"{"eventMessage":"System Policy: Python(25511) deny(1) file-read-data \/x","processID":0}"#;
        assert_eq!(parse_ndjson_line(sp), LogLine::Ignored);
        assert_eq!(parse_ndjson_line("Filtering the log data using \"x\""), LogLine::Ignored);
        let dup = r#"{"eventMessage":"41 duplicate reports for Sandbox: cat(22304) deny(1) file-read-data \/x","processID":0}"#;
        let LogLine::Duplicate { n, of } = parse_ndjson_line(dup) else { panic!() };
        assert_eq!((n, of.pid()), (41, 22304));
        let one = r#"{"eventMessage":"1 duplicate report for Sandbox: cat(7) deny(1) file-read-data \/x","processID":0}"#;
        assert!(matches!(parse_ndjson_line(one), LogLine::Duplicate { n: 1, .. }));
        let bad = r#"{"eventMessage":"Sandbox: garbage","processID":0}"#;
        assert!(matches!(parse_ndjson_line(bad), LogLine::Unparsed(_)));
    }

    #[test]
    fn names_with_parens_and_other_ops() {
        let l = r#"{"eventMessage":"Sandbox: Codex (Service)(123) deny(1) mach-lookup com.apple.pasteboard.1","processID":0}"#;
        let LogLine::Denial(d) = parse_ndjson_line(l) else { panic!() };
        assert_eq!((d.proc_name(), d.pid()), ("Codex (Service)", 123));
        assert_eq!(describe(&d), ("ipc.mach-lookup".into(), "com.apple.pasteboard.1".into()));
        let io = r#"{"eventMessage":"Sandbox: sh(9) deny(1) file-ioctl path:\/dev\/dtracehelper ioctl-command:(_IO x)","processID":0}"#;
        let LogLine::Denial(d) = parse_ndjson_line(io) else { panic!() };
        assert_eq!(describe(&d), ("sandbox.file-ioctl".into(), "/dev/dtracehelper".into()));
        let nb = r#"{"eventMessage":"Sandbox: nc(9) deny(1) network-bind local:*:18777","processID":0}"#;
        let LogLine::Denial(d) = parse_ndjson_line(nb) else { panic!() };
        assert_eq!(describe(&d).0, "network.listen");
    }

    #[test]
    fn live_denial_is_observed() {
        let dir = tempfile::tempdir().unwrap();
        let target = std::fs::canonicalize(dir.path()).unwrap().join("sentinel");
        std::fs::write(&target, "x").unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let want = target.to_string_lossy().into_owned();
        let obs = SandboxLogObserver::start(move |l| {
            if let LogLine::Denial(d) = l {
                if d.target() == want {
                    let _ = tx.send(d.pid());
                }
            }
        })
        .unwrap();
        // The stream needs a moment to attach; retry the trigger until seen.
        let mut seen = false;
        for _ in 0..10 {
            trigger_sentinel(&target).unwrap();
            if rx.recv_timeout(std::time::Duration::from_millis(700)).is_ok() {
                seen = true;
                break;
            }
        }
        obs.stop();
        assert!(seen, "kernel denial not observed via log stream");
    }
}
