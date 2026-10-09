//! `agentacl audit`: what an agent session could reach, and what to fix
//! first ("revoke first, gate second, tooling third").
//!
//! Every answer comes from the same policy `agentacl run` would load for this
//! agent and project, evaluated deterministically. The report never contains
//! a secret value: only names (of files, variables, servers and hosts).

use crate::access;
use crate::config::Paths;
use crate::netlive;
use crate::supervisor::{
    self,
    env::{glob_match, SECRET_ENV},
};
use agentacl_policy::set::PolicySet;
use agentacl_policy::{Action, Decision, Effect, PolicyEngine, Request, Resource, Subject};
use anyhow::Result;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Info,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub fix: String,
}

/// One thing checked, and how it stands for this agent.
#[derive(Debug, Clone, Serialize)]
pub struct Item {
    pub name: String,
    /// protected | readable | blocked | reachable | asks | granted | passed | withheld | inside-sandbox | remote
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub agent: String,
    pub project: String,
    pub findings: Vec<Finding>,
    pub credentials: Vec<Item>,
    pub cloud_drives: Vec<Item>,
    pub data_services: Vec<Item>,
    pub mcp_servers: Vec<Item>,
    pub keychain: Item,
    pub environment: Vec<Item>,
    pub sockets: Vec<Item>,
    pub grants: Vec<Item>,
    pub network_mode: String,
}

impl Report {
    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }
}

pub struct Inputs<'a> {
    pub paths: &'a Paths,
    pub agent: &'a str,
    pub project: &'a Path,
    pub home: &'a Path,
    /// The environment `agentacl run` would start from.
    pub env: &'a [(String, String)],
}

/// Credential files and folders: (path under home, what it is).
const CREDENTIALS: &[(&str, &str)] = &[
    (".ssh", "SSH keys"),
    (".aws/credentials", "AWS credentials"),
    (".aws/sso/cache", "AWS SSO session"),
    (".config/gcloud", "Google Cloud (gcloud) login"),
    (".azure", "Azure CLI login"),
    (".kube/config", "Kubernetes config"),
    (".config/gh/hosts.yml", "GitHub CLI login"),
    (".git-credentials", "Git saved passwords"),
    (".netrc", ".netrc passwords"),
    (".npmrc", "npm token"),
    (".pypirc", "PyPI token"),
    (".docker/config.json", "Docker registry login"),
    (".cargo/credentials.toml", "crates.io token"),
    (".terraform.d/credentials.tfrc.json", "Terraform Cloud token"),
    (".gnupg", "GPG keys"),
];

/// Services that hold company data, by hosts their APIs use (tenant hosts
/// by an example name, so a `*.sharepoint.com` rule is caught). The proxy
/// decides per host, so reaching any of them is reaching the service.
const DATA_SERVICES: &[(&str, &[&str])] = &[
    ("Google Drive, Docs and Sheets", &["www.googleapis.com", "drive.googleapis.com", "docs.googleapis.com", "sheets.googleapis.com", "drive.google.com", "docs.google.com"]),
    ("Dropbox", &["api.dropboxapi.com", "content.dropboxapi.com", "www.dropbox.com"]),
    ("Box", &["api.box.com", "upload.box.com", "app.box.com"]),
    ("Microsoft 365 (OneDrive, SharePoint, Outlook)", &["graph.microsoft.com", "onedrive.live.com", "example.sharepoint.com", "outlook.office.com"]),
    ("Slack", &["slack.com", "files.slack.com", "example.slack.com"]),
    ("Notion", &["api.notion.com", "www.notion.so"]),
    ("Atlassian (Jira, Confluence)", &["api.atlassian.com", "example.atlassian.net"]),
    ("GitHub API", &["api.github.com", "uploads.github.com"]),
    ("Amazon S3", &["s3.amazonaws.com", "example.s3.amazonaws.com"]),
];

fn is_secret_name(k: &str) -> bool {
    let u = k.to_ascii_uppercase().replace('-', "_");
    SECRET_ENV.iter().any(|p| glob_match(p, &u)) || u == "AUTHORIZATION" || ["TOKEN", "API_KEY", "APIKEY", "SECRET", "PASSWORD", "BEARER"].iter().any(|w| u.contains(w))
}

/// Cloud-drive folder names carry an account, often an email
/// (`~/Library/CloudStorage/GoogleDrive-<account>`,
/// `/Volumes/GoogleDrive-<id>`): keep the provider, drop the account.
pub fn mask_accounts(s: &str) -> String {
    const PREFIXES: [&str; 4] = ["GoogleDrive-", "OneDrive-", "Box-", "Dropbox-"];
    let parts: Vec<&str> = s.split('/').collect();
    let mut out: Vec<String> = Vec::with_capacity(parts.len());
    for (n, c) in parts.iter().enumerate() {
        let under_storage = n > 0 && parts[n - 1] == "CloudStorage";
        let known = PREFIXES.iter().any(|p| c.starts_with(p));
        match c.split_once('-') {
            Some((provider, _)) if under_storage || known => out.push(format!("{provider}-…")),
            _ => out.push(c.to_string()),
        }
    }
    out.join("/")
}

/// The folders whose files the cloud-drives rules protect, as they exist on
/// this Mac: the storage roots, each drive, and a drive's top level
/// (Google Drive's `My Drive` and each shared drive).
fn drive_roots(home: &Path) -> Vec<PathBuf> {
    let mut roots = vec![home.join("Library/CloudStorage"), home.join("Library/Mobile Documents")];
    let with_top = |d: PathBuf, roots: &mut Vec<PathBuf>| {
        for top in ["My Drive", "Shared drives"] {
            let t = d.join(top);
            if t.is_dir() {
                if top == "Shared drives" {
                    roots.extend(std::fs::read_dir(&t).into_iter().flatten().flatten().map(|e| e.path()));
                }
                roots.push(t);
            }
        }
        roots.push(d);
    };
    for e in std::fs::read_dir(home.join("Library/CloudStorage")).into_iter().flatten().flatten() {
        with_top(e.path(), &mut roots);
    }
    for e in std::fs::read_dir(home).into_iter().flatten().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n == "Dropbox" || n.starts_with("Dropbox (") || n == "Google Drive" || n == "OneDrive" || n.starts_with("OneDrive - ") || n == "Box" || n == "Box Sync" {
            with_top(e.path(), &mut roots);
        }
    }
    for e in std::fs::read_dir("/Volumes").into_iter().flatten().flatten() {
        if e.file_name().to_string_lossy().starts_with("GoogleDrive") {
            with_top(e.path(), &mut roots);
        }
    }
    roots
}

/// A cloud-drive folder the project is (or contains), so that the
/// `${PROJECT}` exception opens it, if any.
pub fn project_opens_drive(home: &Path, project: &Path) -> Option<String> {
    drive_roots(home).into_iter().find(|r| supervisor::canon_or(r).starts_with(project)).map(|r| mask_accounts(&tilde(&r, home)))
}

fn tilde(p: &Path, home: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(r) => format!("~/{}", r.display()),
        Err(_) => p.display().to_string(),
    }
}

struct Eval<'a> {
    set: &'a PolicySet,
    subject: Subject,
}

impl Eval<'_> {
    fn read(&self, p: &Path) -> Decision {
        let path = supervisor::canon_or(p).to_string_lossy().into_owned();
        self.set.evaluate(&Request { subject: self.subject.clone(), action: Action::FsRead, resource: Resource::Path(path) })
    }
    fn write(&self, p: &Path) -> Decision {
        let path = supervisor::canon_or(p).to_string_lossy().into_owned();
        self.set.evaluate(&Request { subject: self.subject.clone(), action: Action::FsWrite(agentacl_policy::WriteOp::Write), resource: Resource::Path(path) })
    }
    fn host(&self, host: &str) -> Decision {
        self.set.evaluate(&Request { subject: self.subject.clone(), action: Action::NetConnect, resource: Resource::Host { host: host.into(), port: 443 } })
    }
}

fn rule_of(d: &Decision) -> String {
    if d.rule_id.starts_with(&format!("{}/", d.policy)) {
        d.rule_id.clone()
    } else {
        format!("{}/{}", d.policy, d.rule_id)
    }
}

pub fn report(i: &Inputs) -> Result<Report> {
    let has_env = |k: &str| i.env.iter().any(|(n, v)| n == k && !v.is_empty());
    let (set, reqs) = supervisor::load_policy_with(i.paths, i.agent, i.project, None, i.home, has_env, None)?;
    let proj = i.project.to_string_lossy().into_owned();
    let ev = Eval { set: &set, subject: Subject { agent_id: i.agent.into(), project: proj.clone(), ..Default::default() } };
    let mut findings: Vec<Finding> = vec![];
    let mut add = |severity, title: String, detail: String, fix: String| findings.push(Finding { severity, title, detail, fix });

    // ---- policy-level openings --------------------------------------------
    for g in set.disabled_groups(i.agent, &proj) {
        add(
            Severity::High,
            format!("Built-in protection `{g}` is switched off"),
            "Your policy disables it (`builtin: { disable: [...] }`), so those files are open to the agent.".into(),
            format!("Remove `{g}` from `builtin.disable` unless the agent truly needs it."),
        );
    }
    // Any file in the home folder, by an ordinary name: open means a rule
    // (or `defaults.filesystem: allow`) opens the home folder at large.
    let probe = i.home.join("agentacl-audit-probe/notes.txt");
    for (what, d) in [("read", ev.read(&probe)), ("change", ev.write(&probe))] {
        if d.effect == Effect::Allow {
            add(
                Severity::High,
                format!("The agent can {what} files across your home folder"),
                format!("Allowed by {}. Built-in protections still apply, but everything else in your home is open.", rule_of(&d)),
                "Allow the folders the agent needs instead (the project is always open), and keep `defaults.filesystem: deny`.".into(),
            );
        }
    }

    // ---- credential files ----------------------------------------------------
    let mut credentials = vec![];
    for (rel, label) in CREDENTIALS {
        let p = i.home.join(rel);
        if !p.exists() {
            continue;
        }
        let d = ev.read(&p);
        let open = d.effect == Effect::Allow;
        credentials.push(Item { name: label.to_string(), status: if open { "readable" } else { "protected" }.into(), detail: format!("{} ({})", tilde(&p, i.home), rule_of(&d)) });
        if open {
            add(
                Severity::High,
                format!("{label} readable by the agent"),
                format!("{} is allowed by {}.", tilde(&p, i.home), rule_of(&d)),
                "Remove the rule that allows it, or re-enable the built-in protection.".into(),
            );
        }
    }

    // ---- cloud drives --------------------------------------------------------
    let mut drives: Vec<(String, PathBuf)> = vec![];
    if let Ok(rd) = std::fs::read_dir(i.home.join("Library/CloudStorage")) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let provider = ["GoogleDrive", "OneDrive", "Dropbox", "Box"].iter().find(|p| n.starts_with(*p)).map(|p| match *p {
                "GoogleDrive" => "Google Drive",
                o => o,
            });
            // The folder name carries the account (an email): show the provider only.
            drives.push((provider.unwrap_or("Cloud storage").to_string(), e.path()));
        }
    }
    let icloud = i.home.join("Library/Mobile Documents/com~apple~CloudDocs");
    if icloud.exists() {
        // "Desktop & Documents" sync: the synced folders stay at ~/Desktop
        // and ~/Documents (iCloud links to them), outside the drive rules.
        for f in ["Desktop", "Documents"] {
            let link = icloud.join(f);
            if std::fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()) {
                let target = supervisor::canon_or(&link);
                let open = ev.read(&target.join(".agentacl-probe")).effect == Effect::Allow;
                add(
                    if open { Severity::High } else { Severity::Info },
                    format!("iCloud syncs your {f} folder"),
                    format!(
                        "{} is synced to iCloud but lives outside the cloud-drives protection; it is {} to the agent.",
                        tilde(&target, i.home),
                        if open { "open" } else { "closed (by the default rules)" }
                    ),
                    if open { format!("Narrow the rule that opens {}.", tilde(&target, i.home)) } else { "Nothing to do; keep rules that open your home folder narrow.".into() },
                );
            }
        }
        drives.push(("iCloud Drive".into(), icloud));
    }
    if let Ok(rd) = std::fs::read_dir(i.home) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            // The same names the built-in cloud-drives rules cover.
            let provider = if n == "Dropbox" || n.starts_with("Dropbox (") {
                "Dropbox"
            } else if n == "Google Drive" {
                "Google Drive"
            } else if n == "OneDrive" || n.starts_with("OneDrive - ") {
                "OneDrive"
            } else if n == "Box" || n == "Box Sync" {
                "Box"
            } else {
                continue;
            };
            if e.path().is_dir() {
                drives.push((provider.into(), e.path()));
            }
        }
    }
    let mut cloud_drives = vec![];
    let opened = project_opens_drive(i.home, i.project);
    if let Some(loc) = &opened {
        add(
            Severity::High,
            "The project contains a cloud drive".into(),
            format!("The project is {}, which includes {loc}. The project is always open to the agent, so the cloud-drives protection doesn't apply there.", mask_accounts(&tilde(i.project, i.home))),
            "Start agents from a project folder inside the drive (or outside it), not from the drive or a folder above it.".into(),
        );
    }
    for (name, p) in drives {
        // Resolve symlinks: a drive folder can point somewhere else.
        let real = supervisor::canon_or(&p);
        let d = ev.read(&real.join(".agentacl-probe"));
        let project_inside = i.project.starts_with(&real) && i.project != real;
        // Opened through the project itself (reported above), not by a rule.
        let via_project = opened.is_some() && (real.starts_with(i.project) || i.project.starts_with(&real));
        let open = d.effect == Effect::Allow;
        cloud_drives.push(Item {
            name: name.clone(),
            status: if open || via_project { "readable".into() } else { "protected".into() },
            detail: if via_project {
                "the project includes this drive's files".into()
            } else if project_inside && !open {
                "this project is inside it: the project stays usable, the rest is protected".into()
            } else {
                rule_of(&d)
            },
        });
        if open && !via_project {
            add(
                Severity::High,
                format!("{name} folder readable by the agent"),
                format!("Synced cloud files are allowed by {}.", rule_of(&d)),
                "Re-enable the built-in `cloud-drives` protection, or narrow the rule that allows it.".into(),
            );
        }
    }

    // ---- company data services over the network ---------------------------------
    let live = netlive::read_live(&supervisor::canon_or(&i.paths.state_dir));
    let mut data_services = vec![];
    for (label, hosts) in DATA_SERVICES {
        let rank = |s: &str| match s {
            "reachable" => 0,
            "asks" => 1,
            _ => 2,
        };
        let mut best: Option<(&str, String, Decision)> = None;
        for host in *hosts {
            let d = ev.host(host);
            let live_allow = live.rules.iter().any(|r| r.host == *host && r.effect == Effect::Allow && r.applies(i.agent, &proj));
            let live_block = live.rules.iter().any(|r| r.host == *host && r.effect == Effect::Deny && r.applies(i.agent, &proj));
            let status = if live_block {
                "blocked"
            } else if d.effect == Effect::Allow || (live_allow && d.rule_id == "default") {
                "reachable"
            } else if d.rule_id == "default" && (d.effect == Effect::Ask || live.mode == netlive::Mode::Ask) {
                "asks"
            } else {
                "blocked"
            };
            if best.as_ref().is_none_or(|(s, _, _)| rank(status) < rank(s)) {
                best = Some((status, host.to_string(), d));
            }
        }
        let Some((status, host, d)) = best else { continue };
        data_services.push(Item { name: label.to_string(), status: status.into(), detail: format!("{host} ({})", rule_of(&d)) });
        if status == "reachable" {
            add(
                Severity::Medium,
                format!("The agent can reach {label}"),
                format!(
                    "{host} is allowed ({}). With a token it holds, or one an MCP server holds, it can read and change data there; AgentACL decides per host and can't tell a read from a write.",
                    rule_of(&d)
                ),
                format!("Block {host} unless the agent's task needs it (Network page, or `network.deny`)."),
            );
        }
    }

    // ---- MCP servers -----------------------------------------------------------
    let mut mcp_servers = vec![];
    for (label, path, servers, used_by) in mcp_configs(i.home, i.project) {
        let readable = ev.read(&path).effect == Effect::Allow;
        let ours = used_by.contains(&i.agent);
        for s in servers {
            let (status, detail) = match (&s.url, ours) {
                (Some(u), true) => {
                    let host = host_of(u);
                    let d = ev.host(&host);
                    let reach = if d.effect == Effect::Allow { "reachable" } else { "blocked" };
                    ("remote".to_string(), format!("remote server at {host} ({reach}); from {label}"))
                }
                (None, true) => ("inside-sandbox".to_string(), format!("runs `{}` inside the agent's sandbox; from {label}", s.command.as_deref().unwrap_or("?"))),
                (_, false) => ("other-app".to_string(), format!("configured for another app ({label}); it runs there, outside AgentACL unless that app is started with `agentacl run`")),
            };
            mcp_servers.push(Item { name: s.name.clone(), status, detail });
            if !s.inline_secrets.is_empty() && readable {
                add(
                    Severity::High,
                    format!("Token in MCP server `{}` config is readable by the agent", s.name),
                    format!("{} holds {} in plain text, and the agent can read that file.", tilde(&path, i.home), s.inline_secrets.join(", ")),
                    "Use the server's own sign-in (OAuth) where it has one, or reference the value (e.g. `${VAR}`) instead of writing it into the file; rotate the token if the agent has run with it."
                        .into(),
                );
            }
            if let Some(u) = s.url.as_ref().filter(|_| ours) {
                let host = host_of(u);
                if ev.host(&host).effect == Effect::Allow {
                    add(
                        Severity::Info,
                        format!("Remote MCP server `{}` can receive data", s.name),
                        format!("{host} is reachable; whatever the agent sends that server leaves your Mac."),
                        "Keep only the remote servers you trust with your project's data.".into(),
                    );
                }
            }
        }
    }

    // ---- keychain ----------------------------------------------------------------
    let keychain_granted = reqs.mach_services.iter().any(|m| m == "com.apple.SecurityServer");
    let keychain = Item {
        name: "macOS keychain".into(),
        status: if keychain_granted { "granted" } else { "blocked" }.into(),
        detail: if keychain_granted { "granted for the agent's /login".into() } else { "no keychain access".into() },
    };
    if keychain_granted {
        add(
            Severity::High,
            "The agent can use your keychain".into(),
            "Its login lives in the keychain, so the session can reach it, run credential helpers other items trust (git's returns saved GitHub tokens without asking) and read the keychain database."
                .into(),
            "Run `claude setup-token` once and set CLAUDE_CODE_OAUTH_TOKEN (or ANTHROPIC_API_KEY) in the shell you run `agentacl run` from.".into(),
        );
    }

    // ---- environment and sockets ----------------------------------------------------
    let mut environment = vec![];
    let passthrough = &reqs.env_passthrough;
    for (k, v) in i.env {
        if v.is_empty() || !SECRET_ENV.iter().any(|p| glob_match(p, k)) {
            continue;
        }
        let passed = passthrough.iter().any(|p| glob_match(p, k));
        environment.push(Item {
            name: k.clone(),
            status: if passed { "passed" } else { "withheld" }.into(),
            detail: if passed { "the agent's own login, passed through".into() } else { "removed from the agent's environment".into() },
        });
    }
    environment.sort_by(|a, b| a.name.cmp(&b.name));
    let mut sockets = vec![];
    if i.env.iter().any(|(k, v)| k == "SSH_AUTH_SOCK" && !v.is_empty()) {
        sockets.push(Item { name: "ssh-agent".into(), status: "blocked".into(), detail: "SSH_AUTH_SOCK withheld and the socket denied".into() });
    }
    let docker: Vec<String> = [PathBuf::from("/var/run/docker.sock"), i.home.join(".docker/run/docker.sock")].iter().filter(|p| p.exists()).map(|p| tilde(p, i.home)).collect();
    if !docker.is_empty() {
        sockets.push(Item { name: "Docker".into(), status: "blocked".into(), detail: format!("{} denied", docker.join(", ")) });
    }

    // ---- grants from the console ---------------------------------------------------------
    let mut grants = vec![];
    for (file, _, doc) in access::list(i.paths).unwrap_or_default() {
        let s = access::scope_of(&doc);
        if s.agent.as_deref().is_some_and(|a| a != i.agent) || s.project.as_deref().is_some_and(|p| p != i.project) {
            continue;
        }
        for (section, rules) in [("read", &doc.filesystem.allow_read), ("change", &doc.filesystem.allow_write), ("site", &doc.network.allow)] {
            for r in rules {
                let folder = r.pattern.ends_with("/**");
                grants.push(Item { name: r.pattern.clone(), status: "granted".into(), detail: format!("{section}, from {file}") });
                if folder && section != "site" {
                    add(
                        Severity::Medium,
                        format!("Folder grant: {}", r.pattern.trim_end_matches("/**")),
                        "A whole folder was allowed from a request. It also covers files the agent never asked for, and allowed reads aren't recorded.".into(),
                        "Replace it with the exact files the agent needs (Agents page → Access you granted).".into(),
                    );
                }
            }
        }
    }

    findings.sort_by_key(|f| f.severity);
    // Paths can carry a drive account (`GoogleDrive-<email>`): mask everywhere.
    for f in findings.iter_mut() {
        for t in [&mut f.title, &mut f.detail, &mut f.fix] {
            *t = mask_accounts(t);
        }
    }
    let mask_items = |v: Vec<Item>| v.into_iter().map(|i| Item { name: mask_accounts(&i.name), status: i.status, detail: mask_accounts(&i.detail) }).collect::<Vec<_>>();
    let (credentials, cloud_drives, data_services, mcp_servers, grants) = (mask_items(credentials), mask_items(cloud_drives), mask_items(data_services), mask_items(mcp_servers), mask_items(grants));
    let proj = mask_accounts(&proj);
    Ok(Report {
        agent: i.agent.into(),
        project: proj,
        findings,
        credentials,
        cloud_drives,
        data_services,
        mcp_servers,
        keychain,
        environment,
        sockets,
        grants,
        network_mode: match live.mode {
            netlive::Mode::Ask => "ask".into(),
            netlive::Mode::Block => "block".into(),
        },
    })
}

fn host_of(url: &str) -> String {
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hostport = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = hostport.rsplit_once('@').map(|(_, h)| h).unwrap_or(hostport);
    if let Some(v6) = host.strip_prefix('[') {
        return v6.split(']').next().unwrap_or("").to_ascii_lowercase();
    }
    host.split(':').next().unwrap_or("").to_ascii_lowercase()
}

/// The program a command runs, without its path or arguments (arguments can
/// hold secrets: they're scanned, never shown).
fn program_name(c: &str) -> String {
    let first = c.split_whitespace().next().unwrap_or("");
    let name = Path::new(first).file_name().map(|f| f.to_string_lossy().into_owned()).unwrap_or_default();
    // Only a plain program name; anything else (`NAME=value`, odd text) could be a secret.
    if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || "._+-".contains(c)) {
        name
    } else {
        "?".into()
    }
}

/// A value that names a variable instead of holding the secret
/// (`${TOKEN}`, `Bearer ${TOKEN}`, `$TOKEN`, `${input:token}`).
fn is_reference(s: &str) -> bool {
    let b = s.as_bytes();
    s.contains("${") || b.windows(2).any(|w| w[0] == b'$' && (w[1].is_ascii_alphabetic() || w[1] == b'_'))
}

/// Secrets written into arguments: `--token VALUE`, `--api-key=VALUE`,
/// `NAME=VALUE` (e.g. `docker -e`), `--header "Authorization: Bearer …"`.
fn scan_args(words: &[String]) -> Vec<String> {
    let mut found = vec![];
    for (n, w) in words.iter().enumerate() {
        let next = words.get(n + 1);
        if w.starts_with('-') {
            let (flag, val) = match w.split_once('=') {
                Some((f, v)) => (f, Some(v.to_string())),
                None => (w.as_str(), next.filter(|x| !x.starts_with('-')).cloned()),
            };
            let flag_name = flag.trim_start_matches('-');
            if matches!(flag_name, "header" | "H") {
                if let Some((h, v)) = val.as_deref().and_then(|v| v.split_once(':')) {
                    if is_secret_name(h.trim()) && !v.trim().is_empty() && !is_reference(v) {
                        found.push(format!("header {}", h.trim()));
                    }
                }
            } else if is_secret_name(flag_name) && val.as_deref().is_some_and(|v| !v.is_empty() && !is_reference(v)) {
                found.push(format!("argument --{flag_name}"));
            }
        } else if let Some((k, v)) = w.split_once('=') {
            if !k.is_empty() && !k.contains(' ') && is_secret_name(k) && !v.is_empty() && !is_reference(v) {
                found.push(format!("argument {k}"));
            }
        }
    }
    found
}

#[derive(Debug, Default)]
struct McpServer {
    name: String,
    command: Option<String>,
    url: Option<String>,
    /// Names of secret-looking env vars or headers with a literal value.
    inline_secrets: Vec<String>,
}

fn literal(v: &serde_json::Value) -> bool {
    v.as_str().is_some_and(|s| !s.trim().is_empty() && !is_reference(s))
}

fn servers_from_json(map: Option<&serde_json::Value>) -> Vec<McpServer> {
    let Some(obj) = map.and_then(|m| m.as_object()) else { return vec![] };
    obj.iter()
        .map(|(name, v)| {
            let mut s = McpServer { name: name.clone(), ..Default::default() };
            s.command = v["command"].as_str().map(program_name);
            s.url = v["url"].as_str().or(v["httpUrl"].as_str()).or(v["serverUrl"].as_str()).map(str::to_string);
            // `--token VALUE` / `--api-key=VALUE` in the arguments or the command line.
            let mut words: Vec<String> = v["args"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
            if let Some(c) = v["command"].as_str() {
                words.extend(c.split_whitespace().map(str::to_string));
            }
            s.inline_secrets.extend(scan_args(&words));
            // `?token=…` in a URL.
            if let Some((_, q)) = s.url.as_deref().and_then(|u| u.split_once('?')) {
                for pair in q.split('&') {
                    if let Some((k, val)) = pair.split_once('=') {
                        if is_secret_name(k) && !val.is_empty() && !is_reference(val) {
                            s.inline_secrets.push(format!("URL parameter {k}"));
                        }
                    }
                }
            }
            for key in ["env", "headers", "http_headers"] {
                if let Some(o) = v[key].as_object() {
                    for (k, val) in o {
                        if is_secret_name(k) && literal(val) {
                            s.inline_secrets.push(k.clone());
                        }
                    }
                }
            }
            s
        })
        .collect()
}

/// `[mcp_servers.<name>]` tables in Codex's config.toml (enough for names,
/// command, url and literal secrets; no TOML dependency). Keys outside an
/// `mcp_servers` table are ignored.
fn servers_from_codex_toml(text: &str) -> Vec<McpServer> {
    let mut out: Vec<McpServer> = vec![];
    // The server the current table belongs to, and whether it's a secrets table.
    let mut cur: Option<usize> = None;
    let mut secrets_table = false;
    let unquote = |x: &str| x.trim().trim_matches('"').trim_matches('\'').to_string();
    for line in text.lines() {
        let t = line.split(" #").next().unwrap_or(line).trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            cur = None;
            secrets_table = false;
            let h = t.trim_start_matches('[').trim_end_matches(']').trim();
            let Some(rest) = h.strip_prefix("mcp_servers.") else { continue };
            // A quoted name may contain dots.
            let (name, sub) = if let Some(q) = rest.strip_prefix('"') {
                let end = q.find('"').unwrap_or(q.len());
                (q[..end].to_string(), q[end..].trim_start_matches('"').strip_prefix('.').map(str::to_string))
            } else {
                match rest.split_once('.') {
                    Some((n, sub)) => (n.to_string(), Some(sub.to_string())),
                    None => (rest.to_string(), None),
                }
            };
            let idx = match out.iter().position(|s| s.name == name) {
                Some(i) => i,
                None => {
                    out.push(McpServer { name, ..Default::default() });
                    out.len() - 1
                }
            };
            cur = Some(idx);
            secrets_table = matches!(sub.as_deref(), Some("env" | "http_headers" | "headers"));
            continue;
        }
        let Some(idx) = cur else { continue };
        let Some((k, v)) = t.split_once('=') else { continue };
        let (k, v) = (unquote(k), v.trim());
        let val = unquote(v);
        let literal = !val.is_empty() && !is_reference(&val);
        let s = &mut out[idx];
        if secrets_table {
            if is_secret_name(&k) && literal {
                s.inline_secrets.push(k);
            }
            continue;
        }
        match k.as_str() {
            "command" => s.command = Some(program_name(&val)),
            "url" => s.url = Some(val),
            "bearer_token" if literal => s.inline_secrets.push("bearer_token".into()),
            "args" if v.starts_with('[') => {
                let words: Vec<String> = v.trim_matches(['[', ']']).split(',').map(unquote).filter(|w| !w.is_empty()).collect();
                s.inline_secrets.extend(scan_args(&words));
            }
            "env" | "http_headers" | "headers" if v.starts_with('{') => {
                for pair in v.trim_matches(['{', '}']).split(',') {
                    if let Some((ek, ev)) = pair.split_once('=') {
                        let (ek, ev) = (unquote(ek), unquote(ev));
                        if is_secret_name(&ek) && !ev.is_empty() && !is_reference(&ev) {
                            s.inline_secrets.push(ek);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// (label, file, servers, agents that load it) for every MCP configuration found.
#[allow(clippy::type_complexity)]
fn mcp_configs(home: &Path, project: &Path) -> Vec<(String, PathBuf, Vec<McpServer>, Vec<&'static str>)> {
    let mut out = vec![];
    let read_json = |p: &Path| std::fs::read(p).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let claude = home.join(".claude.json");
    if let Some(v) = read_json(&claude) {
        let mut servers = servers_from_json(v.get("mcpServers"));
        if let Some(projects) = v["projects"].as_object() {
            for (p, pv) in projects {
                if Path::new(p) == project {
                    servers.extend(servers_from_json(pv.get("mcpServers")));
                }
            }
        }
        if !servers.is_empty() {
            out.push(("~/.claude.json".into(), claude, servers, vec!["claude-code"]));
        }
    }
    let none: &[&'static str] = &[];
    for (label, p, key, used_by) in [
        (".mcp.json (project)", project.join(".mcp.json"), "mcpServers", &["claude-code"][..]),
        (".cursor/mcp.json (project)", project.join(".cursor/mcp.json"), "mcpServers", none),
        (".gemini/settings.json (project)", project.join(".gemini/settings.json"), "mcpServers", &["gemini-cli"][..]),
        (".vscode/mcp.json (project)", project.join(".vscode/mcp.json"), "servers", none),
        ("~/.cursor/mcp.json", home.join(".cursor/mcp.json"), "mcpServers", none),
        ("~/.gemini/settings.json", home.join(".gemini/settings.json"), "mcpServers", &["gemini-cli"][..]),
        ("~/.codeium/windsurf/mcp_config.json", home.join(".codeium/windsurf/mcp_config.json"), "mcpServers", none),
        ("Claude Desktop", home.join("Library/Application Support/Claude/claude_desktop_config.json"), "mcpServers", none),
    ] {
        if let Some(v) = read_json(&p) {
            let servers = servers_from_json(v.get(key));
            if !servers.is_empty() {
                out.push((label.into(), p, servers, used_by.to_vec()));
            }
        }
    }
    let codex = home.join(".codex/config.toml");
    if let Ok(t) = std::fs::read_to_string(&codex) {
        let servers = servers_from_codex_toml(&t);
        if !servers.is_empty() {
            out.push(("~/.codex/config.toml".into(), codex, servers, vec!["codex"]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Paths, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(t.path()).unwrap();
        let home = root.join("home");
        let project = home.join("src/app");
        std::fs::create_dir_all(&project).unwrap();
        let paths = Paths::with_dirs(home.clone(), root.join("state"), root.join("config"));
        (t, paths, home, project)
    }

    fn write(p: &Path, s: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    #[test]
    fn reports_what_the_agent_can_reach_without_secret_values() {
        let (_t, paths, home, project) = setup();
        write(&home.join(".aws/credentials"), "[default]\naws_secret_access_key=FAKE-VALUE-123\n");
        write(&home.join(".ssh/id_ed25519"), "FAKE");
        write(&home.join("Library/CloudStorage/GoogleDrive-someone@example.com/My Drive/evidence.txt"), "FAKE");
        write(&home.join("Dropbox/x.txt"), "FAKE");
        write(
            &home.join(".claude.json"),
            r#"{"mcpServers":{"github":{"command":"/usr/local/bin/github-mcp","env":{"GITHUB_TOKEN":"ghp_FAKEVALUE"}},
               "docs":{"type":"http","url":"https://mcp.example.com/sse","headers":{"Authorization":"${DOCS_TOKEN}"}}},
               "projects":{"PROJECT":{"mcpServers":{"drive":{"command":"npx","env":{"GOOGLE_API_KEY":"FAKE-KEY"}}}}}}"#
                .replace("PROJECT", &project.to_string_lossy())
                .as_str(),
        );
        write(&home.join(".codex/config.toml"), "[mcp_servers.jira]\ncommand = \"jira-mcp\"\n[mcp_servers.jira.env]\nJIRA_API_TOKEN = \"FAKE\"\nOTHER = \"x\"\n");
        let env = vec![("GITHUB_TOKEN".to_string(), "FAKE".to_string()), ("ANTHROPIC_API_KEY".into(), "FAKE".into()), ("HOME".into(), home.to_string_lossy().into())];
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &project, home: &home, env: &env }).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        for secret in ["FAKE-VALUE-123", "ghp_FAKEVALUE", "FAKE-KEY", "someone@example.com"] {
            assert!(!json.contains(secret), "the report leaks {secret}");
        }
        // Credential files are protected by the built-ins.
        assert!(r.credentials.iter().any(|c| c.name == "AWS credentials" && c.status == "protected"), "{:?}", r.credentials);
        assert!(r.credentials.iter().any(|c| c.name == "SSH keys" && c.status == "protected"));
        // Cloud drives found by provider (account hidden) and protected.
        let names: Vec<&str> = r.cloud_drives.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"Google Drive") && names.contains(&"Dropbox"), "{names:?}");
        assert!(r.cloud_drives.iter().all(|d| d.status == "protected"), "{:?}", r.cloud_drives);
        // MCP: an inline token in ~/.claude.json, which Claude can read, is a high finding; a ${VAR} reference isn't.
        assert!(r.findings.iter().any(|f| f.severity == Severity::High && f.title.contains("`github`")), "{:?}", r.findings);
        assert!(r.findings.iter().any(|f| f.severity == Severity::High && f.title.contains("`drive`")), "project-scoped server: {:?}", r.findings);
        assert!(!r.findings.iter().any(|f| f.title.contains("`docs`") && f.severity == Severity::High));
        assert!(r.mcp_servers.iter().any(|s| s.name == "jira"), "codex servers: {:?}", r.mcp_servers);
        // API key in the environment: Claude gets no keychain.
        assert_eq!(r.keychain.status, "blocked");
        assert!(r.environment.iter().any(|e| e.name == "GITHUB_TOKEN" && e.status == "withheld"));
        assert!(r.environment.iter().any(|e| e.name == "ANTHROPIC_API_KEY" && e.status == "passed"));
        // Default policy: no data service is reachable.
        assert!(r.data_services.iter().all(|d| d.status != "reachable"), "{:?}", r.data_services);
    }

    #[test]
    fn flags_openings() {
        let (_t, paths, home, project) = setup();
        write(&home.join(".aws/credentials"), "FAKE");
        write(&home.join("Library/CloudStorage/OneDrive-Acme/x.txt"), "FAKE");
        write(&paths.user_policy, "version: v1\nbuiltin: { disable: [aws, cloud-drives] }\nfilesystem:\n  allow_read: [\"${HOME}/**\"]\nnetwork:\n  allow: [\"www.googleapis.com\"]\n");
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &project, home: &home, env: &[] }).unwrap();
        let titles: Vec<&str> = r.findings.iter().map(|f| f.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("`aws` is switched off")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("across your home folder")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("AWS credentials readable")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("OneDrive folder readable")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("Google Drive, Docs")), "{titles:?}");
        assert!(titles.iter().any(|t| t.contains("keychain")), "no token in the environment: {titles:?}");
        assert_eq!(r.findings[0].severity, Severity::High, "sorted most severe first");
    }

    #[test]
    fn secrets_in_commands_and_urls_are_found_not_shown() {
        let (_t, paths, home, project) = setup();
        write(
            &home.join(".claude.json"),
            r#"{"mcpServers":{"a":{"command":"npx -y server --api-key sk-LEAKME123"},
               "b":{"command":"srv","args":["--token","tok-LEAKME456"]},
               "c":{"url":"https://mcp.example.com/sse?api_key=key-LEAKME789&x=1"},
               "d":{"command":"srv","args":["--token","${MY_TOKEN}"]}}}"#,
        );
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &project, home: &home, env: &[] }).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("LEAKME"), "a secret value leaked: {json}");
        for n in ["`a`", "`b`", "`c`"] {
            assert!(r.findings.iter().any(|f| f.severity == Severity::High && f.title.contains(n)), "{n}: {:?}", r.findings);
        }
        assert!(!r.findings.iter().any(|f| f.title.contains("`d`")), "a ${{VAR}} reference is not a secret");
        assert!(r.mcp_servers.iter().any(|s| s.name == "a" && s.detail.contains("runs `npx`")), "{:?}", r.mcp_servers);
    }

    #[test]
    fn codex_toml_edge_cases() {
        let t = "[mcp_servers.one] # comment\ncommand = \"/usr/bin/one --x\"\n[mcp_servers.\"dotted.name\".env]\nGH_TOKEN = \"FAKE\"\n[profiles.p]\nurl = \"https://not-a-server.example\"\n[mcp_servers.remote]\nurl = \"https://r.example.com\"\nbearer_token = \"FAKE\"\n";
        let s = servers_from_codex_toml(t);
        let one = s.iter().find(|x| x.name == "one").unwrap();
        assert_eq!((one.command.as_deref(), one.url.as_deref()), (Some("one"), None), "a later [profiles] url isn't attached");
        assert_eq!(s.iter().find(|x| x.name == "dotted.name").unwrap().inline_secrets, vec!["GH_TOKEN"]);
        assert_eq!(s.iter().find(|x| x.name == "remote").unwrap().inline_secrets, vec!["bearer_token"]);
    }

    #[test]
    fn accounts_are_masked_and_drive_projects_flagged() {
        assert_eq!(mask_accounts("~/Library/CloudStorage/GoogleDrive-a@b.com/My Drive"), "~/Library/CloudStorage/GoogleDrive-…/My Drive");
        assert_eq!(mask_accounts("/Volumes/GoogleDrive-1234/My Drive"), "/Volumes/GoogleDrive-…/My Drive");
        assert_eq!(mask_accounts("~/Library/CloudStorage/ProtonDrive-me@proton.me/x"), "~/Library/CloudStorage/ProtonDrive-…/x");
        assert_eq!(mask_accounts("~/src/my-app"), "~/src/my-app", "other names are untouched");
        let (_t, paths, home, _project) = setup();
        write(&home.join("Library/CloudStorage/Dropbox/a.txt"), "FAKE");
        let lib = home.join("Library");
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &lib, home: &home, env: &[] }).unwrap();
        assert!(r.findings.iter().any(|f| f.severity == Severity::High && f.title.contains("contains a cloud drive")), "{:?}", r.findings);
        let drive = home.join("Library/CloudStorage/Dropbox");
        assert_eq!(project_opens_drive(&home, &drive).as_deref(), Some("~/Library/CloudStorage/Dropbox"));
        assert_eq!(project_opens_drive(&home, &drive.join("code")), None, "a folder inside a drive is fine");
    }

    #[test]
    fn wildcard_tenant_rules_and_icloud_documents() {
        let (_t, paths, home, project) = setup();
        write(&paths.user_policy, "version: v1\nfilesystem:\n  allow_read: [\"${HOME}/Documents/**\"]\nnetwork:\n  allow: [\"*.sharepoint.com\"]\n");
        std::fs::create_dir_all(home.join("Documents")).unwrap();
        std::fs::create_dir_all(home.join("Library/Mobile Documents/com~apple~CloudDocs")).unwrap();
        std::os::unix::fs::symlink(home.join("Documents"), home.join("Library/Mobile Documents/com~apple~CloudDocs/Documents")).unwrap();
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &project, home: &home, env: &[] }).unwrap();
        assert!(r.data_services.iter().any(|d| d.name.starts_with("Microsoft 365") && d.status == "reachable"), "{:?}", r.data_services);
        assert!(r.findings.iter().any(|f| f.severity == Severity::High && f.title == "iCloud syncs your Documents folder"), "{:?}", r.findings);
    }

    #[test]
    fn review_cases() {
        let (_t, paths, home, project) = setup();
        write(
            &home.join(".claude.json"),
            r#"{"mcpServers":{
               "ref":{"type":"http","url":"https://m.example.com","headers":{"Authorization":"Bearer ${MY_TOKEN}"}},
               "remote":{"command":"npx","args":["mcp-remote","https://m.example.com","--header","Authorization: Bearer sk-LEAKA"]},
               "dock":{"command":"docker","args":["run","-e","GITHUB_PERSONAL_ACCESS_TOKEN=ghp_LEAKB","img"]},
               "envcmd":{"command":"GITHUB_TOKEN=ghp_LEAKC npx srv"}}}"#,
        );
        write(&home.join("Library/Application Support/Claude/claude_desktop_config.json"), r#"{"mcpServers":{"desk":{"command":"desk-mcp"}}}"#);
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &project, home: &home, env: &[] }).unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("LEAK"), "a secret value leaked: {json}");
        let high = |n: &str| r.findings.iter().any(|f| f.severity == Severity::High && f.title.contains(n));
        assert!(!high("`ref`"), "a `Bearer ${{VAR}}` header is a reference");
        assert!(high("`remote`") && high("`dock`"), "{:?}", r.findings);
        assert!(r.mcp_servers.iter().any(|s| s.name == "envcmd" && s.detail.contains("runs `?`")), "{:?}", r.mcp_servers);
        assert!(r.mcp_servers.iter().any(|s| s.name == "desk" && s.status == "other-app"), "{:?}", r.mcp_servers);

        // A project that is a whole Google Drive.
        let my_drive = home.join("Library/CloudStorage/GoogleDrive-me@corp.com/My Drive");
        std::fs::create_dir_all(&my_drive).unwrap();
        assert!(project_opens_drive(&home, &my_drive).is_some_and(|l| l.contains("GoogleDrive-…") && !l.contains("corp.com")));
        assert!(project_opens_drive(&home, &my_drive.join("code")).is_none());
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &my_drive, home: &home, env: &[] }).unwrap();
        assert!(r.findings.iter().any(|f| f.title.contains("contains a cloud drive")), "{:?}", r.findings);
        assert!(!serde_json::to_string(&r).unwrap().contains("corp.com"), "account masked in the project field too");
        // A legacy home drive as the project.
        std::fs::create_dir_all(home.join("Dropbox")).unwrap();
        assert!(project_opens_drive(&home, &home.join("Dropbox")).is_some());

        // `defaults.filesystem: allow` opens the home folder.
        write(&paths.user_policy, "version: v1\ndefaults: {filesystem: allow}\n");
        let r = report(&Inputs { paths: &paths, agent: "claude-code", project: &project, home: &home, env: &[] }).unwrap();
        assert!(r.findings.iter().any(|f| f.severity == Severity::High && f.title.contains("read files across your home folder")), "{:?}", r.findings);
    }

    #[test]
    fn hosts_from_urls() {
        assert_eq!(host_of("https://user:pw@MCP.Example.com:8443/sse?x=1"), "mcp.example.com");
        assert_eq!(host_of("mcp.example.com/path"), "mcp.example.com");
        assert_eq!(host_of("http://[::1]:99/x"), "::1");
    }
}
