//! `agentfence`: identity, authorization and audit for AI agents on macOS.

mod render;
mod ui;

use agentfence_core::audit::{EventQuery, Store};
use agentfence_core::config::Paths;
use agentfence_core::enforce::{rule_views, EnforcementBackend, MacOSEndpointSecurityBackend, SeatbeltBackend};
use agentfence_core::escape::term_safe;
use agentfence_core::supervisor::{self, RunOptions};
use agentfence_core::{agents, identity, proc};
use agentfence_policy::{Action, Effect, PolicyEngine, Request, Resource, Subject, WriteOp};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use render::{agent_display, card, decision_label, table, tilde};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "agentfence", version, about = "Identity, authorization and audit for AI coding agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find AI coding agents installed or running on this Mac
    Discover(JsonArg),
    /// List agent sessions supervised by AgentFence
    Agents(AgentsArgs),
    /// Show enforcement backend, capabilities and active sessions
    Status(JsonArg),
    /// Policy tools
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Show authorization and audit events
    Events(EventsArgs),
    /// Launch an agent under AgentFence supervision
    Run(RunArgs),
    /// Relaunch a running session under the current policy (keeps the conversation where the agent supports it)
    Restart(RestartArgs),
    /// Stop a supervised agent (its session ends and is recorded)
    Stop(RestartArgs),
    /// Local policy UI in your browser (127.0.0.1 only)
    Ui(UiArgs),
}

#[derive(Args)]
struct UiArgs {
    /// Port on 127.0.0.1 (default: random)
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Print the link instead of opening the browser
    #[arg(long)]
    no_open: bool,
}

#[derive(Args)]
struct RestartArgs {
    /// Session id (default: the only active session)
    session: Option<String>,
}

#[derive(Args)]
struct JsonArg {
    /// Machine-readable output
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AgentsArgs {
    /// Also list running agents that AgentFence is not supervising
    #[arg(long)]
    all: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Validate policies, show effective rules and their enforceability, or evaluate one request
    Check(PolicyCheckArgs),
    /// Trust this project's .agentfence/policy.yaml (exact bytes, this project only) so it may grant access
    Trust(TrustArgs),
}

#[derive(Args)]
struct TrustArgs {
    /// sha256 of the policy bytes you reviewed (shown by `agentfence policy check`)
    #[arg(long)]
    sha256: String,
    /// Project root (default: git toplevel of the current directory)
    #[arg(long)]
    project: Option<PathBuf>,
}

#[derive(Args)]
struct PolicyCheckArgs {
    /// Agent id to evaluate for
    #[arg(long, default_value = "claude-code")]
    agent: String,
    /// Project root (default: git toplevel of the current directory)
    #[arg(long)]
    project: Option<PathBuf>,
    /// Use this user policy file instead of ~/.config/agentfence/policy.yaml
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Evaluate a filesystem request for this path
    #[arg(long)]
    path: Option<PathBuf>,
    /// Filesystem action for --path: read, write, rename, unlink
    #[arg(long, default_value = "read")]
    action: String,
    /// Evaluate an exec request, e.g. --exec "git push origin main"
    #[arg(long)]
    exec: Option<String>,
    /// Evaluate a network request, host:port
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct EventsArgs {
    #[arg(long)]
    session: Option<String>,
    /// Filter by decision: allow, deny, ask
    #[arg(long)]
    decision: Option<String>,
    #[arg(long, default_value_t = 50)]
    limit: usize,
    /// Keep printing new events
    #[arg(long, short)]
    follow: bool,
    /// Newline-delimited JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RunArgs {
    /// Project root (default: git toplevel of the current directory)
    #[arg(long)]
    project: Option<PathBuf>,
    /// Use this user policy file
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Agent id to use when the binary is not a known agent
    #[arg(long)]
    agent_id: Option<String>,
    /// Print identity, enforceability and the sandbox profile without launching
    #[arg(long)]
    dry_run: bool,
    /// Allow launching although this path is a hard link to a protected file
    #[arg(long = "accept-hardlink")]
    accept_hardlinks: Vec<PathBuf>,
    /// Pass this environment variable to the agent even though it looks like a secret
    #[arg(long = "keep-env")]
    keep_env: Vec<String>,
    /// The agent command and its arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = (|| -> Result<i32> {
        let paths = Paths::from_env()?;
        match cli.command {
            Command::Discover(a) => discover(&paths, a.json),
            Command::Agents(a) => agents_cmd(&paths, a),
            Command::Status(a) => status(&paths, a.json),
            Command::Policy(PolicyCmd::Check(a)) => policy_check(&paths, a),
            Command::Policy(PolicyCmd::Trust(a)) => {
                let h = identity::human()?;
                let project = identity::resolve_project(&std::env::current_dir()?, a.project.as_deref(), &h.home)?;
                agentfence_core::trust::trust(&paths, &project, &a.sha256)?;
                println!("Trusted {}/.agentfence/policy.yaml ({}) for this project only.", project.display(), a.sha256);
                Ok(0)
            }
            Command::Events(a) => events(&paths, a),
            Command::Run(a) => run(&paths, a),
            Command::Restart(a) => restart(&paths, a),
            Command::Stop(a) => stop(&paths, a),
            Command::Ui(a) => ui::run(paths, ui::UiOptions { port: a.port, open: !a.no_open }),
        }
    })();
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("agentfence: {}", term_safe(&format!("{e:#}")));
            ExitCode::from(1)
        }
    }
}

fn home() -> String {
    identity::human().map(|h| h.home.to_string_lossy().into_owned()).unwrap_or_default()
}

fn discover(_paths: &Paths, json: bool) -> Result<i32> {
    let h = identity::human()?;
    let (found, running) = agents::discover(&h.home);
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "installed": found, "running": running }))?);
        return Ok(0);
    }
    let home = h.home.to_string_lossy().into_owned();
    println!("INSTALLED AGENTS\n");
    if found.is_empty() {
        println!("(none found)");
    } else {
        let rows: Vec<Vec<String>> = found
            .iter()
            .map(|d| {
                let signer = d
                    .signature
                    .as_ref()
                    .and_then(|s| s.team_id.clone().map(|t| format!("{} ({t})", s.signing_id.clone().unwrap_or_default())))
                    .unwrap_or_else(|| "unsigned".into());
                vec![d.display_name.clone(), d.version.clone().unwrap_or_else(|| "-".into()), tilde(&d.path, &home), signer, format!("{:?}", d.confidence).to_lowercase()]
            })
            .collect();
        print!("{}", table(&["AGENT", "VERSION", "PATH", "SIGNER", "CONFIDENCE"], &rows));
    }
    println!("\nRUNNING AGENTS\n");
    let store = Store::open(&_paths.db_path).ok();
    let supervised: Vec<i32> = store
        .as_ref()
        .and_then(|s| s.active_sessions().ok())
        .unwrap_or_default()
        .iter()
        .filter_map(|s| s.agent_pid)
        .collect();
    if running.is_empty() {
        println!("(none running)");
    } else {
        let rows: Vec<Vec<String>> = running
            .iter()
            .map(|r| {
                vec![
                    r.display_name.clone(),
                    r.pid.to_string(),
                    r.version.clone().unwrap_or_else(|| "-".into()),
                    if supervised.contains(&r.pid) || supervised.contains(&r.ppid) { "supervised".into() } else { "UNSUPERVISED".into() },
                    tilde(r.exe.as_deref().unwrap_or("-"), &home),
                ]
            })
            .collect();
        print!("{}", table(&["AGENT", "PID", "VERSION", "STATUS", "EXECUTABLE"], &rows));
    }
    Ok(0)
}

/// Active sessions, reconciling crashed supervisors.
fn live_sessions(store: &Store) -> Result<Vec<agentfence_core::audit::SessionRecord>> {
    let mut out = vec![];
    for s in store.active_sessions()? {
        let sup_alive = proc::facts(s.supervisor_pid).is_some();
        if !sup_alive {
            store.end_session(&s.session_id, &agentfence_core::audit::now_rfc3339(), None)?;
            continue;
        }
        out.push(s);
    }
    Ok(out)
}

fn agents_cmd(paths: &Paths, a: AgentsArgs) -> Result<i32> {
    let store = Store::open(&paths.db_path)?;
    let sessions = live_sessions(&store)?;
    let unsupervised = if a.all {
        let snap = proc::snapshot();
        let sup: Vec<i32> = sessions.iter().filter_map(|s| s.agent_pid).collect();
        agents::running_agents(&snap).into_iter().filter(|r| !sup.contains(&r.pid) && !sup.contains(&r.ppid)).collect()
    } else {
        vec![]
    };
    if a.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "sessions": sessions, "unsupervised": unsupervised }))?);
        return Ok(0);
    }
    let home = home();
    println!("ACTIVE AGENTS\n");
    let mut rows: Vec<Vec<String>> = sessions
        .iter()
        .map(|s| {
            vec![
                agent_display(&s.agent),
                s.agent_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                tilde(&s.project, &home),
                s.policy_name.clone(),
                s.session_id.clone(),
            ]
        })
        .collect();
    for u in &unsupervised {
        rows.push(vec![u.display_name.clone(), u.pid.to_string(), "-".into(), "UNSUPERVISED".into(), "-".into()]);
    }
    if rows.is_empty() {
        println!("(no supervised agents; start one with `agentfence run -- <agent>`)");
    } else {
        print!("{}", table(&["AGENT", "PID", "PROJECT", "POLICY", "SESSION"], &rows));
    }
    Ok(0)
}

fn status(paths: &Paths, json: bool) -> Result<i32> {
    let seatbelt = SeatbeltBackend.available();
    let es = MacOSEndpointSecurityBackend.available();
    let store = Store::open(&paths.db_path)?;
    let sessions = live_sessions(&store)?;
    let enforced = ["filesystem read/write (kernel, Seatbelt)", "network egress (proxy + sandbox lock)", "exec by executable (coarse)", "unix sockets (ssh-agent, docker)"];
    let observed = ["exec rules with arguments (e.g. `git push *`)", "delegation chain (100 ms polling)", "agents not launched via `agentfence run`"];
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "backend": "seatbelt",
                "seatbelt": seatbelt.as_ref().map(|_| "available").unwrap_or_else(|e| e.as_str()),
                "endpoint_security": es.as_ref().err(),
                "enforced": enforced,
                "observed_only": observed,
                "sessions": sessions,
                "state_dir": paths.state_dir,
            }))?
        );
        return Ok(0);
    }
    println!("AGENTFENCE STATUS\n");
    println!("Backend:            seatbelt ({})", seatbelt.map(|_| "available".to_string()).unwrap_or_else(|e| e));
    println!("Endpoint Security:  unavailable ({})", es.err().unwrap_or_default());
    println!("Enforced:           {}", enforced.join("; "));
    println!("Observed only:      {}", observed.join("; "));
    println!("State:              {}", paths.state_dir.display());
    println!();
    if sessions.is_empty() {
        println!("No active sessions.");
    } else {
        let home = home();
        let rows: Vec<Vec<String>> = sessions
            .iter()
            .map(|s| vec![agent_display(&s.agent), s.agent_pid.map(|p| p.to_string()).unwrap_or_default(), tilde(&s.project, &home), s.policy_name.clone(), s.policy_sha256[..12.min(s.policy_sha256.len())].to_string()])
            .collect();
        print!("{}", table(&["AGENT", "PID", "PROJECT", "POLICY", "POLICY SHA"], &rows));
    }
    Ok(0)
}

fn policy_check(paths: &Paths, a: PolicyCheckArgs) -> Result<i32> {
    let h = identity::human()?;
    let cwd = std::env::current_dir()?;
    let project = identity::resolve_project(&cwd, a.project.as_deref(), &h.home)?;
    let (set, reqs) = supervisor::load_policy_for_check(paths, &a.agent, &project, a.policy.as_deref())?;
    let proj = project.to_string_lossy().into_owned();
    let subject = Subject { human: h.user.clone(), agent_id: a.agent.clone(), project: proj.clone(), ..Default::default() };

    let query = if let Some(p) = &a.path {
        let abs = if p.is_absolute() { p.clone() } else { cwd.join(p) };
        let abs = supervisor::canon_or(&abs);
        let action = match a.action.as_str() {
            "read" => Action::FsRead,
            "write" => Action::FsWrite(WriteOp::Write),
            "rename" => Action::FsWrite(WriteOp::Rename),
            "unlink" => Action::FsWrite(WriteOp::Unlink),
            other => bail!("unknown --action {other:?} (read, write, rename, unlink)"),
        };
        Some(Request { subject: subject.clone(), action, resource: Resource::Path(abs.to_string_lossy().into()) })
    } else if let Some(cmd) = &a.exec {
        let argv: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
        let exe = argv.first().and_then(|c| agents::path_lookup(c)).map(|p| supervisor::canon_or(&p).to_string_lossy().into_owned()).unwrap_or_else(|| argv.first().cloned().unwrap_or_default());
        Some(Request { subject: subject.clone(), action: Action::Exec, resource: Resource::Exec { exe, argv } })
    } else if let Some(hp) = &a.host {
        let (host, port) = match hp.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().context("bad port")?),
            None => (hp.clone(), 443),
        };
        Some(Request { subject: subject.clone(), action: Action::NetConnect, resource: Resource::Host { host, port } })
    } else {
        None
    };
    if let Some(req) = query {
        let d = set.evaluate(&req);
        if a.json {
            println!("{}", serde_json::to_string_pretty(&d)?);
        } else {
            println!("Decision:  {}", d.effect.as_str().to_uppercase());
            println!("Policy:    {} ({})", term_safe(&d.policy), term_safe(&d.rule_id));
            println!("Reason:    {}", term_safe(&d.reason));
            if !d.trace.is_empty() {
                println!("Matched:   {}", term_safe(&d.trace.join("; ")));
            }
        }
        return Ok(0);
    }

    let views = rule_views(&SeatbeltBackend, &set, &a.agent, &proj);
    let defaults = set.effective_defaults(&a.agent, &proj);
    // Same warnings as the console (agentfence_core::draft::warnings).
    let mut warnings = agentfence_core::draft::warnings(&set, &a.agent, &proj);
    if defaults.process == Effect::Deny {
        warnings.push("defaults.process: deny is not supported by the seatbelt backend; `agentfence run` will refuse to start".to_string());
    }
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "policy_sha256": set.sha256, "defaults": defaults, "rules": views, "warnings": warnings,
                "provider": { "mach_services": reqs.mach_services, "env_passthrough": reqs.env_passthrough, "launch_args": reqs.launch_args },
                "mach_allow": agentfence_core::enforce::baseline::MACH_ALLOW,
                "mach_deny": agentfence_core::enforce::baseline::MACH_DENY,
            }))?
        );
        return Ok(0);
    }
    println!("POLICY CHECK  agent={}  project={}\n", a.agent, tilde(&proj, &home()));
    println!("Policy sha256: {}", set.sha256);
    println!("Defaults:      filesystem={}  network={}  process={}", defaults.filesystem.as_str(), defaults.network.as_str(), defaults.process.as_str());
    let pp = project.join(".agentfence/policy.yaml");
    if let Ok(bytes) = std::fs::read(&pp) {
        let sha = agentfence_policy::set::sha256_hex(&bytes);
        let trusted = agentfence_core::trust::hashes_for(paths, &project).unwrap_or_default().contains(&sha);
        println!("Project policy: {} sha256={sha} ({})", tilde(&pp.to_string_lossy(), &home()), if trusted { "trusted" } else { "restrict-only; trust with `agentfence policy trust --sha256 <sha>`" });
    }
    if let Ok(t) = agentfence_core::trust::load(paths) {
        if t.legacy_ignored > 0 {
            warnings.push(format!("{} legacy hash-only trust entries in config.yaml are ignored; re-trust with `agentfence policy trust`", t.legacy_ignored));
        }
    }
    println!();
    let rows: Vec<Vec<String>> = views
        .iter()
        .map(|v| {
            let mut pat = v.pattern.clone();
            if !v.excepts.is_empty() {
                pat.push_str(&format!(" (except {})", v.excepts.len()));
            }
            vec![v.policy.clone(), v.id.clone(), v.section.to_string(), v.effect.as_str().to_string(), pat, v.enforceability.as_str().to_string()]
        })
        .collect();
    print!("{}", table(&["POLICY", "RULE", "SECTION", "EFFECT", "PATTERN", "ENFORCEMENT"], &rows));
    println!("\nMach services allowed: {}", agentfence_core::enforce::baseline::MACH_ALLOW.iter().chain(reqs.mach_services.iter().map(String::as_str).collect::<Vec<_>>().iter()).cloned().collect::<Vec<_>>().join(", "));
    if !warnings.is_empty() {
        println!("\nWARNINGS");
        for w in &warnings {
            println!("  - {}", term_safe(w));
        }
    }
    Ok(0)
}

fn restart(paths: &Paths, a: RestartArgs) -> Result<i32> {
    let store = Store::open(&paths.db_path)?;
    let sessions = live_sessions(&store)?;
    let s = match &a.session {
        Some(id) => sessions.iter().find(|s| &s.session_id == id).with_context(|| format!("no active session {id}"))?,
        None => match sessions.as_slice() {
            [one] => one,
            [] => bail!("no active sessions"),
            _ => bail!("several sessions are active; pass one of: {}", sessions.iter().map(|s| s.session_id.as_str()).collect::<Vec<_>>().join(", ")),
        },
    };
    // Supervisors from before restart support would be killed by SIGUSR1.
    let ident: serde_json::Value = serde_json::from_str(&s.identity_json).unwrap_or_default();
    if ident.get("agentfence_version").and_then(|v| v.as_str()).is_none() {
        bail!("session {} was started by an older agentfence without restart support; exit the agent and run it again", s.session_id);
    }
    // Only signal a pid that is still this session's supervisor (guards pid reuse).
    let pid = agentfence_core::supervisor::verified_supervisor(s)?;
    agentfence_core::supervisor::request_restart(pid)?;
    println!("Restart requested for {} ({}); it relaunches under the current policy.", s.session_id, agent_display(&s.agent));
    Ok(0)
}

fn stop(paths: &Paths, a: RestartArgs) -> Result<i32> {
    let store = Store::open(&paths.db_path)?;
    let sessions = live_sessions(&store)?;
    let s = match &a.session {
        Some(id) => sessions.iter().find(|s| &s.session_id == id).with_context(|| format!("no active session {id}"))?,
        None => match sessions.as_slice() {
            [one] => one,
            [] => bail!("no active sessions"),
            _ => bail!("several sessions are active; pass one of: {}", sessions.iter().map(|s| s.session_id.as_str()).collect::<Vec<_>>().join(", ")),
        },
    };
    let pid = agentfence_core::supervisor::verified_supervisor(s)?;
    agentfence_core::supervisor::request_stop(pid)?;
    println!("Stop requested for {} ({}).", s.session_id, agent_display(&s.agent));
    Ok(0)
}

fn parse_effect(s: &str) -> Result<Effect> {
    Ok(match s {
        "allow" => Effect::Allow,
        "deny" => Effect::Deny,
        "ask" => Effect::Ask,
        _ => bail!("--decision must be allow, deny or ask"),
    })
}

fn events(paths: &Paths, a: EventsArgs) -> Result<i32> {
    let store = Store::open(&paths.db_path)?;
    let decision = a.decision.as_deref().map(parse_effect).transpose()?;
    let mut q = EventQuery { session: a.session.clone(), decision, after_rowid: None, limit: Some(a.limit) };
    let print = |rows: &[(i64, agentfence_core::audit::Event)], follow: bool| -> Result<()> {
        if a.json {
            for (_, e) in rows {
                println!("{}", serde_json::to_string(e)?);
            }
            return Ok(());
        }
        if follow {
            for (_, e) in rows {
                if matches!(e.decision, Some(Effect::Deny | Effect::Ask)) {
                    println!("{}", card(e, &agent_display(&e.agent)));
                } else {
                    println!("{}  {}  {}  {}", e.timestamp, term_safe(&e.action), term_safe(&e.resource), decision_label(e));
                }
            }
            return Ok(());
        }
        let r: Vec<Vec<String>> = rows
            .iter()
            .map(|(_, e)| {
                let rule = match (&e.policy, &e.rule_id) {
                    (Some(p), Some(r)) => format!("{p}/{r}"),
                    _ => "-".into(),
                };
                let decision = match (e.decision, e.enforcement) {
                    (None, _) => "-".to_string(),
                    _ => decision_label(e).to_string(),
                };
                vec![e.timestamp.get(11..19).unwrap_or(&e.timestamp).to_string(), agent_display(&e.agent), e.action.clone(), e.resource.clone(), decision, rule]
            })
            .collect();
        print!("{}", table(&["TIME", "AGENT", "ACTION", "RESOURCE", "DECISION", "RULE"], &r));
        Ok(())
    };
    let rows = store.events(&q)?;
    if rows.is_empty() && !a.follow && !a.json {
        println!("No events.");
    } else {
        print(&rows, a.follow)?;
    }
    if !a.follow {
        return Ok(0);
    }
    q.after_rowid = rows.last().map(|(r, _)| *r).or(Some(0));
    q.limit = Some(1000);
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let rows = store.events(&q)?;
        if let Some((r, _)) = rows.last() {
            q.after_rowid = Some(*r);
        }
        print(&rows, true)?;
    }
}

fn run(paths: &Paths, a: RunArgs) -> Result<i32> {
    let opts = RunOptions {
        argv: a.command,
        project: a.project,
        policy_file: a.policy,
        agent_id: a.agent_id,
        accept_hardlinks: a.accept_hardlinks,
        keep_env: a.keep_env,
        cwd: None,
    };
    let home = home();
    if a.dry_run {
        let p = supervisor::prepare(paths, &opts)?;
        let plan = p.dry_run()?;
        let s = &p.session;
        println!("AGENTFENCE DRY RUN (nothing launched)\n");
        println!("Agent:      {} {}", s.agent.display_name, s.agent.version.clone().unwrap_or_default());
        println!("Binary:     {}", term_safe(&s.agent.binary));
        println!("Signer:     {}", s.agent.team_id.clone().map(|t| format!("{} ({t})", s.agent.signing_id.clone().unwrap_or_default())).unwrap_or_else(|| "unsigned".into()));
        println!("Human:      {} (uid {})", s.human.user, s.human.uid);
        println!("Machine:    {}", s.machine);
        println!("Project:    {}", tilde(&s.project.to_string_lossy(), &home));
        println!("Policy:     {} (sha256 {})", s.policy.name, &s.policy.sha256[..16]);
        println!("Backend:    seatbelt (kernel-enforced)");
        println!("Command:    {} {}", plan.program.display(), term_safe(&plan.args.join(" ")));
        let mut counts = std::collections::BTreeMap::new();
        for r in &p.rules {
            *counts.entry(r.enforceability.as_str()).or_insert(0) += 1;
        }
        println!("Rules:      {}", counts.iter().map(|(k, v)| format!("{v} {k}")).collect::<Vec<_>>().join(", "));
        println!("\nProfile:\n{}", plan.profile_text);
        p.cleanup();
        return Ok(0);
    }
    supervisor::run(paths, opts, |summary| print_summary(summary, &home))
}

fn print_summary(summary: &supervisor::Summary, home: &str) {
    let mut err = String::new();
    err.push_str(&format!("\nAgentFence session {} ended (exit {})\n", summary.session_id, summary.exit_code));
    err.push_str(&format!(
        "  Blocked by policy: {}    Blocked by sandbox default: {}    Observed (not blocked): {}\n",
        summary.denied_by_policy,
        summary.denied_by_baseline,
        summary.observed.len()
    ));
    for (action, resource, rule, n) in summary.denied.iter().take(8) {
        err.push_str(&format!("  BLOCKED   {:<16} {} ({rule}){}\n", action, term_safe(&tilde(resource, home)), if *n > 1 { format!(" ×{n}") } else { String::new() }));
    }
    for (action, resource, rule) in summary.observed.iter().take(10) {
        err.push_str(&format!("  OBSERVED  {:<16} {} ({rule}) — NOT BLOCKED\n", action, term_safe(resource)));
    }
    for f in &summary.integrity_changes {
        err.push_str(&format!("  REVIEW BEFORE RUNNING: {} changed during the session\n", term_safe(&tilde(&f.to_string_lossy(), home))));
    }
    if !summary.stripped_env.is_empty() {
        err.push_str(&format!("  Withheld environment variables: {}\n", summary.stripped_env.join(", ")));
    }
    for w in &summary.warnings {
        err.push_str(&format!("  warning: {}\n", term_safe(w)));
    }
    err.push_str(&format!("  Details: agentfence events --session {}\n", summary.session_id));
    if summary.restarted {
        err.push_str(&format!("\nRelaunching {} under the updated policy{}…\n", summary.agent_argv0, if summary.resume_args.is_empty() { String::new() } else { format!(" ({})", summary.resume_args.join(" ")) }));
    } else if summary.policy_changed {
        let resume = if summary.resume_args.is_empty() { String::new() } else { format!(" {}", summary.resume_args.join(" ")) };
        err.push_str(&format!(
            "  Policy changed during this session; it applies from the next launch.\n  Tip: `agentfence restart` relaunches a running session in place, or run: agentfence run -- {}{resume}\n",
            summary.agent_argv0
        ));
    }
    eprint!("{err}");
}
