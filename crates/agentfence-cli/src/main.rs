//! `agentfence`: identity, authorization and audit for AI agents on macOS.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "agentfence", version, about = "Identity, authorization and audit for AI coding agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find AI coding agents installed or running on this Mac
    Discover(DiscoverArgs),
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
}

#[derive(Args)]
struct JsonArg {
    /// Machine-readable output
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DiscoverArgs {
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
}

#[derive(Args)]
struct PolicyCheckArgs {
    /// Agent id to evaluate for (default: claude-code)
    #[arg(long)]
    agent: Option<String>,
    /// Project root (default: git toplevel of the current directory)
    #[arg(long)]
    project: Option<PathBuf>,
    /// Use this user policy file instead of ~/.config/agentfence/policy.yaml
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Evaluate a filesystem request for this path
    #[arg(long)]
    path: Option<PathBuf>,
    /// Filesystem action for --path: read, write, rename
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
    /// Print identity, enforceability and the sandbox profile path without launching
    #[arg(long)]
    dry_run: bool,
    /// Allow launching although this path is a hard link to a protected file
    #[arg(long = "accept-hardlink")]
    accept_hardlinks: Vec<PathBuf>,
    /// The agent command and its arguments
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
    command: Vec<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result: anyhow::Result<i32> = match cli.command {
        Command::Discover(_)
        | Command::Agents(_)
        | Command::Status(_)
        | Command::Policy(_)
        | Command::Events(_)
        | Command::Run(_) => {
            eprintln!("agentfence: not implemented yet");
            Ok(2)
        }
    };
    match result {
        Ok(code) => ExitCode::from(code.clamp(0, 255) as u8),
        Err(e) => {
            eprintln!("agentfence: {e:#}");
            ExitCode::from(1)
        }
    }
}
