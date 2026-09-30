//! What kind of site a host is, to help decide on it (a hint, never a rule).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    AiProvider,
    PackageRegistry,
    SourceHosting,
    Telemetry,
    Docs,
    Cloud,
    Unknown,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::AiProvider => "AI provider",
            Category::PackageRegistry => "Package registry",
            Category::SourceHosting => "Source hosting",
            Category::Telemetry => "Telemetry & analytics",
            Category::Docs => "Documentation",
            Category::Cloud => "Cloud API",
            Category::Unknown => "Unknown",
        }
    }

    /// What usually makes sense; the human decides.
    pub fn advice(self) -> &'static str {
        match self {
            Category::AiProvider => "Agents need their model provider to work.",
            Category::PackageRegistry => "Needed to install dependencies; allow the registries your projects use.",
            Category::SourceHosting => "Needed for clone, fetch and GitHub/GitLab APIs.",
            Category::Telemetry => "Usage and crash reporting. Usually safe to keep blocked.",
            Category::Docs => "Read-only documentation sites.",
            Category::Cloud => "Cloud control-plane APIs can change real infrastructure. Allow only deliberately.",
            Category::Unknown => "Not a known service. Check what it is before allowing.",
        }
    }
}

/// Suffix match on a dot boundary: `api.github.com` matches `github.com`.
fn under(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

pub fn categorize(host: &str) -> Category {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    const AI: &[&str] = &[
        "anthropic.com",
        "claude.ai",
        "openai.com",
        "chatgpt.com",
        "generativelanguage.googleapis.com",
        "aiplatform.googleapis.com",
        "githubcopilot.com",
        "copilot-proxy.githubusercontent.com",
        "opencode.ai",
        "mistral.ai",
        "groq.com",
        "together.xyz",
        "openrouter.ai",
        "x.ai",
        "deepseek.com",
        "cohere.com",
    ];
    const REG: &[&str] = &[
        "registry.npmjs.org",
        "npmjs.org",
        "npmjs.com",
        "yarnpkg.com",
        "pypi.org",
        "pythonhosted.org",
        "crates.io",
        "rust-lang.org",
        "proxy.golang.org",
        "sum.golang.org",
        "golang.org",
        "rubygems.org",
        "maven.org",
        "repo.maven.apache.org",
        "gradle.org",
        "nuget.org",
        "packagist.org",
        "hex.pm",
        "pub.dev",
        "cocoapods.org",
        "brew.sh",
        "ghcr.io",
        "docker.io",
        "docker.com",
        "quay.io",
        "jsdelivr.net",
        "unpkg.com",
        "deno.land",
        "jsr.io",
    ];
    const SRC: &[&str] = &["github.com", "githubusercontent.com", "githubassets.com", "gitlab.com", "bitbucket.org", "codeberg.org", "sourcegraph.com", "git-scm.com"];
    const TEL: &[&str] = &[
        "datadoghq.com",
        "datadoghq.eu",
        "sentry.io",
        "segment.io",
        "segment.com",
        "mixpanel.com",
        "amplitude.com",
        "statsig.com",
        "statsigapi.net",
        "featuregates.org",
        "launchdarkly.com",
        "honeycomb.io",
        "newrelic.com",
        "nr-data.net",
        "bugsnag.com",
        "posthog.com",
        "google-analytics.com",
        "googletagmanager.com",
        "doubleclick.net",
        "hotjar.com",
        "fullstory.com",
        "logrocket.io",
        "rollbar.com",
        "intercom.io",
        "growthbook.io",
    ];
    const DOCS: &[&str] = &[
        "docs.rs",
        "developer.mozilla.org",
        "stackoverflow.com",
        "stackexchange.com",
        "readthedocs.io",
        "readthedocs.org",
        "wikipedia.org",
        "man7.org",
        "developer.apple.com",
        "learn.microsoft.com",
        "python.org",
        "nodejs.org",
        "reactjs.org",
        "react.dev",
        "typescriptlang.org",
    ];
    const CLOUD: &[&str] = &[
        "amazonaws.com",
        "googleapis.com",
        "azure.com",
        "windows.net",
        "microsoftonline.com",
        "cloudflare.com",
        "digitalocean.com",
        "heroku.com",
        "vercel.com",
        "netlify.com",
        "fly.io",
        "supabase.co",
        "firebaseio.com",
    ];
    let hit = |list: &[&str]| list.iter().any(|d| under(&h, d));
    // Datadog also uses flat names such as browser-intake-us5-datadoghq.com.
    let flat_telemetry = ["-datadoghq.com", "-datadoghq.eu"].iter().any(|s| h.ends_with(s));
    // Most specific first: telemetry and AI hosts live under broad cloud domains.
    if hit(TEL) || flat_telemetry {
        Category::Telemetry
    } else if hit(AI) {
        Category::AiProvider
    } else if hit(REG) {
        Category::PackageRegistry
    } else if hit(SRC) {
        Category::SourceHosting
    } else if hit(DOCS) {
        Category::Docs
    } else if hit(CLOUD) {
        Category::Cloud
    } else {
        Category::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        assert_eq!(categorize("http-intake.logs.us5.datadoghq.com"), Category::Telemetry);
        assert_eq!(categorize("browser-intake-us5-datadoghq.com"), Category::Telemetry);
        assert_eq!(categorize("api.anthropic.com"), Category::AiProvider);
        assert_eq!(categorize("generativelanguage.googleapis.com"), Category::AiProvider);
        assert_eq!(categorize("storage.googleapis.com"), Category::Cloud);
        assert_eq!(categorize("registry.npmjs.org"), Category::PackageRegistry);
        assert_eq!(categorize("raw.githubusercontent.com"), Category::SourceHosting);
        assert_eq!(categorize("docs.rs"), Category::Docs);
        assert_eq!(categorize("notgithub.com"), Category::Unknown, "suffix match needs a dot boundary");
        assert_eq!(categorize("example.org"), Category::Unknown);
    }
}
