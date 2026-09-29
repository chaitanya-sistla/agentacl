//! Command patterns for `process.*` rules (policy-model §2.3). A pattern is
//! matched against each exec (executable + argv), never against shell text.

use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone)]
enum ExeMatch {
    Basename(Regex, String),
    Absolute(String),
}

#[derive(Debug, Clone)]
pub struct CommandPattern {
    source: String,
    exe: ExeMatch,
    args: Vec<Regex>,
    rest: bool,
}

impl PartialEq for CommandPattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

fn token_regex(tok: &str, case_insensitive: bool) -> Result<Regex, String> {
    let mut body = String::from("^");
    for c in tok.chars() {
        match c {
            '*' => body.push_str(".*"),
            '?' => body.push('.'),
            c => body.push_str(&regex::escape(&c.to_string())),
        }
    }
    body.push('$');
    RegexBuilder::new(&body).case_insensitive(case_insensitive).build().map_err(|e| e.to_string())
}

impl CommandPattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let toks: Vec<&str> = s.split_whitespace().collect();
        let Some((first, rest_toks)) = toks.split_first() else {
            return Err("empty command pattern".into());
        };
        let exe = if first.starts_with('/') {
            if first.contains(['*', '?']) {
                return Err("absolute executable paths may not contain globs".into());
            }
            ExeMatch::Absolute(crate::expand::canonical_prefix_map(first))
        } else {
            if first.contains('/') {
                return Err("executable must be a basename or an absolute path".into());
            }
            // Case-insensitive: APFS resolves `SUDO` to `sudo`.
            ExeMatch::Basename(token_regex(first, true)?, first.to_string())
        };
        let (args, rest) = match rest_toks.split_last() {
            Some((&"*", init)) => (init, true),
            _ => (rest_toks, false),
        };
        let args = args.iter().map(|t| token_regex(t, false)).collect::<Result<Vec<_>, _>>()?;
        Ok(CommandPattern { source: s.to_string(), exe, args, rest })
    }

    /// `argv[0]` is ignored; the executable is identified by `exe_path`.
    pub fn matches(&self, exe_path: &str, argv: &[String]) -> bool {
        let exe_ok = match &self.exe {
            ExeMatch::Absolute(p) => crate::expand::canonical_prefix_map(exe_path).eq_ignore_ascii_case(p),
            ExeMatch::Basename(re, _) => re.is_match(exe_path.rsplit('/').next().unwrap_or(exe_path)),
        };
        if !exe_ok {
            return false;
        }
        let args = argv.get(1..).unwrap_or(&[]);
        if args.len() < self.args.len() || (!self.rest && args.len() != self.args.len()) {
            return false;
        }
        self.args.iter().zip(args).all(|(re, a)| re.is_match(a))
    }

    /// True for `x` and `x *`: the rule is about the executable, not its args.
    pub fn is_executable_only(&self) -> bool {
        self.args.is_empty()
    }

    /// True when the executable token is a plain name without glob characters.
    pub fn exe_basename(&self) -> Option<&str> {
        match &self.exe {
            ExeMatch::Basename(_, name) if !name.contains(['*', '?']) => Some(name),
            _ => None,
        }
    }

    /// The executable token when it is a basename (may contain `*`/`?`).
    pub fn exe_basename_glob(&self) -> Option<&str> {
        match &self.exe {
            ExeMatch::Basename(_, name) => Some(name),
            _ => None,
        }
    }

    pub fn exe_abs(&self) -> Option<&str> {
        match &self.exe {
            ExeMatch::Absolute(p) => Some(p),
            _ => None,
        }
    }

    pub fn source(&self) -> &str {
        &self.source
    }
}
