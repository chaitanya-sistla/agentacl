//! Path glob patterns (policy-model §2.2).
//!
//! `*` matches within a segment, `?` one non-`/` character, `**` zero or more
//! whole segments; `X/**` matches `X` itself. Matching is ASCII
//! case-insensitive because APFS is case-insensitive by default.

use crate::expand::{canonical_prefix_map, Expanded};
use regex::{Regex, RegexBuilder};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatKind {
    /// Exact path.
    Literal(String),
    /// `prefix/**` with no other glob characters: `prefix` and everything below.
    Subpath(String),
    Glob,
}

#[derive(Debug, Clone)]
pub struct PathPattern {
    source: String,
    kind: PatKind,
    anchor: String,
    var_root: Option<String>,
    body: String,
    re: Regex,
}

impl PartialEq for PathPattern {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source && self.var_root == other.var_root
    }
}

fn has_glob(s: &str) -> bool {
    s.contains('*') || s.contains('?')
}

/// Translates a canonical absolute glob into an unanchored regex body.
/// `fold` emits `[aA]` classes for letters (Seatbelt regexes).
fn translate(pat: &str, fold: bool) -> Result<String, String> {
    let segs: Vec<&str> = pat.split('/').skip(1).collect();
    let mut out = String::new();
    for seg in &segs {
        if *seg == "**" {
            // zero or more whole segments, whether trailing or in the middle
            out.push_str("(/.*)?");
            continue;
        }
        if seg.contains("**") {
            return Err("`**` must be a whole path segment".into());
        }
        out.push('/');
        for c in seg.chars() {
            match c {
                '*' => out.push_str("[^/]*"),
                '?' => out.push_str("[^/]"),
                c if c.is_ascii_alphabetic() && fold => {
                    out.push('[');
                    out.push(c.to_ascii_lowercase());
                    out.push(c.to_ascii_uppercase());
                    out.push(']');
                }
                c if "\\.+()[]{}^$|".contains(c) => {
                    out.push('\\');
                    out.push(c);
                }
                c => out.push(c),
            }
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    Ok(out)
}

impl PathPattern {
    pub fn parse(expanded: &Expanded) -> Result<Self, String> {
        let raw = expanded.text.as_str();
        if !raw.starts_with('/') {
            return Err("pattern must be absolute (start with `/` or a variable)".into());
        }
        if raw.split('/').any(|s| s == "..") {
            return Err("`..` is not allowed in patterns".into());
        }
        let source = canonical_prefix_map(raw);
        // canonical_prefix_map drops a trailing '/', which is what we want.
        let var_root = expanded.var_root.as_deref().map(canonical_prefix_map);
        let kind = if !has_glob(&source) {
            PatKind::Literal(source.clone())
        } else if let Some(prefix) = source.strip_suffix("/**").filter(|p| !has_glob(p)) {
            PatKind::Subpath(if prefix.is_empty() { "/".into() } else { prefix.to_string() })
        } else {
            PatKind::Glob
        };
        let anchor = match &kind {
            PatKind::Literal(p) => parent(p),
            PatKind::Subpath(p) => p.clone(),
            PatKind::Glob => {
                let first = source.find(['*', '?']).unwrap();
                let dir = &source[..first];
                let dir = &dir[..dir.rfind('/').unwrap()];
                if dir.is_empty() {
                    "/".to_string()
                } else {
                    dir.to_string()
                }
            }
        };
        let body = translate(&source, false)?;
        let re = RegexBuilder::new(&format!("^{body}$")).case_insensitive(true).build().map_err(|e| e.to_string())?;
        Ok(PathPattern { source, kind, anchor, var_root, body, re })
    }

    /// An `except` entry: may start with `**/`, in which case it is anchored at
    /// the owning rule's anchor.
    pub fn parse_except(pat: &str, rule_anchor: &str) -> Result<Self, String> {
        let text = if let Some(rest) = pat.strip_prefix("**/") { format!("{}/**/{}", rule_anchor.trim_end_matches('/'), rest) } else { pat.to_string() };
        Self::parse(&Expanded { text, var_root: None })
    }

    pub fn matches(&self, canonical_path: &str) -> bool {
        self.re.is_match(canonical_path)
    }

    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn kind(&self) -> &PatKind {
        &self.kind
    }
    pub fn anchor(&self) -> &str {
        &self.anchor
    }

    /// Seatbelt regex: anchored POSIX ERE with case-folded letters.
    pub fn sbpl_regex(&self) -> String {
        format!("^{}$", translate(&self.source, true).expect("validated in parse"))
    }

    /// Every directory above the protected location (and a glob's anchor
    /// itself), excluding `/`. Renaming any of them moves protected files out
    /// from under this pattern — e.g. `mv ~/.claude $TMPDIR/c`, edit, move back
    /// — so unlink/rename/link of each is denied (policy-model §4).
    pub fn protected_ancestors(&self) -> Vec<String> {
        let top = match &self.kind {
            PatKind::Literal(p) | PatKind::Subpath(p) => parent(p),
            PatKind::Glob => self.anchor.clone(),
        };
        ancestors_inclusive(&top)
    }

    /// For a glob `<anchor>/**/<tail>`: the same `**/<tail>` below `root`.
    /// Protects matched names in places a directory holding a match can be
    /// renamed to (`mv certs $TMPDIR/c`), where the original anchor no longer
    /// applies. `None` for any other shape.
    pub fn rerooted(&self, root: &str) -> Option<PathPattern> {
        if self.kind != PatKind::Glob {
            return None;
        }
        let rest = self.source.strip_prefix(self.anchor.trim_end_matches('/'))?;
        if !rest.starts_with("/**/") {
            return None;
        }
        Self::parse(&Expanded { text: format!("{}{rest}", root.trim_end_matches('/')), var_root: None }).ok()
    }

    #[doc(hidden)]
    pub fn regex_body(&self) -> &str {
        &self.body
    }
}

/// `p` and each of its ancestors, excluding `/`, shallowest first.
pub fn ancestors_inclusive(p: &str) -> Vec<String> {
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    (1..=segs.len()).map(|i| format!("/{}", segs[..i].join("/"))).collect()
}

fn parent(p: &str) -> String {
    match p.rfind('/') {
        Some(0) | None => "/".into(),
        Some(i) => p[..i].to_string(),
    }
}
