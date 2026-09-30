use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("{doc}: invalid YAML: {msg}")]
    Yaml { doc: String, msg: String },
    #[error("{doc}: unsupported policy version {found:?} (expected \"v1\")")]
    Version { doc: String, found: String },
    #[error("{doc}: project policies may not contain `{key}` (project policies are restrict-only; trust the file by hash to lift this)")]
    ProjectForbidden { doc: String, key: String },
    #[error("{doc}: {section}[{index}]: {msg}")]
    BadRule { doc: String, section: String, index: usize, msg: String },
    #[error("{doc}: unknown variable ${{{var}}}")]
    UnknownVariable { doc: String, var: String },
    #[error("{doc}: invalid pattern {pattern:?}: {msg}")]
    BadPattern { doc: String, pattern: String, msg: String },
    #[error("{doc}: {msg}")]
    Invalid { doc: String, msg: String },
}
