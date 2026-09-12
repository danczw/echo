use std::path::PathBuf;

/// Why a sandbox operation was refused.
///
/// Every variant is a refusal. There is deliberately no "allowed with warning"
/// case: a caller that believes it is sandboxed and is not is worse off than
/// one that gets an error.
#[derive(Debug)]
pub enum SandboxError {
    /// The path is not inside any root the policy allows.
    PathNotAllowed {
        /// The path as the caller supplied it.
        requested: PathBuf,
    },

    /// The path could not be resolved to a real location, so it cannot be
    /// proven to be inside an allowed root.
    ///
    /// Treated as a refusal rather than a pass: an unresolvable path is exactly
    /// what a traversal attempt looks like.
    Unresolvable {
        /// The path as the caller supplied it.
        requested: PathBuf,
        /// The underlying resolution failure.
        source: std::io::Error,
    },
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathNotAllowed { requested } => {
                write!(
                    f,
                    "path is outside every allowed root: {}",
                    requested.display()
                )
            }
            Self::Unresolvable { requested, source } => {
                write!(
                    f,
                    "could not resolve path {}: {source}",
                    requested.display()
                )
            }
        }
    }
}

impl std::error::Error for SandboxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PathNotAllowed { .. } => None,
            Self::Unresolvable { source, .. } => Some(source),
        }
    }
}
