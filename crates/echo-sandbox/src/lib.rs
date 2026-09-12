//! Sandboxed execution for echo.
//!
//! Every tool an agent runs passes through this crate. It is the only place in
//! the workspace permitted to spawn a subprocess or use `unsafe`; every other
//! crate forbids both at compile time.

use std::path::{Path, PathBuf};

/// What a sandboxed process is allowed to do.
///
/// Default-deny: a policy grants nothing until something is explicitly added.
/// Construct with [`SandboxPolicy::default`] and widen from there, so forgetting
/// to configure it yields a useless sandbox rather than an open one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
    network: bool,
}

impl SandboxPolicy {
    /// Paths the process may read.
    pub fn readable_paths(&self) -> &[PathBuf] {
        &self.readable
    }

    /// Paths the process may write.
    ///
    /// Writable does not imply readable — the two are granted separately, so a
    /// write-only drop directory stays unreadable.
    pub fn writable_paths(&self) -> &[PathBuf] {
        &self.writable
    }

    /// Whether the process may reach the network.
    pub fn allows_network(&self) -> bool {
        self.network
    }

    /// Grant read access to `path`.
    #[must_use]
    pub fn allow_read(mut self, path: impl AsRef<Path>) -> Self {
        self.readable.push(path.as_ref().to_path_buf());
        self
    }

    /// Grant write access to `path`.
    #[must_use]
    pub fn allow_write(mut self, path: impl AsRef<Path>) -> Self {
        self.writable.push(path.as_ref().to_path_buf());
        self
    }

    /// Grant network access.
    #[must_use]
    pub fn allow_network(mut self) -> Self {
        self.network = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The foundational guarantee: a policy nobody configured grants nothing.
    ///
    /// Every other sandbox behaviour is built on top of this. If the default
    /// ever grants an access, a caller that forgets to configure the policy
    /// silently gets an unsandboxed agent.
    #[test]
    fn default_policy_denies_everything() {
        let policy = SandboxPolicy::default();

        assert!(
            policy.readable_paths().is_empty(),
            "default policy must not grant read access to any path"
        );
        assert!(
            policy.writable_paths().is_empty(),
            "default policy must not grant write access to any path"
        );
        assert!(
            !policy.allows_network(),
            "default policy must not grant network access"
        );
    }
}
