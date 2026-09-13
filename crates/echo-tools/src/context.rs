use echo_sandbox::{FsGuard, SandboxError, SandboxPolicy};

/// What a tool is allowed to touch, and the machinery for enforcing it.
///
/// Built once per session from a [`SandboxPolicy`] and shared by every tool
/// call. Holds both halves of the sandbox because the built-ins split across
/// them: native-Rust tools check paths through [`FsGuard`], while `bash` spawns
/// through the kernel-enforced path and needs the policy itself.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    guard: FsGuard,
    policy: SandboxPolicy,
    helper: Option<std::path::PathBuf>,
}

impl ExecutionContext {
    /// Resolve `policy` into a context tools can execute against.
    pub fn new(policy: SandboxPolicy) -> Result<Self, SandboxError> {
        Ok(Self {
            guard: FsGuard::new(&policy)?,
            policy,
            helper: None,
        })
    }

    /// Spawn through a specific sandbox helper instead of re-executing the
    /// current binary.
    ///
    /// The default assumes the running binary calls
    /// `echo_sandbox::dispatch_helper_mode` at startup, which the shipped `echo`
    /// does and a test harness does not.
    #[must_use]
    pub fn with_helper(mut self, path: impl AsRef<std::path::Path>) -> Self {
        self.helper = Some(path.as_ref().to_path_buf());
        self
    }

    /// An explicit helper, if one was set.
    pub fn helper(&self) -> Option<&std::path::Path> {
        self.helper.as_deref()
    }

    /// Path checks for tools that touch the filesystem in-process.
    pub fn guard(&self) -> &FsGuard {
        &self.guard
    }

    /// The policy itself, for tools that spawn a sandboxed process.
    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }
}
