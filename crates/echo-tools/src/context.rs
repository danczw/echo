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
}

impl ExecutionContext {
    /// Resolve `policy` into a context tools can execute against.
    pub fn new(policy: SandboxPolicy) -> Result<Self, SandboxError> {
        Ok(Self {
            guard: FsGuard::new(&policy)?,
            policy,
        })
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
