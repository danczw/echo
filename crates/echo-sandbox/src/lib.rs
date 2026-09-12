//! Sandboxed execution for echo.
//!
//! Every tool an agent runs passes through this crate. It is the only place in
//! the workspace permitted to spawn a subprocess or use `unsafe`; every other
//! crate forbids both at compile time.
//!
//! Two layers, because they cover different things:
//!
//! - [`FsGuard`] checks paths in-process, for tools written in Rust that never
//!   spawn anything and so are never seen by the kernel enforcement.
//! - Kernel enforcement (Landlock, seccomp, namespaces) restricts child
//!   processes, and is applied between `fork` and `exec`.
//!
//! Both are default-deny: see [`SandboxPolicy`].

mod error;
mod fs_guard;
mod policy;
mod support;

pub use error::SandboxError;
pub use fs_guard::FsGuard;
pub use policy::SandboxPolicy;
pub use support::KernelSupport;
