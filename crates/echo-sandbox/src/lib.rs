//! Sandboxed execution for echo.
//!
//! Every tool an agent runs passes through this crate. It is the only place in
//! the workspace permitted to spawn a subprocess or use `unsafe`; every other
//! crate forbids both at compile time.
//!
//! Default-deny throughout: see [`SandboxPolicy`].

mod policy;

pub use policy::SandboxPolicy;
