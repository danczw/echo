use std::path::{Path, PathBuf};

use crate::{SandboxError, SandboxPolicy};

/// Checks paths against a [`SandboxPolicy`] before echo's own code touches them.
///
/// This is the in-process complement to the kernel enforcement applied to child
/// processes: tools implemented in Rust (`read`, `write`, `edit`) never spawn
/// anything, so Landlock never sees them. `FsGuard` is what keeps those honest.
///
/// Roots are canonicalized once at construction, and every checked path is
/// canonicalized before comparison, so neither `..` nor a symlink can present a
/// path that merely *looks* like it is inside an allowed root.
#[derive(Debug, Clone)]
pub struct FsGuard {
    readable: Vec<PathBuf>,
    writable: Vec<PathBuf>,
}

impl FsGuard {
    /// Resolve `policy`'s roots into a guard.
    ///
    /// Roots that do not exist are dropped rather than rejected: a policy may
    /// name a directory that has not been created yet, and a root that cannot be
    /// resolved can never match a canonical path anyway — so dropping it is the
    /// conservative choice, not a permissive one.
    pub fn new(policy: &SandboxPolicy) -> Result<Self, SandboxError> {
        Ok(Self {
            readable: canonical_roots(policy.readable_paths()),
            writable: canonical_roots(policy.writable_paths()),
        })
    }

    /// Permit reading `path`, returning its resolved location.
    ///
    /// The path must already exist — you cannot read what is not there.
    pub fn check_read(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = canonicalize(path)?;
        permit(resolved, &self.readable, path, "read")
    }

    /// Permit writing `path`, returning its resolved location.
    ///
    /// Unlike reads, the target need not exist yet — writes create files. Only
    /// the parent directory is resolved, and the filename is appended to that
    /// resolved parent, so `..` in the path is still collapsed before the check.
    pub fn check_write(&self, path: &Path) -> Result<PathBuf, SandboxError> {
        let resolved = match canonicalize(path) {
            Ok(existing) => existing,
            Err(_) => {
                // `canonicalize` fails the same way on a nonexistent path and on
                // a *dangling* symlink. Resolving only the parent would approve
                // the link, and the caller's write would then follow it out of
                // the root — so refuse a symlink leaf outright rather than
                // treating it as a file yet to be created.
                if path.symlink_metadata().is_ok_and(|m| m.is_symlink()) {
                    crate::AuditEvent::denied(
                        "write",
                        &path.display().to_string(),
                        "symlink leaf may resolve outside the allowed root",
                    )
                    .emit();
                    return Err(SandboxError::PathNotAllowed {
                        requested: path.to_path_buf(),
                    });
                }

                let parent = path.parent().ok_or_else(|| SandboxError::PathNotAllowed {
                    requested: path.to_path_buf(),
                })?;
                let file_name = path
                    .file_name()
                    .ok_or_else(|| SandboxError::PathNotAllowed {
                        requested: path.to_path_buf(),
                    })?;
                canonicalize(parent)?.join(file_name)
            }
        };

        permit(resolved, &self.writable, path, "write")
    }
}

/// Resolve every root that currently exists, discarding the rest.
fn canonical_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    roots.iter().filter_map(|r| canonicalize(r).ok()).collect()
}

fn canonicalize(path: &Path) -> Result<PathBuf, SandboxError> {
    path.canonicalize()
        .map_err(|source| SandboxError::Unresolvable {
            requested: path.to_path_buf(),
            source,
        })
}

/// Allow `resolved` only if it sits inside one of `roots`.
///
/// Compares whole path components, not string prefixes: `/work-secrets` must not
/// match the root `/work`, which a `starts_with` on strings would allow.
/// `Path::starts_with` is component-wise, which is exactly the needed semantics.
fn permit(
    resolved: PathBuf,
    roots: &[PathBuf],
    requested: &Path,
    operation: &str,
) -> Result<PathBuf, SandboxError> {
    let subject = requested.display().to_string();

    if roots.iter().any(|root| resolved.starts_with(root)) {
        crate::AuditEvent::allowed(operation, &subject).emit();
        Ok(resolved)
    } else {
        crate::AuditEvent::denied(operation, &subject, "outside every allowed root").emit();
        Err(SandboxError::PathNotAllowed {
            requested: requested.to_path_buf(),
        })
    }
}
