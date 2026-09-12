use crate::{HelperArgs, SandboxError};

/// Apply a policy to *this* process, then become the requested command.
///
/// Intended to run in a freshly executed helper process, never inside echo:
/// Landlock restrictions are irreversible and inherited, so applying them here
/// would cage echo itself.
///
/// Because this process is fresh, it is single-threaded, and the restriction
/// code runs in an ordinary context — no `fork`/`exec` window, so no
/// async-signal-safety constraint and no `unsafe`.
///
/// On success this never returns: the process image is replaced. Any return is
/// an error, and the caller must exit non-zero rather than continue — a helper
/// that fell through to running the command unrestricted would be the exact
/// failure the sandbox exists to prevent.
pub fn exec_sandboxed(argv: &[String]) -> Result<std::convert::Infallible, SandboxError> {
    let request = HelperArgs::decode(argv)?;

    apply(&request.policy)?;

    // `exec` replaces this process image, so the restrictions just applied carry
    // into the command. It only returns on failure.
    //
    // The workspace bans `Command::new` so nothing can spawn around the sandbox.
    // This is the one sanctioned call: `apply` has already restricted this
    // process, so the command inherits the cage rather than escaping it. The
    // allow is per-call-site, not crate-wide, so any other use still fails the
    // lint.
    let error = {
        use std::os::unix::process::CommandExt;
        #[allow(clippy::disallowed_methods)]
        std::process::Command::new(&request.program)
            .args(&request.args)
            .exec()
    };

    Err(SandboxError::SpawnFailed {
        detail: "could not execute the sandboxed command",
        source: error,
    })
}

/// Restrict the current process according to `policy`.
#[cfg(target_os = "linux")]
fn apply(policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreatedAttr, RulesetStatus,
    };

    let abi = ABI::V1;
    let read_only = AccessFs::from_read(abi);
    let read_write = AccessFs::from_all(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(read_write)
        .map_err(landlock_failed)?
        .create()
        .map_err(landlock_failed)?;

    // Directory-only rights (ReadDir, MakeDir, …) are invalid on a regular file
    // and the kernel rejects the whole ruleset if one is attached to it. A
    // policy may name either, so narrow the rights to what the target can
    // actually carry. Intersecting rather than substituting keeps this a
    // restriction: a file can never end up with more than the directory case.
    let file_rights = AccessFs::from_file(abi);
    for (paths, rights) in [
        (policy.readable_paths(), read_only),
        (policy.writable_paths(), read_write),
    ] {
        for path in paths {
            let rights = if path.is_dir() {
                rights
            } else {
                rights & file_rights
            };
            let fd = PathFd::new(path).map_err(landlock_failed)?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, rights))
                .map_err(landlock_failed)?;
        }
    }

    let status = ruleset.restrict_self().map_err(landlock_failed)?;

    // The kernel may accept a ruleset and enforce only part of it. Partial
    // enforcement is treated as failure: it would leave the caller believing in
    // restrictions that are not actually in place.
    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Unsupported {
            detail: "kernel accepted the ruleset but enforced none of it",
        });
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn apply(_policy: &crate::SandboxPolicy) -> Result<(), SandboxError> {
    Err(SandboxError::Unsupported {
        detail: "sandboxing is only implemented for Linux",
    })
}

#[cfg(target_os = "linux")]
fn landlock_failed(source: impl std::fmt::Display) -> SandboxError {
    // Carry the kernel's own reason: "refused" without a cause is unactionable
    // for whoever has to work out which path or access right it objected to.
    SandboxError::Landlock {
        detail: source.to_string(),
    }
}
