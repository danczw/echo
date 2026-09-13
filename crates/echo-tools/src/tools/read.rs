use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

/// Arguments for the `read` tool.
///
/// The JSON schema the model is shown is derived from this struct, so the
/// contract advertised and the contract parsed cannot drift apart.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadInput {
    /// Absolute path of the file to read.
    pub path: PathBuf,
}

/// Read a file's contents.
///
/// Never spawns a process, so the kernel enforcement never sees it — the
/// `FsGuard` check below is the only thing keeping it inside the policy.
pub fn execute(input: ReadInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let resolved = ctx
        .guard()
        .check_read(&input.path)
        .map_err(crate::denied(&input.path))?;

    // Read the *resolved* path, not the requested one: the guard canonicalized
    // it, and re-reading the original would reopen the traversal it just closed.
    let content = std::fs::read_to_string(&resolved).map_err(|error| ToolError::Failed {
        subject: format!("read {}", input.path.display()),
        detail: error.to_string(),
    })?;

    Ok(ToolOutput {
        content: ctx.limits().take_bytes(content),
    })
}
