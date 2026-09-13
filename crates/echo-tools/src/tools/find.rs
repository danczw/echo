use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

/// Arguments for the `find` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FindInput {
    /// Absolute path of the directory to search.
    pub path: PathBuf,
    /// Substring to match against file names.
    pub name: String,
}

/// Find files beneath a directory whose name contains a substring.
pub fn execute(input: FindInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let root = ctx
        .guard()
        .check_read(&input.path)
        .map_err(|error| ToolError::Denied {
            subject: input.path.display().to_string(),
            reason: error.to_string(),
        })?;

    let mut found = Vec::new();
    let mut stack = vec![root];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            // Re-checked per entry: a symlink inside a readable directory can
            // point outside the allowed roots.
            let Ok(resolved) = ctx.guard().check_read(&entry.path()) else {
                continue;
            };

            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(resolved);
                continue;
            }

            if entry.file_name().to_string_lossy().contains(&input.name) {
                found.push(resolved.display().to_string());
            }
        }
    }

    found.sort();

    Ok(ToolOutput {
        content: if found.is_empty() {
            "no matches".to_string()
        } else {
            found.join("\n")
        },
    })
}
