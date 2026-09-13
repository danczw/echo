use std::path::PathBuf;

use serde::Deserialize;

use crate::{ExecutionContext, ToolError, ToolOutput};

/// Arguments for the `grep` tool.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GrepInput {
    /// Absolute path of the directory to search.
    pub path: PathBuf,
    /// Literal text to look for. Not a regular expression.
    pub pattern: String,
}

/// Search file contents beneath a directory for a literal string.
///
/// Deliberately a literal search, not a regex: a regex would pull in a
/// dependency and a whole class of pathological-pattern behaviour, for a tool
/// whose common use is "find where this symbol is mentioned".
pub fn execute(input: GrepInput, ctx: &ExecutionContext) -> Result<ToolOutput, ToolError> {
    let root = ctx
        .guard()
        .check_read(&input.path)
        .map_err(|error| ToolError::Denied {
            subject: input.path.display().to_string(),
            reason: error.to_string(),
        })?;

    let mut hits = Vec::new();
    let mut stack = vec![root];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue; // an unreadable subdirectory is skipped, not fatal
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Re-check every path rather than trusting the walk: a symlink in a
            // readable directory can point outside the allowed roots.
            let Ok(resolved) = ctx.guard().check_read(&path) else {
                continue;
            };

            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(resolved);
                continue;
            }

            // Binary files are skipped rather than mangled into the output.
            let Ok(content) = std::fs::read_to_string(&resolved) else {
                continue;
            };

            for (number, line) in content.lines().enumerate() {
                if line.contains(&input.pattern) {
                    hits.push(format!(
                        "{}:{}: {}",
                        resolved.display(),
                        number + 1,
                        line.trim()
                    ));
                }
            }
        }
    }

    hits.sort();

    Ok(ToolOutput {
        content: if hits.is_empty() {
            "no matches".to_string()
        } else {
            hits.join("\n")
        },
    })
}
