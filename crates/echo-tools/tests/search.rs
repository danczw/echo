//! Public contract of the `grep` and `find` tools.
//!
//! Both walk a directory tree, which is where confinement gets interesting: a
//! symlink inside a readable directory can point anywhere, so each entry is
//! re-checked rather than trusted because its parent was allowed.

use echo_sandbox::SandboxPolicy;
use echo_tools::{BuiltinTool, ExecutionContext, ToolError};
use serde_json::json;

fn context(policy: SandboxPolicy) -> ExecutionContext {
    ExecutionContext::new(policy).unwrap()
}

#[test]
fn grep_finds_matching_lines_with_locations() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.rs"), "fn alpha() {}\nfn beta() {}\n").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "beta" }),
            &ctx,
        )
        .unwrap();

    assert!(
        out.content.contains("a.rs:2"),
        "no location: {}",
        out.content
    );
    assert!(
        out.content.contains("fn beta()"),
        "no line: {}",
        out.content
    );
}

#[test]
fn grep_searches_subdirectories() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub/deep.txt"), "needle here\n").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "needle" }),
            &ctx,
        )
        .unwrap();

    assert!(out.content.contains("deep.txt"), "got: {}", out.content);
}

#[test]
fn grep_reports_no_matches_rather_than_failing() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a.txt"), "nothing\n").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "absent" }),
            &ctx,
        )
        .unwrap();

    assert_eq!(out.content, "no matches");
}

/// A symlink in a searched directory must not leak the contents of its target.
#[cfg(unix)]
#[test]
fn grep_does_not_follow_a_symlink_out_of_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret.txt"), "SECRET-NEEDLE\n").unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), root.path().join("escape")).unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Grep
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "pattern": "SECRET-NEEDLE" }),
            &ctx,
        )
        .unwrap();

    assert!(
        !out.content.contains("SECRET-NEEDLE"),
        "grep followed a symlink outside the allowed root: {}",
        out.content
    );
}

#[test]
fn grep_refuses_a_root_outside_the_policy() {
    let allowed = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(allowed.path()));
    let err = BuiltinTool::Grep
        .execute(
            json!({ "path": elsewhere.path().to_str().unwrap(), "pattern": "x" }),
            &ctx,
        )
        .unwrap_err();

    assert!(matches!(err, ToolError::Denied { .. }), "got {err:?}");
}

#[test]
fn find_matches_file_names() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("sub")).unwrap();
    std::fs::write(root.path().join("sub/target.rs"), "").unwrap();
    std::fs::write(root.path().join("other.txt"), "").unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Find
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "name": "target" }),
            &ctx,
        )
        .unwrap();

    assert!(out.content.contains("target.rs"), "got: {}", out.content);
    assert!(!out.content.contains("other.txt"), "got: {}", out.content);
}

/// The same symlink guarantee for `find`: names outside the root stay hidden.
#[cfg(unix)]
#[test]
fn find_does_not_follow_a_symlink_out_of_the_root() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::fs::write(elsewhere.path().join("secret-name.txt"), "").unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), root.path().join("escape")).unwrap();

    let ctx = context(SandboxPolicy::default().allow_read(root.path()));
    let out = BuiltinTool::Find
        .execute(
            json!({ "path": root.path().to_str().unwrap(), "name": "secret-name" }),
            &ctx,
        )
        .unwrap();

    assert!(
        !out.content.contains("secret-name"),
        "find followed a symlink outside the allowed root: {}",
        out.content
    );
}
