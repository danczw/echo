//! Does the kernel actually block an escape?
//!
//! Everything else in this crate tests our own logic. These tests spawn real
//! processes and assert the *kernel* refuses them, which is the only evidence
//! that the sandbox does anything at all.
//!
//! Gated behind `--features sandbox-integration` because they need a Linux
//! kernel with Landlock available (5.13+, enabled at boot).
#![cfg(all(feature = "sandbox-integration", target_os = "linux"))]
// Both `Command::new` uses below spawn the sandbox helper itself — never a
// command that bypasses it. The workspace ban exists to stop code executing
// *around* the sandbox; launching the sandbox is the subject of these tests.
#![allow(clippy::disallowed_methods)]

use std::path::Path;
use std::process::Command;

use echo_sandbox::{HelperArgs, SandboxPolicy};

/// Paths the helper itself needs in order to `exec` anything at all.
///
/// `exec` happens *after* the restrictions are applied, so the interpreter and
/// shared libraries must stay readable or nothing can start — including the
/// commands these tests use to probe the sandbox.
fn runtime_paths(policy: SandboxPolicy) -> SandboxPolicy {
    ["/usr", "/bin", "/lib", "/lib64", "/etc/ld.so.cache"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .fold(policy, |acc, p| acc.allow_read(p))
}

fn run(policy: &SandboxPolicy, program: &str, args: &[&str]) -> std::process::Output {
    let owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    Command::new(env!("CARGO_BIN_EXE_echo-sandbox-helper"))
        .args(HelperArgs::encode(policy, program, &owned))
        .output()
        .expect("helper should start")
}

/// Baseline: with the path allowed, the command works. Without this the denial
/// tests below would pass even if the sandbox broke everything indiscriminately.
#[test]
fn allowed_path_can_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("readable.txt");
    std::fs::write(&file, b"visible").unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read(dir.path());
    let output = run(&policy, "/bin/cat", &[file.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "reading an allowed path failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible");
}

/// The point of the whole crate: a path the policy never granted is unreadable,
/// enforced by the kernel rather than by our own checks.
#[test]
fn unallowed_path_cannot_be_read() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    // Note the temp dir is deliberately NOT granted.
    let policy = runtime_paths(SandboxPolicy::default());
    let output = run(&policy, "/bin/cat", &[secret.to_str().unwrap()]);

    assert!(
        !output.status.success(),
        "kernel allowed a read the policy never granted"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("secret"),
        "secret contents leaked through the sandbox"
    );
}

/// Read access must not carry write access, at the kernel level and not merely
/// in `FsGuard`.
#[test]
fn read_only_grant_cannot_write() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("readonly.txt");
    std::fs::write(&file, b"original").unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_read(dir.path());
    let output = run(
        &policy,
        "/bin/sh",
        &["-c", &format!("echo overwritten > {}", file.display())],
    );

    assert!(!output.status.success(), "wrote to a read-only grant");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "original",
        "file was modified despite a read-only grant"
    );
}

#[test]
fn write_grant_can_write() {
    let dir = tempfile::tempdir().unwrap();

    let policy = runtime_paths(SandboxPolicy::default()).allow_write(dir.path());
    let created = dir.path().join("created.txt");
    let output = run(
        &policy,
        "/bin/sh",
        &["-c", &format!("echo written > {}", created.display())],
    );

    assert!(
        output.status.success(),
        "writing to an allowed path failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_to_string(&created).unwrap(), "written\n");
}

/// A helper that cannot enforce must not run the command anyway.
#[test]
fn malformed_arguments_do_not_run_the_command() {
    let marker = tempfile::tempdir().unwrap().path().join("should-not-exist");

    let output = Command::new(env!("CARGO_BIN_EXE_echo-sandbox-helper"))
        .args(["--not-a-flag", "--", "/bin/touch", marker.to_str().unwrap()])
        .output()
        .expect("helper should start");

    assert!(!output.status.success());
    assert!(
        !marker.exists(),
        "helper ran the command despite refusing its arguments"
    );
}

/// Network denial comes from an empty network namespace, not from Landlock.
///
/// A fresh netns has only the loopback interface, so reading the caller's own
/// interface list is a hermetic check — no external network required.
#[test]
fn network_is_denied_by_default() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/net/dev"]);

    assert!(
        output.status.success(),
        "could not read the interface list: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let interfaces = String::from_utf8_lossy(&output.stdout);
    let named: Vec<&str> = interfaces
        .lines()
        .skip(2) // two header lines
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();

    assert_eq!(
        named,
        vec!["lo"],
        "a sandbox denying network must see only loopback, found: {named:?}"
    );
}

/// The opposite direction: granting network must actually grant it, or the flag
/// is decorative.
#[test]
fn allowed_network_keeps_host_interfaces() {
    let policy = runtime_paths(SandboxPolicy::default())
        .allow_read("/proc")
        .allow_network();
    let output = run(&policy, "/bin/cat", &["/proc/self/net/dev"]);

    assert!(output.status.success());
    let interfaces = String::from_utf8_lossy(&output.stdout);
    assert!(
        interfaces.lines().skip(2).count() > 1,
        "granting network should leave the host interfaces visible, got: {interfaces}"
    );
}

/// A seccomp filter must actually be installed, not merely constructed.
///
/// `/proc/self/status` reports `Seccomp: 2` once a BPF filter is in force, so
/// the sandboxed process can confirm its own state without needing a tool that
/// attempts a blocked syscall.
#[test]
fn seccomp_filter_is_installed() {
    let policy = runtime_paths(SandboxPolicy::default()).allow_read("/proc");
    let output = run(&policy, "/bin/cat", &["/proc/self/status"]);

    assert!(
        output.status.success(),
        "could not read process status: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let status = String::from_utf8_lossy(&output.stdout);
    let mode = status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp:"))
        .map(str::trim);

    assert_eq!(
        mode,
        Some("2"),
        "expected seccomp filter mode (2); process reported {mode:?}"
    );
}
