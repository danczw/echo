//! Public contract of [`SandboxedCommand`].

use echo_sandbox::{HELPER_FLAG, SandboxPolicy, SandboxedCommand};

/// Without an explicit helper, the command re-runs this executable with the
/// dispatch flag — so a shipped echo needs no second binary installed.
#[test]
fn defaults_to_re_executing_the_current_binary() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .command_line()
        .unwrap();

    assert_eq!(helper, std::env::current_exe().unwrap());
    assert_eq!(argv.first().map(String::as_str), Some(HELPER_FLAG));
}

/// The policy must reach the helper intact: a grant lost here is a permission
/// the tool silently does not get, and one invented here is one it should not
/// have had.
#[test]
fn carries_the_policy_into_the_command_line() {
    let (_, argv) = SandboxedCommand::new("/bin/sh", SandboxPolicy::default().allow_read("/usr"))
        .arg("-c")
        .arg("true")
        .helper("/nonexistent/helper")
        .command_line()
        .unwrap();

    assert!(argv.windows(2).any(|w| w == ["--ro", "/usr"]));
    assert_eq!(&argv[argv.len() - 3..], &["/bin/sh", "-c", "true"]);
}

/// An explicit helper suppresses the dispatch flag: that binary is already a
/// helper and does not need telling.
#[test]
fn explicit_helper_takes_no_dispatch_flag() {
    let (helper, argv) = SandboxedCommand::new("/bin/true", SandboxPolicy::default())
        .helper("/some/helper")
        .command_line()
        .unwrap();

    assert_eq!(helper, std::path::Path::new("/some/helper"));
    assert!(!argv.contains(&HELPER_FLAG.to_string()));
}

/// End-to-end through the real helper: the policy is enforced by the kernel,
/// not merely encoded.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn runs_a_command_under_the_policy() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("readable.txt");
    std::fs::write(&file, b"visible").unwrap();

    let policy = SandboxPolicy::default()
        .allow_read("/usr")
        .allow_read("/bin")
        .allow_read("/lib")
        .allow_read("/lib64")
        .allow_read(dir.path());

    let output = SandboxedCommand::new("/bin/cat", policy)
        .arg(file.to_str().unwrap())
        .helper(env!("CARGO_BIN_EXE_echo-sandbox-helper"))
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "visible");
}

/// A path the policy never granted stays unreadable through this API too.
#[cfg(all(feature = "sandbox-integration", target_os = "linux"))]
#[test]
fn refuses_a_path_the_policy_omits() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret.txt");
    std::fs::write(&secret, b"secret").unwrap();

    let policy = SandboxPolicy::default()
        .allow_read("/usr")
        .allow_read("/bin")
        .allow_read("/lib")
        .allow_read("/lib64");

    let output = SandboxedCommand::new("/bin/cat", policy)
        .arg(secret.to_str().unwrap())
        .helper(env!("CARGO_BIN_EXE_echo-sandbox-helper"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret"));
}
