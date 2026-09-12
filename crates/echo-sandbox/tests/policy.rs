//! Public contract of [`SandboxPolicy`].

use echo_sandbox::SandboxPolicy;

/// The foundational guarantee: a policy nobody configured grants nothing.
///
/// Every other sandbox behaviour builds on this. If the default ever grants an
/// access, a caller that forgets to configure the policy silently gets an
/// unsandboxed agent.
#[test]
fn default_policy_denies_everything() {
    let policy = SandboxPolicy::default();

    assert!(
        policy.readable_paths().is_empty(),
        "default policy must not grant read access to any path"
    );
    assert!(
        policy.writable_paths().is_empty(),
        "default policy must not grant write access to any path"
    );
    assert!(
        !policy.allows_network(),
        "default policy must not grant network access"
    );
}
