//! Applies a sandbox policy to itself, then becomes the requested command.
//!
//! Usage: `echo-sandbox-helper [--ro PATH]... [--rw PATH]... [--allow-network] -- PROGRAM [ARGS]...`
//!
//! Exists as a standalone binary so the enforcement path can be tested
//! end-to-end. In a shipped echo, the `echo` binary re-execs itself into the
//! same [`echo_sandbox::exec_sandboxed`] entry point rather than requiring this
//! to be installed alongside.

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    // On success this never returns — the process image is replaced. Reaching
    // the next line therefore always means failure, and the command must NOT be
    // run: falling through to an unrestricted execution is the exact failure the
    // sandbox exists to prevent.
    match echo_sandbox::exec_sandboxed(&argv) {
        Err(error) => {
            eprintln!("echo-sandbox-helper: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
