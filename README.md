# echo

[![CI](https://github.com/danczw/echo/actions/workflows/ci.yml/badge.svg)](https://github.com/danczw/echo/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org)

A security-first AI coding agent harness, written in Rust.

Most agent harnesses delegate isolation to an external container. echo treats
sandboxed tool execution as part of the harness itself: every command an agent
runs goes through a Landlock + seccomp boundary, and the sandbox fails closed
rather than degrading to unrestricted execution.

> **Pre-alpha.** Not usable yet. Each release states which enforcement is
> actually active — do not assume a version sandboxes anything until it says so.

## Development

```sh
cargo test --workspace                                 # default suite
cargo test --workspace --features sandbox-integration  # needs Linux kernel ≥ 5.13
cargo clippy --workspace --all-targets -- -D warnings
git config core.hooksPath .githooks                    # fmt + clippy on commit
```

`unsafe` is forbidden workspace-wide except in `echo-sandbox`, and spawning a
subprocess outside it is a clippy error — the sandbox boundary is enforced by
the build, not by convention alone.

## License

MIT
