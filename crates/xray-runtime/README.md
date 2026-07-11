# xray-runtime

`xray-runtime` is the narrow Xray boundary intended for the future Node Host
agent. It is a standalone Rust 1.80 crate.

## Included

- A typed, deterministic VLESS + REALITY server configuration builder.
- Conservative validation for listen endpoints, REALITY targets, server names,
  private keys, short IDs, and VLESS users.
- Explicit Xray executable selection by absolute path and caller-provided
  SHA-256 digest. No `PATH` lookup is performed. This stage requires Unix so it
  can enforce executable bits, reject group/world-writable or unbounded files,
  and use no-follow file opening.
- Bounded asynchronous `xray version` and
  `xray run -test -config <private-tempfile>` operations with no shell.
- Redacted error messages that never include the generated configuration,
  REALITY private key, or child stdout/stderr contents.

Disabled users are checked for duplicate UUIDs and emails but omitted from the
rendered `settings.users` list. An empty enabled set is valid and revokes all
VLESS identities. Server names, short IDs, and users are sorted before
serialization so equivalent input sets produce identical JSON.

## Explicitly not included

This stage does **not** download or update Xray, discover binaries, generate
keys, supervise a long-running Xray process, activate configuration, perform an
atomic swap, or roll back a failed activation. Those responsibilities must sit
in a later Node Host orchestration layer with their own persistence and recovery
protocol.

The caller is also responsible for provisioning a trusted Xray binary and
trusted expected digest. The crate revalidates the digest before each bounded
operation, but the binary's containing directory must still be protected from
untrusted writers.

## Verification

```bash
cargo fmt --manifest-path crates/xray-runtime/Cargo.toml -- --check
cargo test --manifest-path crates/xray-runtime/Cargo.toml --all-targets
cargo clippy --manifest-path crates/xray-runtime/Cargo.toml --all-targets -- -D warnings
git diff --check -- crates/xray-runtime
```
