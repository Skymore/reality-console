# xray-runtime

`xray-runtime` is the narrow Xray boundary intended for the future Node Host
agent. It is a standalone Rust 1.80 crate.

## Included

- A typed, deterministic VLESS + REALITY server configuration builder.
- An optional least-privilege Stats API topology: a dedicated IPv4-loopback
  `dokodemo-door` inbound, one fixed API routing rule, `StatsService` only, and
  per-user byte counters enabled through policy level `0`.
- Conservative validation for listen endpoints, REALITY targets, server names,
  private keys, short IDs, and VLESS users.
- Explicit Xray executable selection by absolute path and caller-provided
  SHA-256 digest. No `PATH` lookup is performed. This stage requires Unix so it
  can enforce executable bits, reject group/world-writable or unbounded files,
  and use no-follow file opening.
- Explicit managed-config selection by absolute path and caller-provided SHA-256
  digest. Config files must be regular, non-empty, at most 2 MiB, and mode
  `0600`; symbolic links are rejected.
- Bounded asynchronous `xray version` and
  `xray run -test -config <private-tempfile>` operations with no shell.
- Bounded, non-resetting `xray api statsquery` execution against IPv4 loopback,
  with strict cumulative per-user counter parsing and no response contents in
  errors.
- Constrained `xray run -config <path>` startup with a cleared environment,
  null standard streams, drop-triggered kill, nonblocking status checks, and a
  bounded forceful kill/reap operation for an external supervisor.
- Redacted error messages that never include configuration contents, paths,
  REALITY private keys, or child stdout/stderr contents.

Disabled users are checked for duplicate UUIDs and emails but omitted from the
rendered `settings.users` list. An empty enabled set is valid and revokes all
VLESS identities. Server names, short IDs, and users are sorted before
serialization so equivalent input sets produce identical JSON.

## Explicitly not included

This stage does **not** download or update Xray, discover binaries, generate
keys, implement the long-running supervisor itself, activate configuration,
perform an atomic swap, or roll back a failed activation. Those responsibilities
must sit in a later Node Host orchestration layer with their own persistence and
recovery protocol.

The caller is also responsible for provisioning a trusted Xray binary and
trusted expected digests for both the binary and managed configuration. The
crate revalidates both immediately before managed startup, but their containing
directories must still be protected from untrusted writers.

## Verification

```bash
cargo fmt --manifest-path crates/xray-runtime/Cargo.toml -- --check
cargo clippy --manifest-path crates/xray-runtime/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path crates/xray-runtime/Cargo.toml --locked
git diff --check -- crates/xray-runtime
```
