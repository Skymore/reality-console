# release-manifest

This crate is the non-networked trust boundary used before a Private Network component installs an
update. It does not download, unpack, execute, or replace artifacts.

It verifies:

- a domain-separated Ed25519 signature from a pinned offline release key;
- closed manifest schema and deterministic sorted artifact inventory;
- exact product, operating system, architecture, version, size, SHA-256, SBOM SHA-256, bundled Xray
  version, and supported configuration schema range;
- an operator/controller minimum version floor; and
- a separately signed, exact, short-lived authorization for emergency downgrades.

After policy verification, `verify_artifact` streams the package through SHA-256 with an exact
signed length bound. Package extraction and platform signature verification remain installer-owned
steps and must happen before mutation.

Offline signers call `release_signing_transcript` or `rollback_signing_transcript` and sign the exact
returned bytes. The signing key never enters this crate's verifier or ordinary CI. Multiple pinned
public roots permit an explicit overlap during key rotation; unknown key IDs fail closed.

Verification:

```bash
cargo fmt --manifest-path crates/release-manifest/Cargo.toml -- --check
cargo test --manifest-path crates/release-manifest/Cargo.toml --all-targets --locked
cargo clippy --manifest-path crates/release-manifest/Cargo.toml --all-targets --locked -- -D warnings
cargo rustdoc --manifest-path crates/release-manifest/Cargo.toml --locked -- -D warnings
```
