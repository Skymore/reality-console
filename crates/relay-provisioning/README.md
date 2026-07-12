# Relay Provisioning

Controller-side least-privilege boundary for two operations:

- issue a short-lived relay client certificate, private key, and random route token in memory;
- atomically publish or revoke an already controller-signed, non-secret route document.

The crate has no HTTP or database behavior. Control owns the durable outbox and calls this boundary
until the exact route digest is observed. The Relay independently verifies the controller signature.

CA and managed-route directories must already exist and be owner-only. Symlinks, non-regular files,
unknown directory entries, oversized files, conflicting idempotent writes, and unsafe permissions
fail closed.
