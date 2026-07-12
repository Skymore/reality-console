# Control Backup And Recovery

Control backups contain the SQLite database and the controller Ed25519 signing seed. The seed is
not encrypted by Control. A backup is safe only when the complete destination directory is stored
inside an operator-managed encrypted destination such as an encrypted APFS volume, encrypted
object-store repository, or encrypted backup agent destination.

`--external-encryption-contract` is a non-secret identifier recorded in the manifest. It is an
explicit operator acknowledgement, not an encryption implementation or an encryption check.

## Create And Verify

SQLite Online Backup produces a transactionally consistent standalone snapshot while Control is
running. The snapshot is finalized out of WAL mode before publication. Staging directories use
owner-only permissions and are renamed into place only after all checks pass. The destination must
not already exist.

```bash
control-server backup create \
  --database /var/lib/private-network/control.sqlite3 \
  --destination /Volumes/EncryptedBackups/control-2026-07-11 \
  --external-encryption-contract encrypted-apfs-v1

control-server backup verify \
  --backup /Volumes/EncryptedBackups/control-2026-07-11
```

The artifact has exactly three owner-only files:

- `control.sqlite3`: consistent database snapshot
- `control.sqlite3.controller-ed25519`: controller signing seed sidecar
- `manifest.json`: database and identity digests, controller signature, schema/migration identity,
  controller binding, and high-water marks

Verification performs full SQLite integrity and foreign-key checks, exact migration history checks,
artifact and manifest digest checks, controller manifest signature checks, signing-key and controller
instance binding checks, and high-water recomputation. Command output contains only public IDs,
fingerprints, digests, schema versions, and the non-secret encryption contract identifier.

## Recovery

Stop Control before recovery. Recovery never replaces an existing directory. It verifies and copies
the artifact into an owner-only sibling staging directory, verifies the staged copy again, and then
atomically renames it to a previously absent generation directory. Point `CONTROL_DATABASE_PATH` at
`GENERATION/control.sqlite3` only after a successful restore.

Always run a dry run first:

```bash
control-server restore \
  --backup /Volumes/EncryptedBackups/control-2026-07-11 \
  --destination /var/lib/private-network/generations/restore-2026-07-11 \
  --current-database /var/lib/private-network/current/control.sqlite3 \
  --recovery-mode \
  --dry-run
```

Remove `--dry-run` to create the generation. `--current-database` is locked exclusively and supplies
the controller identity and high-water rollback baseline. Recovery rejects another controller,
another controller instance, a running Control process, and any candidate behind a durable counter.

For first installation or total loss where no local controller history exists, replace
`--current-database` with `--no-local-history`. That option explicitly waives local rollback
comparison; it must not be used merely to bypass a rollback failure.

The service has no implicit recovery mode. Every restore, including dry runs, requires the explicit
`--recovery-mode` capability flag. A failure before final rename leaves the current controller and
requested destination unchanged. Switching service configuration, retention of old generations,
and deletion of failed staging remnants are operator-owned deployment actions.
