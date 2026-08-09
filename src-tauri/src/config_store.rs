use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BACKUPS_PER_FILE: usize = 20;
const BACKUP_PREFIX: &str = "private-network-backup-";

pub fn persist_validated_pair<F>(
    config_path: &Path,
    metadata_path: &Path,
    expected_config: &[u8],
    expected_metadata: Option<&[u8]>,
    config_bytes: &[u8],
    metadata_bytes: &[u8],
    validate_config: F,
) -> Result<PathBuf, String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    let staged_config = stage_file(config_path, config_bytes)?;
    validate_config(staged_config.path())?;
    let staged_metadata = stage_file(metadata_path, metadata_bytes)?;

    ensure_unchanged(config_path, Some(expected_config))?;
    ensure_unchanged(metadata_path, expected_metadata)?;

    let config_backup = create_backup(config_path)?;
    let metadata_backup = if metadata_path.exists() {
        Some(create_backup(metadata_path)?)
    } else {
        None
    };
    if let Err(error) = ensure_unchanged(config_path, Some(expected_config))
        .and_then(|_| ensure_unchanged(metadata_path, expected_metadata))
    {
        let _ = fs::remove_file(&config_backup);
        if let Some(path) = metadata_backup.as_deref() {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }

    staged_metadata
        .persist(metadata_path)
        .map_err(|error| format!("Failed to replace metadata file: {}", error.error))?;

    if let Err(error) = staged_config.persist(config_path) {
        let rollback = restore_optional_backup(metadata_path, metadata_backup.as_deref());
        return Err(match rollback {
            Ok(()) => format!("Failed to replace config file: {}", error.error),
            Err(rollback_error) => format!(
                "Failed to replace config file: {}; metadata rollback also failed: {rollback_error}",
                error.error
            ),
        });
    }

    let _ = sync_parent(config_path);
    if metadata_path.parent() != config_path.parent() {
        let _ = sync_parent(metadata_path);
    }
    prune_backups(config_path, MAX_BACKUPS_PER_FILE);
    prune_backups(metadata_path, MAX_BACKUPS_PER_FILE);

    Ok(config_backup)
}

fn ensure_unchanged(path: &Path, expected: Option<&[u8]>) -> Result<(), String> {
    let unchanged = match expected {
        Some(expected) => fs::read(path)
            .map(|current| current == expected)
            .unwrap_or(false),
        None => !path.exists(),
    };
    if unchanged {
        Ok(())
    } else {
        Err(format!(
            "{} changed outside Private Network; refresh before saving.",
            path.display()
        ))
    }
}

fn stage_file(target: &Path, bytes: &[u8]) -> Result<tempfile::NamedTempFile, String> {
    let parent = target
        .parent()
        .ok_or_else(|| format!("Path has no parent: {}", target.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Failed to create {}: {error}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("Failed to stage {}: {error}", target.display()))?;
    temporary
        .write_all(bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("Failed to write staged {}: {error}", target.display()))?;
    copy_permissions(target, temporary.path())?;
    Ok(temporary)
}

fn create_backup(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("Path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("config.json");
    let backup_path = parent.join(format!("{file_name}.{BACKUP_PREFIX}{}", unique_timestamp()));
    fs::copy(path, &backup_path)
        .map_err(|error| format!("Failed to back up {}: {error}", path.display()))?;
    let backup = fs::OpenOptions::new()
        .read(true)
        .open(&backup_path)
        .map_err(|error| format!("Failed to open backup {}: {error}", backup_path.display()))?;
    backup
        .sync_all()
        .map_err(|error| format!("Failed to sync backup {}: {error}", backup_path.display()))?;
    Ok(backup_path)
}

fn restore_optional_backup(target: &Path, backup: Option<&Path>) -> Result<(), String> {
    match backup {
        Some(backup) => {
            let bytes = fs::read(backup)
                .map_err(|error| format!("Failed to read rollback backup: {error}"))?;
            stage_file(target, &bytes)?
                .persist(target)
                .map_err(|error| {
                    format!("Failed to restore {}: {}", target.display(), error.error)
                })?;
        }
        None => {
            if target.exists() {
                fs::remove_file(target)
                    .map_err(|error| format!("Failed to remove rolled-back metadata: {error}"))?;
            }
        }
    }
    sync_parent(target)
}

fn copy_permissions(source: &Path, target: &Path) -> Result<(), String> {
    if source.exists() {
        let permissions = fs::metadata(source)
            .map_err(|error| {
                format!(
                    "Failed to read permissions for {}: {error}",
                    source.display()
                )
            })?
            .permissions();
        fs::set_permissions(target, permissions).map_err(|error| {
            format!(
                "Failed to set permissions for {}: {error}",
                target.display()
            )
        })?;
    } else {
        set_private_permissions(target)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("Failed to secure {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| format!("Path has no parent: {}", path.display()))?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("Failed to sync {}: {error}", parent.display()))?;
    }
    Ok(())
}

fn prune_backups(path: &Path, keep: usize) {
    let Some(parent) = path.parent() else {
        return;
    };
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return;
    };
    let prefix = format!("{file_name}.{BACKUP_PREFIX}");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    let mut backups: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.starts_with(&prefix))
        })
        .collect();
    backups.sort_unstable();
    let remove_count = backups.len().saturating_sub(keep);
    for backup in backups.into_iter().take(remove_count) {
        let _ = fs::remove_file(backup);
    }
}

fn unique_timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn commits_both_files_after_validation() {
        let directory = tempdir().expect("temp dir");
        let config = directory.path().join("config.json");
        let metadata = directory.path().join("users.json");
        fs::write(&config, b"old config").expect("old config");
        fs::write(&metadata, b"old metadata").expect("old metadata");

        let backup = persist_validated_pair(
            &config,
            &metadata,
            b"old config",
            Some(b"old metadata"),
            b"new config",
            b"new metadata",
            |path| {
                assert_eq!(fs::read(path).expect("staged config"), b"new config");
                Ok(())
            },
        )
        .expect("persist pair");

        assert_eq!(fs::read(&config).expect("config"), b"new config");
        assert_eq!(fs::read(&metadata).expect("metadata"), b"new metadata");
        assert_eq!(fs::read(backup).expect("backup"), b"old config");
    }

    #[test]
    fn validation_failure_leaves_originals_untouched() {
        let directory = tempdir().expect("temp dir");
        let config = directory.path().join("config.json");
        let metadata = directory.path().join("users.json");
        fs::write(&config, b"old config").expect("old config");
        fs::write(&metadata, b"old metadata").expect("old metadata");

        let result = persist_validated_pair(
            &config,
            &metadata,
            b"old config",
            Some(b"old metadata"),
            b"invalid config",
            b"new metadata",
            |_| Err("invalid".to_string()),
        );

        assert!(result.is_err());
        assert_eq!(fs::read(&config).expect("config"), b"old config");
        assert_eq!(fs::read(&metadata).expect("metadata"), b"old metadata");
    }

    #[test]
    fn creates_private_metadata_when_missing() {
        let directory = tempdir().expect("temp dir");
        let config = directory.path().join("config.json");
        let metadata = directory.path().join("users.json");
        fs::write(&config, b"old config").expect("old config");

        persist_validated_pair(
            &config,
            &metadata,
            b"old config",
            None,
            b"new config",
            b"metadata",
            |_| Ok(()),
        )
        .expect("persist pair");

        assert_eq!(fs::read(&metadata).expect("metadata"), b"metadata");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&metadata)
                    .expect("metadata permissions")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn refuses_to_overwrite_external_changes() {
        let directory = tempdir().expect("temp dir");
        let config = directory.path().join("config.json");
        let metadata = directory.path().join("users.json");
        fs::write(&config, b"externally changed").expect("config");

        let result = persist_validated_pair(
            &config,
            &metadata,
            b"previous content",
            None,
            b"new config",
            b"metadata",
            |_| Ok(()),
        );

        assert!(result.is_err());
        assert_eq!(fs::read(&config).expect("config"), b"externally changed");
        assert!(!metadata.exists());
    }
}
