use crate::error::ClientError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

const STORE_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StoreDocument {
    version: u8,
    entries: BTreeMap<String, String>,
}

impl Default for StoreDocument {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

/// One owner-only, atomically updated map for application-managed credentials.
pub(crate) struct OwnerOnlySecretFile {
    path: PathBuf,
    gate: Mutex<()>,
}

impl OwnerOnlySecretFile {
    pub(crate) fn new(app_data_dir: &Path, file_name: &str) -> Result<Self, ClientError> {
        let mut components = Path::new(file_name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(local_store_error("file_name_invalid"));
        }
        fs::create_dir_all(app_data_dir).map_err(|_| local_store_error("directory_create"))?;
        validate_directory(app_data_dir)?;
        set_directory_permissions(app_data_dir)?;
        let path = app_data_dir.join(file_name);
        if path.exists() {
            validate_regular_file(&path)?;
            set_file_permissions(&path)?;
        }
        let store = Self {
            path,
            gate: Mutex::new(()),
        };
        let _ = store.read()?;
        Ok(store)
    }

    pub(crate) fn get(&self, key: &str) -> Result<Option<String>, ClientError> {
        Ok(self.read()?.entries.remove(key))
    }

    pub(crate) fn set(&self, key: &str, value: &str) -> Result<(), ClientError> {
        let _guard = self.gate.lock().map_err(|_| local_store_error("lock"))?;
        let mut document = self.read_unlocked()?;
        document.entries.insert(key.to_string(), value.to_string());
        self.write_unlocked(&document)
    }

    pub(crate) fn delete(&self, key: &str) -> Result<(), ClientError> {
        let _guard = self.gate.lock().map_err(|_| local_store_error("lock"))?;
        let mut document = self.read_unlocked()?;
        if document.entries.remove(key).is_some() {
            self.write_unlocked(&document)?;
        }
        Ok(())
    }

    fn read(&self) -> Result<StoreDocument, ClientError> {
        let _guard = self.gate.lock().map_err(|_| local_store_error("lock"))?;
        self.read_unlocked()
    }

    fn read_unlocked(&self) -> Result<StoreDocument, ClientError> {
        if !self.path.exists() {
            return Ok(StoreDocument::default());
        }
        validate_regular_file(&self.path)?;
        let bytes = fs::read(&self.path).map_err(|_| local_store_error("read"))?;
        let document: StoreDocument =
            serde_json::from_slice(&bytes).map_err(|_| local_store_error("invalid"))?;
        if document.version != STORE_VERSION {
            return Err(local_store_error("version"));
        }
        Ok(document)
    }

    fn write_unlocked(&self, document: &StoreDocument) -> Result<(), ClientError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| local_store_error("directory_missing"))?;
        let bytes = serde_json::to_vec(document).map_err(|_| local_store_error("serialize"))?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(parent).map_err(|_| local_store_error("temporary"))?;
        temporary
            .write_all(&bytes)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| local_store_error("write"))?;
        set_file_permissions(temporary.path())?;
        temporary
            .persist(&self.path)
            .map_err(|_| local_store_error("persist"))?;
        set_file_permissions(&self.path)?;
        sync_directory(parent)?;
        Ok(())
    }
}

fn validate_directory(path: &Path) -> Result<(), ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| local_store_error("metadata"))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(local_store_error("unsafe_directory"));
    }
    Ok(())
}

fn validate_regular_file(path: &Path) -> Result<(), ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| local_store_error("metadata"))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(local_store_error("unsafe_path"));
    }
    Ok(())
}

#[cfg(unix)]
fn set_directory_permissions(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| local_store_error("directory_permissions"))
}

#[cfg(not(unix))]
fn set_directory_permissions(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| local_store_error("file_permissions"))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ClientError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| local_store_error("directory_sync"))
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

fn local_store_error(reason: &str) -> ClientError {
    ClientError::internal(
        format!("local_credential_store_{reason}"),
        "The application-managed credential store is unavailable.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_atomically_updates_entries() {
        let directory = tempfile::tempdir().unwrap();
        let store = OwnerOnlySecretFile::new(directory.path(), "credentials.json").unwrap();
        store.set("first", "secret-one").unwrap();
        store.set("second", "secret-two").unwrap();
        assert_eq!(store.get("first").unwrap().as_deref(), Some("secret-one"));

        let reopened = OwnerOnlySecretFile::new(directory.path(), "credentials.json").unwrap();
        assert_eq!(
            reopened.get("second").unwrap().as_deref(),
            Some("secret-two")
        );
        reopened.delete("first").unwrap();
        assert!(reopened.get("first").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn tightens_directory_and_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let store = OwnerOnlySecretFile::new(directory.path(), "credentials.json").unwrap();
        store.set("account", "secret").unwrap();
        assert_eq!(
            fs::metadata(directory.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(directory.path().join("credentials.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn rejects_nested_file_names() {
        let directory = tempfile::tempdir().unwrap();
        assert!(OwnerOnlySecretFile::new(directory.path(), "../credentials.json").is_err());
        assert!(OwnerOnlySecretFile::new(directory.path(), "nested/credentials.json").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_store_directory() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let linked = parent.path().join("credentials");
        symlink(target.path(), &linked).unwrap();
        assert!(OwnerOnlySecretFile::new(&linked, "credentials.json").is_err());
    }
}
