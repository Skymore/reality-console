use crate::core::connection::ConnectionProfile;
use crate::core::invite::parse_invitation;
use crate::error::ClientError;
#[cfg(not(target_os = "windows"))]
use crate::local_store::OwnerOnlySecretFile;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const PROFILE_INDEX_VERSION: u8 = 1;
#[cfg(target_os = "windows")]
const KEYRING_SERVICE: &str = "com.sky.realityclient.profile";

pub trait SecretStore: Send + Sync {
    fn set(&self, key: &str, secret: &str) -> Result<(), ClientError>;
    fn get(&self, key: &str) -> Result<Option<String>, ClientError>;
    fn delete(&self, key: &str) -> Result<(), ClientError>;
}

#[cfg(target_os = "windows")]
pub struct NativeSecretStore;

#[cfg(target_os = "windows")]
impl NativeSecretStore {
    fn entry(key: &str) -> Result<keyring::Entry, ClientError> {
        keyring::Entry::new(KEYRING_SERVICE, key).map_err(|_| {
            ClientError::internal(
                "credential_store_unavailable",
                "The operating system credential store is unavailable.",
            )
        })
    }
}

#[cfg(not(target_os = "windows"))]
struct LocalSecretStore {
    store: OwnerOnlySecretFile,
}

#[cfg(not(target_os = "windows"))]
impl LocalSecretStore {
    fn new(app_data_dir: &Path) -> Result<Self, ClientError> {
        Ok(Self {
            store: OwnerOnlySecretFile::new(app_data_dir, "profile-credentials-v1.json")?,
        })
    }
}

#[cfg(not(target_os = "windows"))]
impl SecretStore for LocalSecretStore {
    fn set(&self, key: &str, secret: &str) -> Result<(), ClientError> {
        self.store.set(key, secret)
    }

    fn get(&self, key: &str) -> Result<Option<String>, ClientError> {
        self.store.get(key)
    }

    fn delete(&self, key: &str) -> Result<(), ClientError> {
        self.store.delete(key)
    }
}

#[cfg(target_os = "windows")]
impl SecretStore for NativeSecretStore {
    fn set(&self, key: &str, secret: &str) -> Result<(), ClientError> {
        Self::entry(key)?.set_password(secret).map_err(|_| {
            ClientError::internal(
                "credential_write_failed",
                "The invitation could not be saved to the credential store.",
            )
        })
    }

    fn get(&self, key: &str) -> Result<Option<String>, ClientError> {
        match Self::entry(key)?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(ClientError::internal(
                "credential_read_failed",
                "The invitation could not be read from the credential store.",
            )),
        }
    }

    fn delete(&self, key: &str) -> Result<(), ClientError> {
        match Self::entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(ClientError::internal(
                "credential_delete_failed",
                "The invitation could not be removed from the credential store.",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredProfile {
    pub id: String,
    pub name: String,
    pub server_address: String,
    pub server_port: u16,
    pub server_name: String,
    pub flow: String,
    pub fingerprint: String,
    pub created_at: u64,
    pub credential_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileRecord {
    id: String,
    name: String,
    server_address: String,
    server_port: u16,
    server_name: String,
    flow: String,
    fingerprint: String,
    created_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProfileIndex {
    version: u8,
    profiles: Vec<ProfileRecord>,
}

impl Default for ProfileIndex {
    fn default() -> Self {
        Self {
            version: PROFILE_INDEX_VERSION,
            profiles: Vec::new(),
        }
    }
}

#[derive(Clone)]
pub struct ProfileRepository {
    index_path: PathBuf,
    secrets: Arc<dyn SecretStore>,
}

impl ProfileRepository {
    pub fn preferred(app_data_dir: PathBuf) -> Result<Self, ClientError> {
        #[cfg(not(target_os = "windows"))]
        {
            let local = Arc::new(LocalSecretStore::new(&app_data_dir)?);
            Self::new(app_data_dir, local)
        }
        #[cfg(target_os = "windows")]
        {
            Self::native(app_data_dir)
        }
    }

    #[cfg(target_os = "windows")]
    pub fn native(app_data_dir: PathBuf) -> Result<Self, ClientError> {
        Self::new(app_data_dir, Arc::new(NativeSecretStore))
    }

    pub fn new(app_data_dir: PathBuf, secrets: Arc<dyn SecretStore>) -> Result<Self, ClientError> {
        fs::create_dir_all(&app_data_dir).map_err(|_| storage_error("profile_directory_failed"))?;

        Ok(Self {
            index_path: app_data_dir.join("profiles.json"),
            secrets,
        })
    }

    pub fn list(&self) -> Result<Vec<StoredProfile>, ClientError> {
        let index = self.read_index()?;
        index
            .profiles
            .into_iter()
            .map(|record| {
                let credential_available = self.secrets.get(&record.id)?.is_some();
                Ok(record.to_stored(credential_available))
            })
            .collect()
    }

    pub fn import(
        &self,
        invitation: &str,
        name_override: Option<&str>,
    ) -> Result<StoredProfile, ClientError> {
        let profile = parse_invitation(invitation)?;
        let id = Uuid::new_v4().to_string();
        let name = normalize_name(name_override).unwrap_or_else(|| profile.name.clone());
        let record = ProfileRecord::from_profile(id.clone(), name, &profile);
        let mut index = self.read_index()?;

        self.secrets.set(&id, invitation.trim())?;

        index.profiles.push(record.clone());
        if let Err(error) = self.write_index(&index) {
            let _ = self.secrets.delete(&id);
            return Err(error);
        }

        Ok(record.to_stored(true))
    }

    pub fn rename(&self, profile_id: &str, name: &str) -> Result<StoredProfile, ClientError> {
        let name = normalize_name(Some(name)).ok_or_else(|| {
            ClientError::invalid_invitation(
                "profile_name_required",
                "name",
                "The profile name cannot be empty.",
            )
        })?;
        let mut index = self.read_index()?;
        let record = index
            .profiles
            .iter_mut()
            .find(|record| record.id == profile_id)
            .ok_or_else(profile_not_found)?;
        record.name = name;
        let result = record.clone();
        let credential_available = self.secrets.get(profile_id)?.is_some();
        self.write_index(&index)?;
        Ok(result.to_stored(credential_available))
    }

    pub fn delete(&self, profile_id: &str) -> Result<(), ClientError> {
        let mut index = self.read_index()?;
        let previous_len = index.profiles.len();
        index.profiles.retain(|profile| profile.id != profile_id);
        if index.profiles.len() == previous_len {
            return Err(profile_not_found());
        }

        self.secrets.delete(profile_id)?;
        self.write_index(&index)
    }

    pub fn load_connection(&self, profile_id: &str) -> Result<ConnectionProfile, ClientError> {
        let index = self.read_index()?;
        if !index
            .profiles
            .iter()
            .any(|profile| profile.id == profile_id)
        {
            return Err(profile_not_found());
        }

        let invitation = self.secrets.get(profile_id)?.ok_or_else(|| {
            ClientError::internal(
                "profile_credential_missing",
                "The profile invitation is missing and must be imported again.",
            )
        })?;
        parse_invitation(&invitation)
    }

    fn read_index(&self) -> Result<ProfileIndex, ClientError> {
        if !self.index_path.exists() {
            return Ok(ProfileIndex::default());
        }

        let bytes = fs::read(&self.index_path).map_err(|_| storage_error("profile_read_failed"))?;
        let index: ProfileIndex =
            serde_json::from_slice(&bytes).map_err(|_| storage_error("profile_index_invalid"))?;
        if index.version != PROFILE_INDEX_VERSION {
            return Err(storage_error("profile_index_unsupported"));
        }
        Ok(index)
    }

    fn write_index(&self, index: &ProfileIndex) -> Result<(), ClientError> {
        let bytes = serde_json::to_vec_pretty(index)
            .map_err(|_| storage_error("profile_serialize_failed"))?;
        let parent = self
            .index_path
            .parent()
            .ok_or_else(|| storage_error("profile_directory_failed"))?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .map_err(|_| storage_error("profile_write_failed"))?;
        temporary
            .write_all(&bytes)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|_| storage_error("profile_write_failed"))?;
        set_owner_only_permissions(temporary.path())?;
        temporary
            .persist(&self.index_path)
            .map(|_| ())
            .map_err(|_| storage_error("profile_write_failed"))
    }
}

impl ProfileRecord {
    fn from_profile(id: String, name: String, profile: &ConnectionProfile) -> Self {
        Self {
            id,
            name,
            server_address: profile.server_address.clone(),
            server_port: profile.server_port,
            server_name: profile.server_name.clone(),
            flow: profile.flow.clone(),
            fingerprint: profile.fingerprint.clone(),
            created_at: unix_timestamp(),
        }
    }

    fn to_stored(&self, credential_available: bool) -> StoredProfile {
        StoredProfile {
            id: self.id.clone(),
            name: self.name.clone(),
            server_address: self.server_address.clone(),
            server_port: self.server_port,
            server_name: self.server_name.clone(),
            flow: self.flow.clone(),
            fingerprint: self.fingerprint.clone(),
            created_at: self.created_at,
            credential_available,
        }
    }
}

fn normalize_name(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(80).collect())
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn profile_not_found() -> ClientError {
    ClientError::internal(
        "profile_not_found",
        "The selected profile no longer exists.",
    )
}

fn storage_error(code: &str) -> ClientError {
    ClientError::internal(code, "The local profile store could not be updated.")
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), ClientError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| storage_error("profile_permissions_failed"))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), ClientError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tempfile::tempdir;

    const VALID_INVITATION: &str = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=753bd0a1&type=tcp&headerType=none#Friend";

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<HashMap<String, String>>,
    }

    impl SecretStore for MemorySecretStore {
        fn set(&self, key: &str, secret: &str) -> Result<(), ClientError> {
            self.values
                .lock()
                .expect("secret lock")
                .insert(key.to_string(), secret.to_string());
            Ok(())
        }

        fn get(&self, key: &str) -> Result<Option<String>, ClientError> {
            Ok(self.values.lock().expect("secret lock").get(key).cloned())
        }

        fn delete(&self, key: &str) -> Result<(), ClientError> {
            self.values.lock().expect("secret lock").remove(key);
            Ok(())
        }
    }

    fn repository() -> (tempfile::TempDir, Arc<MemorySecretStore>, ProfileRepository) {
        let directory = tempdir().expect("temp dir");
        let secrets = Arc::new(MemorySecretStore::default());
        let repository = ProfileRepository::new(directory.path().to_path_buf(), secrets.clone())
            .expect("repository");
        (directory, secrets, repository)
    }

    #[test]
    fn import_keeps_credentials_out_of_profile_index() {
        let (directory, secrets, repository) = repository();
        let stored = repository
            .import(VALID_INVITATION, Some("  Laptop  "))
            .expect("import profile");
        let index = fs::read_to_string(directory.path().join("profiles.json")).expect("index");

        assert_eq!(stored.name, "Laptop");
        assert!(stored.credential_available);
        assert!(!index.contains("11111111-1111-4111-8111-111111111111"));
        assert!(!index.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        assert!(!index.contains("vless://"));
        assert_eq!(
            secrets
                .values
                .lock()
                .expect("secret lock")
                .get(&stored.id)
                .map(String::as_str),
            Some(VALID_INVITATION)
        );
    }

    #[test]
    fn list_reports_missing_credential() {
        let (_directory, secrets, repository) = repository();
        let stored = repository
            .import(VALID_INVITATION, None)
            .expect("import profile");
        secrets
            .values
            .lock()
            .expect("secret lock")
            .remove(&stored.id);

        let profiles = repository.list().expect("list profiles");
        assert_eq!(profiles.len(), 1);
        assert!(!profiles[0].credential_available);
    }

    #[test]
    fn delete_removes_metadata_and_secret() {
        let (_directory, secrets, repository) = repository();
        let stored = repository
            .import(VALID_INVITATION, None)
            .expect("import profile");

        repository.delete(&stored.id).expect("delete profile");

        assert!(repository.list().expect("list profiles").is_empty());
        assert!(!secrets
            .values
            .lock()
            .expect("secret lock")
            .contains_key(&stored.id));
    }

    #[test]
    fn load_connection_reads_and_parses_secret() {
        let (_directory, _secrets, repository) = repository();
        let stored = repository
            .import(VALID_INVITATION, None)
            .expect("import profile");

        let connection = repository
            .load_connection(&stored.id)
            .expect("load connection");
        assert_eq!(connection.server_address, "203.0.113.10");
    }
}
