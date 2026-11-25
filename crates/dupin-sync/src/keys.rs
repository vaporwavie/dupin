//! Where a Mac keeps the vault key: its own local copy, which never leaves it, and, in builds
//! that can, a synchronizable iCloud Keychain item that carries the key to the owner's other
//! Macs. Platform adapters implement these; tests use [`MemoryKeys`].

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use dupin_storage::DataKey;

use crate::error::Error;
use crate::fsx::{hex, unhex};

/// This Mac's own copy of each vault key epoch it has joined: `ThisDeviceOnly`, never
/// synchronizable, so losing the shared item later never locks local data.
pub trait LocalKeyStore: Send + Sync {
    fn load(&self, vault: [u8; 16], epoch: u32) -> Result<Option<DataKey>, Error>;
    fn store(&self, vault: [u8; 16], epoch: u32, key: &DataKey) -> Result<(), Error>;
    fn delete(&self, vault: [u8; 16], epoch: u32) -> Result<(), Error>;
}

/// The synchronizable item, `vault-<vault id>-<epoch>`, end-to-end encrypted by iCloud
/// Keychain. Only a build with a keychain access group entitlement has one.
pub trait SharedKeyStore: Send + Sync {
    fn load(&self, vault: [u8; 16], epoch: u32) -> Result<Option<DataKey>, Error>;
    fn store(&self, vault: [u8; 16], epoch: u32, key: &DataKey) -> Result<(), Error>;
    fn delete(&self, vault: [u8; 16], epoch: u32) -> Result<(), Error>;
}

pub fn account(vault: [u8; 16], epoch: u32) -> String {
    format!("vault-{}-{epoch}", hex(&vault))
}

/// Keys in memory, for tests and fixtures; it stands in for either store.
#[derive(Default)]
pub struct MemoryKeys(Mutex<BTreeMap<String, DataKey>>);

impl MemoryKeys {
    fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, DataKey>> {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner())
    }
}

impl LocalKeyStore for MemoryKeys {
    fn load(&self, vault: [u8; 16], epoch: u32) -> Result<Option<DataKey>, Error> {
        Ok(self.map().get(&account(vault, epoch)).cloned())
    }

    fn store(&self, vault: [u8; 16], epoch: u32, key: &DataKey) -> Result<(), Error> {
        self.map().insert(account(vault, epoch), key.clone());
        Ok(())
    }

    fn delete(&self, vault: [u8; 16], epoch: u32) -> Result<(), Error> {
        self.map().remove(&account(vault, epoch));
        Ok(())
    }
}

impl SharedKeyStore for MemoryKeys {
    fn load(&self, vault: [u8; 16], epoch: u32) -> Result<Option<DataKey>, Error> {
        LocalKeyStore::load(self, vault, epoch)
    }

    fn store(&self, vault: [u8; 16], epoch: u32, key: &DataKey) -> Result<(), Error> {
        LocalKeyStore::store(self, vault, epoch, key)
    }

    fn delete(&self, vault: [u8; 16], epoch: u32) -> Result<(), Error> {
        LocalKeyStore::delete(self, vault, epoch)
    }
}

/// `vault.key`, a `0600` file beside `storage.key` holding one key per epoch, for systems
/// without a key store. Anyone who can read it can read everything that syncs.
#[derive(Debug, Clone)]
pub struct FileVaultKeys {
    path: PathBuf,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    keys: BTreeMap<String, String>,
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        for value in self.keys.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
    }
}

impl FileVaultKeys {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn read(&self) -> Result<KeyFile, Error> {
        let bytes = match std::fs::metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(KeyFile::default()),
            Err(error) => return Err(error.into()),
            Ok(meta) => {
                use std::os::unix::fs::PermissionsExt;
                let mode = meta.permissions().mode();
                if mode & 0o077 != 0 {
                    return Err(Error::KeyStore(format!(
                        "{} is readable by other users (mode {:o}); make it 0600",
                        self.path.display(),
                        mode & 0o777
                    )));
                }
                Zeroizing::new(std::fs::read(&self.path)?)
            }
        };
        serde_json::from_slice(&bytes)
            .map_err(|_| Error::KeyStore(format!("{} is damaged", self.path.display())))
    }

    fn write(&self, file: &KeyFile) -> Result<(), Error> {
        let json = Zeroizing::new(serde_json::to_vec(file).expect("the key file serializes"));
        write_private(&self.path, &json)
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let temp = dir.join(format!(".{}.tmp", hex(&crate::seal::random::<8>())));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written.and_then(|()| std::fs::rename(&temp, path)) {
        let _ = std::fs::remove_file(&temp);
        return Err(error.into());
    }
    Ok(())
}

impl LocalKeyStore for FileVaultKeys {
    fn load(&self, vault: [u8; 16], epoch: u32) -> Result<Option<DataKey>, Error> {
        let file = self.read()?;
        let Some(text) = file.keys.get(&account(vault, epoch)) else {
            return Ok(None);
        };
        let bytes =
            Zeroizing::new(unhex::<32>(text).ok_or_else(|| Error::KeyStore("a damaged vault key".into()))?);
        Ok(Some(DataKey::from_slice(bytes.as_ref())?))
    }

    fn store(&self, vault: [u8; 16], epoch: u32, key: &DataKey) -> Result<(), Error> {
        let mut file = self.read()?;
        file.keys.insert(account(vault, epoch), hex(key.as_bytes()));
        self.write(&file)
    }

    fn delete(&self, vault: [u8; 16], epoch: u32) -> Result<(), Error> {
        let mut file = self.read()?;
        if let Some(mut removed) = file.keys.remove(&account(vault, epoch)) {
            zeroize::Zeroize::zeroize(&mut removed);
            self.write(&file)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_file_keeps_one_key_per_epoch_and_stays_private() {
        let dir = tempfile::tempdir().unwrap();
        let keys = FileVaultKeys::new(dir.path().join("vault.key"));
        let first = DataKey::generate().unwrap();
        let second = DataKey::generate().unwrap();
        keys.store([1; 16], 1, &first).unwrap();
        keys.store([1; 16], 2, &second).unwrap();
        assert_eq!(
            keys.load([1; 16], 1).unwrap().unwrap().as_bytes(),
            first.as_bytes()
        );
        assert_eq!(
            keys.load([1; 16], 2).unwrap().unwrap().as_bytes(),
            second.as_bytes()
        );
        assert!(keys.load([2; 16], 1).unwrap().is_none());
        keys.delete([1; 16], 1).unwrap();
        assert!(keys.load([1; 16], 1).unwrap().is_none());

        use std::os::unix::fs::PermissionsExt;
        let path = dir.path().join("vault.key");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(keys.load([1; 16], 2), Err(Error::KeyStore(_))));
    }
}
