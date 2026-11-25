//! Sync between Macs through a folder some other tool keeps in step, end-to-end encrypted with
//! one vault key. See `docs/design/sync.md` for the design and `docs/features/sync.md` for
//! what it does.
//!
//! Every call blocks on file I/O and must run on a worker thread, never the UI thread.

mod descriptor;
mod engine;
mod error;
mod folder;
mod fsx;
mod keys;
mod passphrase;
mod seal;
mod setup;
mod vault;

pub use descriptor::{Ack, Descriptor};
pub use engine::{
    BLOB_UNREFERENCED_FOR, DeviceInfo, DeviceStatus, Engine, Fold, INACTIVE_AFTER, MAX_DRIFT, Mode,
    Namespace, Report, TOMBSTONE_MIN_AGE,
};
pub use error::{Error, Refusal};
pub use folder::{Folder, FolderOptions, icloud_drive_default};
pub use keys::{FileVaultKeys, LocalKeyStore, MemoryKeys, SharedKeyStore, account};
pub use passphrase::{GENERATED_WORDS, MIN_CHARS, Passphrase, Weakness};
pub use setup::{Joined, create, join, resume};
pub use vault::{HEADER_NAME, KdfParams, KeyMode, VaultHeader};
