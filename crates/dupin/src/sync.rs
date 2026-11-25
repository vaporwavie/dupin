//! Sync between Macs as a host service: a worker that owns the vault and the engine, runs a
//! full pass every five minutes, and answers `dupin sync` through the control socket. It never
//! runs on the UI thread or the per-keystroke path.

use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dupin_mac::keychain::{ICloudKeychain, VaultKeychain};
use dupin_storage::Storage;
use dupin_sync::{DeviceInfo, Engine, Folder, FolderOptions, Joined, KdfParams, Passphrase, Report};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::control::{Call, SyncAction};

const FULL_SCAN_EVERY: Duration = Duration::from_secs(5 * 60);
const STATE_FILE: &str = "sync.json";

/// What this Mac joined, kept beside the storage root: which vault, which key epoch and, unless
/// `[sync] folder` names one, the folder. Not a secret; the key itself is in the Keychain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    folder: PathBuf,
    vault: String,
    epoch: u32,
}

fn state_path() -> Option<PathBuf> {
    crate::store::data_dir().map(|dir| dir.join(STATE_FILE))
}

fn read_state() -> Option<State> {
    let bytes = std::fs::read(state_path()?).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_state(state: Option<&State>) -> Result<(), String> {
    let path = state_path().ok_or("Dupin's data folder needs HOME")?;
    match state {
        None => match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
            _ => Ok(()),
        },
        Some(state) => {
            let json = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
            write_private(&path, &json).map_err(|error| error.to_string())
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let temp = dir.join(format!(".{STATE_FILE}.{}.tmp", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temp, path)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return None;
    }
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

enum Job {
    Config(dupin_core::config::Sync),
    Control(SyncAction, Call),
}

/// The handle the UI keeps. Dropping it stops the worker.
pub struct Sync {
    jobs: Option<mpsc::Sender<Job>>,
}

impl Sync {
    /// Starts the worker with `[sync]` as configured now.
    pub fn start(config: &dupin_core::config::Sync) -> Self {
        let Some(storage) = crate::extensions::access::storage() else {
            return Self { jobs: None };
        };
        let (jobs, receive) = mpsc::channel();
        let _ = jobs.send(Job::Config(config.clone()));
        let spawned = std::thread::Builder::new()
            .name("dupin-sync".into())
            .spawn(move || Worker::new(storage).run(receive));
        match spawned {
            Ok(_) => Self { jobs: Some(jobs) },
            Err(error) => {
                crate::log::warn(&format!("couldn't start sync: {error}"));
                Self { jobs: None }
            }
        }
    }

    /// For headless runs and tests, which never touch the Keychain or a sync folder.
    pub fn disabled() -> Self {
        Self { jobs: None }
    }

    pub fn apply(&self, config: &dupin_core::config::Sync) {
        if let Some(jobs) = &self.jobs {
            let _ = jobs.send(Job::Config(config.clone()));
        }
    }

    pub fn control(&self, action: SyncAction, call: Call) {
        match &self.jobs {
            Some(jobs) => {
                if let Err(mpsc::SendError(Job::Control(_, call))) = jobs.send(Job::Control(action, call)) {
                    call.finish(Err("sync stopped".into()));
                }
            }
            None => call.finish(Err("sync is not available in this build or session".into())),
        }
    }
}

struct Worker {
    storage: Arc<Storage>,
    config: dupin_core::config::Sync,
    state: Option<State>,
    engine: Option<Engine>,
    last: Option<(u64, Report)>,
    problem: Option<String>,
}

impl Worker {
    fn new(storage: Arc<Storage>) -> Self {
        Self {
            storage,
            config: dupin_core::config::Sync::default(),
            state: read_state(),
            engine: None,
            last: None,
            problem: None,
        }
    }

    fn run(mut self, jobs: mpsc::Receiver<Job>) {
        loop {
            match jobs.recv_timeout(FULL_SCAN_EVERY) {
                Ok(Job::Config(config)) => {
                    if config != self.config || self.engine.is_none() {
                        self.config = config;
                        self.engine = None;
                        self.resume();
                        self.pass();
                    }
                }
                Ok(Job::Control(action, call)) => {
                    let result = self.control(action);
                    call.finish(result);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => self.pass(),
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    fn data_dir() -> Result<PathBuf, String> {
        crate::store::data_dir().ok_or_else(|| "Dupin's data folder needs HOME".into())
    }

    fn options(&self) -> FolderOptions {
        FolderOptions {
            allow_nfs: self.config.allow_nfs,
        }
    }

    /// The folder `[sync] folder` names, which wins, or the one chosen when sync was turned on.
    fn folder_path(&self, chosen: Option<&Path>) -> Option<PathBuf> {
        match self.config.folder.trim() {
            "" => chosen.map(Path::to_owned),
            configured => Some(expand_home(configured)),
        }
    }

    fn open_folder(&self, path: &Path) -> Result<Folder, String> {
        Folder::open(path, &Self::data_dir()?, self.options()).map_err(|error| error.to_string())
    }

    fn resume(&mut self) {
        self.problem = None;
        let Some(state) = self.state.clone() else {
            return;
        };
        let Some(vault) = unhex16(&state.vault) else {
            self.problem = Some("sync.json is damaged; turn sync off and on again".into());
            return;
        };
        let Some(path) = self.folder_path(Some(&state.folder)) else {
            return;
        };
        let result = self
            .open_folder(&path)
            .and_then(|folder| {
                dupin_sync::resume(vault, state.epoch, Some(&folder), &VaultKeychain)
                    .map(|joined| (folder, joined))
                    .map_err(|error| error.to_string())
            })
            .and_then(|(folder, joined)| self.engine_for(folder, joined));
        match result {
            Ok(engine) => self.engine = Some(engine),
            Err(error) => self.problem = Some(error),
        }
    }

    fn engine_for(&self, folder: Folder, joined: Joined) -> Result<Engine, String> {
        let mut engine = Engine::new(
            folder,
            self.storage.clone(),
            joined.key,
            joined.header,
            DeviceInfo {
                name: dupin_mac::machine::computer_name().unwrap_or_else(|| "Mac".into()),
                platform: "macos".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            Arc::new(dupin_storage::SystemClock),
        )
        .map_err(|error| error.to_string())?;
        let root = engine.folder_path().to_owned();
        engine.on_dataless(move |relative| dupin_mac::machine::request_download(&root.join(relative)));
        Ok(engine)
    }

    fn pass(&mut self) {
        let Some(engine) = &mut self.engine else {
            return;
        };
        match engine.run() {
            Ok(report) => {
                self.problem = None;
                self.last = Some((now_millis(), report));
            }
            Err(error) => self.problem = Some(error.to_string()),
        }
    }

    fn control(&mut self, action: SyncAction) -> Result<Value, String> {
        match action {
            SyncAction::Status {} => Ok(self.status()),
            SyncAction::On { folder, passphrase } => self.turn_on(folder, passphrase),
            SyncAction::Join { folder, passphrase } => self.join(folder, passphrase),
            SyncAction::Off {} => self.turn_off(),
            SyncAction::RemoveDevice { device } => {
                let engine = self.engine.as_mut().ok_or("sync is off")?;
                let device = device.parse().map_err(|_| "not a device ID")?;
                engine.retire(device).map_err(|error| error.to_string())?;
                self.pass();
                Ok(self.status())
            }
            SyncAction::Now {} => {
                self.pass();
                Ok(self.status())
            }
        }
    }

    fn chosen_folder(&self, folder: Option<String>) -> Result<PathBuf, String> {
        let configured = self.folder_path(None);
        match (folder, configured) {
            (Some(asked), Some(configured)) if expand_home(&asked) != configured => Err(format!(
                "[sync] folder in config.toml names {}; change it there",
                configured.display()
            )),
            (Some(asked), _) => Ok(expand_home(&asked)),
            (None, Some(configured)) => Ok(configured),
            (None, None) => std::env::var_os("HOME")
                .and_then(|home| dupin_sync::icloud_drive_default(Path::new(&home)))
                .ok_or_else(|| "iCloud Drive isn't set up on this Mac; choose a folder with --folder".into()),
        }
    }

    fn turn_on(&mut self, folder: Option<String>, passphrase: Option<String>) -> Result<Value, String> {
        if self.state.is_some() {
            return Err("sync is already on; turn it off first to change folders".into());
        }
        let path = self.chosen_folder(folder)?;
        let folder = self.open_folder(&path)?;
        let (passphrase, generated) = match passphrase {
            Some(text) => (Passphrase::chosen(&text).map_err(|weak| weak.to_string())?, false),
            None => (Passphrase::generate().map_err(|error| error.to_string())?, true),
        };
        let shared = ICloudKeychain::available();
        let device = self.storage.device_id().map_err(|error| error.to_string())?;
        let joined = dupin_sync::create(
            &folder,
            device,
            &passphrase,
            KdfParams::DEFAULT,
            &VaultKeychain,
            shared
                .as_ref()
                .map(|keychain| keychain as &dyn dupin_sync::SharedKeyStore),
        )
        .map_err(|error| match error {
            dupin_sync::Error::Refused(dupin_sync::Refusal::HoldsAVault) => {
                "the folder already holds a sync vault; join it with `dupin sync join`".into()
            }
            other => other.to_string(),
        })?;
        self.joined(path, folder, joined)?;
        let mut status = self.status();
        if generated {
            status["passphrase"] = json!(passphrase.expose());
        }
        Ok(status)
    }

    fn join(&mut self, folder: Option<String>, passphrase: Option<String>) -> Result<Value, String> {
        if self.state.is_some() {
            return Err("sync is already on".into());
        }
        let path = self.chosen_folder(folder)?;
        let folder = self.open_folder(&path)?;
        let passphrase = passphrase.as_deref().map(Passphrase::entered);
        let shared = ICloudKeychain::available();
        let joined = dupin_sync::join(
            &folder,
            passphrase.as_ref(),
            &VaultKeychain,
            shared
                .as_ref()
                .map(|keychain| keychain as &dyn dupin_sync::SharedKeyStore),
        )
        .map_err(|error| error.to_string())?;
        self.joined(path, folder, joined)?;
        Ok(self.status())
    }

    fn joined(&mut self, path: PathBuf, folder: Folder, joined: Joined) -> Result<(), String> {
        let state = State {
            folder: path,
            vault: hex(&joined.key.id()),
            epoch: joined.key.epoch(),
        };
        write_state(Some(&state))?;
        self.state = Some(state);
        self.engine = Some(self.engine_for(folder, joined)?);
        self.pass();
        Ok(())
    }

    /// This Mac stops syncing. Nothing syncs yet, so there is nothing to hand over; its local
    /// copy of the vault key stays in the Keychain for turning sync on again.
    fn turn_off(&mut self) -> Result<Value, String> {
        write_state(None)?;
        self.state = None;
        self.engine = None;
        self.last = None;
        self.problem = None;
        Ok(self.status())
    }

    fn status(&self) -> Value {
        let report = self.last.as_ref().map(|(at, report)| {
            json!({
                "at": at,
                "exported": report.exported,
                "imported": report.imported,
                "removed": report.removed,
                "not_arrived": report.not_arrived,
                "unreadable": report.unreadable,
                "clock_ahead": report.clock_ahead.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "losing_vault": report.losing_vault,
                "newer_format": report.newer_format,
                "newer_epoch": report.newer_epoch,
                "reminted": report.reminted,
                "blocked_adoption": report.blocked_adoption.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "devices": report.devices.iter().map(|device| json!({
                    "id": device.id.to_string(),
                    "name": device.name,
                    "seen_at": device.seen_at,
                    "inactive": device.inactive,
                    "retired": device.retired,
                })).collect::<Vec<_>>(),
            })
        });
        json!({
            "on": self.state.is_some(),
            "folder": self
                .state
                .as_ref()
                .and_then(|state| self.folder_path(Some(&state.folder)))
                .or_else(|| self.folder_path(None))
                .map(|path| path.display().to_string()),
            "vault": self.state.as_ref().map(|state| state.vault.clone()),
            "mode": self.engine.as_ref().map(|engine| match engine.key_mode() {
                dupin_sync::KeyMode::Keychain => "icloud-keychain",
                dupin_sync::KeyMode::Passphrase => "passphrase",
            }),
            "device": self.storage.device_id().ok().map(|id| id.to_string()),
            "problem": self.problem,
            "last": report,
        })
    }
}

fn expand_home(path: &str) -> PathBuf {
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_rejects_anything_else() {
        let id = [0xab; 16];
        assert_eq!(unhex16(&hex(&id)), Some(id));
        assert_eq!(unhex16("AB"), None);
        assert_eq!(unhex16(&"AB".repeat(16)), None);
    }

    #[test]
    fn a_home_relative_folder_expands() {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap();
        assert_eq!(expand_home("~/Sync"), home.join("Sync"));
        assert_eq!(expand_home("/Volumes/Sync"), PathBuf::from("/Volumes/Sync"));
    }
}
