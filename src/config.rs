//! `config.json`, the configuration and data directories, atomic writes and
//! private file modes (0600 for files, 0700 for directories).
//!
//! The format follows `aberoham/ms-entra-cli`. Unknown keys are ignored, so
//! sections that later releases read can already be present.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{PurviewError, Result};

/// The directory name under the platform configuration and data roots.
pub const APP_DIR: &str = "purview";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_account: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub clients: BTreeMap<String, ClientConfig>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,
}

impl Config {
    /// Loads `config.json` from `dir`. A missing file is the default
    /// configuration; a symlink is refused. A file readable by others is
    /// tightened to 0600, with a warning written to `warnings` (the
    /// command's redacted stderr).
    pub fn load(dir: &Path, warnings: &mut dyn Write) -> Result<Self> {
        Self::load_from(&dir.join("config.json"), warnings)
    }

    pub fn load_from(path: &Path, warnings: &mut dyn Write) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() {
            return Err(PurviewError::message(format!(
                "config file {} is a symlink, refusing to load",
                path.display()
            )));
        }
        harden_file_permissions(path, &metadata, warnings)?;
        let contents = fs::read(path)?;
        serde_json::from_slice(&contents).map_err(|error| {
            PurviewError::from(error).context(format!("reading {}", path.display()))
        })
    }

    /// Writes `config.json` into `dir` atomically, creating the directory
    /// tree with mode 0700 first.
    pub fn save(&self, dir: &Path) -> Result<()> {
        ensure_config_dirs(dir)?;
        let data = serde_json::to_vec_pretty(self)?;
        atomic_write(&dir.join("config.json"), &data)
    }
}

/// The configuration directory: `override_dir` when given (from
/// `PURVIEW_CONFIG_DIR`, carried in `Env`), else `purview` under the
/// platform configuration directory.
pub fn config_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(dir.to_path_buf());
    }
    dirs::config_dir()
        .map(|root| root.join(APP_DIR))
        .ok_or_else(|| {
            PurviewError::message("could not determine the user configuration directory")
        })
}

pub fn accounts_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("accounts")
}

/// The root for downloaded files: `purview` under the platform's local data
/// directory, outside any repository on purpose. Downloads go below it in
/// `cases/<case-id>/<operation-id>/`.
pub fn data_dir() -> Result<PathBuf> {
    dirs::data_local_dir()
        .map(|root| root.join(APP_DIR))
        .ok_or_else(|| PurviewError::message("could not determine the user data directory"))
}

/// Creates the configuration directory and its `accounts` directory, each
/// with mode 0700.
pub fn ensure_config_dirs(config_dir: &Path) -> Result<()> {
    ensure_private_dir(config_dir)?;
    ensure_private_dir(&accounts_dir(config_dir))
}

/// Creates `path` and its parents and sets mode 0700 on `path`. A symlink
/// at `path` is refused.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(PurviewError::message(format!(
                "{} is a symlink, refusing to use it",
                path.display()
            )));
        }
    }
    fs::create_dir_all(path)?;
    set_mode(path, 0o700)
}

/// Writes `data` to `path` through a temporary file in the same directory
/// (mode 0600, synced) and a rename, so readers never see a partial file.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| PurviewError::message("configuration path has no parent directory"))?;
    fs::create_dir_all(parent)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(PurviewError::message(format!(
                "{} is a symlink, refusing to replace it",
                path.display()
            )));
        }
    }
    let unique = format!(
        ".tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let temporary = parent.join(unique);
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        set_mode(&temporary, 0o600)?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn harden_file_permissions(
    path: &Path,
    metadata: &fs::Metadata,
    warnings: &mut dyn Write,
) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            writeln!(
                warnings,
                "warning: config file {} has permissions {:o}, expected 600; fixing",
                path.display(),
                mode
            )?;
            set_mode(path, 0o600)?;
        }
    }
    #[cfg(not(unix))]
    let _ = (path, metadata, warnings);
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn a_missing_config_is_the_default() {
        let dir = tempdir().unwrap();
        assert_eq!(
            Config::load(dir.path(), &mut Vec::new()).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn reads_the_stored_config_format_and_ignores_later_sections() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("config.json"),
            br#"{"default_account":"alex@contoso.example",
                "clients":{"alex@contoso.example":{"client_id":"00000000-0000-4000-8000-000000000001","tenant_id":"00000000-0000-4000-8000-000000000002"}},
                "naming":{"marker":"[created-by:purview-cli]"}}"#,
        )
        .unwrap();
        let config = Config::load(dir.path(), &mut Vec::new()).unwrap();
        assert_eq!(config.default_account, "alex@contoso.example");
        assert_eq!(
            config.clients["alex@contoso.example"].client_id,
            "00000000-0000-4000-8000-000000000001"
        );
    }

    #[test]
    fn malformed_config_names_the_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("config.json"), b"{not json").unwrap();
        let message = Config::load(dir.path(), &mut Vec::new())
            .unwrap_err()
            .to_string();
        assert!(message.contains("config.json"), "{message}");
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("purview");
        let mut config = Config {
            default_account: "sam@contoso.example".into(),
            ..Config::default()
        };
        config.clients.insert(
            "sam@contoso.example".into(),
            ClientConfig {
                client_id: "00000000-0000-4000-8000-000000000003".into(),
                tenant_id: String::new(),
            },
        );
        config.save(&root).unwrap();
        assert_eq!(Config::load(&root, &mut Vec::new()).unwrap(), config);
        assert!(accounts_dir(&root).is_dir());
        let leftovers: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn an_override_wins_over_the_platform_directory() {
        let dir = tempdir().unwrap();
        assert_eq!(config_dir(Some(dir.path())).unwrap(), dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn files_are_0600_and_directories_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("purview");
        Config::default().save(&root).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&accounts_dir(&root)), 0o700);
        assert_eq!(mode(&root.join("config.json")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn a_readable_config_is_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut warnings = Vec::new();
        Config::load_from(&path, &mut warnings).unwrap();
        assert!(String::from_utf8(warnings)
            .unwrap()
            .contains("expected 600"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"{}").unwrap();
        let link = dir.path().join("config.json");
        symlink(&target, &link).unwrap();
        assert!(Config::load_from(&link, &mut Vec::new())
            .unwrap_err()
            .to_string()
            .contains("symlink"));
        assert!(atomic_write(&link, b"{}")
            .unwrap_err()
            .to_string()
            .contains("symlink"));
        let linked_dir = dir.path().join("linked");
        symlink(dir.path(), &linked_dir).unwrap();
        assert!(ensure_private_dir(&linked_dir)
            .unwrap_err()
            .to_string()
            .contains("symlink"));
    }
}
