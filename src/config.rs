//! `config.json`, the configuration and data directories, atomic writes and
//! private file modes.
//!
//! The format follows `aberoham/ms-entra-cli`. Unknown keys, at the top
//! level and inside a client record, are kept on load and written back on
//! save, so sections that later releases read survive an older release.
//!
//! Platform guarantees:
//!
//! - Unix: directories are created with mode 0700 and files with 0600, and
//!   looser modes found on load are tightened, with a warning.
//! - Windows: the configuration lives under the user's profile and relies on
//!   that directory's default access control list (ACL). The tool does not
//!   set ACLs itself.
//! - Everywhere: a symlink, or on Windows any reparse point (a symlink or a
//!   junction), is refused as the configuration directory, the accounts
//!   directory or `config.json`.
//! - `config.json` never holds a secret: `save` refuses a value the
//!   Redactor recognises.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{PurviewError, Result};
use crate::output::sanitize;
use crate::redact::Redactor;

/// The directory name under the platform configuration and data roots.
pub const APP_DIR: &str = "purview";

const CONFIG_FILE: &str = "config.json";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub default_account: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub clients: BTreeMap<String, ClientConfig>,
    /// Keys this release does not read, kept as they were.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tenant_id: String,
    /// Keys this release does not read, kept as they were.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Config {
    /// Loads `config.json` from `dir`. A missing directory or file is the
    /// default configuration. A linked directory or file is refused. Modes
    /// readable by others are tightened, with a warning written to
    /// `warnings` (the command's redacted stderr).
    pub fn load(dir: &Path, warnings: &mut dyn Write) -> Result<Self> {
        let dir = normalise(dir);
        if !check_existing_dir(&dir, warnings)? {
            return Ok(Self::default());
        }
        Self::load_from(&dir.join(CONFIG_FILE), warnings)
    }

    /// Loads one file. It is inspected without following links, then opened,
    /// and the opened file must be the one inspected; its mode is tightened
    /// and its contents read through that same handle.
    pub fn load_from(path: &Path, warnings: &mut dyn Write) -> Result<Self> {
        let metadata = match fs::symlink_metadata(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
        };
        if is_link_like(&metadata) {
            return Err(refusal(path, "is a link, refusing to load it"));
        }
        if !metadata.is_file() {
            return Err(refusal(path, "is not a regular file"));
        }
        let contents = read_verified(path, &metadata, warnings)?;
        serde_json::from_slice(&contents)
            .map_err(|error| PurviewError::from(error).context(format!("reading {}", shown(path))))
    }

    /// Writes `config.json` into `dir` atomically, creating the directory
    /// tree privately first. A value the Redactor recognises (a registered
    /// secret or a JSON Web Token) is refused before anything is written.
    pub fn save(&self, dir: &Path, redactor: &Redactor) -> Result<()> {
        let value = serde_json::to_value(self)?;
        if redactor.recognises_value(&value) {
            return Err(PurviewError::message(
                "refusing to save config.json: a value in it looks like a secret (a token the \
                 tool holds, or a JSON Web Token); configuration never holds secrets",
            ));
        }
        let dir = normalise(dir);
        ensure_config_dirs(&dir)?;
        let data = serde_json::to_vec_pretty(&value)?;
        atomic_write(&dir.join(CONFIG_FILE), &data)
    }
}

/// The configuration directory: `override_dir` when given (from
/// `PURVIEW_CONFIG_DIR`, carried in `Env`), else `purview` under the
/// platform configuration directory.
pub fn config_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = override_dir {
        return Ok(normalise(dir));
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

/// Creates the configuration directory and its `accounts` directory
/// privately.
pub fn ensure_config_dirs(config_dir: &Path) -> Result<()> {
    ensure_private_dir(config_dir)?;
    ensure_private_dir(&accounts_dir(config_dir))
}

/// Creates `path` and any missing parents, created with mode 0700 on Unix,
/// and sets 0700 on `path` itself. A link at `path`, before or after
/// creation, or a non-directory, is refused.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    let path = normalise(path);
    check_dir_kind(&path)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&path)?;
    check_dir_kind(&path)?;
    set_mode(&path, 0o700)
}

/// Writes `data` to `path` through a new temporary file in the same
/// directory (mode 0600, synced, closed) and a rename, so readers never see
/// a partial file. The temporary file is removed on failure only if this
/// call created it.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write_named(path, data, temporary_names(path))
}

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Candidate temporary names: the target's name, the process id, a
/// process-wide counter and the time, so two writers never pick the same
/// name by accident; a collision is retried with the next candidate.
fn temporary_names(path: &Path) -> impl Iterator<Item = String> {
    let stem = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    (0..16).map(move |_| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!(
            ".{stem}.tmp-{}-{}-{nanos}",
            std::process::id(),
            TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
        )
    })
}

fn atomic_write_named(path: &Path, data: &[u8], names: impl Iterator<Item = String>) -> Result<()> {
    let parent = parent_dir(path);
    // A missing parent is created privately; an existing one keeps its mode
    // but must not be a link.
    if check_dir_kind(&parent)?.is_none() {
        ensure_private_dir(&parent)?;
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if is_link_like(&metadata) {
            return Err(refusal(path, "is a link, refusing to replace it"));
        }
    }
    let (mut file, temporary) = create_temporary(&parent, names)?;
    let mut guard = TemporaryFile(Some(temporary));
    let path_for_guard = guard.path().to_path_buf();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(data)?;
    file.sync_all()?;
    drop(file); // Windows cannot rename a file that is still open.
    fs::rename(&path_for_guard, path)?;
    guard.keep();
    Ok(())
}

/// Creates the first candidate name that does not exist yet.
fn create_temporary(parent: &Path, names: impl Iterator<Item = String>) -> Result<(File, PathBuf)> {
    for name in names {
        let candidate = parent.join(name);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(file) => return Ok((file, candidate)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(PurviewError::message(format!(
        "could not create a temporary file in {}: every candidate name was taken",
        shown(parent)
    )))
}

/// A temporary file this process created; removed when dropped unless
/// kept.
struct TemporaryFile(Option<PathBuf>);

impl TemporaryFile {
    fn path(&self) -> &Path {
        self.0.as_deref().unwrap_or(Path::new(""))
    }

    fn keep(&mut self) {
        self.0 = None;
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

/// The directory that holds `path`; `.` for a bare file name.
fn parent_dir(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// Removes trailing separators and `.` components, so that checking
/// `dir/` without following links checks `dir` itself and not its target.
fn normalise(path: &Path) -> PathBuf {
    let normalised: PathBuf = path.components().collect();
    if normalised.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalised
    }
}

/// Whether metadata read without following links shows a link: a symlink,
/// or on Windows any reparse point, junctions included.
fn is_link_like(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

/// Refuses a link or a non-directory at `path`; a missing path passes.
fn check_dir_kind(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_link_like(&metadata) => {
            Err(refusal(path, "is a link, refusing to use it"))
        }
        Ok(metadata) if !metadata.is_dir() => Err(refusal(path, "is not a directory")),
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Checks an existing configuration directory before reading from it, and
/// tightens a mode open to others. Returns whether it exists.
fn check_existing_dir(dir: &Path, warnings: &mut dyn Write) -> Result<bool> {
    let Some(metadata) = check_dir_kind(dir)? else {
        return Ok(false);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            writeln!(
                warnings,
                "warning: config directory {} has permissions {:o}, expected 700; fixing",
                shown(dir),
                mode
            )?;
            set_mode(dir, 0o700)?;
        }
    }
    #[cfg(not(unix))]
    let _ = (metadata, warnings);
    Ok(true)
}

/// Opens `path`, checks that the opened file is the one `expected`
/// describes (so a swap after inspection is refused), tightens its mode
/// through the handle, and reads it through the same handle.
fn read_verified(
    path: &Path,
    expected: &fs::Metadata,
    warnings: &mut dyn Write,
) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || !same_file(expected, &opened) {
        return Err(refusal(path, "changed while it was being opened"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = opened.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            writeln!(
                warnings,
                "warning: config file {} has permissions {:o}, expected 600; fixing",
                shown(path),
                mode
            )?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = warnings;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

/// Whether two metadata records describe the same file. On Unix this is
/// the device and inode; elsewhere the size and modification time, a
/// weaker check, since Windows reports file ids only through unstable APIs.
fn same_file(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.dev() == second.dev() && first.ino() == second.ino()
    }
    #[cfg(not(unix))]
    {
        first.len() == second.len() && first.modified().ok() == second.modified().ok()
    }
}

/// A path as shown to a person: sanitised, since it may come from the
/// environment.
fn shown(path: &Path) -> String {
    sanitize(&path.display().to_string())
}

fn refusal(path: &Path, reason: &str) -> PurviewError {
    PurviewError::message(format!("{} {reason}", shown(path)))
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

    fn no_warnings() -> Vec<u8> {
        Vec::new()
    }

    #[test]
    fn a_missing_directory_or_config_is_the_default() {
        let dir = tempdir().unwrap();
        assert_eq!(
            Config::load(dir.path(), &mut no_warnings()).unwrap(),
            Config::default()
        );
        assert_eq!(
            Config::load(&dir.path().join("absent"), &mut no_warnings()).unwrap(),
            Config::default()
        );
    }

    #[test]
    fn reads_the_stored_config_format() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("config.json"),
            br#"{"default_account":"alex@contoso.example",
                "clients":{"alex@contoso.example":{"client_id":"00000000-0000-4000-8000-000000000001","tenant_id":"00000000-0000-4000-8000-000000000002"}}}"#,
        )
        .unwrap();
        let config = Config::load(dir.path(), &mut no_warnings()).unwrap();
        assert_eq!(config.default_account, "alex@contoso.example");
        assert_eq!(
            config.clients["alex@contoso.example"].client_id,
            "00000000-0000-4000-8000-000000000001"
        );
    }

    #[test]
    fn saving_keeps_keys_this_release_does_not_read() {
        let dir = tempdir().unwrap();
        let original = serde_json::json!({
            "default_account": "alex@contoso.example",
            "clients": {"alex@contoso.example": {
                "client_id": "00000000-0000-4000-8000-000000000001",
                "tenant_id": "00000000-0000-4000-8000-000000000002",
                "later_field": {"x": 1}
            }},
            "defaults": {"teams_context": true, "top": 20},
            "naming": {"marker": "[created-by:purview-cli]"}
        });
        fs::write(dir.path().join("config.json"), original.to_string()).unwrap();
        let mut config = Config::load(dir.path(), &mut no_warnings()).unwrap();
        config.default_account = "sam@contoso.example".into();
        config.save(dir.path(), &Redactor::new()).unwrap();
        let saved: Value =
            serde_json::from_slice(&fs::read(dir.path().join("config.json")).unwrap()).unwrap();
        let mut expected = original;
        expected["default_account"] = "sam@contoso.example".into();
        assert_eq!(saved, expected);
    }

    #[test]
    fn malformed_config_names_the_file() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("config.json"), b"{not json").unwrap();
        let message = Config::load(dir.path(), &mut no_warnings())
            .unwrap_err()
            .to_string();
        assert!(message.contains("config.json"), "{message}");
    }

    #[test]
    fn save_then_load_round_trips_and_leaves_no_temporary_file() {
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
                ..ClientConfig::default()
            },
        );
        config.save(&root, &Redactor::new()).unwrap();
        assert_eq!(Config::load(&root, &mut no_warnings()).unwrap(), config);
        assert!(accounts_dir(&root).is_dir());
        let names: Vec<String> = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|name| !name.contains(".tmp-")),
            "{names:?}"
        );
    }

    #[test]
    fn save_refuses_a_secret_or_a_jwt_before_writing() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("config.json"), b"{}").unwrap();
        let redactor = Redactor::new();
        redactor.register("canary-refresh-0001");
        let jwt = [
            "eyJ",
            "hbGciOiJub25lIn0",
            ".",
            "eyJzdWIiOiJ4In0",
            ".",
            "c2ln",
        ]
        .concat();
        for value in ["canary-refresh-0001", jwt.as_str()] {
            let mut config = Config::default();
            config
                .extra
                .insert("note".into(), Value::String(format!("x {value}")));
            let message = config.save(dir.path(), &redactor).unwrap_err().to_string();
            assert!(message.contains("looks like a secret"), "{message}");
            assert!(!message.contains(value), "{message}");
            assert_eq!(fs::read(dir.path().join("config.json")).unwrap(), b"{}");
        }
        let mut keyed = Config::default();
        keyed
            .clients
            .insert("canary-refresh-0001".into(), ClientConfig::default());
        assert!(keyed.save(dir.path(), &redactor).is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn an_override_wins_over_the_platform_directory_and_is_normalised() {
        let dir = tempdir().unwrap();
        assert_eq!(config_dir(Some(dir.path())).unwrap(), dir.path());
        let trailing = PathBuf::from(format!("{}/", dir.path().display()));
        assert_eq!(config_dir(Some(&trailing)).unwrap(), dir.path());
    }

    #[test]
    fn a_taken_temporary_name_is_skipped_and_left_alone() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("config.json");
        let taken = dir.path().join("taken");
        fs::write(&taken, b"another writer").unwrap();
        atomic_write_named(
            &target,
            b"{}",
            ["taken".to_owned(), "free".to_owned()].into_iter(),
        )
        .unwrap();
        assert_eq!(fs::read(&taken).unwrap(), b"another writer");
        assert_eq!(fs::read(&target).unwrap(), b"{}");
        assert!(!dir.path().join("free").exists());
        let error = atomic_write_named(&target, b"{}", ["taken".to_owned()].into_iter())
            .unwrap_err()
            .to_string();
        assert!(error.contains("every candidate name was taken"), "{error}");
        assert_eq!(fs::read(&taken).unwrap(), b"another writer");
    }

    #[test]
    fn temporary_names_differ_within_one_process() {
        let path = Path::new("config.json");
        let first: Vec<String> = temporary_names(path).take(3).collect();
        let second: Vec<String> = temporary_names(path).take(3).collect();
        let all: std::collections::BTreeSet<_> = first.iter().chain(&second).collect();
        assert_eq!(all.len(), 6);
        assert!(first[0].starts_with(".config.json.tmp-"));
    }

    #[test]
    fn a_bare_file_name_writes_in_the_current_directory() {
        assert_eq!(parent_dir(Path::new("config.json")), PathBuf::from("."));
        assert_eq!(parent_dir(Path::new("a/config.json")), PathBuf::from("a"));
    }

    #[cfg(unix)]
    #[test]
    fn files_are_0600_and_directories_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("new-parent").join("purview");
        Config::default().save(&root, &Redactor::new()).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(root.parent().unwrap()), 0o700, "created parents too");
        assert_eq!(mode(&accounts_dir(&root)), 0o700);
        assert_eq!(mode(&root.join("config.json")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn readable_files_and_directories_are_tightened_on_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("purview");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let path = root.join("config.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut warnings = Vec::new();
        Config::load(&root, &mut warnings).unwrap();
        let warnings = String::from_utf8(warnings).unwrap();
        assert!(warnings.contains("expected 700"), "{warnings}");
        assert!(warnings.contains("expected 600"), "{warnings}");
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn the_warning_path_is_sanitised() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("pur\u{1b}[31mview");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let mut warnings = Vec::new();
        Config::load(&root, &mut warnings).unwrap();
        let warnings = String::from_utf8(warnings).unwrap();
        assert!(!warnings.contains('\u{1b}'), "{warnings:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_swapped_after_inspection_is_refused() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, b"{}").unwrap();
        let inspected = fs::symlink_metadata(&path).unwrap();
        let other = dir.path().join("other.json");
        fs::write(&other, br#"{"default_account":"x@contoso.example"}"#).unwrap();
        fs::rename(&other, &path).unwrap();
        let error = read_verified(&path, &inspected, &mut no_warnings())
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("changed while it was being opened"),
            "{error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_refused_at_every_level() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, b"{}").unwrap();
        let link = dir.path().join("config.json");
        symlink(&target, &link).unwrap();
        assert!(Config::load_from(&link, &mut no_warnings())
            .unwrap_err()
            .to_string()
            .contains("is a link"));
        assert!(atomic_write(&link, b"{}")
            .unwrap_err()
            .to_string()
            .contains("is a link"));

        // A linked configuration root, with and without a trailing slash.
        let real_root = dir.path().join("real");
        fs::create_dir(&real_root).unwrap();
        fs::write(real_root.join("config.json"), b"{}").unwrap();
        let linked_root = dir.path().join("linked");
        symlink(&real_root, &linked_root).unwrap();
        let trailing = PathBuf::from(format!("{}/", linked_root.display()));
        for root in [&linked_root, &trailing] {
            for error in [
                Config::load(root, &mut no_warnings()).unwrap_err(),
                Config::default().save(root, &Redactor::new()).unwrap_err(),
                ensure_private_dir(root).unwrap_err(),
            ] {
                assert!(error.to_string().contains("is a link"), "{error}");
            }
        }

        // A linked accounts directory.
        let root = dir.path().join("purview");
        fs::create_dir(&root).unwrap();
        symlink(&real_root, accounts_dir(&root)).unwrap();
        assert!(Config::default().save(&root, &Redactor::new()).is_err());
    }

    /// Junctions need no special privilege to create, unlike symlinks.
    #[cfg(windows)]
    fn junction(link: &Path, target: &Path) {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed");
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_is_refused_as_the_configuration_directory() {
        let dir = tempdir().unwrap();
        let real_root = dir.path().join("real");
        fs::create_dir(&real_root).unwrap();
        fs::write(real_root.join("config.json"), b"{}").unwrap();
        let linked_root = dir.path().join("linked");
        junction(&linked_root, &real_root);
        assert!(is_link_like(&fs::symlink_metadata(&linked_root).unwrap()));
        for error in [
            Config::load(&linked_root, &mut no_warnings()).unwrap_err(),
            Config::default()
                .save(&linked_root, &Redactor::new())
                .unwrap_err(),
            ensure_private_dir(&linked_root).unwrap_err(),
        ] {
            assert!(error.to_string().contains("is a link"), "{error}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_is_refused_as_the_accounts_directory() {
        let dir = tempdir().unwrap();
        let other = dir.path().join("other");
        fs::create_dir(&other).unwrap();
        let root = dir.path().join("purview");
        fs::create_dir(&root).unwrap();
        junction(&accounts_dir(&root), &other);
        let error = Config::default().save(&root, &Redactor::new()).unwrap_err();
        assert!(error.to_string().contains("is a link"), "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn a_plain_directory_is_not_mistaken_for_a_link() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("purview");
        Config::default().save(&root, &Redactor::new()).unwrap();
        assert!(!is_link_like(&fs::symlink_metadata(&root).unwrap()));
        assert_eq!(
            Config::load(&root, &mut no_warnings()).unwrap(),
            Config::default()
        );
    }
}
