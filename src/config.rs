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
    /// The registration saved for an account, matching the key without
    /// regard to case.
    pub fn client(&self, email: &str) -> Option<&ClientConfig> {
        self.clients
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(email.trim()))
            .map(|(_, client)| client)
    }

    /// Saves a registration under the lowercased address. Every key that
    /// names the same account in another case is folded into it, keeping
    /// their unknown fields (the existing lowercase entry's win), so no
    /// stale entry can shadow the new one.
    pub fn set_client(&mut self, email: &str, client_id: &str, tenant_id: &str) {
        let key = email.trim().to_ascii_lowercase();
        let same: Vec<String> = self
            .clients
            .keys()
            .filter(|existing| existing.eq_ignore_ascii_case(&key))
            .cloned()
            .collect();
        let mut extra = BTreeMap::new();
        // The exact lowercase key goes last, so its fields win.
        let mut ordered = same;
        ordered.sort_by_key(|existing| *existing == key);
        for existing in ordered {
            if let Some(client) = self.clients.remove(&existing) {
                extra.extend(client.extra);
            }
        }
        self.clients.insert(
            key,
            ClientConfig {
                client_id: client_id.to_owned(),
                tenant_id: tenant_id.to_owned(),
                extra,
            },
        );
    }

    /// Loads `config.json` from `dir`. A missing directory or file is the
    /// default configuration. A linked directory or file is refused. Modes
    /// readable by others are tightened, with a warning written to
    /// `warnings` (the command's redacted stderr).
    ///
    /// This is the only way to load. The checks, in order:
    ///
    /// 1. The directory is inspected without following links; a link (any
    ///    reparse point on Windows) or a non-directory is refused.
    /// 2. `config.json` is looked up by name in it, inspected the same way,
    ///    opened, and read through that handle. The opened file's metadata
    ///    must match the inspection: device and inode on Unix, size and
    ///    modification time on Windows.
    /// 3. The directory is inspected again. On Unix its device and inode
    ///    must match step 1; on Windows only its kind is checked again.
    ///
    /// A directory replaced and put back between steps 1 and 3 is not
    /// detected: standard Rust cannot open a file relative to a directory
    /// handle, so this race is accepted.
    pub fn load(dir: &Path, warnings: &mut dyn Write) -> Result<Self> {
        let dir = normalise(dir);
        let Some(checked) = check_existing_dir(&dir, warnings)? else {
            return Ok(Self::default());
        };
        let config = Self::load_file(&dir.join(CONFIG_FILE), warnings)?;
        #[cfg(test)]
        tests::run_between_reads_hook();
        checked.still_the_same()?;
        Ok(config)
    }

    /// Loads one file. It is inspected without following links, then opened,
    /// and the opened file must be the one inspected; its mode is tightened
    /// and its contents read through that same handle.
    fn load_file(path: &Path, warnings: &mut dyn Write) -> Result<Self> {
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
        let data = serde_json::to_vec_pretty(&value)?;
        // The value check covers strings whose JSON escaping hides a match;
        // the byte check covers numbers and everything else as written.
        if redactor.recognises_value(&value) || redactor.recognises_bytes(&data) {
            return Err(PurviewError::message(
                "refusing to save config.json: a value in it looks like a secret (a token the \
                 tool holds, or a JSON Web Token); configuration never holds secrets",
            ));
        }
        let dir = normalise(dir);
        ensure_config_dirs(&dir)?;
        atomic_write(&dir.join(CONFIG_FILE), &data)
    }
}

/// One signed-in account, as `accounts/<email>.json` (`docs/SPEC.md`
/// section 5.3). It holds no secret: the tokens are in the credential
/// store under the same address.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountRecord {
    /// The account key: the id token's `preferred_username`, else `upn`,
    /// else `email`, lowercased.
    pub email: String,
    /// The `upn` claim, when the id token had one.
    #[serde(default)]
    pub upn: Option<String>,
    #[serde(default)]
    pub oid: String,
    /// The `name` claim, when the id token had one.
    #[serde(default)]
    pub display_name: Option<String>,
    /// The `tid` claim: the tenant the account signed in to.
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub login_time: String,
    /// Keys this release does not read, kept as they were.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl AccountRecord {
    /// Whether `wanted` names this account: its key or its `upn`, ignoring
    /// case. There is no alias resolution.
    pub fn matches(&self, wanted: &str) -> bool {
        let wanted = wanted.trim();
        self.email.eq_ignore_ascii_case(wanted)
            || self
                .upn
                .as_deref()
                .is_some_and(|upn| upn.eq_ignore_ascii_case(wanted))
    }
}

/// The account file for an address. The address becomes a file name, so a
/// character that separates paths or is invalid in a Windows file name is
/// refused outright; rewriting it instead would let two addresses share one
/// file.
pub fn account_file_path(config_dir: &Path, email: &str) -> Result<PathBuf> {
    const UNSAFE: &str = "/\\:*?\"<>|";
    let lowered = email.trim().to_ascii_lowercase();
    let safe = !lowered.is_empty()
        && !lowered.starts_with('.')
        && !lowered.ends_with('.')
        && !lowered.contains("..")
        && !lowered
            .chars()
            .any(|character| character.is_control() || UNSAFE.contains(character));
    if !safe {
        return Err(PurviewError::message(format!(
            "account name {:?} cannot be used as a file name",
            sanitize(email)
        )));
    }
    Ok(accounts_dir(&normalise(config_dir)).join(format!("{lowered}.json")))
}

/// Writes `accounts/<email>.json` atomically, creating the directories
/// privately. A value the Redactor recognises is refused, as for
/// `config.json`.
pub fn save_account(config_dir: &Path, record: &AccountRecord, redactor: &Redactor) -> Result<()> {
    let path = account_file_path(config_dir, &record.email)?;
    let value = serde_json::to_value(record)?;
    let data = serde_json::to_vec_pretty(&value)?;
    if redactor.recognises_value(&value) || redactor.recognises_bytes(&data) {
        return Err(PurviewError::message(
            "refusing to save the account file: a value in it looks like a secret",
        ));
    }
    ensure_config_dirs(&normalise(config_dir))?;
    atomic_write(&path, &data)
}

/// Every account file, sorted by address. A missing directory means no
/// accounts. The configuration and accounts directories get the checks
/// `Config::load` makes: a link is refused, a mode open to others is
/// tightened with a warning, and each directory must still be the one
/// inspected after the files are read. A linked, unreadable or malformed
/// file is skipped with a warning.
pub fn list_accounts(config_dir: &Path, warnings: &mut dyn Write) -> Result<Vec<AccountRecord>> {
    let config_dir = normalise(config_dir);
    let Some(config_checked) = check_existing_dir(&config_dir, warnings)? else {
        return Ok(Vec::new());
    };
    let dir = accounts_dir(&config_dir);
    let Some(accounts_checked) = check_existing_dir(&dir, warnings)? else {
        return Ok(Vec::new());
    };
    let mut accounts = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        match read_account(&path, warnings) {
            Ok(Some(record)) => accounts.push(record),
            Ok(None) => {}
            Err(error) => writeln!(
                warnings,
                "warning: skipping account file {}: {}",
                shown(&path),
                sanitize(&error.to_string())
            )?,
        }
    }
    accounts_checked.still_the_same()?;
    config_checked.still_the_same()?;
    accounts.sort_by_key(|record: &AccountRecord| record.email.to_ascii_lowercase());
    Ok(accounts)
}

fn read_account(path: &Path, warnings: &mut dyn Write) -> Result<Option<AccountRecord>> {
    let metadata = fs::symlink_metadata(path)?;
    if is_link_like(&metadata) {
        return Err(refusal(path, "is a link"));
    }
    if !metadata.is_file() {
        return Ok(None);
    }
    let contents = read_verified(path, &metadata, warnings)?;
    Ok(Some(serde_json::from_slice(&contents)?))
}

/// Removes an account's file. A missing file is not an error. A link at
/// the file, the accounts directory or the configuration directory is
/// refused rather than followed; the directories are checked before and
/// after the file is inspected, just before it is removed.
pub fn remove_account(config_dir: &Path, email: &str) -> Result<()> {
    let config_dir = normalise(config_dir);
    let path = account_file_path(&config_dir, email)?;
    let parents = [config_dir.clone(), accounts_dir(&config_dir)];
    let check_parents = || -> Result<bool> {
        for parent in &parents {
            if check_dir_kind(parent)?.is_none() {
                return Ok(false);
            }
        }
        Ok(true)
    };
    if !check_parents()? {
        return Ok(());
    }
    match fs::symlink_metadata(&path) {
        Ok(metadata) if is_link_like(&metadata) => {
            Err(refusal(&path, "is a link, refusing to remove it"))
        }
        Ok(_) => {
            if !check_parents()? {
                return Ok(());
            }
            Ok(fs::remove_file(&path)?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
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
    let (file, temporary) = create_temporary(&parent, names)?;
    let mut guard = TemporaryFile(Some(temporary));
    // Declared after the guard, so on an early return the file is closed
    // before the guard removes it, which Windows requires.
    let mut file = file;
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
    metadata.file_type().is_symlink() || is_reparse_point(metadata)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
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

/// An existing configuration directory, inspected without following links.
/// Its identity is checked again after the read (see `Config::load`).
/// When its mode must be tightened on Unix, it is opened, checked to be the
/// directory inspected, and changed through that handle, which is held
/// until the final check. If it cannot be opened (`PermissionDenied`, as
/// with mode 0310), no handle is kept: the mode is set by path after a
/// fresh inspection. A directory that needs no change is not opened, so
/// one the owner may search but not list (mode 0100) still works.
struct CheckedDir {
    path: PathBuf,
    metadata: fs::Metadata,
    #[cfg(unix)]
    _handle: Option<File>,
}

impl CheckedDir {
    /// Refuses if the directory was replaced, or became a link, since it
    /// was checked. On Windows only the kind is checked again, because a
    /// directory's size and modification time change with its entries.
    fn still_the_same(&self) -> Result<()> {
        let now = check_dir_kind(&self.path)?
            .ok_or_else(|| refusal(&self.path, "disappeared while it was being read"))?;
        if cfg!(unix) && !same_file(&self.metadata, &now) {
            return Err(refusal(&self.path, "changed while it was being read"));
        }
        Ok(())
    }
}

/// Checks an existing configuration directory before reading from it, and
/// tightens a mode open to others. `None` when it does not exist.
fn check_existing_dir(dir: &Path, warnings: &mut dyn Write) -> Result<Option<CheckedDir>> {
    let Some(metadata) = check_dir_kind(dir)? else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        let mut handle = None;
        if mode & 0o077 != 0 {
            writeln!(
                warnings,
                "warning: config directory {} has permissions {:o}, expected 700; fixing",
                shown(dir),
                mode
            )?;
            handle = tighten_dir(dir, &metadata)?;
        }
        Ok(Some(CheckedDir {
            path: dir.to_path_buf(),
            metadata,
            _handle: handle,
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = warnings;
        Ok(Some(CheckedDir {
            path: dir.to_path_buf(),
            metadata,
        }))
    }
}

/// Sets mode 0700 on the inspected directory. Through a verified handle
/// when the directory can be opened; when it cannot (the owner may not list
/// it, as with mode 0310), by path after inspecting it again, which leaves
/// a short race between that inspection and the change.
#[cfg(unix)]
fn tighten_dir(dir: &Path, expected: &fs::Metadata) -> Result<Option<File>> {
    use std::os::unix::fs::PermissionsExt;
    match File::open(dir) {
        Ok(handle) => {
            let opened = handle.metadata()?;
            if !opened.is_dir() || !same_file(expected, &opened) {
                return Err(refusal(dir, "changed while it was being opened"));
            }
            handle.set_permissions(fs::Permissions::from_mode(0o700))?;
            Ok(Some(handle))
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let now = check_dir_kind(dir)?
                .ok_or_else(|| refusal(dir, "disappeared while it was being opened"))?;
            if !same_file(expected, &now) {
                return Err(refusal(dir, "changed while it was being opened"));
            }
            set_mode(dir, 0o700)?;
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

/// Opens `path`, checks that the opened file is the one `expected`
/// describes (so a swap after inspection is refused), tightens its mode
/// through the handle, and reads it through the same handle.
fn read_verified(
    path: &Path,
    expected: &fs::Metadata,
    warnings: &mut dyn Write,
) -> Result<Vec<u8>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        #[cfg(unix)]
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            repair_unreadable(path, expected, warnings)?;
            File::open(path)?
        }
        Err(error) => return Err(error.into()),
    };
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

/// A config file its owner cannot read, such as mode 0240: open it for
/// writing only, check it is the file inspected, and set 0600 through that
/// handle. The caller then reopens it for reading and checks it again.
#[cfg(unix)]
fn repair_unreadable(path: &Path, expected: &fs::Metadata, warnings: &mut dyn Write) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let handle = OpenOptions::new().write(true).open(path)?;
    let opened = handle.metadata()?;
    if !opened.is_file() || !same_file(expected, &opened) {
        return Err(refusal(path, "changed while it was being opened"));
    }
    writeln!(
        warnings,
        "warning: config file {} has permissions {:o}, expected 600; fixing",
        shown(path),
        opened.permissions().mode() & 0o777
    )?;
    handle.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
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

    fn record(email: &str, upn: Option<&str>) -> AccountRecord {
        AccountRecord {
            email: email.into(),
            upn: upn.map(str::to_owned),
            oid: "00000000-0000-4000-8000-000000000011".into(),
            display_name: Some("Alex Wilber".into()),
            tenant_id: "00000000-0000-4000-8000-000000000002".into(),
            client_id: "00000000-0000-4000-8000-000000000001".into(),
            login_time: "2026-01-05T09:00:00Z".into(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn account_files_round_trip_in_address_order_and_keep_unknown_keys() {
        let dir = tempdir().unwrap();
        let mut sam = record("sam@contoso.example", None);
        sam.extra.insert("later".into(), Value::from(1));
        save_account(dir.path(), &sam, &Redactor::new()).unwrap();
        save_account(
            dir.path(),
            &record("alex@contoso.example", Some("alex.w@contoso.example")),
            &Redactor::new(),
        )
        .unwrap();
        let listed = list_accounts(dir.path(), &mut no_warnings()).unwrap();
        let names: Vec<&str> = listed.iter().map(|r| r.email.as_str()).collect();
        assert_eq!(names, ["alex@contoso.example", "sam@contoso.example"]);
        assert_eq!(listed[1], sam);
        let stored: Value = serde_json::from_slice(
            &fs::read(account_file_path(dir.path(), "alex@contoso.example").unwrap()).unwrap(),
        )
        .unwrap();
        let mut keys: Vec<&str> = stored
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "client_id",
                "display_name",
                "email",
                "login_time",
                "oid",
                "tenant_id",
                "upn"
            ]
        );
        remove_account(dir.path(), "alex@contoso.example").unwrap();
        remove_account(dir.path(), "alex@contoso.example").unwrap();
        assert_eq!(
            list_accounts(dir.path(), &mut no_warnings()).unwrap(),
            [sam]
        );
    }

    #[test]
    fn a_registration_is_saved_under_one_lowercase_key_keeping_unknown_fields() {
        let mut config: Config = serde_json::from_value(serde_json::json!({
            "clients": {
                "Alex@Contoso.Example": {"client_id": "old", "tenant_id": "old", "note": 1},
                "alex@contoso.example": {"client_id": "older", "later": 2},
                "sam@contoso.example": {"client_id": "sam"}
            }
        }))
        .unwrap();
        config.set_client("ALEX@contoso.example", "new-client", "new-tenant");
        let saved = serde_json::to_value(&config).unwrap();
        assert_eq!(
            saved["clients"],
            serde_json::json!({
                "alex@contoso.example": {
                    "client_id": "new-client", "tenant_id": "new-tenant", "note": 1, "later": 2
                },
                "sam@contoso.example": {"client_id": "sam"}
            })
        );
        assert_eq!(
            config.client("Alex@Contoso.Example").unwrap().client_id,
            "new-client"
        );
    }

    #[cfg(unix)]
    #[test]
    fn listing_tightens_a_loose_accounts_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let root = dir.path().join("purview");
        save_account(
            &root,
            &record("alex@contoso.example", None),
            &Redactor::new(),
        )
        .unwrap();
        fs::set_permissions(accounts_dir(&root), fs::Permissions::from_mode(0o755)).unwrap();
        let mut warnings = Vec::new();
        assert_eq!(list_accounts(&root, &mut warnings).unwrap().len(), 1);
        let text = String::from_utf8(warnings).unwrap();
        assert!(text.contains("has permissions 755"), "{text}");
        let mode = fs::metadata(accounts_dir(&root))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_accounts_directory_is_refused_for_listing_and_removal() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("purview");
        fs::create_dir(&root).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let victim = elsewhere.join(format!("{}.json", "alex@contoso.example"));
        fs::write(&victim, b"{}").unwrap();
        std::os::unix::fs::symlink(&elsewhere, accounts_dir(&root)).unwrap();
        assert!(list_accounts(&root, &mut no_warnings()).is_err());
        assert!(remove_account(&root, "alex@contoso.example").is_err());
        assert!(victim.exists());
    }

    #[test]
    fn an_account_matches_its_key_or_upn_ignoring_case_and_nothing_else() {
        let alex = record("alex@contoso.example", Some("alex.w@contoso.example"));
        assert!(alex.matches("ALEX@contoso.example"));
        assert!(alex.matches("Alex.W@Contoso.Example"));
        assert!(!alex.matches("alex"));
        assert!(!record("sam@contoso.example", None).matches(""));
    }

    #[test]
    fn unsafe_account_names_are_refused_as_file_names() {
        let dir = tempdir().unwrap();
        for name in [
            "",
            "../x@contoso.example",
            "a/b@contoso.example",
            "a:b",
            ".hidden",
            "x\ny",
        ] {
            assert!(account_file_path(dir.path(), name).is_err(), "{name:?}");
        }
        assert!(account_file_path(dir.path(), "o'brien+x@contoso.example").is_ok());
    }

    #[test]
    fn a_malformed_account_file_is_skipped_with_a_warning() {
        let dir = tempdir().unwrap();
        ensure_config_dirs(dir.path()).unwrap();
        fs::write(
            account_file_path(dir.path(), "bad@contoso.example").unwrap(),
            b"{",
        )
        .unwrap();
        let mut warnings = Vec::new();
        assert!(list_accounts(dir.path(), &mut warnings).unwrap().is_empty());
        let text = String::from_utf8(warnings).unwrap();
        // A looser mode is reported and fixed first on Unix.
        assert!(text.contains("warning: skipping account file"), "{text}");
    }

    #[test]
    fn an_account_file_holding_a_secret_is_refused() {
        let dir = tempdir().unwrap();
        let redactor = Redactor::new();
        redactor.register("canary-oid-0001");
        let mut leaky = record("alex@contoso.example", None);
        leaky.oid = "canary-oid-0001".into();
        assert!(save_account(dir.path(), &leaky, &redactor).is_err());
        assert!(!accounts_dir(dir.path()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn linked_account_files_are_skipped_and_not_removed_through() {
        let dir = tempdir().unwrap();
        ensure_config_dirs(dir.path()).unwrap();
        let target = dir.path().join("elsewhere.json");
        fs::write(
            &target,
            serde_json::to_vec(&record("alex@contoso.example", None)).unwrap(),
        )
        .unwrap();
        let link = account_file_path(dir.path(), "alex@contoso.example").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let mut warnings = Vec::new();
        assert!(list_accounts(dir.path(), &mut warnings).unwrap().is_empty());
        assert!(String::from_utf8(warnings).unwrap().contains("is a link"));
        assert!(remove_account(dir.path(), "alex@contoso.example").is_err());
        assert!(target.exists());
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

    /// Runs the ignored child test below in a fresh temporary working
    /// directory, so this process's directory never changes and nothing is
    /// written into the repository.
    #[test]
    fn a_bare_file_name_writes_in_the_current_directory() {
        assert_eq!(parent_dir(Path::new("config.json")), PathBuf::from("."));
        assert_eq!(parent_dir(Path::new("a/config.json")), PathBuf::from("a"));
        let dir = tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "config::tests::bare_name_child_writes_in_its_working_directory",
                "--test-threads=1",
            ])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("1 passed"),
            "{output:?}"
        );
        assert_eq!(
            fs::read(dir.path().join("bare.json")).unwrap(),
            br#"{"ok":true}"#
        );
        let names: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["bare.json"]);
    }

    /// An existing `bare.json` stops the child before it writes.
    #[test]
    fn the_bare_name_child_leaves_an_existing_file_alone() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("bare.json"), b"sentinel").unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "config::tests::bare_name_child_writes_in_its_working_directory",
                "--test-threads=1",
            ])
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(fs::read(dir.path().join("bare.json")).unwrap(), b"sentinel");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    /// The child half of the test above. It writes only when its working
    /// directory lies under the system temporary directory, so a plain
    /// `cargo test -- --ignored` from the repository writes nothing and
    /// passes. It first reserves `bare.json` with `create_new`; if a file of
    /// that name already exists, it stops without writing.
    #[test]
    #[ignore = "run by a_bare_file_name_writes_in_the_current_directory"]
    fn bare_name_child_writes_in_its_working_directory() {
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        let temporary = std::env::temp_dir().canonicalize().unwrap();
        if !cwd.starts_with(&temporary) {
            return; // not started by the parent test: write nothing
        }
        let reserved = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open("bare.json");
        match reserved {
            Ok(file) => drop(file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return,
            Err(error) => panic!("could not reserve bare.json: {error}"),
        }
        atomic_write(Path::new("bare.json"), br#"{"ok":true}"#).unwrap();
    }

    #[test]
    fn save_refuses_a_registered_number() {
        let dir = tempdir().unwrap();
        let redactor = Redactor::new();
        redactor.register("4815162");
        let mut config = Config::default();
        config
            .extra
            .insert("later_count".into(), serde_json::json!(4815162));
        let message = config.save(dir.path(), &redactor).unwrap_err().to_string();
        assert!(message.contains("looks like a secret"), "{message}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn an_owner_unreadable_config_is_repaired_and_read() {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o240, 0o644] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("config.json");
            fs::write(&path, br#"{"default_account":"alex@contoso.example"}"#).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            let mut warnings = Vec::new();
            let config = Config::load(dir.path(), &mut warnings).unwrap();
            assert_eq!(config.default_account, "alex@contoso.example", "{mode:o}");
            let warnings = String::from_utf8(warnings).unwrap();
            assert!(warnings.contains("expected 600"), "{mode:o}: {warnings}");
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600,
                "{mode:o}"
            );
        }
    }

    thread_local! {
        static BETWEEN_READS: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
            std::cell::RefCell::new(None);
    }

    /// Called by `Config::load` between reading the file and checking the
    /// directory again; runs the hook a test installed on this thread.
    pub(super) fn run_between_reads_hook() {
        if let Some(hook) = BETWEEN_READS.with(|slot| slot.borrow_mut().take()) {
            hook();
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_replaced_during_a_load_is_refused() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("purview");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("config.json"), b"{}").unwrap();
        assert!(Config::load(&root, &mut no_warnings()).is_ok());
        let (moved, again) = (dir.path().join("moved"), root.clone());
        BETWEEN_READS.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                fs::rename(&again, &moved).unwrap();
                fs::create_dir(&again).unwrap();
            }));
        });
        let error = Config::load(&root, &mut no_warnings())
            .unwrap_err()
            .to_string();
        assert!(error.contains("changed while it was being read"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_the_owner_cannot_list_still_loads() {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o100, 0o310] {
            let dir = tempdir().unwrap();
            let root = dir.path().join("purview");
            fs::create_dir(&root).unwrap();
            fs::write(
                root.join("config.json"),
                br#"{"default_account":"alex@contoso.example"}"#,
            )
            .unwrap();
            fs::set_permissions(root.join("config.json"), fs::Permissions::from_mode(0o600))
                .unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(mode)).unwrap();
            let result = Config::load(&root, &mut no_warnings());
            let after = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(
                result.unwrap().default_account,
                "alex@contoso.example",
                "{mode:o}"
            );
            let expected = if mode & 0o077 == 0 { mode } else { 0o700 };
            assert_eq!(after, expected, "{mode:o}");
        }
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
        assert!(Config::load_file(&link, &mut no_warnings())
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
