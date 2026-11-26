//! The operating-system credential store: the only place a token persists.
//!
//! Copied from `aberoham/ms-entra-cli` (`src/secrets.rs`) and maintained
//! separately; a fix to the copied code may be needed in both repositories.
//! The service name, key, macOS label and description below are part of
//! the credential compatibility promise in `AGENTS.md`: changing them signs
//! every user out.
//!
//! - macOS: one keychain item per account, labelled `purview — <email>`.
//! - Linux: one keyutils key per account (`keyring`'s `linux-native`).
//! - Windows: Credential Manager holds at most 2,560 bytes per credential,
//!   so the value is split into chunks behind a header, written under a
//!   file lock (see `CredentialLock`).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{PurviewError, Result};

const SERVICE_NAME: &str = "purview";
const TOKEN_PREFIX: &str = "purview:token:";
#[cfg(target_os = "macos")]
const ITEM_DESCRIPTION: &str = "Microsoft Purview eDiscovery token";
const MAX_CHUNKS: usize = 128;
// Serialises credential access across `purview` processes on Windows. The lock
// covers storage operations only, never a network refresh, so the wait is
// short unless another process has stopped part way through one.
const LOCK_FILE: &str = "credentials.lock";
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(25);

/// Windows Credential Manager limits one credential blob to 2560 bytes. Two
/// access tokens and a refresh token routinely exceed that once serialised
/// together.
#[cfg(windows)]
const CHUNK_BYTES: Option<usize> = Some(2560);
#[cfg(not(windows))]
const CHUNK_BYTES: Option<usize> = None;

pub trait CredentialStore: Send + Sync {
    fn get_password(&self, key: &str) -> Result<Option<String>>;
    fn set_password(&self, key: &str, value: &str) -> Result<()>;
    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()>;
    fn delete(&self, key: &str) -> Result<bool>;

    /// Locks the store against other processes until the returned guard is
    /// dropped. A store whose single operations are already atomic needs no
    /// lock and returns `None`.
    fn lock(&self) -> Result<Option<CredentialLock>> {
        Ok(None)
    }

    /// The largest value one entry may hold, when values are split into
    /// chunks: Windows Credential Manager's limit on Windows, none
    /// elsewhere. A test store may choose the Windows layout anywhere.
    fn chunk_bytes(&self) -> Option<usize> {
        CHUNK_BYTES
    }
}

/// An exclusive operating-system file lock, released when dropped. Windows
/// Credential Manager has no transactions, and a chunked credential spans
/// several entries, so two processes refreshing one account at once could
/// otherwise interleave their chunks, and a reader could follow a header to
/// chunks that a writer is deleting. Reads take the lock exclusively too:
/// they last milliseconds, and a shared lock would let a run of overlapping
/// readers keep a writer out indefinitely.
#[derive(Debug)]
pub struct CredentialLock {
    _file: File,
}

impl CredentialLock {
    /// Takes the lock, retrying for up to `wait` while another holder has it
    /// or while another program briefly keeps the file from being opened.
    pub fn acquire(path: &Path, wait: Duration) -> Result<Self> {
        let failed = |action, source| PurviewError::CredentialLockFailed {
            action,
            path: path.display().to_string(),
            source,
        };
        // A bare file name has an empty parent: there is no folder to create,
        // and the working directory is not the tool's to narrow.
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            create_private_dir(parent).map_err(|error| failed("create the folder for", error))?;
        }
        let deadline = Instant::now() + wait;
        let file = loop {
            let mut options = OpenOptions::new();
            options.create(true).truncate(false).read(true).write(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            match options.open(path) {
                Ok(file) => break file,
                Err(error) if is_transient_open_error(&error) && Instant::now() < deadline => {
                    std::thread::sleep(LOCK_POLL);
                }
                Err(error) => return Err(failed("open", error)),
            }
        };
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(LOCK_POLL);
                }
                Err(TryLockError::WouldBlock) => {
                    return Err(PurviewError::CredentialLockBusy {
                        path: path.display().to_string(),
                        seconds: wait.as_secs(),
                    });
                }
                Err(TryLockError::Error(error)) => return Err(failed("lock", error)),
            }
        }
    }
}

/// Creates a lock folder and any missing parents with mode 0700. On macOS the
/// local data directory is also the configuration directory, so a lock taken
/// first would otherwise create `purview/` with the default mode. A folder
/// that already exists keeps its mode: changing the mode of an existing path
/// would need a no-follow open that standard Rust does not offer. A lock
/// folder that is a link, or not a folder, is refused. Windows has no modes
/// and relies on the profile's access control list.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        if !std::fs::symlink_metadata(dir)?.file_type().is_dir() {
            return Err(std::io::Error::other(
                "the lock folder is a link or not a folder; refusing to use it",
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Windows refuses to open a file that antivirus or an indexer briefly holds
/// open without sharing (a sharing violation, a lock violation, or access
/// denied); those clear on their own, so they are retried like a busy lock.
fn is_transient_open_error(error: &std::io::Error) -> bool {
    cfg!(windows) && matches!(error.raw_os_error(), Some(5 | 32 | 33))
}

#[derive(Debug, Default)]
pub struct KeyringStore;

impl KeyringStore {
    fn entry(key: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(SERVICE_NAME, key).map_err(Into::into)
    }
}

#[cfg(any(target_os = "macos", test))]
fn item_label(key: &str) -> String {
    match key.strip_prefix(TOKEN_PREFIX) {
        Some(account) if !account.is_empty() => format!("purview — {account}"),
        _ => "purview (Microsoft Purview eDiscovery CLI)".to_owned(),
    }
}

#[cfg(target_os = "macos")]
fn set_macos_item_metadata(key: &str) -> Result<()> {
    use security_framework::item::{update_item, ItemClass, ItemSearchOptions, ItemUpdateOptions};
    use security_framework::os::macos::keychain::{SecKeychain, SecPreferencesDomain};

    let keychain =
        SecKeychain::default_for_domain(SecPreferencesDomain::User).map_err(|error| {
            PurviewError::message(format!("opening the macOS user keychain: {error}"))
        })?;
    let mut search = ItemSearchOptions::new();
    search
        .keychains(&[keychain])
        .class(ItemClass::generic_password())
        .service(SERVICE_NAME)
        .account(key);

    let mut update = ItemUpdateOptions::new();
    update
        .set_label(item_label(key))
        .set_description(ITEM_DESCRIPTION);

    update_item(&search, &update).map_err(|error| {
        PurviewError::message(format!(
            "labelling the macOS keychain item for {key:?}: {error}"
        ))
    })
}

fn absent_as_none<T>(result: keyring::Result<T>, operation: &str) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(keyring::Error::BadEncoding(_)) => Err(PurviewError::CredentialEncoding(
            "the entry is not text in the backend's encoding".to_owned(),
        )
        .context(operation)),
        Err(error) => Err(PurviewError::from(error).context(operation)),
    }
}

impl CredentialStore for KeyringStore {
    fn get_password(&self, key: &str) -> Result<Option<String>> {
        absent_as_none(
            Self::entry(key)?.get_password(),
            "retrieving stored credential",
        )
    }

    fn set_password(&self, key: &str, value: &str) -> Result<()> {
        // set_password updates in place. Deleting first would replace the
        // macOS keychain item and discard its existing "Always Allow" ACL.
        Self::entry(key)?.set_password(value)?;
        // keyring's macOS backend intentionally ignores attributes other than
        // service and account. Add a human-readable label so the authorisation
        // dialog identifies both this CLI and the account being unlocked.
        #[cfg(target_os = "macos")]
        set_macos_item_metadata(key)?;
        Ok(())
    }

    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
        absent_as_none(
            Self::entry(key)?.get_secret(),
            "retrieving stored credential",
        )
    }

    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
        Self::entry(key)?.set_secret(value)?;
        #[cfg(target_os = "macos")]
        set_macos_item_metadata(key)?;
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<bool> {
        Ok(absent_as_none(
            Self::entry(key)?.delete_credential(),
            "deleting stored credential",
        )?
        .is_some())
    }

    /// Only chunked storage spans several entries; a single keychain or
    /// keyutils item is replaced in one operation and needs no lock.
    fn lock(&self) -> Result<Option<CredentialLock>> {
        lock_when_chunked(CHUNK_BYTES, credential_lock_path, LOCK_WAIT)
    }
}

/// Locks only when credentials are chunked: a single macOS keychain item or
/// Linux keyutils key is replaced in one operation and needs no lock.
fn lock_when_chunked(
    chunk_bytes: Option<usize>,
    path: impl FnOnce() -> Result<std::path::PathBuf>,
    wait: Duration,
) -> Result<Option<CredentialLock>> {
    if chunk_bytes.is_none() {
        return Ok(None);
    }
    CredentialLock::acquire(&path()?, wait).map(Some)
}

/// The lock file for this user's credentials. It is deliberately not under
/// the configuration directory: `PURVIEW_CONFIG_DIR` moves that, but not the
/// credential store, and two processes guarding the same credentials must
/// always meet at the same lock.
fn credential_lock_path() -> Result<std::path::PathBuf> {
    dirs::data_local_dir()
        .map(|root| root.join(crate::config::APP_DIR).join(LOCK_FILE))
        .ok_or_else(|| PurviewError::CredentialLockFailed {
            action: "find the folder for",
            path: LOCK_FILE.to_owned(),
            source: std::io::Error::other(
                "this account has no local application data folder; check that the account \
                 running purview has a loaded user profile and that its AppData\\Local folder \
                 exists and is writable",
            ),
        })
}

/// Chunks live in one of two slots so that a rewrite never touches the chunks
/// the current header points at. Slot 0 uses the original `<key>:<n>` names,
/// which keeps headers written before slots existed readable.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkHeader {
    chunks: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    slot: u8,
}

fn is_zero(slot: &u8) -> bool {
    *slot == 0
}

const SLOTS: [u8; 2] = [0, 1];

pub fn store_value(store: &dyn CredentialStore, key: &str, value: &str) -> Result<()> {
    let _lock = store.lock()?;
    store_value_inner(store, key, value, store.chunk_bytes(), false)
}

/// `store_value` for a sign-in the ownership check has authorised to
/// replace a damaged entry: a primary entry the backend cannot decode is
/// then treated as an unusable header and overwritten. Every other error,
/// store-access failures included, still fails.
pub fn store_value_repairing(store: &dyn CredentialStore, key: &str, value: &str) -> Result<()> {
    let _lock = store.lock()?;
    store_value_inner(store, key, value, store.chunk_bytes(), true)
}

pub fn get_value(store: &dyn CredentialStore, key: &str) -> Result<String> {
    find_value(store, key)?
        .ok_or_else(|| PurviewError::message(format!("no stored credential exists for {key:?}")))
}

/// The stored value, or `None` when there is no entry for `key`.
pub fn find_value(store: &dyn CredentialStore, key: &str) -> Result<Option<String>> {
    let _lock = store.lock()?;
    let Some(primary) = store.get_password(key)? else {
        return Ok(None);
    };
    let value = match parse_chunk_header(&primary)? {
        Some(header) => read_chunks(store, key, header.slot, header.chunks)?,
        None => primary,
    };
    Ok(Some(value))
}

pub fn delete_value(store: &dyn CredentialStore, key: &str) -> Result<()> {
    let _lock = store.lock()?;
    delete_value_with_chunk_size(store, key, store.chunk_bytes())
}

/// Whether anything is stored under `key`: the primary entry or, in the
/// chunked layout, any chunk in either slot, header or not. Nothing is
/// parsed, reassembled or decoded, so a damaged entry, or chunks a failed
/// first write left without a header, still count.
pub fn entry_exists(store: &dyn CredentialStore, key: &str) -> Result<bool> {
    let _lock = store.lock()?;
    if store.get_secret(key)?.is_some() {
        return Ok(true);
    }
    if store.chunk_bytes().is_some() {
        for slot in SLOTS {
            for index in 0..MAX_CHUNKS {
                if store.get_secret(&chunk_key(key, slot, index))?.is_some() {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Serialises the commands that write one account's local state, across
/// processes: `auth login` from its ownership check to its last write or
/// rollback, `auth logout`, and each refresh commit. It is a lock file per
/// account key, taken with the same file lock the credential store uses on
/// Windows, but a different file, so taking it never nests inside a store
/// operation.
#[derive(Debug, Clone)]
pub struct AccountLocks {
    pub dir: std::path::PathBuf,
    pub wait: Duration,
}

impl AccountLocks {
    /// The production locks: under the local data directory, like the
    /// credential lock, and not under `PURVIEW_CONFIG_DIR`, because two
    /// processes guarding the same credentials must meet at the same file.
    pub fn production() -> Option<Self> {
        dirs::data_local_dir().map(|root| Self {
            dir: root.join(crate::config::APP_DIR).join("account-locks"),
            wait: LOCK_WAIT,
        })
    }

    /// The lock file for `email`: the SHA-256 of the normalised key, in
    /// hexadecimal. The key itself never becomes a file name, since an
    /// account name comes from the identity platform and could hold
    /// anything, a path separator or a token included.
    pub fn path(&self, email: &str) -> std::path::PathBuf {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(email.trim().to_ascii_lowercase().as_bytes());
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        self.dir.join(format!("{hex}.lock"))
    }

    /// Takes the lock for `email`, waiting up to `wait` for another holder.
    /// The wait runs on a blocking thread.
    pub async fn lock(&self, email: &str) -> Result<CredentialLock> {
        let path = self.path(email);
        let wait = self.wait;
        tokio::task::spawn_blocking(move || CredentialLock::acquire(&path, wait))
            .await
            .map_err(|error| {
                PurviewError::message(format!("waiting for the account lock: {error}"))
            })?
    }
}

fn delete_value_with_chunk_size(
    store: &dyn CredentialStore,
    key: &str,
    chunk_bytes: Option<usize>,
) -> Result<()> {
    // The header goes first: if deletion stops part way, readers find no
    // credential rather than a header pointing at missing chunks, and the
    // next sign-in sweeps any chunks left behind.
    store.delete(key)?;
    if chunk_bytes.is_some() {
        delete_all_chunks(store, key)?;
    }
    Ok(())
}

fn delete_all_chunks(store: &dyn CredentialStore, key: &str) -> Result<()> {
    for slot in SLOTS {
        delete_chunks(store, key, slot, 0)?;
    }
    Ok(())
}

fn chunk_key(key: &str, slot: u8, index: usize) -> String {
    match slot {
        0 => format!("{key}:{index}"),
        _ => format!("{key}:s{slot}:{index}"),
    }
}

#[cfg(test)]
fn store_value_with_chunk_size(
    store: &dyn CredentialStore,
    key: &str,
    value: &str,
    chunk_bytes: Option<usize>,
) -> Result<()> {
    store_value_inner(store, key, value, chunk_bytes, false)
}

fn store_value_inner(
    store: &dyn CredentialStore,
    key: &str,
    value: &str,
    chunk_bytes: Option<usize>,
    repair: bool,
) -> Result<()> {
    match chunk_bytes {
        None => store.set_password(key, value),
        Some(0) => Err(PurviewError::message(
            "credential chunk size cannot be zero",
        )),
        Some(size) => {
            let chunks: Vec<_> = value.as_bytes().chunks(size).collect();
            if chunks.is_empty() || chunks.len() > MAX_CHUNKS {
                return Err(PurviewError::message(format!(
                    "credential needs {} chunks; supported range is 1..={MAX_CHUNKS}",
                    chunks.len()
                )));
            }
            let previous = stored_header(store, key, repair)?;
            // Write into the slot the current header does not use, so a
            // failure part way leaves the stored credential intact.
            let slot = match &previous {
                Some(header) if header.slot == 0 => 1,
                _ => 0,
            };
            for (index, chunk) in chunks.iter().enumerate() {
                store.set_secret(&chunk_key(key, slot, index), chunk)?;
            }
            // An earlier interrupted write may have left longer data here.
            delete_chunks(store, key, slot, chunks.len())?;
            let header = serde_json::to_string(&ChunkHeader {
                chunks: chunks.len(),
                slot,
            })?;
            store.set_password(key, &header)?;
            // The new header is live; the other slot now holds only old data.
            delete_chunks(store, key, 1 - slot, 0)
        }
    }
}

fn parse_chunk_header(value: &str) -> Result<Option<ChunkHeader>> {
    let Ok(header) = serde_json::from_str::<ChunkHeader>(value) else {
        return Ok(None);
    };
    if header.chunks == 0 || header.chunks > MAX_CHUNKS {
        return Err(PurviewError::message(format!(
            "stored credential has invalid chunk count {}",
            header.chunks
        )));
    }
    if !SLOTS.contains(&header.slot) {
        return Err(PurviewError::message(format!(
            "stored credential has invalid chunk slot {}",
            header.slot
        )));
    }
    Ok(Some(header))
}

/// The current header, or `None` when there is no entry, the entry is a
/// legacy single value, or its header is unusable and will be overwritten.
/// The entry is read through the backend's password decoder (UTF-16LE on
/// Windows), as it was written: reading the bytes raw would make a valid
/// header look unusable, and the writer would then overwrite the slot the
/// live credential uses. A decoding failure is an unusable header only
/// when `repair` says the ownership check authorised replacing the entry;
/// store-access errors always fail.
fn stored_header(
    store: &dyn CredentialStore,
    key: &str,
    repair: bool,
) -> Result<Option<ChunkHeader>> {
    match store.get_password(key) {
        Ok(Some(primary)) => Ok(parse_chunk_header(&primary).ok().flatten()),
        Ok(None) => Ok(None),
        Err(error) if repair && error.is_credential_encoding() => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_chunks(store: &dyn CredentialStore, key: &str, slot: u8, count: usize) -> Result<String> {
    let mut bytes = Vec::new();
    for index in 0..count {
        let chunk = store
            .get_secret(&chunk_key(key, slot, index))?
            .ok_or_else(|| {
                PurviewError::message(format!(
                    "stored credential is incomplete (chunk {index} of {count} is missing); run \
                     'purview auth login' again"
                ))
            })?;
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes)
        .map_err(|error| PurviewError::message(format!("stored credential is not UTF-8: {error}")))
}

/// Delete every chunk in `slot` from `start` to the bound. The sweep does not
/// stop at the first absent entry, because an interrupted cleanup can leave
/// later chunks behind a gap, and those hold pieces of a refresh token.
fn delete_chunks(store: &dyn CredentialStore, key: &str, slot: u8, start: usize) -> Result<()> {
    for index in start..MAX_CHUNKS {
        store.delete(&chunk_key(key, slot, index))?;
    }
    Ok(())
}

/// The credential key for an account: `purview:token:<email>`, lowercased.
pub fn token_key(email: &str) -> String {
    format!("{TOKEN_PREFIX}{}", email.to_ascii_lowercase())
}

/// A credential store held in memory, for tests. It never touches the
/// operating-system store. Writes can be made to fail, to test that a
/// command reports a credential the store did not accept.
#[doc(hidden)]
pub struct MemoryStore {
    values: Mutex<BTreeMap<String, Vec<u8>>>,
    locks: AtomicUsize,
    fail_writes: AtomicBool,
    fail_deletes: AtomicBool,
    fail_headers: AtomicBool,
    chunk_bytes: Option<usize>,
    /// Password entries are kept as UTF-16LE, as keyring's Windows backend
    /// stores them; secret entries stay raw.
    utf16_passwords: bool,
}

/// The platform's layout: chunked on Windows, as the real store is, so
/// every in-memory flow runs on the layout of the platform under test.
impl Default for MemoryStore {
    fn default() -> Self {
        Self {
            values: Mutex::default(),
            locks: AtomicUsize::default(),
            fail_writes: AtomicBool::default(),
            fail_deletes: AtomicBool::default(),
            fail_headers: AtomicBool::default(),
            chunk_bytes: CHUNK_BYTES,
            utf16_passwords: cfg!(windows),
        }
    }
}

/// Names the stored keys and counts, never the stored values.
impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MemoryStore")
            .field("keys", &self.keys())
            .field("locks", &self.locks())
            .finish_non_exhaustive()
    }
}

#[doc(hidden)]
impl MemoryStore {
    /// A store that splits values into chunks of `size` bytes behind a
    /// header, as Windows Credential Manager requires.
    pub fn chunked(size: usize) -> Self {
        Self {
            chunk_bytes: Some(size),
            ..Self::default()
        }
    }

    /// The Windows layout on any platform: chunks of `size` bytes behind a
    /// header, and password entries encoded as UTF-16LE.
    pub fn windows(size: usize) -> Self {
        Self {
            chunk_bytes: Some(size),
            utf16_passwords: true,
            ..Self::default()
        }
    }

    /// Makes every later primary-entry write (`set_password`, which holds a
    /// value or a chunk header) fail, while chunk writes succeed: a chunked
    /// write that stops after its chunks and before its header.
    pub fn fail_headers(&self, fail: bool) {
        self.fail_headers.store(fail, Ordering::SeqCst);
    }

    pub fn remove(&self, key: &str) {
        self.values().remove(key);
    }

    pub fn keys(&self) -> Vec<String> {
        self.values().keys().cloned().collect()
    }

    /// Every stored value, for scanning in tests.
    pub fn all_values(&self) -> Vec<Vec<u8>> {
        self.values().values().cloned().collect()
    }

    /// How many times the store has been locked.
    pub fn locks(&self) -> usize {
        self.locks.load(Ordering::SeqCst)
    }

    /// Makes every later write fail, or succeed again.
    pub fn fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::SeqCst);
    }

    /// Makes every later deletion of a credential's primary entry fail, or
    /// succeed again. Chunk entries (`<key>:<n>`, `<key>:s<slot>:<n>`) are
    /// still deleted, so a chunked write's own clean-up is unaffected.
    pub fn fail_deletes(&self, fail: bool) {
        self.fail_deletes.store(fail, Ordering::SeqCst);
    }

    fn values(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.values
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl CredentialStore for MemoryStore {
    fn get_password(&self, key: &str) -> Result<Option<String>> {
        let Some(bytes) = self.get_secret(key)? else {
            return Ok(None);
        };
        let decoded = if self.utf16_passwords {
            if bytes.len() % 2 != 0 {
                None
            } else {
                let units: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes(*pair))
                    .collect();
                String::from_utf16(&units).ok()
            }
        } else {
            String::from_utf8(bytes).ok()
        };
        decoded.map(Some).ok_or_else(|| {
            PurviewError::CredentialEncoding("the in-memory entry is not valid text".to_owned())
        })
    }

    fn set_password(&self, key: &str, value: &str) -> Result<()> {
        if self.fail_headers.load(Ordering::SeqCst) {
            return Err(PurviewError::message(
                "the in-memory credential store refused the primary entry",
            ));
        }
        if self.utf16_passwords {
            let bytes: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
            return self.set_secret(key, &bytes);
        }
        self.set_secret(key, value.as_bytes())
    }

    fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.values().get(key).cloned())
    }

    fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
        if self.fail_writes.load(Ordering::SeqCst) {
            return Err(PurviewError::message(
                "the in-memory credential store refused the write",
            ));
        }
        self.values().insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<bool> {
        let is_chunk = key
            .rsplit_once(':')
            .is_some_and(|(_, last)| last.chars().all(|c| c.is_ascii_digit()));
        if self.fail_deletes.load(Ordering::SeqCst) && !is_chunk {
            return Err(PurviewError::message(
                "the in-memory credential store refused the deletion",
            ));
        }
        Ok(self.values().remove(key).is_some())
    }

    fn lock(&self) -> Result<Option<CredentialLock>> {
        self.locks.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn chunk_bytes(&self) -> Option<usize> {
        self.chunk_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_service_key_and_label_are_the_compatibility_values() {
        assert_eq!(SERVICE_NAME, "purview");
        assert_eq!(
            token_key("Alex@Contoso.Example"),
            "purview:token:alex@contoso.example"
        );
        assert_eq!(
            item_label("purview:token:alex@contoso.example"),
            "purview — alex@contoso.example"
        );
    }

    #[test]
    fn unknown_or_empty_keys_still_have_a_useful_item_label() {
        for key in ["", "profile-index", "purview:token:"] {
            assert_eq!(
                item_label(key),
                "purview (Microsoft Purview eDiscovery CLI)"
            );
        }
    }

    #[test]
    fn the_memory_store_debug_form_shows_no_value() {
        let store = MemoryStore::default();
        store.set_password("account", "canary-secret-0001").unwrap();
        // The whole form: key names and the lock count, and no bytes in
        // any rendering (a derived Debug would print them as numbers).
        assert_eq!(
            format!("{store:?}"),
            "MemoryStore { keys: [\"account\"], locks: 0, .. }"
        );
    }

    #[test]
    fn a_refused_header_write_keeps_a_utf16_header_and_its_chunks_intact() {
        // The Windows layout: a two-chunk value behind a UTF-16LE header.
        let store = MemoryStore::windows(4);
        store_value(&store, "account", "abcdefg").unwrap();
        let header = store.get_secret("account").unwrap().unwrap();
        assert_eq!(header[1], 0, "the header is UTF-16LE: {header:?}");
        // A one-chunk replacement whose header write is refused must go to
        // the other slot, leaving the live chunks alone.
        store.fail_headers(true);
        assert!(store_value(&store, "account", "xyz").is_err());
        store.fail_headers(false);
        assert_eq!(get_value(&store, "account").unwrap(), "abcdefg");
    }

    #[test]
    fn only_a_repair_replaces_a_primary_the_backend_cannot_decode() {
        let store = MemoryStore::windows(4);
        store.set_secret("account", &[0xff, 0xfe, 0x00]).unwrap();
        let error = store_value(&store, "account", "abcdefg").unwrap_err();
        assert!(error.is_credential_encoding(), "{error}");
        store_value_repairing(&store, "account", "abcdefg").unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "abcdefg");
    }

    #[test]
    fn a_failing_memory_store_refuses_writes_and_keeps_what_it_had() {
        let store = MemoryStore::default();
        store_value(&store, "account", "first").unwrap();
        store.fail_writes(true);
        assert!(store_value(&store, "account", "second").is_err());
        assert_eq!(get_value(&store, "account").unwrap(), "first");
    }

    #[test]
    fn reads_writes_and_deletes_each_lock_the_store() {
        let store = MemoryStore::default();
        store_value(&store, "account", "value").unwrap();
        assert_eq!(store.locks(), 1);
        get_value(&store, "account").unwrap();
        assert_eq!(store.locks(), 2);
        delete_value(&store, "account").unwrap();
        assert_eq!(store.locks(), 3);
    }

    fn is_busy(path: &Path) -> bool {
        match CredentialLock::acquire(path, Duration::ZERO) {
            Ok(_) => false,
            Err(error) => {
                assert!(error.is_credential_lock_busy(), "{error}");
                true
            }
        }
    }

    /// A store that locks a real file and checks, inside every storage
    /// operation, that the lock is still held.
    struct LockCheckingStore {
        inner: MemoryStore,
        path: std::path::PathBuf,
    }

    impl LockCheckingStore {
        fn assert_locked(&self) {
            assert!(
                is_busy(&self.path),
                "a storage operation ran without the credential lock"
            );
        }
    }

    impl CredentialStore for LockCheckingStore {
        fn get_password(&self, key: &str) -> Result<Option<String>> {
            self.assert_locked();
            self.inner.get_password(key)
        }

        fn set_password(&self, key: &str, value: &str) -> Result<()> {
            self.assert_locked();
            self.inner.set_password(key, value)
        }

        fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.assert_locked();
            self.inner.get_secret(key)
        }

        fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
            self.assert_locked();
            self.inner.set_secret(key, value)
        }

        fn delete(&self, key: &str) -> Result<bool> {
            self.assert_locked();
            self.inner.delete(key)
        }

        fn lock(&self) -> Result<Option<CredentialLock>> {
            CredentialLock::acquire(&self.path, Duration::from_secs(1)).map(Some)
        }
    }

    #[test]
    fn every_storage_operation_runs_while_the_lock_is_held() {
        let directory = tempfile::tempdir().unwrap();
        let store = LockCheckingStore {
            inner: MemoryStore::default(),
            path: directory.path().join(LOCK_FILE),
        };
        let value = "x".repeat(10);
        // A chunk size of four splits the value across slots, as on Windows.
        {
            let _lock = store.lock().unwrap();
            store_value_with_chunk_size(&store, "account", &value, Some(4)).unwrap();
            store_value_with_chunk_size(&store, "account", &value, Some(4)).unwrap();
        }
        // The header still names chunks, so this read assembles them, on
        // every platform.
        assert_eq!(get_value(&store, "account").unwrap(), value);
        {
            let _lock = store.lock().unwrap();
            delete_all_chunks(&store, "account").unwrap();
        }
        store_value(&store, "account", &value).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), value);
        delete_value(&store, "account").unwrap();
        assert!(store.inner.keys().is_empty(), "{:?}", store.inner.keys());
        // Outside every operation the lock is free again.
        assert!(!is_busy(&store.path));
    }

    #[test]
    fn chunked_storage_locks_and_single_items_do_not() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join(LOCK_FILE);
        let unlocked = lock_when_chunked(None, || panic!("no lock path is needed"), LOCK_POLL);
        assert!(unlocked.unwrap().is_none());

        let lock = lock_when_chunked(Some(2560), || Ok(path.clone()), LOCK_POLL).unwrap();
        assert!(lock.is_some());
        assert!(is_busy(&path));
        drop(lock);
        assert!(!is_busy(&path));
    }

    #[test]
    fn a_held_lock_excludes_every_other_holder_until_dropped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        let holder = CredentialLock::acquire(&path, Duration::ZERO).unwrap();
        let error = CredentialLock::acquire(&path, Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.metadata(), ("CredentialLockBusy", 0));
        drop(holder);
        CredentialLock::acquire(&path, Duration::ZERO).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn lock_folders_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let directory = tempfile::tempdir().unwrap();
        // A first run: neither the app folder nor the lock folder exists.
        let app = directory.path().join("purview");
        let path = app.join("account-locks").join("key.lock");
        drop(CredentialLock::acquire(&path, Duration::ZERO).unwrap());
        assert_eq!(mode(&app), 0o700);
        assert_eq!(mode(&app.join("account-locks")), 0o700);
        assert_eq!(mode(&path), 0o600);
        // An existing folder keeps its mode; only new paths are created private.
        std::fs::set_permissions(
            app.join("account-locks"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        drop(CredentialLock::acquire(&path, Duration::ZERO).unwrap());
        assert_eq!(mode(&app.join("account-locks")), 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_lock_folder_is_refused_and_its_target_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let shared = directory.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        let app = directory.path().join("purview");
        std::fs::create_dir(&app).unwrap();
        std::os::unix::fs::symlink(&shared, app.join("account-locks")).unwrap();
        let path = app.join("account-locks").join("key.lock");
        let error = CredentialLock::acquire(&path, Duration::ZERO).unwrap_err();
        assert_eq!(error.metadata().0, "CredentialLockFailed");
        let target = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        assert_eq!(target, 0o755);
        assert!(!shared.join("key.lock").exists());
    }

    #[test]
    fn a_waiting_process_gets_the_lock_once_the_holder_drops_it() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(LOCK_FILE);
        let holder = CredentialLock::acquire(&path, Duration::ZERO).unwrap();
        let waiting_path = path.clone();
        let waiter = std::thread::spawn(move || {
            CredentialLock::acquire(&waiting_path, Duration::from_secs(30))
                .map(|_lock| Instant::now())
        });
        std::thread::sleep(Duration::from_millis(100));
        let released_at = Instant::now();
        drop(holder);
        // However the threads were scheduled, the waiter can only have got
        // the lock after the holder let it go.
        let acquired_at = waiter.join().unwrap().unwrap();
        assert!(acquired_at >= released_at);
    }

    #[test]
    fn deleting_removes_the_header_before_its_chunks() {
        struct HeaderFirst(MemoryStore, std::sync::atomic::AtomicBool);
        impl CredentialStore for HeaderFirst {
            fn get_password(&self, key: &str) -> Result<Option<String>> {
                self.0.get_password(key)
            }
            fn set_password(&self, key: &str, value: &str) -> Result<()> {
                self.0.set_password(key, value)
            }
            fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
                self.0.get_secret(key)
            }
            fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
                self.0.set_secret(key, value)
            }
            fn delete(&self, key: &str) -> Result<bool> {
                let deleting = self.1.load(std::sync::atomic::Ordering::SeqCst);
                if deleting && key != "account" {
                    assert!(
                        self.0.get_password("account").unwrap().is_none(),
                        "chunk {key} deleted while the header still pointed at it"
                    );
                }
                self.0.delete(key)
            }
        }
        let store = HeaderFirst(MemoryStore::default(), Default::default());
        store_value_with_chunk_size(&store, "account", "0123456789", Some(4)).unwrap();
        // A header and three chunks: the layout Windows writes.
        assert_eq!(store.0.keys().len(), 4, "{:?}", store.0.keys());
        store.1.store(true, std::sync::atomic::Ordering::SeqCst);
        delete_value_with_chunk_size(&store, "account", Some(4)).unwrap();
        // Every chunk went, so the order check above ran for each of them.
        assert!(store.0.keys().is_empty(), "{:?}", store.0.keys());
    }

    #[test]
    fn legacy_single_entry_remains_readable() {
        let store = MemoryStore::default();
        store.set_password("account", "legacy-json").unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "legacy-json");
    }

    #[test]
    fn chunked_round_trip_uses_raw_bytes() {
        let store = MemoryStore::default();
        let value = "Ünïcödé ✓ 日本語".repeat(20);
        store_value_with_chunk_size(&store, "account", &value, Some(7)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), value);
        assert!(store.keys().len() > 2);
    }

    #[test]
    fn shrinking_a_value_removes_stale_chunks() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(500), Some(32)).unwrap();
        let before = store.keys().len();
        store_value_with_chunk_size(&store, "account", "short", Some(32)).unwrap();
        assert!(store.keys().len() < before);
        assert_eq!(get_value(&store, "account").unwrap(), "short");
    }

    #[test]
    fn incomplete_chunk_set_has_actionable_error() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(200), Some(32)).unwrap();
        store.remove("account:1");
        let error = get_value(&store, "account").unwrap_err().to_string();
        assert!(error.contains("incomplete"));
        assert!(error.contains("purview auth login"));
    }

    #[test]
    fn deletion_sweeps_recorded_chunks_despite_gaps_and_trailing_entries() {
        let store = MemoryStore::default();
        store.set_password("account", r#"{"chunks":3}"#).unwrap();
        for index in [0, 1, 3, 4, 5] {
            store
                .set_secret(&chunk_key("account", 0, index), b"x")
                .unwrap();
        }
        delete_chunks(&store, "account", 0, 0).unwrap();
        assert_eq!(store.keys(), vec!["account"]);
    }

    // An interrupted cleanup can delete the first chunks of a slot and leave
    // later ones. Neither a rewrite nor logout may stop at that gap.
    #[test]
    fn stale_chunks_behind_a_gap_are_removed_by_writes_and_logout() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", "live", Some(32)).unwrap();
        store_value_with_chunk_size(&store, "account", "live", Some(32)).unwrap();
        store.set_secret("account:2", b"stale").unwrap();
        store.set_secret("account:3", b"stale").unwrap();

        store_value_with_chunk_size(&store, "account", "next", Some(32)).unwrap();
        assert_eq!(store.keys(), vec!["account", "account:0"]);

        store.set_secret("account:s1:5", b"stale").unwrap();
        delete_all_chunks(&store, "account").unwrap();
        store.delete("account").unwrap();
        assert!(store.keys().is_empty());
    }

    #[test]
    fn rewrites_alternate_slots_and_leave_no_old_chunks() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store_value_with_chunk_size(&store, "account", &"b".repeat(40), Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "b".repeat(40));
        assert_eq!(
            store.keys(),
            vec!["account", "account:s1:0", "account:s1:1"]
        );
        store_value_with_chunk_size(&store, "account", "c", Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "c");
        assert_eq!(store.keys(), vec!["account", "account:0"]);
    }

    #[test]
    fn a_header_from_before_slots_existed_is_read_and_replaced() {
        let store = MemoryStore::default();
        store.set_password("account", r#"{"chunks":2}"#).unwrap();
        store.set_secret("account:0", b"ab").unwrap();
        store.set_secret("account:1", b"cd").unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "abcd");
        store_value_with_chunk_size(&store, "account", "new", Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "new");
        assert_eq!(store.keys(), vec!["account", "account:s1:0"]);
    }

    /// Fails every chunk write after the first `allowed`, and every header
    /// write while `fail_header` is set.
    struct FailingStore {
        inner: MemoryStore,
        allowed: std::sync::atomic::AtomicUsize,
        fail_header: std::sync::atomic::AtomicBool,
    }

    impl FailingStore {
        fn new() -> Self {
            Self {
                inner: MemoryStore::default(),
                allowed: std::sync::atomic::AtomicUsize::new(usize::MAX),
                fail_header: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl CredentialStore for FailingStore {
        fn get_password(&self, key: &str) -> Result<Option<String>> {
            self.inner.get_password(key)
        }
        fn set_password(&self, key: &str, value: &str) -> Result<()> {
            if self.fail_header.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(PurviewError::message("simulated header write failure"));
            }
            self.inner.set_password(key, value)
        }
        fn get_secret(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get_secret(key)
        }
        fn set_secret(&self, key: &str, value: &[u8]) -> Result<()> {
            use std::sync::atomic::Ordering;
            let remaining = self.allowed.load(Ordering::SeqCst);
            if remaining == 0 {
                return Err(PurviewError::message("simulated credential store failure"));
            }
            self.allowed.store(remaining - 1, Ordering::SeqCst);
            self.inner.set_secret(key, value)
        }
        fn delete(&self, key: &str) -> Result<bool> {
            self.inner.delete(key)
        }
    }

    #[test]
    fn a_failed_rewrite_leaves_the_previous_credential_readable() {
        let store = FailingStore::new();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store.allowed.store(2, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store_value_with_chunk_size(&store, "account", &"b".repeat(100), Some(32)).is_err()
        );
        assert_eq!(get_value(&store, "account").unwrap(), "a".repeat(100));

        store
            .allowed
            .store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
        store_value_with_chunk_size(&store, "account", "b", Some(32)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "b");
        assert!(!store
            .inner
            .keys()
            .iter()
            .any(|key| key.starts_with("account:0")));
    }

    #[test]
    fn a_failed_header_write_leaves_a_slot_one_credential_readable() {
        let store = FailingStore::new();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store_value_with_chunk_size(&store, "account", &"b".repeat(100), Some(32)).unwrap();
        assert!(store.inner.keys().iter().any(|key| key.contains(":s1:")));

        store
            .fail_header
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store_value_with_chunk_size(&store, "account", &"c".repeat(100), Some(32)).is_err()
        );
        assert_eq!(get_value(&store, "account").unwrap(), "b".repeat(100));
    }

    #[test]
    fn logout_removes_chunks_in_both_slots() {
        let store = MemoryStore::default();
        store_value_with_chunk_size(&store, "account", &"a".repeat(100), Some(32)).unwrap();
        store.set_secret("account:s1:0", b"stale").unwrap();
        delete_all_chunks(&store, "account").unwrap();
        store.delete("account").unwrap();
        assert!(store.keys().is_empty());
    }

    #[test]
    fn invalid_chunk_headers_are_bounded() {
        let store = MemoryStore::default();
        store
            .set_password("account", r#"{"chunks":999999}"#)
            .unwrap();
        assert!(get_value(&store, "account")
            .unwrap_err()
            .to_string()
            .contains("invalid chunk count"));
    }

    #[test]
    fn a_new_write_heals_an_invalid_header() {
        let store = MemoryStore::default();
        store
            .set_password("account", r#"{"chunks":999999}"#)
            .unwrap();
        store_value_with_chunk_size(&store, "account", "replacement", Some(4)).unwrap();
        assert_eq!(get_value(&store, "account").unwrap(), "replacement");
    }
}
