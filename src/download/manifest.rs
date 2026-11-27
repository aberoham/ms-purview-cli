//! `manifest.json`: one entry per file downloaded into a directory
//! (`docs/SPEC.md` section 4.7, step 9).
//!
//! The manifest is written atomically (a temporary file and a rename) and
//! is never followed through a link. It keeps the server's original file
//! name, which `export index` matches item zips by. Keys this release does
//! not read are kept.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{PurviewError, Result};
use crate::output::sanitize;
use crate::redact::Redactor;

pub const MANIFEST_FILE: &str = "manifest.json";

/// The manifest format this release writes.
pub const MANIFEST_VERSION: u64 = 1;

/// The largest manifest read.
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub version: u64,
    #[serde(default)]
    pub files: Vec<Entry>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: MANIFEST_VERSION,
            files: Vec::new(),
            extra: BTreeMap::new(),
        }
    }
}

/// One downloaded file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub case_id: String,
    pub operation_id: String,
    /// `estimate`, `report`, `export`, or Graph's own action name.
    pub action: String,
    /// The name the service gave the file.
    pub server_file_name: String,
    /// The name in this directory.
    pub file_name: String,
    pub size: u64,
    /// Lowercase hexadecimal.
    pub sha256: String,
    /// RFC 3339, UTC.
    pub downloaded_at: String,
    /// The file was found in the directory with no entry, verified and
    /// recorded, rather than downloaded by the run that recorded it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recovered: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Manifest {
    pub fn path(dir: &Path) -> PathBuf {
        dir.join(MANIFEST_FILE)
    }

    /// The manifest in `dir`; a missing one is empty. A link, a file that
    /// is not a regular file, one too large, or one that does not parse is
    /// refused, so that it is never replaced by a manifest that forgets its
    /// entries.
    pub fn load(dir: &Path) -> Result<Self> {
        let path = Self::path(dir);
        let refused = |reason: &str| {
            PurviewError::message(format!(
                "{} {reason}; move it aside to start a new manifest",
                shown(&path)
            ))
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => return Err(error.into()),
        };
        // Read without following links, so a link is not a file either.
        if !metadata.is_file() || crate::config::is_link_like(&metadata) {
            return Err(refused("is a link or not a regular file"));
        }
        let mut contents = Vec::new();
        fs::File::open(&path)?
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut contents)?;
        if contents.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(refused("is larger than 16 MiB"));
        }
        let manifest: Self =
            serde_json::from_slice(&contents).map_err(|_| refused("is not a manifest"))?;
        if manifest.version != MANIFEST_VERSION {
            return Err(refused(&format!(
                "has version {}, which this release does not read",
                manifest.version
            )));
        }
        Ok(manifest)
    }

    /// Writes the manifest into `dir` atomically. A value the Redactor
    /// recognises is refused before anything is written.
    pub fn save(&self, dir: &Path, redactor: &Redactor) -> Result<()> {
        let value = serde_json::to_value(self)?;
        let data = serde_json::to_vec_pretty(&value)?;
        if redactor.recognises_value(&value) || redactor.recognises_bytes(&data) {
            return Err(PurviewError::message(
                "refusing to write manifest.json: a value in it looks like a secret",
            ));
        }
        crate::config::atomic_write(&Self::path(dir), &data)
    }

    /// The entry for a local file name.
    pub fn entry(&self, file_name: &str) -> Option<&Entry> {
        self.files.iter().find(|entry| entry.file_name == file_name)
    }

    /// Adds `entry`, replacing any entry for the same local file name.
    pub fn record(&mut self, entry: Entry) {
        self.files
            .retain(|existing| existing.file_name != entry.file_name);
        self.files.push(entry);
    }
}

fn shown(path: &Path) -> String {
    sanitize(&path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, sha: &str) -> Entry {
        Entry {
            case_id: "00000000-0000-4000-8000-000000000031".into(),
            operation_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001".into(),
            action: "estimate".into(),
            server_file_name: name.into(),
            file_name: name.into(),
            size: 3,
            sha256: sha.into(),
            downloaded_at: "2026-01-05T09:00:00Z".into(),
            recovered: false,
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn a_missing_manifest_is_empty_and_a_saved_one_reads_back_with_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Manifest::load(dir.path()).unwrap(), Manifest::default());
        let mut manifest = Manifest::default();
        manifest.extra.insert("later".into(), Value::from("kept"));
        manifest.record(entry("a.zip", "00"));
        manifest.record(entry("a.zip", "11"));
        manifest.save(dir.path(), &Redactor::new()).unwrap();
        let read = Manifest::load(dir.path()).unwrap();
        assert_eq!(read, manifest);
        assert_eq!(read.files.len(), 1);
        assert_eq!(read.entry("a.zip").unwrap().sha256, "11");
    }

    #[test]
    fn an_unreadable_manifest_is_refused_rather_than_replaced() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(Manifest::path(dir.path()), b"not json").unwrap();
        assert!(Manifest::load(dir.path()).is_err());
        fs::write(
            Manifest::path(dir.path()),
            br#"{"version": 2, "files": []}"#,
        )
        .unwrap();
        assert!(Manifest::load(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_linked_manifest_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("elsewhere.json");
        fs::write(&other, br#"{"version": 1, "files": []}"#).unwrap();
        std::os::unix::fs::symlink(&other, Manifest::path(dir.path())).unwrap();
        assert!(Manifest::load(dir.path()).is_err());
    }

    #[test]
    fn a_secret_is_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let redactor = Redactor::new();
        redactor.register("canary-manifest-0001");
        let mut manifest = Manifest::default();
        manifest.record(entry("canary-manifest-0001.zip", "00"));
        assert!(manifest.save(dir.path(), &redactor).is_err());
        assert!(!Manifest::path(dir.path()).exists());
    }
}
