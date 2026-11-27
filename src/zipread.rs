//! Reading report and estimate zips (`docs/SPEC.md` section 4.8).
//!
//! Entries are never extracted to disk. Each is read through a counting
//! reader that enforces the limits on the bytes actually decompressed,
//! not on the sizes the zip's headers claim: bytes per entry, bytes over
//! the whole zip, and the ratio of decompressed to compressed bytes. Every
//! entry name must pass `enclosed_name()`, and the number of entries is
//! capped, before any entry is read.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::rc::Rc;

use serde_json::Value;

use crate::error::{PurviewError, Result};

/// The default entry cap of a report or estimate zip.
pub const REPORT_ZIP_ENTRIES: usize = 1_000;
/// Decompressed bytes one entry of a report zip may have: 4 GiB.
pub const REPORT_ENTRY_BYTES: u64 = 4 << 30;
/// Decompressed bytes a whole report zip may have: 64 GiB.
pub const REPORT_TOTAL_BYTES: u64 = 64 << 30;
/// The highest ratio of decompressed to compressed bytes in an entry.
pub const MAX_RATIO: u64 = 1_000;
/// The ratio is checked only once an entry has given this many bytes, so
/// that a small, very repetitive file is not refused.
pub const RATIO_FLOOR: u64 = 1 << 20;

/// The limits a zip is read under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZipLimits {
    pub entries: usize,
    pub entry_bytes: u64,
    pub total_bytes: u64,
    pub ratio: u64,
}

impl ZipLimits {
    /// The limits of a report or estimate zip, with `limits.report_zip_entries`
    /// from `config.json` when it is set.
    pub fn report(extra: &BTreeMap<String, Value>) -> Result<Self> {
        let mut limits = Self {
            entries: REPORT_ZIP_ENTRIES,
            entry_bytes: REPORT_ENTRY_BYTES,
            total_bytes: REPORT_TOTAL_BYTES,
            ratio: MAX_RATIO,
        };
        if let Some(value) = config_limit(extra, "report_zip_entries")? {
            limits.entries = value
                .as_u64()
                .filter(|count| *count > 0)
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| {
                    PurviewError::message(
                        "config.json: limits.report_zip_entries must be a positive whole number",
                    )
                })?;
        }
        Ok(limits)
    }
}

/// `limits.<key>` in `config.json`: `None` when the object or the key is
/// missing or `null`.
pub fn config_limit<'a>(
    extra: &'a BTreeMap<String, Value>,
    key: &str,
) -> Result<Option<&'a Value>> {
    match extra.get("limits") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(limits)) => Ok(limits.get(key).filter(|value| !value.is_null())),
        Some(_) => Err(PurviewError::message(
            "config.json: limits must be an object",
        )),
    }
}

/// An open zip whose entry names have been checked.
pub struct ZipReader {
    archive: zip::ZipArchive<File>,
    names: Vec<String>,
    limits: ZipLimits,
    total: Rc<Cell<u64>>,
}

impl ZipReader {
    /// Opens `path`. A zip with more entries than allowed, or with an
    /// entry name that would leave its folder, is `HostileZip`.
    pub fn open(path: &Path, limits: ZipLimits) -> Result<Self> {
        let file = File::open(path)?;
        let mut archive = zip::ZipArchive::new(file).map_err(|_| {
            PurviewError::HostileZip("the file is not a zip archive that can be read".into())
        })?;
        if archive.len() > limits.entries {
            return Err(PurviewError::HostileZip(format!(
                "the zip has {} entries, more than the {} allowed",
                archive.len(),
                limits.entries
            )));
        }
        let mut names = Vec::with_capacity(archive.len());
        for index in 0..archive.len() {
            let entry = archive.by_index_raw(index).map_err(|_| {
                PurviewError::HostileZip(format!("entry {} of the zip cannot be read", index + 1))
            })?;
            if entry.enclosed_name().is_none() {
                // The name is not repeated: it is the zip's own text.
                return Err(PurviewError::HostileZip(format!(
                    "entry {} of the zip has a name that would leave its folder",
                    index + 1
                )));
            }
            let name = entry.name().map_err(|_| {
                PurviewError::HostileZip(format!(
                    "entry {} of the zip has a name that cannot be read",
                    index + 1
                ))
            })?;
            names.push(name.into_owned());
        }
        Ok(Self {
            archive,
            names,
            limits,
            total: Rc::new(Cell::new(0)),
        })
    }

    /// The entry names, in the zip's order.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The first entry whose file name (after the last `/`) starts with
    /// `prefix` and ends with `.csv`, ignoring the case of `.csv`.
    pub fn find(&self, prefix: &str) -> Option<usize> {
        self.names.iter().position(|name| {
            let base = name.rsplit('/').next().unwrap_or(name);
            base.starts_with(prefix)
                && base.len() >= prefix.len() + 4
                && base[base.len() - 4..].eq_ignore_ascii_case(".csv")
        })
    }

    /// Reads entry `index` to its end through the limits, giving the
    /// reader to `read`.
    pub fn read_entry<T>(
        &mut self,
        index: usize,
        read: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<T> {
        let limits = self.limits;
        let total = self.total.clone();
        let entry = self.archive.by_index(index).map_err(|_| {
            PurviewError::HostileZip(format!("entry {} of the zip cannot be read", index + 1))
        })?;
        let compressed = entry.compressed_size();
        let mut counted = Counted {
            inner: entry,
            read: 0,
            compressed,
            limits,
            total,
        };
        read(&mut counted)
    }
}

/// A reader that counts the bytes it gives and fails past the limits.
struct Counted<R> {
    inner: R,
    read: u64,
    compressed: u64,
    limits: ZipLimits,
    total: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        let count_u64 = count as u64;
        self.read += count_u64;
        self.total.set(self.total.get() + count_u64);
        let refuse = |what: String| io::Error::other(ZipLimitExceeded(what));
        if self.read > self.limits.entry_bytes {
            return Err(refuse(format!(
                "an entry decompresses to more than {} bytes",
                self.limits.entry_bytes
            )));
        }
        if self.total.get() > self.limits.total_bytes {
            return Err(refuse(format!(
                "the zip decompresses to more than {} bytes",
                self.limits.total_bytes
            )));
        }
        if self.read > RATIO_FLOOR
            && self.read > self.compressed.max(1).saturating_mul(self.limits.ratio)
        {
            return Err(refuse(format!(
                "an entry decompresses to more than {} times its compressed size",
                self.limits.ratio
            )));
        }
        Ok(count)
    }
}

/// The reason a counted read stopped, carried through `io::Error`.
#[derive(Debug)]
pub struct ZipLimitExceeded(pub String);

impl std::fmt::Display for ZipLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ZipLimitExceeded {}

/// An I/O error from a counted read, as `HostileZip` when a limit stopped
/// it.
pub fn read_error(error: io::Error) -> PurviewError {
    match error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<ZipLimitExceeded>())
    {
        Some(limit) => PurviewError::HostileZip(limit.0.clone()),
        None => PurviewError::Io(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_with(
        entries: &[(&str, &[u8])],
        method: zip::CompressionMethod,
    ) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        let options = zip::write::SimpleFileOptions::default().compression_method(method);
        for (name, body) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(body).unwrap();
        }
        writer.finish().unwrap();
        file
    }

    fn limits() -> ZipLimits {
        ZipLimits::report(&BTreeMap::new()).unwrap()
    }

    #[test]
    fn entries_are_found_by_prefix_and_read() {
        let file = zip_with(
            &[
                ("Locations-2026-11-25_16-55-23.csv", b"a"),
                ("Summary-2026-11-25_16-55-23.CSV", b"b"),
            ],
            zip::CompressionMethod::Deflated,
        );
        let mut zip = ZipReader::open(file.path(), limits()).unwrap();
        assert_eq!(zip.find("Locations-"), Some(0));
        assert_eq!(zip.find("Summary-"), Some(1));
        assert_eq!(zip.find("Statistics-"), None);
        let text = zip
            .read_entry(1, |reader| {
                let mut text = String::new();
                reader.read_to_string(&mut text).map_err(read_error)?;
                Ok(text)
            })
            .unwrap();
        assert_eq!(text, "b");
    }

    #[test]
    fn a_name_that_leaves_its_folder_is_hostile() {
        let file = zip_with(&[("../evil.csv", b"a")], zip::CompressionMethod::Stored);
        let error = ZipReader::open(file.path(), limits()).err().unwrap();
        assert_eq!(error.metadata().0, "HostileZip");
        assert!(!error.to_string().contains("evil"), "{error}");
    }

    #[test]
    fn too_many_entries_are_hostile() {
        let names: Vec<String> = (0..4).map(|index| format!("f{index}.csv")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|name| (name.as_str(), &b"x"[..]))
            .collect();
        let file = zip_with(&entries, zip::CompressionMethod::Stored);
        let mut small = limits();
        small.entries = 3;
        assert_eq!(
            ZipReader::open(file.path(), small)
                .err()
                .unwrap()
                .metadata()
                .0,
            "HostileZip"
        );
        small.entries = 4;
        assert!(ZipReader::open(file.path(), small).is_ok());
    }

    #[test]
    fn the_limits_count_bytes_actually_read() {
        let body = vec![b'a'; 3 << 20];
        let file = zip_with(
            &[("Locations-x.csv", &body)],
            zip::CompressionMethod::Deflated,
        );
        // The ratio: 3 MiB of one byte compresses far beyond 1,000:1.
        let mut zip = ZipReader::open(file.path(), limits()).unwrap();
        let error = zip
            .read_entry(0, |reader| {
                std::io::copy(reader, &mut std::io::sink()).map_err(read_error)?;
                Ok(())
            })
            .err()
            .unwrap();
        assert_eq!(error.metadata().0, "HostileZip", "{error}");
        // The bytes per entry and in total, on a stored entry.
        for (entry_bytes, total_bytes) in [(1 << 20, u64::MAX), (u64::MAX, 1 << 20)] {
            let file = zip_with(
                &[("Locations-x.csv", &body)],
                zip::CompressionMethod::Stored,
            );
            let mut capped = limits();
            capped.entry_bytes = entry_bytes;
            capped.total_bytes = total_bytes;
            let mut zip = ZipReader::open(file.path(), capped).unwrap();
            let error = zip
                .read_entry(0, |reader| {
                    std::io::copy(reader, &mut std::io::sink()).map_err(read_error)?;
                    Ok(())
                })
                .err()
                .unwrap();
            assert_eq!(error.metadata().0, "HostileZip", "{error}");
        }
    }

    #[test]
    fn the_entry_cap_comes_from_config() {
        let extra: BTreeMap<String, Value> = [(
            "limits".to_owned(),
            serde_json::json!({"report_zip_entries": 5}),
        )]
        .into();
        assert_eq!(ZipLimits::report(&extra).unwrap().entries, 5);
        let bad: BTreeMap<String, Value> = [(
            "limits".to_owned(),
            serde_json::json!({"report_zip_entries": 0}),
        )]
        .into();
        assert!(ZipLimits::report(&bad).is_err());
    }
}
