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

/// The entry cap of an export's items zip (`docs/SPEC.md` section 4.8),
/// and so of any download.
pub const EXPORT_ZIP_ENTRIES: u64 = 1_000_000;
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
/// Bytes a zip may carry after its end record and comment. An export's
/// items part had 296 such bytes, most of them zero (Observed, one
/// export); the zip is read as ending at its end record, and the bytes
/// after it are never read.
pub const MAX_TRAILING_BYTES: usize = 4096;

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
    archive: zip::ZipArchive<Bounded>,
    names: Vec<String>,
    limits: ZipLimits,
    total: Rc<Cell<u64>>,
    /// The zip's size on disk: no entry's compressed bytes can exceed it,
    /// whatever its header says.
    file_len: u64,
}

impl ZipReader {
    /// Opens `path`. A zip with more entries than allowed, or with an
    /// entry name that would leave its folder, is `HostileZip`.
    pub fn open(path: &Path, limits: ZipLimits) -> Result<Self> {
        let mut file = File::open(path)?;
        let file_len = file.metadata()?.len();
        // The count the central directory declares, read before the zip
        // crate indexes it, so that a huge directory is refused unread.
        let (declared, end) = zip_end(&mut file, file_len)?;
        let file_len = end;
        if declared > limits.entries as u64 {
            return Err(PurviewError::HostileZip(format!(
                "the zip has {declared} entries, more than the {} allowed",
                limits.entries
            )));
        }
        let mut archive = zip::ZipArchive::new(Bounded::new(file, end)).map_err(|_| {
            PurviewError::HostileZip("the file is not a zip archive that can be read".into())
        })?;
        // The index keeps one entry per name, so fewer entries than
        // declared means a name is listed twice.
        if archive.len() as u64 != declared || archive.len() > limits.entries {
            return Err(PurviewError::HostileZip(
                "the zip's central directory does not match its entries: a name may be listed \
                 twice"
                    .into(),
            ));
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
            file_len,
        })
    }

    /// The entry names, in the zip's order.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// The first entry whose file name (after the last `/`) starts with
    /// `prefix` and ends with `.csv`, ignoring the case of `.csv`.
    pub fn find(&self, prefix: &str) -> Option<usize> {
        self.find_all(prefix).first().copied()
    }

    /// Every entry `find` would match, in the zip's order.
    pub fn find_all(&self, prefix: &str) -> Vec<usize> {
        (0..self.names.len())
            .filter(|index| {
                let name = &self.names[*index];
                let base = name.rsplit('/').next().unwrap_or(name);
                let bytes = base.as_bytes();
                base.starts_with(prefix)
                    && bytes.len() >= prefix.len() + 4
                    && bytes[bytes.len() - 4..].eq_ignore_ascii_case(b".csv")
            })
            .collect()
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
        let compressed = entry.compressed_size().min(self.file_len);
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

/// The number of entries the zip declares; see `zip_end`.
#[cfg(test)]
pub(crate) fn declared_entries(file: &mut File, len: u64) -> Result<u64> {
    zip_end(file, len).map(|(declared, _)| declared)
}

/// The number of entries the zip's end of central directory record
/// declares, or its ZIP64 record when one is there, and the offset where
/// the zip ends. The zip ends after the comment that ends last among the
/// end records whose comments end at the end of the file or at most
/// `MAX_TRAILING_BYTES` before it. Every record that ends exactly there
/// counts, as when a comment holds something that also looks like one, and
/// the largest count is the answer, so none can hide a large directory. A
/// ZIP64 end record must lie before its locator, never in the bytes after
/// the zip. A file with no such record is not a zip.
pub(crate) fn zip_end(file: &mut File, len: u64) -> Result<(u64, u64)> {
    use std::io::{Seek, SeekFrom};
    let not_zip =
        || PurviewError::HostileZip("the file is not a zip archive that can be read".into());
    let read_at = |file: &mut File, at: u64, buffer: &mut [u8]| -> Result<()> {
        file.seek(SeekFrom::Start(at)).map_err(|_| not_zip())?;
        file.read_exact(buffer).map_err(|_| not_zip())
    };
    // The record is 22 bytes, followed by a comment of at most 65,535 and
    // then at most MAX_TRAILING_BYTES.
    let tail_len = len.min((22 + 65_535 + MAX_TRAILING_BYTES) as u64);
    let tail_start = len - tail_len;
    let mut tail = vec![0_u8; tail_len as usize];
    read_at(file, tail_start, &mut tail)?;
    let record_end =
        |at: usize| at + 22 + usize::from(u16::from_le_bytes([tail[at + 20], tail[at + 21]]));
    // Every record whose comment ends at the end of the file, or at most
    // MAX_TRAILING_BYTES before it, counts, and the largest count is the
    // answer: no record, padded or not, can hide a larger directory.
    let fitting: Vec<usize> = (0..tail.len().saturating_sub(21))
        .filter(|at| tail[*at..].starts_with(b"PK\x05\x06"))
        .filter(|at| {
            let ends = record_end(*at);
            ends <= tail.len() && tail.len() - ends <= MAX_TRAILING_BYTES
        })
        .collect();
    // The zip ends after the comment that ends last: at the end of the
    // file when a record reaches it. Only the records that end exactly
    // there count, so an end record of a zip stored inside this one, which
    // ends before this zip's own directory, is not taken for this zip's.
    let Some(end) = fitting.iter().map(|at| record_end(*at)).max() else {
        return Err(not_zip());
    };
    let records: Vec<usize> = fitting
        .into_iter()
        .filter(|at| record_end(*at) == end)
        .collect();
    let end = tail_start + end as u64;
    let mut declared = 0;
    for at in records {
        let classic = u64::from(u16::from_le_bytes([tail[at + 10], tail[at + 11]]));
        // A ZIP64 locator, when there is one, is the 20 bytes before the
        // end record and names the ZIP64 end record.
        let zip64 = match (tail_start + at as u64).checked_sub(20) {
            None => None,
            Some(locator_at) => {
                let mut locator = [0_u8; 20];
                read_at(file, locator_at, &mut locator)?;
                if locator.starts_with(b"PK\x06\x07") {
                    let record_at =
                        u64::from_le_bytes(locator[8..16].try_into().map_err(|_| not_zip())?);
                    // The ZIP64 end record is at least 56 bytes and comes
                    // before its locator, never in the bytes after the zip.
                    if record_at
                        .checked_add(56)
                        .is_none_or(|ends| ends > locator_at)
                    {
                        return Err(not_zip());
                    }
                    let mut record = [0_u8; 40];
                    read_at(file, record_at, &mut record)?;
                    if !record.starts_with(b"PK\x06\x06") {
                        return Err(not_zip());
                    }
                    Some(u64::from_le_bytes(
                        record[32..40].try_into().map_err(|_| not_zip())?,
                    ))
                } else {
                    None
                }
            }
        };
        // 0xFFFF in the classic field says "see ZIP64"; otherwise the two
        // counts must both be honoured.
        let count = match zip64 {
            Some(total) if classic == 0xFFFF => total,
            Some(total) => classic.max(total),
            None => classic,
        };
        declared = declared.max(count);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| not_zip())?;
    Ok((declared, end))
}

/// A file read as if it ended at `end`: the zip crate never sees the
/// bytes after a zip's end record.
pub(crate) struct Bounded {
    inner: File,
    end: u64,
}

impl Bounded {
    pub(crate) fn new(inner: File, end: u64) -> Self {
        Self { inner, end }
    }
}

impl Read for Bounded {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        use std::io::Seek;
        let at = self.inner.stream_position()?;
        let left = self.end.saturating_sub(at);
        let most = buffer
            .len()
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        if most == 0 {
            return Ok(0);
        }
        self.inner.read(&mut buffer[..most])
    }
}

impl io::Seek for Bounded {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        let position = match position {
            io::SeekFrom::End(offset) => {
                let target = i128::from(self.end) + i128::from(offset);
                let target = u64::try_from(target).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "seek before the start")
                })?;
                io::SeekFrom::Start(target)
            }
            other => other,
        };
        self.inner.seek(position)
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
    fn a_name_ending_inside_a_multibyte_character_is_not_a_match() {
        // The last four bytes start inside the euro sign.
        let file = zip_with(&[("Locations-€é", b"a")], zip::CompressionMethod::Stored);
        let zip = ZipReader::open(file.path(), limits()).unwrap();
        assert_eq!(zip.find("Locations-"), None);
    }

    #[test]
    fn a_name_listed_twice_is_hostile() {
        let file = zip_with(
            &[("Locations-a.csv", b"1"), ("Locations-b.csv", b"2")],
            zip::CompressionMethod::Stored,
        );
        // Rename the second entry to the first's name, in both its local
        // header and the central directory: same length, so offsets hold.
        let mut bytes = std::fs::read(file.path()).unwrap();
        let from = b"Locations-b.csv";
        let mut at = 0;
        while let Some(found) = bytes[at..]
            .windows(from.len())
            .position(|window| window == from)
        {
            bytes[at + found..at + found + from.len()].copy_from_slice(b"Locations-a.csv");
            at += found + from.len();
        }
        std::fs::write(file.path(), &bytes).unwrap();
        let error = ZipReader::open(file.path(), limits()).err().unwrap();
        assert_eq!(error.metadata().0, "HostileZip", "{error}");
    }

    #[test]
    fn an_end_record_inside_a_comment_cannot_lower_the_count() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("Locations-a.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"1").unwrap();
        // A forged end record declaring 1,000 entries, as the zip's
        // comment: the larger count is the one that counts.
        let mut forged = b"PK\x05\x06".to_vec();
        forged.extend_from_slice(&[0; 6]);
        forged.extend_from_slice(&1000_u16.to_le_bytes());
        forged.extend_from_slice(&[0; 10]);
        writer.set_raw_comment(forged.into_boxed_slice()).unwrap();
        writer.finish().unwrap();
        let mut handle = File::open(file.path()).unwrap();
        let len = handle.metadata().unwrap().len();
        assert_eq!(declared_entries(&mut handle, len).unwrap(), 1000);
        let mut small = limits();
        small.entries = 10;
        assert_eq!(
            ZipReader::open(file.path(), small)
                .err()
                .unwrap()
                .metadata()
                .0,
            "HostileZip"
        );
    }

    #[test]
    fn a_zip64_sentinel_is_resolved_to_the_zip64_count() {
        let file = zip_with(&[("Locations-a.csv", b"1")], zip::CompressionMethod::Stored);
        let bytes = std::fs::read(file.path()).unwrap();
        // Split off the classic end record and put a ZIP64 end record and
        // locator before it, with the classic counts set to the sentinel.
        let (body, end) = bytes.split_at(bytes.len() - 22);
        let mut end = end.to_vec();
        let cd_size = u32::from_le_bytes(end[12..16].try_into().unwrap()) as u64;
        let cd_offset = u32::from_le_bytes(end[16..20].try_into().unwrap()) as u64;
        end[8..10].copy_from_slice(&0xFFFF_u16.to_le_bytes());
        end[10..12].copy_from_slice(&0xFFFF_u16.to_le_bytes());
        let zip64_at = body.len() as u64;
        let mut out = body.to_vec();
        out.extend_from_slice(b"PK\x06\x06");
        out.extend_from_slice(&44_u64.to_le_bytes());
        out.extend_from_slice(&45_u16.to_le_bytes());
        out.extend_from_slice(&45_u16.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&1_u64.to_le_bytes());
        out.extend_from_slice(&1_u64.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(b"PK\x06\x07");
        out.extend_from_slice(&0_u32.to_le_bytes());
        out.extend_from_slice(&zip64_at.to_le_bytes());
        out.extend_from_slice(&1_u32.to_le_bytes());
        out.extend_from_slice(&end);
        std::fs::write(file.path(), &out).unwrap();
        let mut handle = File::open(file.path()).unwrap();
        let len = handle.metadata().unwrap().len();
        assert_eq!(declared_entries(&mut handle, len).unwrap(), 1);
    }

    /// `body` with `trailing` bytes after it: a few zeros, some others.
    fn with_trailing(path: &Path, trailing: usize) {
        let mut bytes = std::fs::read(path).unwrap();
        bytes.extend((0..trailing).map(|index| if index % 5 == 0 { b'x' } else { 0 }));
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn bytes_after_the_end_record_are_left_out_and_the_zip_is_read() {
        let file = zip_with(
            &[("Locations-a.csv", b"hello")],
            zip::CompressionMethod::Deflated,
        );
        let original = std::fs::metadata(file.path()).unwrap().len();
        with_trailing(file.path(), 296);
        let mut handle = File::open(file.path()).unwrap();
        let len = handle.metadata().unwrap().len();
        assert_eq!(zip_end(&mut handle, len).unwrap(), (1, original));
        let mut reader = ZipReader::open(file.path(), limits()).unwrap();
        let index = reader.find("Locations-").unwrap();
        let text = reader
            .read_entry(index, |entry| {
                let mut text = String::new();
                entry.read_to_string(&mut text)?;
                Ok(text)
            })
            .unwrap();
        assert_eq!(text, "hello");
        crate::download::check_zip(file.path()).unwrap();
    }

    #[test]
    fn more_bytes_after_the_end_record_than_allowed_is_not_a_zip() {
        let file = zip_with(&[("Locations-a.csv", b"1")], zip::CompressionMethod::Stored);
        with_trailing(file.path(), MAX_TRAILING_BYTES + 1);
        assert_eq!(
            ZipReader::open(file.path(), limits())
                .err()
                .unwrap()
                .metadata()
                .0,
            "HostileZip"
        );
        assert!(crate::download::check_zip(file.path()).is_err());
    }

    #[test]
    fn a_padded_forged_record_cannot_lower_the_count() {
        // The real record, earlier, declares 5 entries; a forged one in
        // its comment, ending at the same place, declares 1; one byte
        // follows. The larger count is the one that counts.
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        for index in 0..5 {
            writer
                .start_file(
                    format!("Locations-{index}.csv"),
                    zip::write::SimpleFileOptions::default(),
                )
                .unwrap();
            writer.write_all(b"1").unwrap();
        }
        let mut forged = b"PK\x05\x06".to_vec();
        forged.extend_from_slice(&[0; 6]);
        forged.extend_from_slice(&1_u16.to_le_bytes());
        forged.extend_from_slice(&[0; 10]);
        writer.set_raw_comment(forged.into_boxed_slice()).unwrap();
        writer.finish().unwrap();
        with_trailing(file.path(), 1);
        let mut handle = File::open(file.path()).unwrap();
        let len = handle.metadata().unwrap().len();
        assert_eq!(declared_entries(&mut handle, len).unwrap(), 5);
    }

    #[test]
    fn a_zip_stored_inside_near_the_end_is_not_taken_for_this_one() {
        // An inner zip of three entries, stored as the last entry of an
        // outer zip of two: the inner end record ends before the outer
        // directory and is not counted.
        let inner = zip_with(
            &[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")],
            zip::CompressionMethod::Stored,
        );
        let inner = std::fs::read(inner.path()).unwrap();
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        let stored = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        writer.start_file("Locations-a.csv", stored).unwrap();
        writer.write_all(b"1").unwrap();
        writer.start_file("attachment.zip", stored).unwrap();
        writer.write_all(&inner).unwrap();
        writer.finish().unwrap();
        let reader = ZipReader::open(file.path(), limits()).unwrap();
        assert_eq!(reader.names().len(), 2);
    }

    #[test]
    fn a_longest_comment_and_trailing_bytes_are_read() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        writer
            .start_file("Locations-a.csv", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"1").unwrap();
        writer
            .set_raw_comment(vec![b'c'; 65_535].into_boxed_slice())
            .unwrap();
        writer.finish().unwrap();
        let original = std::fs::metadata(file.path()).unwrap().len();
        with_trailing(file.path(), MAX_TRAILING_BYTES);
        let mut handle = File::open(file.path()).unwrap();
        let len = handle.metadata().unwrap().len();
        assert_eq!(zip_end(&mut handle, len).unwrap(), (1, original));
        ZipReader::open(file.path(), limits()).unwrap();
    }

    #[test]
    fn a_zip64_locator_pointing_after_itself_is_hostile() {
        let file = zip_with(&[("Locations-a.csv", b"1")], zip::CompressionMethod::Stored);
        let bytes = std::fs::read(file.path()).unwrap();
        let (body, end) = bytes.split_at(bytes.len() - 22);
        let mut out = body.to_vec();
        let locator_at = out.len() as u64;
        out.extend_from_slice(b"PK\x06\x07");
        out.extend_from_slice(&0_u32.to_le_bytes());
        // Names a record in the bytes after the zip.
        out.extend_from_slice(&(locator_at + 20 + 22 + 8).to_le_bytes());
        out.extend_from_slice(&1_u32.to_le_bytes());
        out.extend_from_slice(end);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(b"PK\x06\x06");
        out.extend_from_slice(&[0; 52]);
        std::fs::write(file.path(), &out).unwrap();
        let mut handle = File::open(file.path()).unwrap();
        let len = handle.metadata().unwrap().len();
        assert_eq!(
            zip_end(&mut handle, len).unwrap_err().metadata().0,
            "HostileZip"
        );
    }

    #[test]
    fn bounded_reads_and_seeks_as_if_the_file_ended_there() {
        use std::io::{Seek, SeekFrom};
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"0123456789").unwrap();
        let mut bounded = Bounded::new(File::open(file.path()).unwrap(), 6);
        assert_eq!(bounded.seek(SeekFrom::End(-2)).unwrap(), 4);
        let mut text = Vec::new();
        bounded.read_to_end(&mut text).unwrap();
        assert_eq!(text, b"45");
        assert_eq!(bounded.seek(SeekFrom::Start(3)).unwrap(), 3);
        let mut buffer = [0_u8; 8];
        assert_eq!(bounded.read(&mut buffer).unwrap(), 3);
        assert_eq!(&buffer[..3], b"345");
        assert!(bounded.seek(SeekFrom::End(-7)).is_err());
    }

    #[test]
    fn a_file_that_is_not_a_zip_is_hostile() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"not a zip at all").unwrap();
        assert_eq!(
            ZipReader::open(file.path(), limits())
                .err()
                .unwrap()
                .metadata()
                .0,
            "HostileZip"
        );
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
