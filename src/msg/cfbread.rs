//! The Compound File Binary container of a `.msg` (MS-CFB), through the
//! `cfb` crate, read from memory.

use std::io::{Cursor, Read};

use super::MsgError;

/// An open container over a `.msg` already in memory.
pub struct Container<'a> {
    file: cfb::CompoundFile<Cursor<&'a [u8]>>,
    /// The size of the `.msg`: no stream in it can hold more.
    len: u64,
    /// Whether a stream that exists could not be read, so the item is not
    /// read in full.
    unreadable: bool,
    /// Bytes every stream read may still take. A valid file stores each
    /// stream's data once, so the streams read cannot add up to more than
    /// its size; streams that share sectors could, and are stopped at twice
    /// the size.
    budget: u64,
}

/// The diagnostic of a container that cannot be read. It is fixed: the
/// `cfb` crate's own messages can quote the item's first bytes or its
/// directory names.
const NOT_A_CONTAINER: &str = "not a compound file that can be read";

impl<'a> Container<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self, MsgError> {
        check_header(bytes)?;
        let file = cfb::CompoundFile::open(Cursor::new(bytes))
            .map_err(|_| MsgError::CfbInvalid(NOT_A_CONTAINER.into()))?;
        Ok(Self {
            file,
            len: bytes.len() as u64,
            unreadable: false,
            budget: (bytes.len() as u64).saturating_mul(2),
        })
    }

    /// Whether a stream that exists could not be read.
    pub fn unreadable(&self) -> bool {
        self.unreadable
    }

    /// Records that a stream that exists could not be read in full.
    pub fn mark_unreadable(&mut self) {
        self.unreadable = true;
    }

    /// The stream `name` inside `storage` ("" for the root), or `None` when
    /// it is absent. A stream that exists and cannot be read is `None` too,
    /// and marks the container unreadable.
    pub fn stream(&mut self, storage: &str, name: &str) -> Option<Vec<u8>> {
        // The item already fails; reading more would only cost memory.
        if self.unreadable {
            return None;
        }
        let path = path(storage, name);
        if !self.file.is_stream(&path) {
            return None;
        }
        // One byte past what may be read shows the stream is longer.
        let allowed = self.len.min(self.budget);
        let read = self.file.open_stream(&path).and_then(|stream| {
            let mut bytes = Vec::new();
            stream.take(allowed + 1).read_to_end(&mut bytes)?;
            Ok(bytes)
        });
        match read {
            Ok(bytes) if bytes.len() as u64 <= allowed => {
                self.budget -= bytes.len() as u64;
                Some(bytes)
            }
            // Unreadable, longer than the item, or past the budget.
            _ => {
                self.unreadable = true;
                None
            }
        }
    }

    /// The length of the stream `name` inside `storage`, from the
    /// container's directory, without reading it.
    pub fn stream_len(&self, storage: &str, name: &str) -> Option<u64> {
        // The item already fails; reading more would only cost memory.
        if self.unreadable {
            return None;
        }
        let path = path(storage, name);
        if !self.file.is_stream(&path) {
            return None;
        }
        self.file.entry(&path).ok().map(|entry| entry.len())
    }

    /// Whether the stream `name` inside `storage` exists.
    pub fn has_stream(&self, storage: &str, name: &str) -> bool {
        self.file.is_stream(path(storage, name))
    }

    /// The names of the storages directly inside `storage` whose names
    /// start with `prefix`, sorted.
    pub fn children(&self, storage: &str, prefix: &str) -> Vec<String> {
        let Ok(entries) = self.file.read_storage(path(storage, "")) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter(|entry| entry.is_storage() && entry.name().starts_with(prefix))
            .map(|entry| entry.name().to_owned())
            .collect();
        names.sort();
        names
    }
}

/// The checks made on the header (MS-CFB 2.2) before `cfb` reads the
/// file: the signature, a sector size of 512 or 4,096 bytes, and counts of
/// FAT, DIFAT and mini FAT sectors that fit in the file. This refuses a
/// header that declares more sectors than the item holds; it does not
/// bound every allocation `cfb` makes, because in its permissive mode
/// `cfb` builds the FAT from the DIFAT entries it finds and compares their
/// number with the declared count only in strict mode (Derived from its
/// source).
fn check_header(bytes: &[u8]) -> Result<(), MsgError> {
    const SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    let invalid = || MsgError::CfbInvalid(NOT_A_CONTAINER.into());
    if bytes.len() < 512 || bytes[..8] != SIGNATURE {
        return Err(invalid());
    }
    let u16_at = |at: usize| u64::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]));
    let u32_at = |at: usize| {
        u64::from(u32::from_le_bytes([
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
        ]))
    };
    let sector = match u16_at(0x1E) {
        9 => 512_u64,
        12 => 4_096,
        _ => return Err(invalid()),
    };
    let len = bytes.len() as u64;
    for count in [u32_at(0x2C), u32_at(0x40), u32_at(0x48)] {
        if count.saturating_mul(sector) > len {
            return Err(invalid());
        }
    }
    Ok(())
}

/// `/<storage>/<name>`, with no empty segments.
fn path(storage: &str, name: &str) -> String {
    let mut path = String::from("/");
    for part in [storage, name] {
        if !part.is_empty() {
            if !path.ends_with('/') {
                path.push('/');
            }
            path.push_str(part);
        }
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_without_empty_segments() {
        assert_eq!(path("", ""), "/");
        assert_eq!(
            path("", "__properties_version1.0"),
            "/__properties_version1.0"
        );
        assert_eq!(
            path("__recip_version1.0_#00000000", "__substg1.0_3001001F"),
            "/__recip_version1.0_#00000000/__substg1.0_3001001F"
        );
    }

    #[test]
    fn bytes_that_are_not_a_container_are_cfb_invalid() {
        let error = Container::open(b"not a compound file").err().unwrap();
        assert_eq!(error.code(), "cfbInvalid");
        // The diagnostic never quotes the item: a header that passes
        // `check_header` and that `cfb` refuses (version 0) gets the fixed
        // text, not `cfb`'s message.
        let mut bytes = vec![b'Q'; 600];
        bytes[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        bytes[0x1A..0x1C].copy_from_slice(&0_u16.to_le_bytes());
        bytes[0x1E..0x20].copy_from_slice(&9_u16.to_le_bytes());
        for at in [0x2C, 0x40, 0x48] {
            bytes[at..at + 4].copy_from_slice(&0_u32.to_le_bytes());
        }
        let error = Container::open(&bytes).err().unwrap();
        assert_eq!(error.detail(), NOT_A_CONTAINER);
    }

    /// A header of `len` bytes with the signature, `shift` as the sector
    /// shift and no FAT, DIFAT or mini FAT sectors.
    fn header(len: usize, shift: u16) -> Vec<u8> {
        let mut bytes = vec![0_u8; len];
        bytes[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        bytes[0x1E..0x20].copy_from_slice(&shift.to_le_bytes());
        bytes
    }

    #[test]
    fn check_header_accepts_both_sector_sizes_and_counts_that_fit() {
        assert!(check_header(&header(512, 9)).is_ok());
        assert!(check_header(&header(4_096, 12)).is_ok());
        // Two FAT sectors, one mini FAT and one DIFAT sector in 2,048 bytes.
        let mut bytes = header(2_048, 9);
        bytes[0x2C..0x30].copy_from_slice(&2_u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(&1_u32.to_le_bytes());
        bytes[0x48..0x4C].copy_from_slice(&1_u32.to_le_bytes());
        assert!(check_header(&bytes).is_ok());
    }

    #[test]
    fn check_header_refuses_counts_that_do_not_fit_and_other_sector_sizes() {
        for at in [0x2C, 0x40, 0x48] {
            let mut bytes = header(1_024, 9);
            bytes[at..at + 4].copy_from_slice(&3_u32.to_le_bytes());
            assert!(check_header(&bytes).is_err(), "{at:#x}");
        }
        assert!(check_header(&header(1_024, 10)).is_err());
        assert!(check_header(&header(511, 9)).is_err());
    }

    #[test]
    fn a_header_listing_more_fat_sectors_than_fit_is_refused() {
        let mut bytes = vec![0_u8; 1_024];
        bytes[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        bytes[0x1E..0x20].copy_from_slice(&9_u16.to_le_bytes());
        bytes[0x2C..0x30].copy_from_slice(&1_000_000_u32.to_le_bytes());
        let error = Container::open(&bytes).err().unwrap();
        assert_eq!(error.code(), "cfbInvalid");
    }
}
