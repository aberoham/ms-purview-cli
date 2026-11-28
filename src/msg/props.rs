//! MAPI properties in a `.msg` storage (MS-OXMSG section 2.4, Docs):
//! variable-length values in streams named `__substg1.0_<PPPP><TTTT>`, and
//! fixed-size values in `__properties_version1.0`, a header followed by
//! 16-byte entries.

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use super::body::{decode_codepage, Html};
use super::cfbread::Container;
use super::MsgError;

/// Property types (MS-OXCDATA 2.11.1).
const PT_LONG: u16 = 0x0003;
const PT_SYSTIME: u16 = 0x0040;
const PT_STRING8: u16 = 0x001E;
const PT_UNICODE: u16 = 0x001F;
const PT_BINARY: u16 = 0x0102;

/// The kind of storage, which fixes the header length of its property
/// stream (MS-OXMSG 2.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// The top-level message: 32 bytes.
    Message,
    /// A recipient: 8 bytes.
    Recipient,
    /// An attachment: 8 bytes (an embedded message would be 24, and is not
    /// read).
    Attachment,
}

impl Header {
    fn len(self) -> usize {
        match self {
            Self::Message => 32,
            Self::Recipient | Self::Attachment => 8,
        }
    }
}

/// The properties of one storage.
pub struct Props<'c, 'a> {
    container: &'c mut Container<'a>,
    storage: String,
    /// Fixed-size values by property id: type and the 8 value bytes.
    fixed: HashMap<u16, (u16, [u8; 8])>,
    /// The code page of `PT_STRING8` values.
    string_codepage: Option<u32>,
}

impl<'c, 'a> Props<'c, 'a> {
    /// Reads the fixed-size property stream of `storage` ("" for the
    /// message). A missing stream leaves only the variable-length values.
    pub fn open(
        container: &'c mut Container<'a>,
        storage: &str,
        header: Header,
    ) -> Result<Self, MsgError> {
        let mut fixed = HashMap::new();
        if let Some(stream) = container.stream(storage, "__properties_version1.0") {
            // A stream shorter than its header, or with a partial entry, is
            // not read in full.
            if stream.len() < header.len() || !(stream.len() - header.len()).is_multiple_of(16) {
                container.mark_unreadable();
            }
            for entry in stream
                .get(header.len()..)
                .unwrap_or_default()
                .as_chunks::<16>()
                .0
            {
                let tag = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
                let value: [u8; 8] = entry[8..16].try_into().expect("8 bytes");
                fixed.insert((tag >> 16) as u16, ((tag & 0xFFFF) as u16, value));
            }
        }
        Ok(Self {
            container,
            storage: storage.to_owned(),
            fixed,
            string_codepage: None,
        })
    }

    pub fn set_string_codepage(&mut self, codepage: Option<u32>) {
        self.string_codepage = codepage;
    }

    fn variable(&mut self, id: u16, kind: u16) -> Option<Vec<u8>> {
        self.container
            .stream(&self.storage, &format!("__substg1.0_{id:04X}{kind:04X}"))
    }

    /// A string property, from its UTF-16LE stream or, failing that, its
    /// 8-bit stream in the message's code page. A trailing NUL is dropped,
    /// and an empty value is `None`.
    pub fn string(&mut self, id: u16) -> Option<String> {
        let text = match self.variable(id, PT_UNICODE) {
            Some(bytes) => utf16le(&bytes),
            None => {
                let bytes = self.variable(id, PT_STRING8)?;
                decode_codepage(&bytes, self.string_codepage.or(Some(1252)))
            }
        };
        let text = text.trim_end_matches('\0').to_owned();
        (!text.is_empty()).then_some(text)
    }

    /// The HTML body property, which is binary in the observed items and
    /// may be a string (Docs: MS-OXPROPS `PidTagHtml`).
    pub fn html(&mut self, id: u16) -> Option<Html> {
        if let Some(bytes) = self.variable(id, PT_BINARY) {
            return Some(Html::Bytes(bytes));
        }
        self.string(id).map(Html::Text)
    }

    /// Whether any stream holds property `id`, of any type.
    pub fn exists(&self, id: u16) -> bool {
        [PT_BINARY, PT_UNICODE, PT_STRING8].iter().any(|kind| {
            self.container
                .has_stream(&self.storage, &format!("__substg1.0_{id:04X}{kind:04X}"))
        })
    }

    /// A `PT_LONG` property.
    pub fn long(&self, id: u16) -> Option<u32> {
        match self.fixed.get(&id) {
            Some((PT_LONG, value)) => {
                Some(u32::from_le_bytes(value[0..4].try_into().expect("4 bytes")))
            }
            _ => None,
        }
    }

    /// A `PT_SYSTIME` property: a FILETIME, 100-nanosecond intervals since
    /// 1601-01-01 UTC. Zero, or a time that cannot be shown, is `None`.
    pub fn time(&self, id: u16) -> Option<DateTime<Utc>> {
        match self.fixed.get(&id) {
            Some((PT_SYSTIME, value)) => filetime(u64::from_le_bytes(*value)),
            _ => None,
        }
    }
}

/// UTF-16LE, with unpaired surrogates replaced.
pub fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16_lossy(&units)
}

/// A FILETIME as a UTC time.
pub fn filetime(ticks: u64) -> Option<DateTime<Utc>> {
    // Seconds from 1601-01-01 to 1970-01-01.
    const EPOCH_GAP: i64 = 11_644_473_600;
    if ticks == 0 {
        return None;
    }
    let seconds = i64::try_from(ticks / 10_000_000).ok()? - EPOCH_GAP;
    let nanos = ((ticks % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(seconds, nanos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_filetime_is_read_as_utc() {
        // 2026-01-05T09:00:00Z.
        let seconds: u64 = 1_767_603_600;
        let ticks = (seconds + 11_644_473_600) * 10_000_000;
        assert_eq!(
            filetime(ticks).unwrap().to_rfc3339(),
            "2026-01-05T09:00:00+00:00"
        );
        assert_eq!(filetime(0), None);
    }

    #[test]
    fn utf16le_replaces_an_unpaired_surrogate() {
        let bytes = [0x41, 0x00, 0x00, 0xD8, 0x42, 0x00];
        assert_eq!(utf16le(&bytes), "A\u{FFFD}B");
    }
}
