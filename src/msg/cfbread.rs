//! The Compound File Binary container of a `.msg` (MS-CFB), through the
//! `cfb` crate, read from memory.

use std::io::{Cursor, Read};

use super::MsgError;

/// An open container over a `.msg` already in memory.
pub struct Container<'a> {
    file: cfb::CompoundFile<Cursor<&'a [u8]>>,
    /// The size of the `.msg`: no stream in it can hold more.
    len: u64,
}

impl<'a> Container<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self, MsgError> {
        let file = cfb::CompoundFile::open(Cursor::new(bytes)).map_err(|error| {
            // The crate's message describes the structure, never content.
            MsgError::CfbInvalid(format!("not a compound file that can be read: {error}"))
        })?;
        Ok(Self {
            file,
            len: bytes.len() as u64,
        })
    }

    /// The stream `name` inside `storage` ("" for the root), or `None` when
    /// it is absent or cannot be read.
    pub fn stream(&mut self, storage: &str, name: &str) -> Option<Vec<u8>> {
        let path = path(storage, name);
        if !self.file.is_stream(&path) {
            return None;
        }
        let stream = self.file.open_stream(&path).ok()?;
        let mut bytes = Vec::new();
        stream.take(self.len).read_to_end(&mut bytes).ok()?;
        Some(bytes)
    }

    /// The length of the stream `name` inside `storage`, from the
    /// container's directory, without reading it.
    pub fn stream_len(&self, storage: &str, name: &str) -> Option<u64> {
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
    }
}
