//! CSV reading for report files (`docs/SPEC.md` section 4.8): `csv` with
//! `flexible(true)`, records read as bytes and turned into text with any
//! invalid UTF-8 replaced, a leading byte-order mark removed from the first
//! field, and a byte budget per record.

use std::cell::Cell;
use std::collections::HashMap;
use std::io::{self, Read};
use std::rc::Rc;

use crate::error::{PurviewError, Result};

/// The default of `limits.csv_max_record_bytes`: 64 MiB.
pub const DEFAULT_RECORD_BYTES: u64 = 64 << 20;

/// The CSV reader's buffer. The reader below may run ahead of a record by
/// this much, so it allows that on top of the budget.
const BUFFER: usize = 64 * 1024;

/// Fails a read once more than `limit` bytes have passed since the last
/// reset: a backstop that keeps one record from growing without bound
/// while it is read. The budget itself is checked on each record's own
/// bytes, in `CsvFile::next_row`.
struct RecordBudget<R> {
    inner: R,
    since_reset: Rc<Cell<u64>>,
    limit: u64,
}

impl<R: Read> Read for RecordBudget<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buffer)?;
        let seen = self.since_reset.get() + count as u64;
        self.since_reset.set(seen);
        if seen > self.limit {
            return Err(io::Error::other(OverBudget));
        }
        Ok(count)
    }
}

#[derive(Debug)]
struct OverBudget;

impl std::fmt::Display for OverBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a CSV record is over its byte budget")
    }
}

impl std::error::Error for OverBudget {}

/// One CSV file being read.
pub struct CsvFile<R> {
    reader: csv::Reader<RecordBudget<R>>,
    since_reset: Rc<Cell<u64>>,
    /// The file's kind, such as `Locations`, for messages.
    what: &'static str,
    limit: u64,
    first: bool,
}

/// A record's fields as text.
pub type Row = Vec<String>;

impl<R: Read> CsvFile<R> {
    /// A file with no header row: every record is data.
    pub fn new(input: R, what: &'static str, limit: u64) -> Self {
        let since_reset = Rc::new(Cell::new(0));
        let reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .buffer_capacity(BUFFER)
            .from_reader(RecordBudget {
                inner: input,
                since_reset: since_reset.clone(),
                // Two buffers: the one that held the end of the last
                // record may also hold the start of this one.
                limit: limit.saturating_add(2 * BUFFER as u64),
            });
        Self {
            reader,
            since_reset,
            what,
            limit,
            first: true,
        }
    }

    /// The next record, or `None` at the end. The byte-order mark is
    /// removed from the first field of the first record.
    pub fn next_row(&mut self) -> Result<Option<Row>> {
        let mut record = csv::ByteRecord::new();
        let more = self
            .reader
            .read_byte_record(&mut record)
            .map_err(|error| self.error(error))?;
        self.since_reset.set(0);
        if !more {
            return Ok(None);
        }
        // The record's own bytes: its fields and the separators between
        // them.
        let size = record.as_slice().len() as u64 + record.len().saturating_sub(1) as u64;
        if size > self.limit {
            return Err(PurviewError::RecordTooLarge {
                file: self.what.to_owned(),
                limit: self.limit,
            });
        }
        let mut row: Row = record
            .iter()
            .map(|field| String::from_utf8_lossy(field).into_owned())
            .collect();
        if std::mem::take(&mut self.first) {
            if let Some(first) = row.first_mut() {
                if let Some(rest) = first.strip_prefix('\u{feff}') {
                    *first = rest.to_owned();
                }
            }
        }
        Ok(Some(row))
    }

    fn error(&self, error: csv::Error) -> PurviewError {
        if let csv::ErrorKind::Io(io) = error.kind() {
            if io
                .get_ref()
                .is_some_and(|inner| inner.downcast_ref::<OverBudget>().is_some())
            {
                return PurviewError::RecordTooLarge {
                    file: self.what.to_owned(),
                    limit: self.limit,
                };
            }
            if let Some(limit) = io
                .get_ref()
                .and_then(|inner| inner.downcast_ref::<crate::zipread::ZipLimitExceeded>())
            {
                return PurviewError::HostileZip(limit.0.clone());
            }
        }
        // The message names the file's kind and the position, never a
        // field's text.
        let place = error
            .position()
            .map(|position| format!(" at line {}", position.line()))
            .unwrap_or_default();
        PurviewError::message(format!(
            "the {} file cannot be read as CSV{place}",
            self.what
        ))
    }
}

/// A file with a header row, its columns indexed by name.
pub struct Table<R> {
    file: CsvFile<R>,
    columns: HashMap<String, usize>,
}

impl<R: Read> Table<R> {
    /// Reads the header row. An empty file has no columns.
    pub fn new(input: R, what: &'static str, limit: u64) -> Result<Self> {
        let mut file = CsvFile::new(input, what, limit);
        let header = file.next_row()?.unwrap_or_default();
        let columns = header
            .into_iter()
            .enumerate()
            .map(|(index, name)| (name.trim().to_owned(), index))
            .collect();
        Ok(Self { file, columns })
    }

    /// The index of each of `wanted`, and the names of those missing.
    pub fn index(&self, wanted: &[&'static str]) -> (Vec<Option<usize>>, Vec<&'static str>) {
        let indexes: Vec<Option<usize>> = wanted
            .iter()
            .map(|name| self.columns.get(*name).copied())
            .collect();
        let missing = wanted
            .iter()
            .zip(&indexes)
            .filter(|(_, index)| index.is_none())
            .map(|(name, _)| *name)
            .collect();
        (indexes, missing)
    }

    pub fn next_row(&mut self) -> Result<Option<Row>> {
        self.file.next_row()
    }
}

/// `row[index]`, trimmed, or `None` when the column is missing or the field
/// is empty.
pub fn field(row: &Row, index: Option<usize>) -> Option<String> {
    index
        .and_then(|index| row.get(index))
        .map(|text| text.trim())
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bom_is_removed_from_the_first_field_only() {
        let text = "\u{feff}Location,Count\n\u{feff}a,1\n";
        let mut table = Table::new(text.as_bytes(), "Locations", DEFAULT_RECORD_BYTES).unwrap();
        let (indexes, missing) = table.index(&["Location", "Count", "Size"]);
        assert_eq!(indexes, vec![Some(0), Some(1), None]);
        assert_eq!(missing, vec!["Size"]);
        let row = table.next_row().unwrap().unwrap();
        assert_eq!(row[0], "\u{feff}a");
        assert!(table.next_row().unwrap().is_none());
    }

    #[test]
    fn a_file_without_a_bom_reads_the_same() {
        let mut table =
            Table::new("Location,Count\na,1\n".as_bytes(), "Locations", 1 << 20).unwrap();
        assert_eq!(table.index(&["Location"]).0, vec![Some(0)]);
        assert_eq!(table.next_row().unwrap().unwrap(), vec!["a", "1"]);
    }

    #[test]
    fn rows_may_have_fewer_fields_than_the_header() {
        let text = "\"Setting Name\",\"Value\",\"Description\"\nA,1\nB,2,c\n";
        let mut table = Table::new(text.as_bytes(), "Settings", 1 << 20).unwrap();
        assert_eq!(table.next_row().unwrap().unwrap(), vec!["A", "1"]);
        assert_eq!(table.next_row().unwrap().unwrap(), vec!["B", "2", "c"]);
    }

    #[test]
    fn a_record_over_budget_is_refused_and_a_large_one_under_it_is_read() {
        let big = "x".repeat(300 * 1024);
        let text = format!("Location\n{big}\n");
        let mut table = Table::new(text.as_bytes(), "Locations", 1 << 20).unwrap();
        assert_eq!(table.next_row().unwrap().unwrap()[0].len(), big.len());
        let mut table = Table::new(text.as_bytes(), "Locations", 64 * 1024).unwrap();
        let error = table.next_row().err().unwrap();
        assert_eq!(error.metadata().0, "RecordTooLarge");
        assert!(!error.to_string().contains("xxx"));
    }

    #[test]
    fn short_records_next_to_each_other_are_measured_one_by_one() {
        // Each record is 40 bytes, under a 64-byte budget; together they
        // are far over it.
        let row = format!("{}\n", "x".repeat(40));
        let text = format!("Location\n{}", row.repeat(5000));
        let mut table = Table::new(text.as_bytes(), "Locations", 64).unwrap();
        let mut count = 0;
        while table.next_row().unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 5000);
        // One record just over the budget, between short ones.
        let text = format!("Location\n{row}{}\n{row}", "y".repeat(65));
        let mut table = Table::new(text.as_bytes(), "Locations", 64).unwrap();
        assert!(table.next_row().unwrap().is_some());
        assert_eq!(
            table.next_row().err().unwrap().metadata().0,
            "RecordTooLarge"
        );
        // Exactly at the budget is accepted.
        let text = format!("Location\n{}\n", "z".repeat(64));
        let mut table = Table::new(text.as_bytes(), "Locations", 64).unwrap();
        assert!(table.next_row().unwrap().is_some());
    }

    #[test]
    fn fields_are_trimmed_and_empty_ones_are_none() {
        let row: Row = vec![" a ".into(), "".into()];
        assert_eq!(field(&row, Some(0)).as_deref(), Some("a"));
        assert_eq!(field(&row, Some(1)), None);
        assert_eq!(field(&row, Some(5)), None);
        assert_eq!(field(&row, None), None);
    }
}
