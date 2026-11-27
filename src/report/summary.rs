//! `Summary-*.csv` and `Settings-*.csv` (`docs/SPEC.md` section 4.8).
//!
//! A summary has no header: key, value and description rows, with blank
//! lines between groups (Observed). The parser keeps every group as it
//! came and a map of the known keys to their first value. Settings have
//! the header `"Setting Name","Value","Description"`, and some rows have
//! two fields (Observed).

use std::collections::BTreeMap;
use std::io::Read;

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Serialize;

use super::csvread::{field, CsvFile, Row, Table};
use crate::error::Result;

/// The summary keys kept in `values`.
pub const KNOWN_KEYS: &[&str] = &[
    "Job ID",
    "Case Name",
    "Search Name",
    "Is retry",
    "Query",
    "StartTime (UTC)",
    "EndTime (UTC)",
    "SubmittedBySmtp",
    "ItemCount",
    "CompletedItemCount",
    "LocationCount",
    "CompletedLocationCount",
    "Total",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SummaryFile {
    /// Each group's rows, each row's fields, as they came.
    pub groups: Vec<Vec<Row>>,
    /// The known keys, each with the second field of its first row.
    pub values: BTreeMap<String, String>,
}

impl SummaryFile {
    /// Reads a summary of at most `limit` bytes; a summary is a few
    /// kilobytes (Observed), so it is read whole and split into groups at
    /// blank lines outside quoted fields.
    pub fn read(input: impl Read, limit: u64) -> Result<Self> {
        let mut bytes = Vec::new();
        input
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(crate::zipread::read_error)?;
        if bytes.len() as u64 > limit {
            return Err(crate::error::PurviewError::RecordTooLarge {
                file: "Summary".into(),
                limit,
            });
        }
        let text = String::from_utf8_lossy(&bytes);
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
        let mut summary = Self::default();
        for chunk in groups(text) {
            let mut file = CsvFile::new(chunk.as_bytes(), "Summary", limit);
            let mut group: Vec<Row> = Vec::new();
            while let Some(row) = file.next_row()? {
                if let Some(key) = row.first().map(|key| key.trim()) {
                    if KNOWN_KEYS.contains(&key) && !summary.values.contains_key(key) {
                        if let Some(value) = field(&row, Some(1)) {
                            summary.values.insert(key.to_owned(), value);
                        }
                    }
                }
                group.push(row);
            }
            if !group.is_empty() {
                summary.groups.push(group);
            }
        }
        Ok(summary)
    }

    /// `LocationCount`, when it is a whole number.
    pub fn location_count(&self) -> Option<u64> {
        self.values
            .get("LocationCount")
            .and_then(|text| text.replace(',', "").parse().ok())
    }

    /// `StartTime (UTC)` as a time, when it has the observed form
    /// `03/14/2026 9:07:41 AM`.
    pub fn start_time(&self) -> Option<DateTime<Utc>> {
        self.values
            .get("StartTime (UTC)")
            .and_then(|text| summary_time(text))
    }
}

/// `text` cut at each blank line that is not inside a quoted field.
fn groups(text: &str) -> Vec<&str> {
    let mut groups = Vec::new();
    let mut start = 0;
    let mut line_start = 0;
    let mut quoted = false;
    for (at, character) in text.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '\n' if !quoted => {
                if text[line_start..at].trim().is_empty() {
                    if line_start > start {
                        groups.push(&text[start..line_start]);
                    }
                    start = at + 1;
                }
                line_start = at + 1;
            }
            _ => {}
        }
    }
    if start < text.len() && !text[start..].trim().is_empty() {
        groups.push(&text[start..]);
    }
    groups
}

/// A summary time such as `03/14/2026 9:07:41 AM`, in UTC.
pub fn summary_time(text: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(text.trim(), "%m/%d/%Y %I:%M:%S %p")
        .ok()
        .map(|time| time.and_utc())
}

/// One row of `Settings-*.csv`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Setting {
    pub name: String,
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// The rows of `Settings-*.csv`, and the names of missing columns.
pub fn read_settings(input: impl Read, limit: u64) -> Result<(Vec<Setting>, Vec<&'static str>)> {
    let mut table = Table::new(input, "Settings", limit)?;
    let (index, missing) = table.index(&["Setting Name", "Value", "Description"]);
    let mut settings = Vec::new();
    while let Some(row) = table.next_row()? {
        let Some(name) = field(&row, index[0]) else {
            continue;
        };
        settings.push(Setting {
            name,
            value: field(&row, index[1]),
            description: field(&row, index[2]),
        });
    }
    Ok((settings, missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMMARY: &str = "\u{feff}Job ID,aaaaaaaa,The job\r\nCase Name,Orders review,\r\n\r\nStartTime (UTC),11/25/2026 4:55:23 PM,When\r\nLocationCount,\"10,412\",Locations\r\n\r\n\r\nTotal,\"two\nlines\",x\r\nLocationCount,1,second\r\n";

    #[test]
    fn groups_split_at_blank_lines_and_known_keys_are_kept() {
        let summary = SummaryFile::read(SUMMARY.as_bytes(), 1 << 20).unwrap();
        assert_eq!(summary.groups.len(), 3, "{:?}", summary.groups);
        assert_eq!(summary.groups[0][0][0], "Job ID");
        assert_eq!(summary.groups[2][0][1], "two\nlines");
        assert_eq!(summary.values["Case Name"], "Orders review");
        // The first value of a key is kept.
        assert_eq!(summary.location_count(), Some(10_412));
        assert_eq!(
            summary.start_time().unwrap().to_rfc3339(),
            "2026-11-25T16:55:23+00:00"
        );
    }

    #[test]
    fn a_record_after_a_multiline_field_is_in_the_same_group() {
        let text = "A,\"x\ny\",d\nB,2,d\n";
        let summary = SummaryFile::read(text.as_bytes(), 1 << 20).unwrap();
        assert_eq!(summary.groups.len(), 1, "{:?}", summary.groups);
    }

    #[test]
    fn an_unparsable_time_is_none_and_the_text_is_kept() {
        let summary =
            SummaryFile::read("StartTime (UTC),yesterday,x\n".as_bytes(), 1 << 20).unwrap();
        assert_eq!(summary.start_time(), None);
        assert_eq!(summary.values["StartTime (UTC)"], "yesterday");
    }

    #[test]
    fn settings_rows_may_have_two_fields() {
        let text = "\u{feff}\"Setting Name\",\"Value\",\"Description\"\nIncludeTeams,True\nLanguage,en,Query language\n";
        let (settings, missing) = read_settings(text.as_bytes(), 1 << 20).unwrap();
        assert!(missing.is_empty());
        assert_eq!(settings[0].name, "IncludeTeams");
        assert_eq!(settings[0].description, None);
        assert_eq!(settings[1].description.as_deref(), Some("Query language"));
    }
}
