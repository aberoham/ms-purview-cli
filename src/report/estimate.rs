//! `Locations-*.csv` and `Statistics-*.csv` (`docs/SPEC.md` section 4.8),
//! failed locations and the collection check.
//!
//! Columns (Observed):
//! - Locations: `DataSourceName`, `DataSourceType`, `Location`,
//!   `LocationId`, `LocationType`, `LocationSubType`, `Count`, `Size`,
//!   `Status`, `ErrorWarning`, `Query`. `Query` repeats the KQL on every
//!   row; only the first is kept.
//! - Statistics: `DataSourceName`, `DataSourceType`, `Location`,
//!   `LocationType`, `LocationSubType`, `StatType`, `StatName`,
//!   `OriginalStatName`, `Value`. A `StatType` of `Error` names a failed
//!   location, with the message in `StatName`.

use std::collections::BTreeMap;
use std::io::Read;

use serde::Serialize;

use super::csvread::{field, Table};
use crate::error::Result;

const LOCATION_COLUMNS: &[&str] = &[
    "Location",
    "LocationId",
    "LocationType",
    "LocationSubType",
    "Count",
    "Size",
    "Status",
    "ErrorWarning",
    "Query",
];

const STATISTICS_COLUMNS: &[&str] = &["Location", "LocationSubType", "StatType", "StatName"];

/// One row of `Locations-*.csv`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocationRow {
    pub location: String,
    pub location_id: Option<String>,
    pub location_type: Option<String>,
    pub sub_type: Option<String>,
    /// Hits; `None` when the field is empty or not a whole number.
    pub count: Option<u64>,
    pub size: Option<u64>,
    pub status: Option<String>,
    pub error_warning: Option<String>,
}

impl LocationRow {
    pub fn failed(&self) -> bool {
        self.status
            .as_deref()
            .is_some_and(|status| status.eq_ignore_ascii_case("Failed"))
    }
}

/// What `Locations-*.csv` holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Locations {
    pub rows: Vec<LocationRow>,
    /// The first row's `Query`.
    pub query: Option<String>,
    pub missing_columns: Vec<&'static str>,
    /// Rows whose `Count` or `Size` was not a whole number.
    pub unreadable_counts: usize,
    /// Rows with no `Location` or no `Status`, which cannot be shown to
    /// be searched in full.
    pub unusable_rows: usize,
}

/// A whole number such as `1024` or `1,024`.
fn number(text: Option<String>, unreadable: &mut bool) -> Option<u64> {
    let text = text?;
    match text.replace(',', "").parse() {
        Ok(value) => Some(value),
        Err(_) => {
            *unreadable = true;
            None
        }
    }
}

pub fn read_locations(input: impl Read, limit: u64) -> Result<Locations> {
    let mut table = Table::new(input, "Locations", limit)?;
    let (index, missing_columns) = table.index(LOCATION_COLUMNS);
    let mut locations = Locations {
        missing_columns,
        ..Locations::default()
    };
    while let Some(row) = table.next_row()? {
        let Some(location) = field(&row, index[0]) else {
            locations.unusable_rows += 1;
            continue;
        };
        if field(&row, index[6]).is_none() {
            locations.unusable_rows += 1;
        }
        if locations.query.is_none() {
            locations.query = field(&row, index[8]);
        }
        let mut unreadable = false;
        let count = number(field(&row, index[4]), &mut unreadable);
        let size = number(field(&row, index[5]), &mut unreadable);
        if unreadable {
            locations.unreadable_counts += 1;
        }
        locations.rows.push(LocationRow {
            location,
            location_id: field(&row, index[1]),
            location_type: field(&row, index[2]),
            sub_type: field(&row, index[3]),
            count,
            size,
            status: field(&row, index[6]),
            error_warning: field(&row, index[7]),
        });
    }
    Ok(locations)
}

/// A location that was not searched in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailedLocation {
    pub location: String,
    pub sub_type: Option<String>,
    /// `StatName` of a Statistics error, else `ErrorWarning` of the
    /// Locations row; `None` when neither has text.
    #[serde(rename = "failureMessage")]
    pub message: Option<String>,
    /// Where the failure was read: `locations`, `statistics` or both.
    pub sources: Vec<&'static str>,
}

/// The `StatType: Error` rows of `Statistics-*.csv`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatisticsErrors {
    pub errors: Vec<FailedLocation>,
    pub missing_columns: Vec<&'static str>,
    /// Rows with no `StatType`, or an error with no `Location`.
    pub unusable_rows: usize,
}

pub fn read_statistics_errors(input: impl Read, limit: u64) -> Result<StatisticsErrors> {
    let mut table = Table::new(input, "Statistics", limit)?;
    let (index, missing_columns) = table.index(STATISTICS_COLUMNS);
    let mut read = StatisticsErrors {
        missing_columns,
        ..StatisticsErrors::default()
    };
    while let Some(row) = table.next_row()? {
        let Some(kind) = field(&row, index[2]) else {
            read.unusable_rows += 1;
            continue;
        };
        if !kind.eq_ignore_ascii_case("Error") {
            continue;
        }
        let Some(location) = field(&row, index[0]) else {
            read.unusable_rows += 1;
            continue;
        };
        read.errors.push(FailedLocation {
            location,
            sub_type: field(&row, index[1]),
            message: field(&row, index[3]),
            sources: vec!["statistics"],
        });
    }
    Ok(read)
}

/// The union of `Status: Failed` locations and Statistics errors, keyed by
/// location and subtype, in the order first seen: Locations rows first.
pub fn failed_locations(
    locations: Option<&Locations>,
    statistics: Option<&[FailedLocation]>,
) -> Vec<FailedLocation> {
    let mut failed: Vec<FailedLocation> = Vec::new();
    let mut at: BTreeMap<(String, Option<String>), usize> = BTreeMap::new();
    for row in locations
        .into_iter()
        .flat_map(|l| &l.rows)
        .filter(|row| row.failed())
    {
        let key = (row.location.clone(), row.sub_type.clone());
        if at.contains_key(&key) {
            continue;
        }
        at.insert(key, failed.len());
        failed.push(FailedLocation {
            location: row.location.clone(),
            sub_type: row.sub_type.clone(),
            message: row.error_warning.clone(),
            sources: vec!["locations"],
        });
    }
    for error in statistics.into_iter().flatten() {
        let key = (error.location.clone(), error.sub_type.clone());
        match at.get(&key) {
            Some(&index) => {
                let entry = &mut failed[index];
                if !entry.sources.contains(&"statistics") {
                    entry.sources.push("statistics");
                }
                if error.message.is_some() {
                    entry.message = error.message.clone();
                }
            }
            None => {
                at.insert(key, failed.len());
                failed.push(error.clone());
            }
        }
    }
    failed
}

/// Whether every location was searched (`docs/SPEC.md` section 3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collection {
    /// The evidence was read and no location failed.
    Complete,
    /// At least one location failed.
    Incomplete { failed: usize },
    /// The evidence was not read, or a file it needs is missing.
    Unchecked,
}

impl Collection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Incomplete { .. } => "incomplete",
            Self::Unchecked => "unchecked",
        }
    }
}

/// Sorts locations by hits, most first; ties by location, then subtype.
pub fn by_hits(rows: &mut [LocationRow]) {
    rows.sort_by(|a, b| {
        b.count
            .unwrap_or(0)
            .cmp(&a.count.unwrap_or(0))
            .then_with(|| a.location.cmp(&b.location))
            .then_with(|| a.sub_type.cmp(&b.sub_type))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCATIONS: &str = "\u{feff}DataSourceName,DataSourceType,Location,LocationId,LocationType,LocationSubType,Count,Size,Status,ErrorWarning,Query\n\
        Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,PrimaryMailBox,12,\"2,048\",Succeeded,,\"\"\"orders-api\"\"\"\n\
        Exchange,Mailbox,alex@contoso.example,id-1,Mailbox,ArchiveMailBox,0,0,Succeeded,,\"\"\"orders-api\"\"\"\n\
        Exchange,Mailbox,sam@contoso.example,id-2,Mailbox,PrimaryMailBox,,,Failed,Search timed out,\"\"\"orders-api\"\"\"\n\
        Exchange,Mailbox,lee@contoso.example,id-3,Mailbox,PrimaryMailBox,x,1,Succeeded,,\n";

    const STATISTICS: &str = "\u{feff}DataSourceName,DataSourceType,Location,LocationType,LocationSubType,StatType,StatName,OriginalStatName,Value\n\
        Exchange,Mailbox,sam@contoso.example,Mailbox,PrimaryMailBox,Error,OperationCanceledException,x,0\n\
        Exchange,Mailbox,kim@contoso.example,Mailbox,SystemMailbox,Error,OperationCanceledException,x,0\n\
        Exchange,Mailbox,alex@contoso.example,Mailbox,PrimaryMailBox,Hits,Count,x,12\n";

    #[test]
    fn locations_are_read_with_counts_and_the_first_query() {
        let locations = read_locations(LOCATIONS.as_bytes(), 1 << 20).unwrap();
        assert_eq!(locations.rows.len(), 4);
        assert_eq!(locations.rows[0].count, Some(12));
        assert_eq!(locations.rows[0].size, Some(2048));
        assert_eq!(locations.rows[2].count, None);
        assert!(locations.rows[2].failed());
        assert_eq!(locations.query.as_deref(), Some("\"orders-api\""));
        assert_eq!(locations.unreadable_counts, 1);
        assert!(locations.missing_columns.is_empty());
    }

    #[test]
    fn a_row_of_empty_fields_is_unusable() {
        let text = format!("{}\n,,,,,,,,,,\n", LOCATIONS.lines().next().unwrap());
        assert_eq!(
            read_locations(text.as_bytes(), 1 << 20)
                .unwrap()
                .unusable_rows,
            1
        );
        let text = format!("{}\n,,,,,,,,\n", STATISTICS.lines().next().unwrap());
        assert_eq!(
            read_statistics_errors(text.as_bytes(), 1 << 20)
                .unwrap()
                .unusable_rows,
            1
        );
    }

    #[test]
    fn a_missing_column_is_named() {
        let locations = read_locations("Location,Count\na,1\n".as_bytes(), 1 << 20).unwrap();
        assert!(locations.missing_columns.contains(&"Status"));
        assert!(!locations.missing_columns.contains(&"Count"));
        assert_eq!(locations.rows[0].count, Some(1));
    }

    #[test]
    fn failures_are_the_union_of_both_files() {
        let locations = read_locations(LOCATIONS.as_bytes(), 1 << 20).unwrap();
        let read = read_statistics_errors(STATISTICS.as_bytes(), 1 << 20).unwrap();
        assert!(read.missing_columns.is_empty());
        let errors = read.errors;
        assert_eq!(errors.len(), 2);
        let failed = failed_locations(Some(&locations), Some(&errors));
        assert_eq!(failed.len(), 2, "{failed:?}");
        assert_eq!(failed[0].location, "sam@contoso.example");
        assert_eq!(failed[0].sources, vec!["locations", "statistics"]);
        assert_eq!(
            failed[0].message.as_deref(),
            Some("OperationCanceledException")
        );
        assert_eq!(failed[1].location, "kim@contoso.example");
        assert_eq!(failed[1].sub_type.as_deref(), Some("SystemMailbox"));
        assert_eq!(failed_locations(Some(&locations), None).len(), 1);
        assert_eq!(failed_locations(None, Some(&errors)).len(), 2);
    }

    #[test]
    fn locations_sort_by_hits_then_name_then_subtype() {
        let mut rows = read_locations(LOCATIONS.as_bytes(), 1 << 20).unwrap().rows;
        by_hits(&mut rows);
        let order: Vec<(&str, Option<&str>)> = rows
            .iter()
            .map(|row| (row.location.as_str(), row.sub_type.as_deref()))
            .collect();
        assert_eq!(
            order,
            [
                ("alex@contoso.example", Some("PrimaryMailBox")),
                ("alex@contoso.example", Some("ArchiveMailBox")),
                ("lee@contoso.example", Some("PrimaryMailBox")),
                ("sam@contoso.example", Some("PrimaryMailBox")),
            ]
        );
    }
}
