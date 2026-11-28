//! Report and estimate zips (`docs/SPEC.md` section 4.8): the files in
//! them, read through `zipread` and `csvread`, and the collection check.

pub mod csvread;
pub mod estimate;
pub mod summary;
pub mod volume;

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::Value;

use crate::error::{PurviewError, Result};
use crate::zipread::{config_limit, ZipLimits, ZipReader};
use estimate::{Collection, FailedLocation, Locations, StatisticsErrors};
use summary::{Setting, SummaryFile};

/// The kind of report zip, from its entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// It has `Statistics-*.csv`.
    Estimate,
    /// It has `Items_N_*.csv` and no `Items.*.zip`.
    ItemReport,
    /// Neither.
    Other,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Estimate => "estimate",
            Self::ItemReport => "itemReport",
            Self::Other => "other",
        }
    }

    fn of(names: &[String]) -> Self {
        let base = |name: &String| name.rsplit('/').next().unwrap_or(name).to_owned();
        let bases: Vec<String> = names.iter().map(base).collect();
        if bases.iter().any(|name| name.starts_with("Statistics-")) {
            return Self::Estimate;
        }
        let items = regex::Regex::new(r"^Items_\d+_.*\.csv$").expect("a valid pattern");
        let package = regex::Regex::new(r"^Items\..*\.zip$").expect("a valid pattern");
        if bases.iter().any(|name| items.is_match(name))
            && !bases.iter().any(|name| package.is_match(name))
        {
            return Self::ItemReport;
        }
        Self::Other
    }
}

/// The limits for reading report files, from `config.json`'s `limits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportLimits {
    pub zip: ZipLimits,
    pub record_bytes: u64,
}

impl ReportLimits {
    pub fn from_config(extra: &BTreeMap<String, Value>) -> Result<Self> {
        let record_bytes = match config_limit(extra, "csv_max_record_bytes")? {
            None => csvread::DEFAULT_RECORD_BYTES,
            Some(value) => value
                .as_str()
                .and_then(crate::download::parse_size)
                .ok_or_else(|| {
                    PurviewError::message(
                        "config.json: limits.csv_max_record_bytes must be a size such as 64MiB",
                    )
                })?,
        };
        Ok(Self {
            zip: ZipLimits::report(extra)?,
            record_bytes,
        })
    }
}

/// What a report zip holds. A file that is absent is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFiles {
    pub kind: Kind,
    pub locations: Option<Locations>,
    /// The `StatType: Error` rows of `Statistics-*.csv`.
    pub statistics_errors: Option<StatisticsErrors>,
    pub summary: Option<SummaryFile>,
    pub settings: Option<Vec<Setting>>,
    /// Missing columns, as `File: Column`.
    pub missing_columns: Vec<String>,
    /// The kinds of file the zip holds more than one of, such as
    /// `Locations`; only the first is read.
    pub duplicates: Vec<&'static str>,
}

impl ReportFiles {
    /// Reads the files of the zip at `path` that this release parses.
    pub fn read(path: &Path, limits: ReportLimits) -> Result<Self> {
        let mut zip = ZipReader::open(path, limits.zip)?;
        let kind = Kind::of(zip.names());
        let record = limits.record_bytes;
        let mut missing_columns = Vec::new();
        let duplicates = ["Locations", "Statistics", "Summary", "Settings"]
            .into_iter()
            .filter(|kind| zip.find_all(&format!("{kind}-")).len() > 1)
            .collect();
        let locations = match zip.find("Locations-") {
            None => None,
            Some(index) => {
                let locations =
                    zip.read_entry(index, |reader| estimate::read_locations(reader, record))?;
                missing_columns.extend(
                    locations
                        .missing_columns
                        .iter()
                        .map(|c| format!("Locations: {c}")),
                );
                Some(locations)
            }
        };
        let statistics_errors = match zip.find("Statistics-") {
            None => None,
            Some(index) => {
                let read = zip.read_entry(index, |reader| {
                    estimate::read_statistics_errors(reader, record)
                })?;
                missing_columns.extend(
                    read.missing_columns
                        .iter()
                        .map(|c| format!("Statistics: {c}")),
                );
                Some(read)
            }
        };
        let summary = match zip.find("Summary-") {
            None => None,
            Some(index) => Some(zip.read_entry(index, |reader| SummaryFile::read(reader, record))?),
        };
        let settings = match zip.find("Settings-") {
            None => None,
            Some(index) => {
                let (settings, missing) =
                    zip.read_entry(index, |reader| summary::read_settings(reader, record))?;
                missing_columns.extend(missing.iter().map(|c| format!("Settings: {c}")));
                Some(settings)
            }
        };
        Ok(Self {
            kind,
            locations,
            statistics_errors,
            summary,
            settings,
            missing_columns,
            duplicates,
        })
    }

    /// Rows of Locations and Statistics that cannot be shown to be
    /// searched in full.
    pub fn unusable_rows(&self) -> usize {
        self.locations.as_ref().map_or(0, |l| l.unusable_rows)
            + self
                .statistics_errors
                .as_ref()
                .map_or(0, |s| s.unusable_rows)
    }

    /// The failed locations an action's evidence shows: both files for an
    /// estimate, `Locations` alone for a report, which has no Statistics
    /// file (Observed).
    pub fn failed_locations_of(&self, action: EvidenceOf) -> Vec<FailedLocation> {
        match action {
            EvidenceOf::Estimate => self.failed_locations(),
            EvidenceOf::Report => estimate::failed_locations(self.locations.as_ref(), None),
        }
    }

    /// The failed locations of both files.
    pub fn failed_locations(&self) -> Vec<FailedLocation> {
        estimate::failed_locations(
            self.locations.as_ref(),
            self.statistics_errors
                .as_ref()
                .map(|read| read.errors.as_slice()),
        )
    }

    /// The collection check for an action whose evidence this is
    /// (`docs/SPEC.md` section 3.5): an estimate needs both Locations and
    /// Statistics, a report Locations; without them, with a column the
    /// check reads missing, with a row it cannot read, or with more than
    /// one such file, it is `Unchecked`, whatever failures it found.
    pub fn collection(&self, action: EvidenceOf) -> Collection {
        let locations_usable = self.locations.as_ref().is_some_and(|locations| {
            !locations
                .missing_columns
                .iter()
                .any(|column| matches!(*column, "Location" | "Status"))
        });
        let statistics_usable = self.statistics_errors.is_some()
            && !self.missing_columns.iter().any(|column| {
                matches!(
                    column.as_str(),
                    "Statistics: Location" | "Statistics: StatType"
                )
            });
        let usable = match action {
            EvidenceOf::Estimate => locations_usable && statistics_usable,
            EvidenceOf::Report => locations_usable,
        };
        let ambiguous = self.duplicates.iter().any(|kind| match action {
            EvidenceOf::Estimate => matches!(*kind, "Locations" | "Statistics"),
            EvidenceOf::Report => *kind == "Locations",
        });
        let unusable = match action {
            EvidenceOf::Estimate => self.unusable_rows(),
            EvidenceOf::Report => self.locations.as_ref().map_or(0, |l| l.unusable_rows),
        };
        if !usable || ambiguous || unusable > 0 {
            return Collection::Unchecked;
        }
        match self.failed_locations_of(action).len() {
            0 => Collection::Complete,
            failed => Collection::Incomplete { failed },
        }
    }
}

/// Which action's evidence a zip is read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceOf {
    Estimate,
    /// An item report, or the report part of an export.
    Report,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn zip_of(entries: &[(&str, &str)]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut writer = zip::ZipWriter::new(file.reopen().unwrap());
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(body.as_bytes()).unwrap();
        }
        writer.finish().unwrap();
        file
    }

    const HEADER: &str = "DataSourceName,DataSourceType,Location,LocationId,LocationType,LocationSubType,Count,Size,Status,ErrorWarning,Query\n";
    const STATS_HEADER: &str = "DataSourceName,DataSourceType,Location,LocationType,LocationSubType,StatType,StatName,OriginalStatName,Value\n";

    fn limits() -> ReportLimits {
        ReportLimits::from_config(&BTreeMap::new()).unwrap()
    }

    #[test]
    fn kinds_come_from_entry_names() {
        let names = |list: &[&str]| list.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            Kind::of(&names(&["Statistics-1.csv", "Locations-1.csv"])),
            Kind::Estimate
        );
        assert_eq!(
            Kind::of(&names(&["Items_0_2026.csv", "Locations-1.csv"])),
            Kind::ItemReport
        );
        assert_eq!(
            Kind::of(&names(&["Items_0_2026.csv", "Items.1.001.x.zip"])),
            Kind::Other
        );
        assert_eq!(Kind::of(&names(&["Summary-1.csv"])), Kind::Other);
    }

    #[test]
    fn collection_values() {
        let ok_row =
            "Exchange,Mailbox,a@contoso.example,1,Mailbox,PrimaryMailBox,3,10,Succeeded,,q\n";
        let failed_row =
            "Exchange,Mailbox,b@contoso.example,2,Mailbox,PrimaryMailBox,,,Failed,x,q\n";
        let error_row =
            "Exchange,Mailbox,c@contoso.example,Mailbox,ArchiveMailBox,Error,Cancelled,x,0\n";
        let complete = zip_of(&[
            ("Locations-1.csv", &format!("{HEADER}{ok_row}")),
            ("Statistics-1.csv", STATS_HEADER),
        ]);
        let files = ReportFiles::read(complete.path(), limits()).unwrap();
        assert_eq!(files.kind, Kind::Estimate);
        assert_eq!(files.collection(EvidenceOf::Estimate), Collection::Complete);

        let incomplete = zip_of(&[
            ("Locations-1.csv", &format!("{HEADER}{ok_row}{failed_row}")),
            ("Statistics-1.csv", &format!("{STATS_HEADER}{error_row}")),
        ]);
        let files = ReportFiles::read(incomplete.path(), limits()).unwrap();
        assert_eq!(
            files.collection(EvidenceOf::Estimate),
            Collection::Incomplete { failed: 2 }
        );

        // An estimate zip without Statistics cannot be checked; a report
        // needs only Locations.
        let no_stats = zip_of(&[("Locations-1.csv", &format!("{HEADER}{ok_row}"))]);
        let files = ReportFiles::read(no_stats.path(), limits()).unwrap();
        assert_eq!(
            files.collection(EvidenceOf::Estimate),
            Collection::Unchecked
        );
        assert_eq!(files.collection(EvidenceOf::Report), Collection::Complete);

        // A Locations file without its Status column cannot be checked.
        let no_status = zip_of(&[
            ("Locations-1.csv", "Location,Count\na@contoso.example,1\n"),
            ("Statistics-1.csv", STATS_HEADER),
        ]);
        let files = ReportFiles::read(no_status.path(), limits()).unwrap();
        assert_eq!(
            files.collection(EvidenceOf::Estimate),
            Collection::Unchecked
        );
        assert!(files
            .missing_columns
            .contains(&"Locations: Status".to_owned()));
    }

    #[test]
    fn the_record_budget_comes_from_config() {
        let extra: BTreeMap<String, Value> = [(
            "limits".to_owned(),
            serde_json::json!({"csv_max_record_bytes": "1KiB"}),
        )]
        .into();
        let limits = ReportLimits::from_config(&extra).unwrap();
        assert_eq!(limits.record_bytes, 1024);
        let big = format!("{HEADER}{}\n", "x".repeat(100 * 1024));
        let zip = zip_of(&[("Locations-1.csv", &big)]);
        assert_eq!(
            ReportFiles::read(zip.path(), limits)
                .err()
                .unwrap()
                .metadata()
                .0,
            "RecordTooLarge"
        );
    }
}
