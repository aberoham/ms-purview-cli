//! `purview parse locations|failures|summary <zip>` (`docs/SPEC.md`
//! section 3.5): local, no sign-in. The zip is read through the limits of
//! `report::ReportLimits`, which `cli` takes from `config.json`.

use std::io::Write;
use std::path::Path;

use serde_json::json;

use super::Produced;
use crate::env::Env;
use crate::error::{PurviewError, Result};
use crate::output::{sanitize, write_rows, OutputFormat, OutputOptions};
use crate::report::estimate::{by_hits, FailedLocation, LocationRow};
use crate::report::{ReportFiles, ReportLimits};

pub const LOCATION_COLUMNS: &[&str] = &["LOCATION", "SUBTYPE", "COUNT", "SIZE", "STATUS"];
pub const FAILURE_COLUMNS: &[&str] = &["LOCATION", "SUBTYPE", "SOURCES", "MESSAGE"];
pub const SUMMARY_COLUMNS: &[&str] = &["FILE", "KEY", "VALUE"];

/// `--subtype` of `parse locations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubType {
    Primary,
    Archive,
    System,
}

impl SubType {
    /// The `LocationSubType` value (Observed), compared ignoring case.
    fn value(self) -> &'static str {
        match self {
            Self::Primary => "PrimaryMailBox",
            Self::Archive => "ArchiveMailBox",
            Self::System => "SystemMailbox",
        }
    }
}

/// The filters of `parse locations`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LocationFilters {
    pub top: Option<usize>,
    pub with_hits: bool,
    pub sub_type: Option<SubType>,
}

/// Which `parse` subcommand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum What {
    Locations(LocationFilters),
    Failures,
    Summary,
}

impl What {
    pub fn columns(self) -> &'static [&'static str] {
        match self {
            Self::Locations(_) => LOCATION_COLUMNS,
            Self::Failures => FAILURE_COLUMNS,
            Self::Summary => SUMMARY_COLUMNS,
        }
    }
}

/// Reads the zip at `path` and prints what `what` asks for.
pub fn run(
    env: &mut Env,
    output: &OutputOptions,
    path: &Path,
    limits: ReportLimits,
    what: What,
) -> Result<Produced> {
    // The path is the user's own argument and is not repeated.
    let files = ReportFiles::read(path, limits).map_err(|error| match error {
        PurviewError::Io(io) => {
            PurviewError::message(format!("the zip given cannot be read: {}", io.kind()))
        }
        other => other,
    })?;
    warn_missing_columns(&mut env.stderr, &files);
    match what {
        What::Locations(filters) => locations(env, output, &files, filters),
        What::Failures => failures(env, output, &files),
        What::Summary => summary(env, output, &files),
    }
}

/// A warning for each column the parser looked for and did not find.
pub fn warn_missing_columns(log: &mut dyn Write, files: &ReportFiles) {
    if !files.missing_columns.is_empty() {
        let _ = writeln!(
            log,
            "warning: columns missing from the zip's files: {}",
            files.missing_columns.join(", ")
        );
    }
    if let Some(count) = files
        .locations
        .as_ref()
        .map(|locations| locations.unreadable_counts)
        .filter(|count| *count > 0)
    {
        let _ = writeln!(
            log,
            "warning: {count} Locations rows have a Count or Size that is not a whole number; \
             they are shown as unknown"
        );
    }
}

fn locations(
    env: &mut Env,
    output: &OutputOptions,
    files: &ReportFiles,
    filters: LocationFilters,
) -> Result<Produced> {
    let Some(locations) = &files.locations else {
        return Err(PurviewError::NotAReportZip(
            "the zip has no Locations-*.csv, so it is not an estimate or report zip".into(),
        ));
    };
    let mut rows: Vec<LocationRow> = locations
        .rows
        .iter()
        .filter(|row| !filters.with_hits || row.count.is_some_and(|count| count > 0))
        .filter(|row| {
            filters.sub_type.is_none_or(|wanted| {
                row.sub_type
                    .as_deref()
                    .is_some_and(|sub| sub.eq_ignore_ascii_case(wanted.value()))
            })
        })
        .cloned()
        .collect();
    by_hits(&mut rows);
    if let Some(top) = filters.top {
        rows.truncate(top);
    }
    if output.format == OutputFormat::Json {
        let count = rows.len();
        return Ok(Produced::success(Some(output.untrusted_json_value(
            serde_json::to_value(&rows)?,
            count,
            &env.redactor,
        )?)));
    }
    let table: Vec<Vec<String>> = rows.iter().map(|row| location_cells(row, env)).collect();
    write_rows(&mut env.stdout, output, LOCATION_COLUMNS, &table)?;
    Ok(Produced::success(None))
}

/// One location as table cells, tenant text through `redact::shown`.
pub fn location_cells(row: &LocationRow, env: &Env) -> Vec<String> {
    let shown = |text: &str| crate::redact::shown(text, &env.redactor);
    let number = |value: Option<u64>| {
        value
            .map(|value| value.to_string())
            .unwrap_or_else(|| "?".into())
    };
    vec![
        shown(&row.location),
        shown(row.sub_type.as_deref().unwrap_or_default()),
        number(row.count),
        number(row.size),
        shown(row.status.as_deref().unwrap_or_default()),
    ]
}

/// One failed location as table cells.
pub fn failure_cells(failure: &FailedLocation, env: &Env) -> Vec<String> {
    let shown = |text: &str| crate::redact::shown(text, &env.redactor);
    vec![
        shown(&failure.location),
        shown(failure.sub_type.as_deref().unwrap_or_default()),
        failure.sources.join(","),
        shown(failure.message.as_deref().unwrap_or_default()),
    ]
}

fn failures(env: &mut Env, output: &OutputOptions, files: &ReportFiles) -> Result<Produced> {
    if files.locations.is_none() && files.statistics_errors.is_none() {
        return Err(PurviewError::NotAReportZip(
            "the zip has neither Locations-*.csv nor Statistics-*.csv, so it is not an estimate \
             or report zip"
                .into(),
        ));
    }
    if files.kind == crate::report::Kind::Estimate && files.locations.is_none() {
        let _ = writeln!(
            env.stderr,
            "warning: the estimate zip has no Locations-*.csv; only Statistics errors are shown"
        );
    }
    let failed = files.failed_locations();
    if output.format == OutputFormat::Json {
        let count = failed.len();
        return Ok(Produced::success(Some(output.untrusted_json_value(
            serde_json::to_value(&failed)?,
            count,
            &env.redactor,
        )?)));
    }
    let table: Vec<Vec<String>> = failed
        .iter()
        .map(|failure| failure_cells(failure, env))
        .collect();
    write_rows(&mut env.stdout, output, FAILURE_COLUMNS, &table)?;
    Ok(Produced::success(None))
}

fn summary(env: &mut Env, output: &OutputOptions, files: &ReportFiles) -> Result<Produced> {
    if files.summary.is_none() && files.settings.is_none() {
        return Err(PurviewError::NotAReportZip(
            "the zip has neither Summary-*.csv nor Settings-*.csv".into(),
        ));
    }
    if output.format == OutputFormat::Json {
        let value = json!({
            "kind": files.kind.as_str(),
            "summary": files.summary.as_ref().map(|summary| json!({
                "values": summary.values,
                "groups": summary.groups,
                "locationCount": summary.location_count(),
                "startTime": summary.start_time().map(|time| time.to_rfc3339()),
            })),
            "settings": files.settings,
        });
        return Ok(Produced::success(Some(output.untrusted_json_value(
            value,
            1,
            &env.redactor,
        )?)));
    }
    let shown = |text: &str| sanitize(&crate::redact::shown(text, &env.redactor));
    let mut table: Vec<Vec<String>> = Vec::new();
    if let Some(summary) = &files.summary {
        for (key, value) in &summary.values {
            table.push(vec!["Summary".into(), shown(key), shown(value)]);
        }
    }
    for setting in files.settings.iter().flatten() {
        table.push(vec![
            "Settings".into(),
            shown(&setting.name),
            shown(setting.value.as_deref().unwrap_or_default()),
        ]);
    }
    write_rows(&mut env.stdout, output, SUMMARY_COLUMNS, &table)?;
    Ok(Produced::success(None))
}
