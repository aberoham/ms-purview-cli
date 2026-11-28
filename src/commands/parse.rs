//! `purview parse locations|failures|summary|items|profile <zip>` (`docs/SPEC.md`
//! section 3.5): local, no sign-in. The zip is read through the limits of
//! `report::ReportLimits`, which `cli` takes from `config.json`.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;

use super::Produced;
use crate::env::Env;
use crate::error::{PurviewError, Result};
use crate::output::{sanitize, write_rows, OutputFormat, OutputOptions};
use crate::report::estimate::{by_hits, FailedLocation, LocationRow};
use crate::report::items::{self, Dedup, Filters, Tally};
use crate::report::profile::{self, Identity, Options};
use crate::report::{ReportFiles, ReportLimits};

pub const LOCATION_COLUMNS: &[&str] = &["LOCATION", "SUBTYPE", "COUNT", "SIZE", "STATUS"];
pub const FAILURE_COLUMNS: &[&str] = &["LOCATION", "SUBTYPE", "SOURCES", "MESSAGE"];
pub const SUMMARY_COLUMNS: &[&str] = &["FILE", "KEY", "VALUE"];
pub const PROFILE_COLUMNS: &[&str] = &["SECTION", "NAME", "COUNT"];
/// The width `NAME` is cut to in the table; JSON keeps the whole name.
const PROFILE_NAME_WIDTH: usize = 80;

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
    if !files.duplicates.is_empty() {
        let _ = writeln!(
            log,
            "warning: the zip holds more than one file of these kinds, and only the first of \
             each was read: {}",
            files.duplicates.join(", ")
        );
    }
    if files.unusable_rows() > 0 {
        let _ = writeln!(
            log,
            "warning: {} Locations or Statistics rows have no location, status or StatType, so \
             the collection cannot be checked",
            files.unusable_rows()
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

/// `--json` holds every record in memory; above this many it is refused
/// unless `--force-buffer` is given.
pub const JSON_MAX_RECORDS: usize = 10_000;

/// The checked arguments of `parse items`.
#[derive(Debug, Clone)]
pub struct ItemsRequest {
    pub zip: PathBuf,
    pub filters: Filters,
    pub all_rows: bool,
    pub max_unique: usize,
    /// One document rather than JSON Lines.
    pub json: bool,
    pub force_buffer: bool,
}

/// `parse items`: JSON Lines on stdout (after the pass, or as each row is
/// read with `--all-rows`), or one document with `--json`, and a summary
/// on stderr. Exit 4 when a record could not be printed.
pub fn items(
    env: &mut Env,
    output: &OutputOptions,
    request: &ItemsRequest,
    limits: ReportLimits,
) -> Result<Produced> {
    let marker = if output.wrap_untrusted && !request.json {
        let id = crate::output::untrusted_id()?;
        let _ = writeln!(env.stderr, "{}", crate::output::untrusted_notice(&id));
        Some(id)
    } else {
        None
    };
    let too_many = || {
        PurviewError::message(format!(
            "--json holds every record in memory and stops at {JSON_MAX_RECORDS}; use JSON \
             Lines (the default, or --jsonl), or add --force-buffer"
        ))
    };
    let mut buffered: Vec<serde_json::Value> = Vec::new();
    let mut unprinted = 0usize;
    let mut written = 0usize;
    let mut dedup = Dedup::new(request.max_unique);
    let read = {
        let stdout = &mut env.stdout;
        let redactor = env.redactor.clone();
        items::read(&request.zip, limits, &request.filters, |row| {
            if !request.all_rows {
                dedup.add(row)?;
                // A document past the limit is certain to be refused: stop
                // now rather than hold the rest.
                if request.json && !request.force_buffer && dedup.len() > JSON_MAX_RECORDS {
                    return Err(too_many());
                }
                return Ok(());
            }
            if request.json {
                if buffered.len() == JSON_MAX_RECORDS && !request.force_buffer {
                    return Err(too_many());
                }
                buffered.push(row.record());
                return Ok(());
            }
            written += 1;
            if !crate::output::write_json_line(
                stdout,
                &redactor,
                marker.as_deref(),
                row.record(),
                &["key"],
            )? {
                unprinted += 1;
            }
            Ok(())
        })
    };
    // The path is the user's own argument and is not repeated. A failed
    // stdout under --all-rows keeps its own error, for cli to report.
    let tally = read.map_err(|error| match error {
        PurviewError::Io(io) if !env.stdout.has_failed() => {
            PurviewError::message(format!("the zip given cannot be read: {}", io.kind()))
        }
        other => other,
    })?;
    let unique = (dedup.len(), dedup.hash_keys());
    if !request.all_rows {
        let found = dedup.finish();
        if request.json && found.len() > JSON_MAX_RECORDS && !request.force_buffer {
            return Err(too_many());
        }
        for (key, agg) in &found {
            let record = items::unique_record(key, agg);
            if request.json {
                buffered.push(record);
                continue;
            }
            written += 1;
            if !crate::output::write_json_line(
                &mut env.stdout,
                &env.redactor,
                marker.as_deref(),
                record,
                &["key"],
            )? {
                unprinted += 1;
            }
        }
    }
    items_summary(
        &mut env.stderr,
        "parse items",
        &tally,
        request.all_rows.then_some(written),
        unique,
    );
    if unprinted > 0 {
        let _ = writeln!(
            env.stderr,
            "warning: {unprinted} records held a secret that could not be removed, and were \
             written as their key and an error"
        );
    }
    let exit_code = if unprinted > 0 { 4 } else { 0 };
    if request.json {
        let count = buffered.len();
        let document = output.untrusted_json_value(
            serde_json::Value::Array(buffered),
            count,
            &env.redactor,
        )?;
        return Ok(Produced {
            exit_code,
            document: Some(document),
        });
    }
    Ok(Produced {
        exit_code,
        document: None,
    })
}

/// The checked arguments of `parse profile`.
#[derive(Debug, Clone)]
pub struct ProfileRequest {
    pub zip: PathBuf,
    pub filters: Filters,
    pub max_unique: usize,
    pub identity: Identity,
    pub options: Options,
}

/// `parse profile`: one document, or a `SECTION`, `NAME`, `COUNT` table,
/// and the summary of `parse items` on stderr.
pub fn profile(
    env: &mut Env,
    output: &OutputOptions,
    request: &ProfileRequest,
    limits: ReportLimits,
) -> Result<Produced> {
    let read = profile::read(
        &request.zip,
        limits,
        &request.filters,
        request.max_unique,
        &request.identity,
        request.options,
    )
    // The path is the user's own argument and is not repeated.
    .map_err(|error| match error {
        PurviewError::Io(io) => {
            PurviewError::message(format!("the zip given cannot be read: {}", io.kind()))
        }
        other => other,
    })?;
    items_summary(
        &mut env.stderr,
        "parse profile",
        &read.tally,
        None,
        read.unique,
    );
    if output.format == OutputFormat::Json {
        return Ok(Produced::success(Some(output.untrusted_json_value(
            read.profile.to_value(),
            1,
            &env.redactor,
        )?)));
    }
    let table: Vec<Vec<String>> = read
        .profile
        .rows()
        .into_iter()
        .map(|[section, name, count]| {
            vec![
                section,
                super::cut(
                    &sanitize(&crate::redact::shown(&name, &env.redactor)),
                    PROFILE_NAME_WIDTH,
                ),
                count,
            ]
        })
        .collect();
    write_rows(&mut env.stdout, output, PROFILE_COLUMNS, &table)?;
    Ok(Produced::success(None))
}

/// The stderr summary of `parse items` and `parse profile` (`command`):
/// counts and column names only, never a field's text. `rows_written` is
/// set under `--all-rows`. `unique` is the unique items and those keyed by
/// hash.
pub fn items_summary(
    log: &mut dyn Write,
    command: &str,
    tally: &Tally,
    rows_written: Option<usize>,
    unique: (usize, usize),
) {
    let plural =
        |count: u64, word: &str| format!("{count} {word}{}", if count == 1 { "" } else { "s" });
    let what = match rows_written {
        Some(_) => format!("{} written", plural(tally.matched, "row")),
        None => format!(
            "{} ({} keyed by a hash of their fields)",
            plural(unique.0 as u64, "unique item"),
            unique.1
        ),
    };
    let _ = writeln!(
        log,
        "{command}: {} read from {}, {} matched the filters; {what}",
        plural(tally.rows, "row"),
        plural(tally.files as u64, "Items file"),
        tally.matched,
    );
    if !tally.missing_columns.is_empty() {
        let names: Vec<&str> = tally.missing_columns.iter().copied().collect();
        let _ = writeln!(
            log,
            "warning: columns missing from the report's Items files: {}",
            names.join(", ")
        );
    }
    if tally.hash_rows > 0 {
        let _ = writeln!(
            log,
            "warning: {} had neither an Internet message ID nor an Immutable ID and were \
             keyed by a hash of their class, date, sender, subject and conversation name; \
             copies of one item may then count as different items",
            plural(tally.hash_rows, "matched row")
        );
    }
    if tally.unreadable_dates > 0 {
        let _ = writeln!(
            log,
            "warning: {} had a Date that could not be read; their date is null, and a date \
             filter leaves them out",
            plural(tally.unreadable_dates, "row")
        );
    }
}
