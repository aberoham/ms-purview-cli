//! `operation list` and `operation get` (`docs/SPEC.md` section 3.5).

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::{
    case_id, date_text, shown, shown_fields, shown_rows, time_text, warn_incomplete,
    warn_unreadable, Produced, Session,
};
use crate::error::{PurviewError, Result};
use crate::graph::GraphClient;
use crate::model::valid::CaseKey;
use crate::model::wire::{
    identity, Action, OperationDetail, OperationRecord, OperationStatus, Source,
};
use crate::output::{sanitize, write_fields, write_rows, OutputFormat};
use crate::poll::{elapsed_text, PollEnd, Poller, Timing};
use crate::report::estimate::Collection;
use crate::report::EvidenceOf;
use crate::routes::{CaseId, OperationId, Query, ReadRoute};

/// Operations read at once by `operation list --resolve`.
pub const RESOLVE_CONCURRENCY: usize = 4;

pub const LIST_COLUMNS: &[&str] = &[
    "ID",
    "ACTION",
    "STATUS",
    "CREATED",
    "COMPLETED",
    "CREATED BY",
    "ITEMS",
    "FILES",
];

/// `--action` of `operation list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ActionFilter {
    #[default]
    Any,
    Estimate,
    Report,
    Export,
}

impl ActionFilter {
    /// Whether the filter needs each operation read on its own: the list
    /// shows a report and an export alike (Observed).
    pub fn needs_resolve(self) -> bool {
        matches!(self, Self::Report | Self::Export)
    }

    /// Whether an entry of the list could pass, before it is resolved.
    fn may_admit(self, action: &Action) -> bool {
        match self {
            Self::Any => true,
            Self::Estimate => *action == Action::Estimate,
            Self::Report | Self::Export => matches!(
                action,
                Action::ExportReport | Action::ExportResult | Action::ExportReportOrResult
            ),
        }
    }

    fn admits(self, action: &Action) -> bool {
        match self {
            Self::Any => true,
            Self::Estimate => *action == Action::Estimate,
            Self::Report => *action == Action::ExportReport,
            Self::Export => *action == Action::ExportResult,
        }
    }
}

/// The filters of `operation list`, already checked.
#[derive(Debug, Clone, Default)]
pub struct ListFilters {
    pub action: ActionFilter,
    /// A status as Graph spells it.
    pub status: Option<String>,
    pub resolve: bool,
}

/// A `--status` value: one of the documented statuses, ignoring case,
/// returned as Graph spells it.
pub fn status_filter(text: &str) -> Result<String> {
    OperationStatus::KNOWN
        .iter()
        .find(|known| known.eq_ignore_ascii_case(text.trim()))
        .map(|known| (*known).to_owned())
        .ok_or_else(|| {
            PurviewError::message(format!(
                "--status must be one of {}",
                OperationStatus::KNOWN.join(", ")
            ))
        })
}

/// One entry of the list, and where its record came from.
struct Entry {
    record: OperationRecord,
    source: Source,
}

/// `operation list <case>`.
pub async fn list(
    session: &mut Session<'_>,
    case: &CaseKey,
    filters: &ListFilters,
) -> Result<Produced> {
    let case = case_id(&session.graph, case, &mut session.env.stderr).await?;
    let listing = session
        .graph
        .list(
            &ReadRoute::Operations(case),
            &Query::new(),
            &mut session.env.stderr,
        )
        .await?;
    warn_incomplete(&mut session.env.stderr, "operation", &listing);
    let total = listing.items.len();
    let records: Vec<OperationRecord> = listing
        .items
        .into_iter()
        .filter_map(OperationRecord::from_value)
        .collect();
    warn_unreadable(&mut session.env.stderr, "operation", total - records.len());
    let status_admits = |record: &OperationRecord| {
        filters
            .status
            .as_deref()
            .is_none_or(|wanted| record.status.as_str() == wanted)
    };
    let mut entries: Vec<Entry> = records
        .into_iter()
        .filter(|record| status_admits(record))
        .filter(|record| filters.action.may_admit(&record.action(Source::List)))
        .map(|record| Entry {
            record,
            source: Source::List,
        })
        .collect();
    if filters.resolve {
        resolve(session, case, &mut entries).await?;
        entries.retain(|entry| status_admits(&entry.record));
    }
    entries.retain(|entry| filters.action.admits(&entry.record.action(entry.source)));
    warn_invalid_counts(
        &session.env.redactor.clone(),
        &mut session.env.stderr,
        entries.iter().map(|entry| &entry.record),
    );
    if session.output.format == OutputFormat::Json {
        let count = entries.len();
        let raw: Vec<Value> = entries
            .into_iter()
            .map(|entry| {
                let mut raw = entry.record.raw;
                if let Value::Object(object) = &mut raw {
                    object.insert("actionSource".into(), json!(entry.source.as_str()));
                }
                raw
            })
            .collect();
        return Ok(Produced::success(Some(
            session
                .output
                .untrusted_json_value(Value::Array(raw), count, &session.env.redactor)?,
        )));
    }
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|entry| {
            let record = &entry.record;
            let detail = (entry.source == Source::Single)
                .then(|| record.detail())
                .flatten();
            vec![
                record.id.clone().unwrap_or_else(|| "?".to_owned()),
                record.action(entry.source).label().to_owned(),
                record.status.as_str().to_owned(),
                date_text(record.created_date_time),
                date_text(record.completed_date_time),
                identity::shown(record.created_by.as_ref()),
                match &detail {
                    Some(OperationDetail::Estimate(estimate)) => estimate
                        .indexed_item_count
                        .map(|count| count.to_string())
                        .unwrap_or_default(),
                    _ => String::new(),
                },
                detail
                    .as_ref()
                    .map(|detail| detail.files().len().to_string())
                    .unwrap_or_default(),
            ]
        })
        .collect();
    let rows = shown_rows(session, rows);
    write_rows(&mut session.env.stdout, session.output, LIST_COLUMNS, &rows)?;
    if entries
        .iter()
        .any(|entry| entry.record.action(entry.source) == Action::ExportReportOrResult)
    {
        let _ = writeln!(
            session.env.stderr,
            "note: the operation list shows both item reports and exports as exportResult, so \
             their ACTION reads exportResult?; --resolve reads each operation to tell them apart"
        );
    }
    Ok(Produced::success(None))
}

/// Replaces each list entry with a single GET of the operation, at most
/// `RESOLVE_CONCURRENCY` at a time. An entry without a valid id keeps its
/// list record, with a warning. Any failed read fails the command: reads
/// not yet sent are skipped, and a token that cannot be had is reported in
/// preference to Graph's answers.
async fn resolve(session: &mut Session<'_>, case: CaseId, entries: &mut [Entry]) -> Result<()> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(RESOLVE_CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    let mut unresolvable = 0;
    let failed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    for (index, entry) in entries.iter().enumerate() {
        let Some(id) = entry.record.id.as_deref().and_then(OperationId::parse) else {
            unresolvable += 1;
            continue;
        };
        let graph: Arc<GraphClient> = session.graph.clone();
        let semaphore = semaphore.clone();
        let failed = failed.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            let mut log = Vec::new();
            if failed.load(std::sync::atomic::Ordering::SeqCst) {
                return (index, None, log);
            }
            let read = graph
                .get(&ReadRoute::Operation(case, id), &Query::new(), &mut log)
                .await;
            if read.is_err() {
                failed.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            (index, Some(read), log)
        });
    }
    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        results.push(
            joined.map_err(|error| PurviewError::message(format!("a read stopped: {error}")))?,
        );
    }
    results.sort_by_key(|(index, _, _)| *index);
    let mut failure: Option<PurviewError> = None;
    for (index, read, log) in results {
        session.env.stderr.write_all(&log)?;
        let Some(read) = read else {
            continue;
        };
        match read.and_then(|body| {
            OperationRecord::from_value(body).ok_or_else(|| {
                PurviewError::message("Graph returned an operation that is not an object")
            })
        }) {
            Ok(record) => {
                entries[index] = Entry {
                    record,
                    source: Source::Single,
                };
            }
            Err(error) => {
                let keep = failure
                    .as_ref()
                    .is_some_and(|kept| kept.is_token_unavailable());
                if !keep {
                    failure = Some(error);
                }
            }
        }
    }
    if let Some(error) = failure {
        return Err(error.context("resolving the operations"));
    }
    if unresolvable > 0 {
        let _ = writeln!(
            session.env.stderr,
            "warning: {unresolvable} operations have no valid id and were not resolved"
        );
    }
    Ok(())
}

pub(crate) fn warn_invalid_counts<'a>(
    redactor: &crate::redact::Redactor,
    log: &mut dyn Write,
    records: impl Iterator<Item = &'a OperationRecord>,
) {
    for record in records {
        if !record.invalid_counts.is_empty() {
            let _ = writeln!(
                log,
                "warning: operation {} has fields that are not counts ({}); they are shown as \
                 unknown",
                sanitize(&crate::redact::shown(
                    record.id.as_deref().unwrap_or("?"),
                    redactor
                )),
                record.invalid_counts.join(", ")
            );
        }
    }
}

/// What `operation get --check` downloads and reads with.
pub struct Check<'a> {
    pub download: &'a super::download::Context,
    pub limits: crate::report::ReportLimits,
}

/// How `operation get` waits, if it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    pub timing: Timing,
}

/// `operation get <case> <op>`, and with `--wait`, until it finishes. A
/// finished operation whose status is not `succeeded` exits 4; the
/// deadline exits 5, and Ctrl-C 130 (`docs/SPEC.md` section 3.3).
pub async fn get(
    session: &mut Session<'_>,
    case: &CaseKey,
    operation: &OperationId,
    wait: Option<Wait>,
    check: Option<Check<'_>>,
) -> Result<Produced> {
    let command_started = session.env.clock.elapsed();
    let case = case_id(&session.graph, case, &mut session.env.stderr).await?;
    let route = ReadRoute::Operation(case, operation.clone());
    let record = match wait {
        None => {
            let body = session
                .graph
                .get(&route, &Query::new(), &mut session.env.stderr)
                .await?;
            crate::poll::checked(body, &route)?
        }
        Some(wait) => {
            let started = session.env.clock.elapsed();
            let show_progress = session.env.stderr_is_terminal && !session.verbose;
            let interrupt = session.env.interrupt.clone();
            let clock = session.env.clock.clone();
            let poller = Poller {
                graph: &session.graph,
                clock: clock.as_ref(),
                interrupt: interrupt.as_ref(),
                timing: wait.timing,
                not_found_grace: None,
            };
            let shown_id = short_id(operation);
            let redactor = session.env.redactor.clone();
            let mut progress =
                |record: &OperationRecord, waited: Duration, log: &mut (dyn Write + Send)| {
                    if show_progress {
                        let _ = writeln!(
                            log,
                            "{} {shown_id}: {} · {}",
                            sanitize(&crate::redact::shown(
                                record.action(Source::Single).label(),
                                &redactor
                            )),
                            sanitize(&crate::redact::shown(record.status.as_str(), &redactor)),
                            elapsed_text(waited)
                        );
                    }
                };
            let end = poller
                .wait(&route, &mut session.env.stderr, &mut progress)
                .await?;
            let waited = clock.elapsed().saturating_sub(started);
            match end {
                PollEnd::Finished(record) => record,
                PollEnd::TimedOut { last } => {
                    return stopped(session, case, operation, last, waited, false);
                }
                PollEnd::Interrupted { last } => {
                    return stopped(session, case, operation, last, waited, true);
                }
            }
        }
    };
    warn_invalid_counts(
        &session.env.redactor.clone(),
        &mut session.env.stderr,
        std::iter::once(&record),
    );
    let collection = match check {
        Some(check) => match check_collection(session, case, operation, &record, check).await? {
            Some(collection) => Some(collection),
            None => {
                let waited = session.env.clock.elapsed().saturating_sub(command_started);
                return stopped(session, case, operation, Some(record), waited, true);
            }
        },
        None => None,
    };
    show(session, &record, collection)
}

/// `--check`: the evidence file of a finished estimate, item report or
/// export downloaded into the data directory (a verified copy there is
/// reused), and the collection check for its action. An operation that is
/// not finished, or of another action, stays unchecked. `None` when
/// Ctrl-C stopped the download.
async fn check_collection(
    session: &mut Session<'_>,
    case: CaseId,
    operation: &OperationId,
    record: &OperationRecord,
    check: Check<'_>,
) -> Result<Option<Collection>> {
    let action = record.action(Source::Single);
    let evidence_of = match action {
        Action::Estimate => EvidenceOf::Estimate,
        Action::ExportReport | Action::ExportResult => EvidenceOf::Report,
        _ => return Ok(Some(Collection::Unchecked)),
    };
    if !record.status.is_terminal() {
        let _ = writeln!(
            session.env.stderr,
            "notice: the operation is not finished, so --check has nothing to read yet"
        );
        return Ok(Some(Collection::Unchecked));
    }
    // An export's evidence is its report part (Assumption: named
    // Reports-…); the other actions have only the report.
    let file = match action {
        Action::ExportResult => record.detail().and_then(|detail| {
            detail
                .files()
                .iter()
                .filter_map(|file| file.file_name.clone())
                .find(|name| name.starts_with("Reports-"))
        }),
        _ => None,
    };
    if action == Action::ExportResult && file.is_none() {
        let _ = writeln!(
            session.env.stderr,
            "warning: collection unchecked: the export lists no Reports- file"
        );
        return Ok(Some(Collection::Unchecked));
    }
    let request = super::download::Request {
        case: CaseKey::Id(case),
        operation: operation.clone(),
        out: None,
        file,
        overwrite: false,
    };
    let fetched = super::download::fetch(session, case, record, &request, check.download).await?;
    for reason in &fetched.reasons {
        if reason["code"] == "FileNotDownloadable" {
            let _ = writeln!(
                session.env.stderr,
                "warning: {}",
                sanitize(reason["message"].as_str().unwrap_or_default())
            );
        }
    }
    if fetched.interrupted {
        return Ok(None);
    }
    for done in &fetched.done {
        match crate::report::ReportFiles::read(&done.path, check.limits) {
            Ok(files) if files.locations.is_some() || files.statistics_errors.is_some() => {
                super::parse::warn_missing_columns(&mut session.env.stderr, &files);
                let _ = writeln!(
                    session.env.stderr,
                    "notice: checked {}",
                    sanitize(&done.path.display().to_string())
                );
                return Ok(Some(files.collection(evidence_of)));
            }
            Ok(_) => {}
            Err(error) => {
                let _ = writeln!(
                    session.env.stderr,
                    "warning: a downloaded file could not be read as a report zip ({})",
                    error.metadata().0
                );
            }
        }
    }
    let _ = writeln!(
        session.env.stderr,
        "warning: collection unchecked: no downloaded file is a report zip"
    );
    Ok(Some(Collection::Unchecked))
}

/// `3f2a…` for progress lines.
fn short_id(operation: &OperationId) -> String {
    let text = operation.to_string();
    format!("{}…", &text[..8.min(text.len())])
}

/// The exit-4 reason for a finished operation that did not succeed, or
/// `None` when it succeeded.
pub(crate) fn incomplete_reason(record: &OperationRecord) -> Option<Value> {
    let code = match &record.status {
        OperationStatus::Succeeded => return None,
        OperationStatus::PartiallySucceeded => "OperationPartiallySucceeded",
        OperationStatus::Failed => "OperationFailed",
        OperationStatus::SubmissionFailed => "OperationSubmissionFailed",
        OperationStatus::NotStarted | OperationStatus::Running => return None,
        OperationStatus::Missing | OperationStatus::Other(_) => "UnknownStatus",
    };
    let mut message = format!(
        "the operation finished with status {}",
        record.status.as_str()
    );
    if let Some(info) = &record.result_info {
        let summary = info.summary();
        if !summary.is_empty() {
            message.push_str(": ");
            message.push_str(&summary);
        }
    }
    Some(json!({"code": code, "message": message}))
}

/// Prints the operation. JSON keeps Graph's record, `downloadUrl`
/// included, and adds `collection: unchecked` for an estimate, report or
/// export, whose collection check arrives with `--check`.
fn show(
    session: &mut Session<'_>,
    record: &OperationRecord,
    collection: Option<Collection>,
) -> Result<Produced> {
    let collection_text = collection.unwrap_or(Collection::Unchecked).as_str();
    let action = record.action(Source::Single);
    let collects = matches!(
        action,
        Action::Estimate | Action::ExportReport | Action::ExportResult
    );
    // The reason quotes Graph's result message, which can hold a URL.
    let reason = incomplete_reason(record).map(|mut reason| {
        let message = shown(session, reason["message"].as_str().unwrap_or_default());
        reason["message"] = json!(message);
        reason
    });
    let exit_code = if reason.is_some() { 4 } else { 0 };
    if session.output.format == OutputFormat::Json {
        let mut raw = record.raw.clone();
        if let (true, Value::Object(object)) = (collects, &mut raw) {
            object.insert("collection".into(), json!(collection_text));
        }
        let document = match &reason {
            None => session
                .output
                .untrusted_json_value(raw, 1, &session.env.redactor)?,
            // Exit 4 prints the whole envelope, whatever --results-only
            // says, so that the outcome has somewhere to go.
            Some(reason) => {
                let mut output = session.output.clone();
                output.results_only = false;
                let mut document = output.untrusted_json_value(raw, 1, &session.env.redactor)?;
                if let Value::Object(object) = &mut document {
                    object.insert(
                        "outcome".into(),
                        json!({"code": "Incomplete", "reasons": [reason]}),
                    );
                }
                document
            }
        };
        return Ok(Produced {
            exit_code,
            document: Some(document),
        });
    }
    let mut fields = vec![
        ("ID", record.id.clone().unwrap_or_default()),
        ("Action", action.label().to_owned()),
        ("Status", record.status.as_str().to_owned()),
        (
            "Progress",
            record
                .percent_progress
                .map(|percent| format!("{percent}%"))
                .unwrap_or_default(),
        ),
        ("Created", time_text(record.created_date_time)),
        ("Created by", identity::shown(record.created_by.as_ref())),
        ("Completed", time_text(record.completed_date_time)),
        (
            "Result",
            record
                .result_info
                .as_ref()
                .map(|info| info.summary())
                .unwrap_or_default(),
        ),
    ];
    let count = |value: Option<u64>| value.map(|value| value.to_string()).unwrap_or_default();
    let detail = record.detail();
    match &detail {
        Some(OperationDetail::Estimate(estimate)) => fields.extend([
            ("Indexed items", count(estimate.indexed_item_count)),
            ("Indexed size", count(estimate.indexed_items_size)),
            ("Unindexed items", count(estimate.unindexed_item_count)),
            ("Unindexed size", count(estimate.unindexed_items_size)),
            ("Locations with hits", count(estimate.mailbox_count)),
            ("Sites with hits", count(estimate.site_count)),
        ]),
        Some(OperationDetail::SearchExport(export)) => fields.extend([
            ("Name", export.display_name.clone().unwrap_or_default()),
            (
                "Description",
                export.description.clone().unwrap_or_default(),
            ),
            ("Format", export.export_format.clone().unwrap_or_default()),
            (
                "Criteria",
                export.export_criteria.clone().unwrap_or_default(),
            ),
            (
                "Location",
                export.export_location.clone().unwrap_or_default(),
            ),
            (
                "Options",
                export.additional_options.clone().unwrap_or_default(),
            ),
        ]),
        None => {}
    }
    if let Some(detail) = &detail {
        for file in detail.files() {
            fields.push((
                "File",
                format!(
                    "{} ({})",
                    file.file_name.as_deref().unwrap_or("?"),
                    file.size
                        .map(|size| format!("{size} bytes"))
                        .unwrap_or_else(|| "size unknown".to_owned())
                ),
            ));
        }
    }
    if collects {
        fields.push(("Collection", collection_text.to_owned()));
    }
    let fields = shown_fields(session, fields);
    write_fields(&mut session.env.stdout, &fields)?;
    if let Some(reason) = reason {
        let _ = writeln!(
            session.env.stderr,
            "warning: operation {}: {}",
            sanitize(record.id.as_deref().unwrap_or("?")),
            sanitize(&shown(
                session,
                reason["message"].as_str().unwrap_or_default()
            ))
        );
    }
    Ok(Produced {
        exit_code,
        document: None,
    })
}

/// Exit 5 at the deadline, 130 on Ctrl-C: the last status read and the
/// command that resumes the wait (`docs/SPEC.md` section 3.3).
pub(crate) fn stopped(
    session: &mut Session<'_>,
    case: CaseId,
    operation: &OperationId,
    last: Option<OperationRecord>,
    waited: Duration,
    interrupted: bool,
) -> Result<Produced> {
    // An unknown status is Graph's text, so it is shown as tenant text.
    let status = last
        .as_ref()
        .map(|record| shown(session, record.status.as_str()));
    // Only a status read as still running is described as running.
    let still_running = last
        .as_ref()
        .is_some_and(|record| !record.status.is_terminal());
    let carries_on = if still_running {
        "; the service carries on running the operation"
    } else {
        ""
    };
    // The account is named, attached with `=` so that a name beginning
    // with `-` stays its value, and the command resumes as the same
    // identity whatever the default is then.
    let account = shell_word(&session.account.email);
    // Every command of this release that carries on from here: the wait,
    // then the download of the finished operation's files.
    let resume = [
        format!("purview --account={account} operation get {case} {operation} --wait"),
        format!("purview --account={account} download {case} {operation}"),
    ];
    let (exit_code, code, message) = if interrupted {
        (
            130,
            "Interrupted",
            format!("interrupted after {}{carries_on}", elapsed_text(waited)),
        )
    } else {
        (
            5,
            "WaitTimeout",
            format!("stopped waiting after {}{carries_on}", elapsed_text(waited)),
        )
    };
    if session.output.format == OutputFormat::Json {
        return Ok(Produced {
            exit_code,
            document: Some(json!({
                "caseId": case.to_string(),
                "operationId": operation.to_string(),
                "status": status,
                "elapsedSeconds": waited.as_secs(),
                "resume": resume,
                "error": {"code": code, "status": 0, "message": message},
            })),
        });
    }
    let _ = writeln!(
        session.env.stderr,
        "{message}. Operation {operation} was {}. Resume with: {}\nThen download its files \
         with: {}",
        status
            .as_deref()
            .map(sanitize)
            .unwrap_or_else(|| "not read yet".to_owned()),
        sanitize(&resume[0]),
        sanitize(&resume[1])
    );
    Ok(Produced {
        exit_code,
        document: None,
    })
}

/// `text` as one shell word: as it is when it holds only characters no
/// shell treats specially, else in single quotes.
pub(crate) fn shell_word(text: &str) -> String {
    if !text.is_empty()
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "@._+-=:/,".contains(character))
    {
        return text.to_owned();
    }
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_words_are_quoted_only_when_needed() {
        assert_eq!(
            shell_word("alex.w@contoso.example"),
            "alex.w@contoso.example"
        );
        assert_eq!(
            shell_word("o'neil@contoso.example"),
            "'o'\\''neil@contoso.example'"
        );
        assert_eq!(shell_word("a b"), "'a b'");
    }
}
