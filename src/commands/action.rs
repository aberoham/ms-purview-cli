//! The preflight every action on a search runs (`docs/SPEC.md` sections
//! 6.4 and 6.7): the search's scope and sources, the guard on its current
//! query, and the case's active operations that may be duplicates.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::download::{fetch, Request};
use super::operation::{incomplete_reason, stopped, Resume};
use super::{case_id, resolve_search, Produced};
use crate::error::{PurviewError, Result};
use crate::graph::{GraphClient, WriteResponse};
use crate::kql::{enforce, GuardConfig, Override};
use crate::model::valid::{CaseKey, SearchKey, SearchRef};
use crate::model::wire::{OperationDetail, OperationRecord, OperationStatus};
use crate::output::sanitize;
use crate::poll::{elapsed_text, PollEnd, Poller, Timing};
use crate::report::estimate::Collection;
use crate::report::{EvidenceOf, ReportFiles, ReportLimits};
use crate::routes::{CaseId, OperationId, Query, ReadRoute, SearchSources};
use crate::safety::After;

/// The one scope an action may run on.
pub const ALL_TENANT_MAILBOXES: &str = "allTenantMailboxes";

/// How long a 404 on a fresh operation counts as "not visible yet"
/// (`docs/SPEC.md` section 4.6; Assumption).
pub const NOT_FOUND_GRACE: Duration = Duration::from_secs(30);

/// The `action` values the operation list shows for an item report or an
/// export: `exportResult` for both (Observed), and `exportReport`, which a
/// single GET shows, in case the list ever does too.
pub const EXPORT_ACTIONS: [&str; 2] = ["exportResult", "exportReport"];

/// The three source lists, with their names in messages.
const SOURCES: [(SearchSources, &str); 3] = [
    (SearchSources::Custodian, "custodian"),
    (SearchSources::Noncustodial, "non-custodial"),
    (SearchSources::Additional, "additional"),
];

/// A search that passed the action preflight.
#[derive(Debug, Clone)]
pub struct Checked {
    pub case: CaseId,
    pub search: SearchRef,
    /// The search's `contentQuery`, which the guard checked.
    pub query: String,
    /// Whether the guard found it narrowed; `false` means the override
    /// let it through.
    pub narrowed: bool,
}

/// Steps 1 to 4 of section 6.4: the search by id or unique name, read by
/// its id; `dataSourceScopes` exactly `allTenantMailboxes`; the three
/// source lists empty, each read to its last page; and the guard on its
/// current query.
pub async fn check_search(
    graph: &GraphClient,
    case: &CaseKey,
    search: &SearchKey,
    guard: &GuardConfig,
    override_reason: Option<&str>,
    log: &mut (dyn Write + Send),
) -> Result<Checked> {
    let case = case_id(graph, case, log).await?;
    let search = resolve_search(graph, case, search, log).await?;
    match search.record.data_source_scopes.as_deref() {
        Some(ALL_TENANT_MAILBOXES) => {}
        None => {
            return Err(PurviewError::ScopeUnverified(format!(
                "search {} has no dataSourceScopes, so it cannot be shown to cover every tenant \
                 mailbox and nothing else; nothing was sent",
                search.id
            )))
        }
        // The scope is Graph's text and is not repeated.
        Some(_) => {
            return Err(PurviewError::ScopeNotAllowed(format!(
                "search {} has a dataSourceScopes other than {ALL_TENANT_MAILBOXES}, and an action \
                 runs only on a search over every tenant mailbox and nothing else; nothing was \
                 sent",
                search.id
            )))
        }
    }
    for (sources, name) in SOURCES {
        let items = graph
            .list_bound(
                &ReadRoute::SearchSources(case, search.id, sources),
                &Query::new(),
                log,
            )
            .await
            .and_then(|listing| listing.complete())
            .map_err(|error| {
                let (code, status) = error.metadata();
                PurviewError::ScopeUnverified(format!(
                    "the {name} sources of search {} could not be read to their end ({code}{}), \
                     so the search cannot be shown to have none; nothing was sent",
                    search.id,
                    if status == 0 {
                        String::new()
                    } else {
                        format!(", HTTP {status}")
                    }
                ))
            })?;
        if !items.is_empty() {
            return Err(PurviewError::SearchHasSources(format!(
                "search {} has {} {name} source{}, which an action would also collect from; an \
                 action runs only on a search over every tenant mailbox with no sources; nothing \
                 was sent",
                search.id,
                items.len(),
                if items.len() == 1 { "" } else { "s" }
            )));
        }
    }
    let Some(query) = search
        .record
        .content_query
        .clone()
        .filter(|query| !query.trim().is_empty())
    else {
        return Err(PurviewError::message(format!(
            "search {} has no query, so the guard cannot check it; nothing was sent",
            search.id
        )));
    };
    let allow = match override_reason {
        Some(reason) => Override::AllowGeneric { reason },
        None => Override::None,
    };
    let analysis = enforce(&query, guard, allow)
        .map_err(|error| error.context(format!("the query of search {}", search.id)))?;
    Ok(Checked {
        case,
        search,
        query,
        narrowed: analysis.narrowed,
    })
}

/// An operation that may be a duplicate of the one an action would start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active {
    pub id: String,
    pub status: String,
    pub created: Option<DateTime<Utc>>,
}

impl Active {
    /// `<id> (<status>, created <time>)`.
    pub fn describe(&self) -> String {
        format!(
            "{} ({}, created {})",
            self.id,
            self.status,
            self.created
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_else(|| "?".into())
        )
    }
}

/// The case's operations with one of `actions` (`estimateStatistics`, or
/// `EXPORT_ACTIONS` for reports and exports) that are not known to be
/// finished, read to the last page; an entry whose action or status cannot
/// be read is kept, since it cannot be ruled out. `$expand=search` is
/// refused (Observed), so they cannot be narrowed to the search.
pub async fn active_operations(
    graph: &GraphClient,
    case: CaseId,
    actions: &[&str],
    log: &mut (dyn Write + Send),
) -> Result<Vec<Active>> {
    let items = graph
        .list_bound(&ReadRoute::Operations(case), &Query::new(), log)
        .await?
        .complete()
        .map_err(|error| error.context("listing the case's operations"))?;
    let mut active = Vec::new();
    for item in items {
        // An entry that cannot be read could be an unfinished estimate,
        // so it counts as one that may be a duplicate.
        let Some(record) = OperationRecord::from_value(item) else {
            active.push(Active {
                id: "?".into(),
                status: "unreadable".into(),
                created: None,
            });
            continue;
        };
        // Only an entry known to be of another action, or known to be
        // finished, is ruled out.
        let other_action = record
            .action
            .as_deref()
            .map(str::trim)
            .is_some_and(|found| !found.is_empty() && !actions.contains(&found));
        let finished = matches!(
            record.status,
            OperationStatus::Succeeded
                | OperationStatus::PartiallySucceeded
                | OperationStatus::Failed
                | OperationStatus::SubmissionFailed
        );
        if other_action || finished {
            continue;
        }
        // Ids are checked: anything else is Graph's text.
        let id = record
            .id
            .as_deref()
            .and_then(OperationId::parse)
            .map(|id| id.to_string())
            .unwrap_or_else(|| "?".into());
        let status = match &record.status {
            OperationStatus::NotStarted | OperationStatus::Running => {
                record.status.as_str().to_owned()
            }
            _ => "unknown status".to_owned(),
        };
        active.push(Active {
            id,
            status,
            created: record.created_date_time,
        });
    }
    Ok(active)
}

/// The operations with one of `actions` that the signed-in account may
/// have started at or after `since`, for reconciliation (`docs/SPEC.md`
/// section 6.7): by `createdBy` when the record has it, else every one
/// created since then. Pages read before a failure are kept.
pub async fn started_since(
    graph: &GraphClient,
    case: CaseId,
    actions: &[&str],
    since: DateTime<Utc>,
    account: &crate::config::AccountRecord,
    log: &mut (dyn Write + Send),
) -> Result<(Vec<Active>, bool, Option<PurviewError>)> {
    let (listing, failure) = graph
        .list_partial(&ReadRoute::Operations(case), &Query::new(), log)
        .await?;
    let incomplete = failure.is_some() || listing.stopped.is_some();
    let mut found = Vec::new();
    for item in listing.items {
        let Some(record) = OperationRecord::from_value(item) else {
            continue;
        };
        if !record
            .action
            .as_deref()
            .is_some_and(|found| actions.contains(&found))
            || record
                .created_date_time
                .is_none_or(|created| created < since)
        {
            continue;
        }
        if let Some(creator) = record.created_by.as_ref() {
            if !created_by(creator, account) {
                continue;
            }
        }
        found.push(Active {
            id: record
                .id
                .as_deref()
                .and_then(OperationId::parse)
                .map(|id| id.to_string())
                .unwrap_or_else(|| "?".into()),
            // Only a status Graph documents is repeated: anything else is
            // Graph's text.
            status: match &record.status {
                OperationStatus::Missing => "?".to_owned(),
                OperationStatus::Other(_) => "unknown status".to_owned(),
                known => known.as_str().to_owned(),
            },
            created: record.created_date_time,
        });
    }
    Ok((found, incomplete, failure))
}

/// Whether `creator` (a `createdBy` identity set) is the account: by user
/// id, else by user principal name, ignoring case. A set with neither is
/// taken as a match, since it cannot be ruled out.
fn created_by(creator: &Value, account: &crate::config::AccountRecord) -> bool {
    use crate::model::wire::identity;
    if let Some(id) = identity::user_id(creator) {
        return !account.oid.is_empty() && id.eq_ignore_ascii_case(&account.oid);
    }
    match identity::upn(creator) {
        Some(upn) => {
            let stored = account
                .upn
                .as_deref()
                .filter(|upn| !upn.is_empty())
                .unwrap_or(&account.email);
            upn.eq_ignore_ascii_case(stored)
        }
        None => true,
    }
}

/// What an action sent, for the part of its run after the one `POST`: the
/// 202 and its `Location` header, the wait, the check that the operation
/// is of the action sent, the download and the collection check
/// (`docs/SPEC.md` section 3.5).
pub struct ActionRun {
    /// `estimate` or `report`, for messages.
    pub label: &'static str,
    /// `an estimate` or `an item report`.
    pub noun: &'static str,
    /// The operation's `action`: `estimateStatistics` or `exportReport`.
    pub action: &'static str,
    pub evidence_of: EvidenceOf,
    /// The command that lists the operation, after the case id.
    pub list_hint: &'static str,
    pub no_wait: bool,
    pub no_download: bool,
    pub timing: Timing,
    pub out: Option<PathBuf>,
    pub limits: Option<ReportLimits>,
}

/// How the run after the send ended.
#[allow(clippy::large_enum_variant)] // One per command run; never stored.
pub enum Sent {
    /// A document in its own shape: the wait deadline or Ctrl-C.
    Produced(Produced),
    /// `--no-wait`: the operation the 202 named.
    Submitted(OperationId),
    /// The operation finished, and its files were read unless
    /// `--no-download`.
    Finished(Finished),
}

/// A finished action.
pub struct Finished {
    pub operation: OperationId,
    pub record: OperationRecord,
    pub evidence: Option<ReportFiles>,
    /// Why the collection is unchecked, when it is for want of evidence.
    pub evidence_note: Option<String>,
    /// Each file with its path, size, SHA-256 and download status.
    pub files: Vec<Value>,
    /// Exit-4 reasons so far.
    pub reasons: Vec<Value>,
    pub collection: Collection,
}

impl ActionRun {
    fn hint(&self, case: CaseId) -> String {
        format!(
            "the {} may be running; 'purview operation list {case} {}' lists it",
            self.label, self.list_hint
        )
    }

    /// The run after the one `POST`. Before returning a finished run, it
    /// warns of missing columns and, for an operation that succeeded, of
    /// locations not searched in full.
    pub async fn after_send(
        &self,
        after: &mut After<'_>,
        response: WriteResponse,
        case: CaseId,
    ) -> Result<Sent> {
        let label = self.label;
        let hint = self.hint(case);
        if response.status != 202 {
            return Err(PurviewError::UnexpectedLocation(format!(
                "Graph answered the {label} with HTTP {}, where 202 and a Location header were \
                 observed; {hint}",
                response.status
            )));
        }
        let operation = response
            .location
            .as_deref()
            .and_then(|location| after.session.graph.operation_in_location(location, case))
            .ok_or_else(|| {
                // The header is Graph's text and is not repeated.
                PurviewError::UnexpectedLocation(format!(
                    "Graph accepted the {label} (HTTP {}) but its Location header does not name \
                     an operation of case {case} in a known form; {hint}",
                    response.status
                ))
            })?;
        if self.no_wait {
            return Ok(Sent::Submitted(operation));
        }
        let session = &mut after.session;
        let started = session.env.clock.elapsed();
        let clock = session.env.clock.clone();
        let interrupt = session.env.interrupt.clone();
        let graph = session.graph.clone();
        let poller = Poller {
            graph: &graph,
            clock: clock.as_ref(),
            interrupt: interrupt.as_ref(),
            timing: self.timing,
            not_found_grace: Some(NOT_FOUND_GRACE),
        };
        let show_progress = session.env.stderr_is_terminal && !session.verbose;
        let shown_id = format!("{}…", &operation.to_string()[..8]);
        let mut progress =
            |record: &OperationRecord, waited: Duration, log: &mut (dyn Write + Send)| {
                if show_progress {
                    let _ = writeln!(
                        log,
                        "{label} {shown_id}: {} · {}",
                        sanitize(record.status.as_str()),
                        elapsed_text(waited)
                    );
                }
            };
        let route = ReadRoute::Operation(case, operation.clone());
        let end = poller
            .wait(&route, &mut session.env.stderr, &mut progress)
            .await?;
        let waited = clock.elapsed().saturating_sub(started);
        let record = match end {
            PollEnd::Finished(record) => record,
            PollEnd::TimedOut { last } => {
                return Ok(Sent::Produced(stopped(
                    session,
                    case,
                    &operation,
                    last,
                    waited,
                    false,
                    Resume::WaitThenDownload,
                )?))
            }
            PollEnd::Interrupted { last } => {
                return Ok(Sent::Produced(stopped(
                    session,
                    case,
                    &operation,
                    last,
                    waited,
                    true,
                    Resume::WaitThenDownload,
                )?))
            }
        };
        // The operation the header named must be of the action sent: its
        // files are then a report, never item content.
        let detail_matches = matches!(
            (self.evidence_of, record.detail()),
            (EvidenceOf::Estimate, Some(OperationDetail::Estimate(_)))
                | (EvidenceOf::Report, Some(OperationDetail::SearchExport(_)))
        );
        if record.action.as_deref() != Some(self.action) || !detail_matches {
            return Err(PurviewError::UnexpectedLocation(format!(
                "operation {operation} of case {case}, which the {label}'s Location header named, \
                 is not {}; nothing was downloaded. {hint}",
                self.noun
            )));
        }
        super::operation::warn_invalid_counts(
            &after.session.env.redactor.clone(),
            &mut after.session.env.stderr,
            std::iter::once(&record),
        );
        let mut reasons: Vec<Value> = Vec::new();
        let mut files: Vec<Value> = Vec::new();
        let mut evidence: Option<ReportFiles> = None;
        let mut evidence_note: Option<String> = None;
        if self.no_download {
            reasons.extend(incomplete_reason(&record));
            evidence_note = Some("--no-download: the report zip was not read".into());
        } else {
            let context = after
                .download
                .ok_or_else(|| PurviewError::message(format!("{label} has no download client")))?;
            let request = Request {
                case: CaseKey::Id(case),
                operation: operation.clone(),
                out: self.out.clone(),
                file: None,
                overwrite: false,
            };
            let fetched = fetch(&mut after.session, case, &record, &request, context).await?;
            // The deadline covers the wait; the download has its own
            // timeouts (`docs/SPEC.md` section 4.7). Ctrl-C during it
            // reports the time since the action was sent.
            if fetched.interrupted {
                let waited = clock.elapsed().saturating_sub(started);
                return Ok(Sent::Produced(stopped(
                    &mut after.session,
                    case,
                    &operation,
                    Some(record),
                    waited,
                    true,
                    Resume::WaitThenDownload,
                )?));
            }
            reasons.extend(fetched.reasons);
            let limits = self.limits.unwrap_or_else(|| {
                ReportLimits::from_config(&Default::default()).expect("the defaults are valid")
            });
            for done in &fetched.done {
                files.push(json!({
                    "fileName": done.server_name,
                    "path": done.path.to_string_lossy(),
                    "size": done.bytes,
                    "sha256": done.sha256,
                    "status": done.status(),
                }));
                if evidence.is_none() {
                    match ReportFiles::read(&done.path, limits) {
                        Ok(read)
                            if read.locations.is_some() || read.statistics_errors.is_some() =>
                        {
                            evidence = Some(read);
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let (code, _) = error.metadata();
                            evidence_note = Some(format!(
                                "a downloaded file could not be read as a report zip ({code})"
                            ));
                        }
                    }
                }
            }
            if evidence.is_none() && evidence_note.is_none() {
                evidence_note = Some("no downloaded file is a report zip".into());
            }
        }
        let collection = evidence.as_ref().map_or(Collection::Unchecked, |files| {
            files.collection(self.evidence_of)
        });
        let log = &mut after.session.env.stderr;
        if let Some(files) = &evidence {
            super::parse::warn_missing_columns(log, files);
        }
        if let Collection::Incomplete { failed } = collection {
            if record.status == OperationStatus::Succeeded {
                let _ = writeln!(
                    log,
                    "warning: the {label} succeeded, but {failed} location{} {} not searched in \
                     full; --strict makes this exit 4",
                    if failed == 1 { "" } else { "s" },
                    if failed == 1 { "was" } else { "were" }
                );
            }
        }
        Ok(Sent::Finished(Finished {
            operation,
            record,
            evidence,
            evidence_note,
            files,
            reasons,
            collection,
        }))
    }
}

impl Finished {
    /// The warning that the collection is unchecked for want of evidence,
    /// then, under `--strict`, the reason an incomplete or unchecked
    /// collection gives.
    pub fn finish(&mut self, log: &mut (dyn Write + Send), no_download: bool, strict: bool) {
        if let (Collection::Unchecked, Some(note), false) =
            (self.collection, &self.evidence_note, no_download)
        {
            let _ = writeln!(log, "warning: collection unchecked: {note}");
        }
        if strict {
            match self.collection {
                Collection::Incomplete { failed } => self.reasons.push(json!({
                    "code": "FailedLocations",
                    "message": format!("{failed} locations were not searched in full"),
                })),
                Collection::Unchecked => self.reasons.push(json!({
                    "code": "EvidenceMissing",
                    "message": format!(
                        "the collection could not be checked: {}",
                        self.evidence_note.as_deref().unwrap_or(
                            "the report zip lacks a file, column or row value that the check \
                             needs, or holds two of a file"
                        )
                    ),
                })),
                Collection::Complete => {}
            }
        }
    }
}
