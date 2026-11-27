//! `purview estimate <case> <search>` (`docs/SPEC.md` section 3.5).
//!
//! Preflight is the action preflight of section 6.4 and the concurrency
//! check of section 6.7. After approval, one `POST …/estimateStatistics`;
//! then, unless `--no-wait`, the operation is polled to its end, and,
//! unless `--no-download`, its report zip is downloaded and read for the
//! collection check.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::action::{active_operations, check_search, started_since, Checked};
use super::download::{fetch, Request};
use super::operation::{incomplete_reason, stopped, Resume};
use crate::error::{PurviewError, Result};
use crate::graph::WriteResponse;
use crate::kql::GuardConfig;
use crate::model::requests::{EstimateRequest, IncludeQueryStats};
use crate::model::valid::{CaseKey, SearchKey};
use crate::model::wire::{OperationDetail, OperationRecord, OperationStatus};
use crate::output::sanitize;
use crate::poll::{elapsed_text, PollEnd, Poller, Timing};
use crate::report::estimate::{by_hits, Collection};
use crate::report::volume::{Volume, VolumeLimits};
use crate::report::{EvidenceOf, ReportFiles, ReportLimits};
use crate::routes::{CaseId, OperationId, ReadRoute, SearchId, WriteRoute};
use crate::safety::{
    After, Applied, PlanInput, Planned, Preflight, Reconciled, WriteCommand, WritePlan,
    WriteSettings,
};

/// How long a 404 on a fresh operation counts as "not visible yet"
/// (`docs/SPEC.md` section 4.6; Assumption).
pub const NOT_FOUND_GRACE: Duration = Duration::from_secs(30);
/// The locations with most hits that the result shows.
pub const TOP_LOCATIONS: usize = 10;
/// How far before the POST reconciliation looks for new operations, for
/// clock differences.
const CLOCK_SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// The flags of `estimate`, checked.
#[derive(Debug, Clone)]
pub struct EstimateFlags {
    pub case: CaseKey,
    pub search: SearchKey,
    /// `--allow-generic --reason TEXT`.
    pub override_reason: Option<String>,
    pub allow_concurrent: bool,
    pub no_wait: bool,
    pub no_download: bool,
    pub strict: bool,
    pub timing: Timing,
    pub out: Option<PathBuf>,
}

pub struct Estimate {
    flags: EstimateFlags,
    guard: Option<GuardConfig>,
    limits: Option<ReportLimits>,
    volume: Option<VolumeLimits>,
    /// What the plan sends to, and when preflight ended, for
    /// reconciliation.
    planned: Option<(CaseId, SearchId, DateTime<Utc>)>,
    /// The query and verdict the plan showed.
    shown: Option<(String, bool)>,
}

impl Estimate {
    pub fn new(flags: EstimateFlags) -> Self {
        Self {
            flags,
            guard: None,
            limits: None,
            volume: None,
            planned: None,
            shown: None,
        }
    }
}

#[async_trait]
impl WriteCommand for Estimate {
    fn check(&mut self, settings: &WriteSettings) -> Result<()> {
        self.guard = Some(settings.guard.clone());
        self.limits = Some(settings.report);
        self.volume = Some(settings.volume);
        Ok(())
    }

    fn downloads(&self) -> bool {
        !self.flags.no_download && !self.flags.no_wait
    }

    fn reads_volume(&self) -> bool {
        true
    }

    async fn plan(&mut self, preflight: &mut Preflight<'_>) -> Result<Planned> {
        let guard = self
            .guard
            .clone()
            .ok_or_else(|| PurviewError::message("estimate ran without its settings"))?;
        let Checked {
            case,
            search,
            query,
            narrowed,
        } = check_search(
            preflight.graph,
            &self.flags.case,
            &self.flags.search,
            &guard,
            self.flags.override_reason.as_deref(),
            preflight.log,
        )
        .await?;
        let active =
            active_operations(preflight.graph, case, "estimateStatistics", preflight.log).await?;
        let mut warnings = Vec::new();
        if !narrowed {
            warnings.push(format!(
                "the guard found the search's query not narrowed; --allow-generic overrides it, \
                 for this reason: {}",
                self.flags.override_reason.as_deref().unwrap_or_default()
            ));
        }
        for operation in &active {
            warnings.push(format!(
                "estimate {} in the case may be a duplicate: the operation list does not say \
                 which search an operation runs",
                operation.describe()
            ));
        }
        let blocked = (!active.is_empty() && !self.flags.allow_concurrent).then(|| {
            format!(
                "case {case} has {} estimate{} not yet finished that may be a duplicate ({}); \
                 nothing was sent. Wait for {} with 'purview operation get {case} <op> --wait', \
                 or pass --allow-concurrent to start another",
                active.len(),
                if active.len() == 1 { "" } else { "s" },
                active
                    .iter()
                    .map(super::action::Active::describe)
                    .collect::<Vec<_>>()
                    .join("; "),
                if active.len() == 1 { "it" } else { "them" },
            )
        });
        let body = serde_json::to_value(EstimateRequest {
            statistics_options: IncludeQueryStats,
        })?;
        self.planned = Some((case, search.id, preflight.clock.now() - CLOCK_SKEW));
        self.shown = Some((query.clone(), narrowed));
        Ok(Planned::Write(WritePlan::new(PlanInput {
            command: "estimate",
            account: preflight.account.email.clone(),
            tenant: preflight.account.tenant_id.clone(),
            route: WriteRoute::EstimateStatistics(case, search.id),
            body,
            effects: vec![
                format!(
                    "Runs search {} over every mailbox in the tenant, and adds an estimate \
                     operation and its report file to case {case}.",
                    search.id
                ),
                "Reads no item content, changes no mailbox and places no hold.".into(),
            ],
            warnings,
            preflight: vec![
                Value::String(format!(
                    "search {}: dataSourceScopes {}",
                    search.id,
                    super::action::ALL_TENANT_MAILBOXES
                )),
                Value::String(
                    "sources: the custodian, non-custodial and additional source lists are empty"
                        .into(),
                ),
                // An object, so that --wrap-untrusted marks the query.
                json!({ "contentQuery": query }),
                Value::String(if narrowed {
                    "guard: the query is narrowed".into()
                } else {
                    "guard: the query is not narrowed; overridden with --allow-generic".into()
                }),
                Value::String(if active.is_empty() {
                    "estimates not yet finished in the case: none".into()
                } else {
                    format!("estimates not yet finished in the case: {}", active.len())
                }),
            ],
            blocked,
        })?))
    }

    /// The search again, by its id: its scope and sources are checked as
    /// in preflight, and its query and the guard's verdict must be the
    /// ones the plan showed.
    async fn recheck(&mut self, preflight: &mut Preflight<'_>) -> Result<()> {
        let (Some((case, search, _)), Some((query, narrowed)), Some(guard)) =
            (self.planned, self.shown.clone(), self.guard.clone())
        else {
            return Err(PurviewError::message(
                "estimate was approved without a plan",
            ));
        };
        let changed = |what: &str| {
            PurviewError::SearchChanged(format!(
                "search {search} changed after the plan was shown ({what}); nothing was sent. Run \
                 the command again to see a new plan"
            ))
        };
        let again = check_search(
            preflight.graph,
            &CaseKey::Id(case),
            &SearchKey::Id(search),
            &guard,
            self.flags.override_reason.as_deref(),
            preflight.log,
        )
        .await
        // The check's own error keeps its code, a read that failed
        // included.
        .map_err(|error| {
            error.context(format!(
                "reading search {search} again after approval; nothing was sent"
            ))
        })?;
        if again.search.id != search || again.query != query {
            return Err(changed("its query is not the one shown"));
        }
        if again.narrowed != narrowed {
            return Err(changed("the guard's verdict is not the one shown"));
        }
        // An estimate that another person started while the prompt was
        // open may be a duplicate too.
        if !self.flags.allow_concurrent {
            let active =
                active_operations(preflight.graph, case, "estimateStatistics", preflight.log)
                    .await
                    .map_err(|error| {
                        error.context(format!(
                            "listing the operations of case {case} again after approval; \
                             nothing was sent"
                        ))
                    })?;
            if !active.is_empty() {
                return Err(PurviewError::ConcurrentOperation(format!(
                    "an estimate of case {case} was started after the plan was shown and may be \
                     a duplicate ({}); nothing was sent. Pass --allow-concurrent to start \
                     another",
                    active
                        .iter()
                        .map(super::action::Active::describe)
                        .collect::<Vec<_>>()
                        .join("; ")
                )));
            }
        }
        Ok(())
    }

    async fn applied(&mut self, after: &mut After<'_>, response: WriteResponse) -> Result<Applied> {
        let Some((case, _, _)) = self.planned else {
            return Err(PurviewError::message("estimate was applied without a plan"));
        };
        let reconcile_hint = format!(
            "the estimate may be running; 'purview operation list {case} --action estimate' \
             lists it"
        );
        if response.status != 202 {
            return Err(PurviewError::UnexpectedLocation(format!(
                "Graph answered the estimate with HTTP {}, where 202 and a Location header were \
                 observed; {reconcile_hint}",
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
                    "Graph accepted the estimate (HTTP {}) but its Location header does not name \
                     an operation of case {case} in a known form; {reconcile_hint}",
                    response.status
                ))
            })?;
        if self.flags.no_wait {
            return Ok(Applied::result(json!({
                "operationId": operation.to_string(),
                "operationStatus": Value::Null,
                "collection": Collection::Unchecked.as_str(),
                "resume": resume(after, case, &operation),
            })));
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
            timing: self.flags.timing,
            not_found_grace: Some(NOT_FOUND_GRACE),
        };
        let show_progress = session.env.stderr_is_terminal && !session.verbose;
        let shown_id = format!("{}…", &operation.to_string()[..8]);
        let mut progress =
            |record: &OperationRecord, waited: Duration, log: &mut (dyn Write + Send)| {
                if show_progress {
                    let _ = writeln!(
                        log,
                        "estimate {shown_id}: {} · {}",
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
                return Ok(Applied::Produced(stopped(
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
                return Ok(Applied::Produced(stopped(
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
        // The operation the header named must be an estimate: its files are
        // a report, never item content.
        if record.action.as_deref() != Some("estimateStatistics")
            || !matches!(record.detail(), Some(OperationDetail::Estimate(_)))
        {
            return Err(PurviewError::UnexpectedLocation(format!(
                "operation {operation} of case {case}, which the estimate's Location header \
                 named, is not an estimate; nothing was downloaded. {reconcile_hint}"
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
        if self.flags.no_download {
            reasons.extend(incomplete_reason(&record));
            evidence_note = Some("--no-download: the report zip was not read".into());
        } else {
            let context = after
                .download
                .ok_or_else(|| PurviewError::message("estimate has no download client"))?;
            let request = Request {
                case: CaseKey::Id(case),
                operation: operation.clone(),
                out: self.flags.out.clone(),
                file: None,
                overwrite: false,
            };
            let fetched = fetch(&mut after.session, case, &record, &request, context).await?;
            // The deadline covers the wait; the download has its own
            // timeouts (`docs/SPEC.md` section 4.7). Ctrl-C during it
            // reports the time since the estimate was sent.
            if fetched.interrupted {
                let waited = clock.elapsed().saturating_sub(started);
                return Ok(Applied::Produced(stopped(
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
            files.collection(EvidenceOf::Estimate)
        });
        let log = &mut after.session.env.stderr;
        if let Some(files) = &evidence {
            super::parse::warn_missing_columns(log, files);
        }
        if let Collection::Incomplete { failed } = collection {
            if record.status == OperationStatus::Succeeded {
                let _ = writeln!(
                    log,
                    "warning: the estimate succeeded, but {failed} location{} {} not searched in \
                     full; --strict makes this exit 4",
                    if failed == 1 { "" } else { "s" },
                    if failed == 1 { "was" } else { "were" }
                );
            }
        }
        let volume = volume_of(self.volume.unwrap_or_default(), &record, evidence.as_ref());
        for line in volume.warnings() {
            let _ = writeln!(log, "{line}");
        }
        if let (Collection::Unchecked, Some(note), false) =
            (collection, &evidence_note, self.flags.no_download)
        {
            let _ = writeln!(log, "warning: collection unchecked: {note}");
        }
        if self.flags.strict {
            match collection {
                Collection::Incomplete { failed } => reasons.push(json!({
                    "code": "FailedLocations",
                    "message": format!("{failed} locations were not searched in full"),
                })),
                Collection::Unchecked => reasons.push(json!({
                    "code": "EvidenceMissing",
                    "message": format!(
                        "the collection could not be checked: {}",
                        evidence_note.as_deref().unwrap_or(
                            "the report zip lacks a file, column or row value that the check \
                             needs, or holds two of a file"
                        )
                    ),
                })),
                Collection::Complete => {}
            }
        }
        Ok(Applied::Result {
            result: result_value(
                &operation,
                &record,
                collection,
                evidence.as_ref(),
                files,
                &volume,
            ),
            reasons,
        })
    }

    async fn reconcile(&mut self, preflight: &mut Preflight<'_>) -> Result<Reconciled> {
        let Some((case, _, since)) = self.planned else {
            return Ok(Reconciled::default());
        };
        let (found, incomplete, failure) = started_since(
            preflight.graph,
            case,
            "estimateStatistics",
            since,
            preflight.account,
            preflight.log,
        )
        .await?;
        let candidates: Vec<String> = found
            .iter()
            .map(|operation| format!("estimate {} in case {case}", operation.describe()))
            .collect();
        let mut notes = Vec::new();
        if candidates.is_empty() {
            notes.push(format!(
                "No estimate started since the request was listed; Purview may not list a new \
                 operation at once, so run 'purview operation list {case} --action estimate' \
                 again before running the command again"
            ));
        }
        if let Some(failure) = failure {
            let (code, status) = failure.metadata();
            notes.push(format!(
                "The operation list stopped before its last page, at a read that failed ({code}{}), \
                 so others may exist",
                if status == 0 {
                    String::new()
                } else {
                    format!(", HTTP {status}")
                }
            ));
        } else if incomplete {
            notes.push(
                "The operation list stopped before its last page, so others may exist".into(),
            );
        }
        Ok(Reconciled { candidates, notes })
    }
}

/// The commands that carry on from a submitted estimate, as the signed-in
/// account.
fn resume(after: &After<'_>, case: CaseId, operation: &OperationId) -> Vec<String> {
    let account = super::operation::shell_word(&after.session.account.email);
    vec![
        format!("purview --account={account} operation get {case} {operation} --wait"),
        format!("purview --account={account} download {case} {operation}"),
    ]
}

/// The volume check of a finished estimate (`docs/SPEC.md` section 6.9):
/// its counts, and the hits per location when the zip was read. The
/// counts of an estimate that failed, or whose status is not known, are
/// not used: every limit is unchecked.
fn volume_of(
    limits: VolumeLimits,
    record: &OperationRecord,
    evidence: Option<&ReportFiles>,
) -> Volume {
    if !matches!(
        record.status,
        OperationStatus::Succeeded | OperationStatus::PartiallySucceeded
    ) {
        return Volume::check(limits, None, None, None, false);
    }
    let (items, size) = match record.detail() {
        Some(OperationDetail::Estimate(estimate)) => {
            (estimate.indexed_item_count, estimate.indexed_items_size)
        }
        _ => (None, None),
    };
    Volume::check(
        limits,
        items,
        size,
        evidence.and_then(|files| files.locations.as_ref()),
        evidence.is_some_and(|files| files.duplicates.contains(&"Locations")),
    )
}

/// The estimate's result (`docs/SPEC.md` section 3.5).
fn result_value(
    operation: &OperationId,
    record: &OperationRecord,
    collection: Collection,
    evidence: Option<&ReportFiles>,
    files: Vec<Value>,
    volume: &Volume,
) -> Value {
    let (indexed, indexed_size, unindexed, mailboxes) = match record.detail() {
        Some(OperationDetail::Estimate(estimate)) => (
            estimate.indexed_item_count,
            estimate.indexed_items_size,
            estimate.unindexed_item_count,
            estimate.mailbox_count,
        ),
        _ => (None, None, None, None),
    };
    let mut top = evidence
        .and_then(|files| files.locations.as_ref())
        .map(|locations| {
            locations
                .rows
                .iter()
                .filter(|row| row.count.is_some_and(|count| count > 0))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    by_hits(&mut top);
    top.truncate(TOP_LOCATIONS);
    json!({
        "operationId": operation.to_string(),
        "operationStatus": record.status.as_str(),
        "collection": collection.as_str(),
        "indexedItemCount": indexed,
        "indexedItemsSize": indexed_size,
        "unindexedItemCount": unindexed,
        // Locations with hits (Observed meaning).
        "mailboxCount": mailboxes,
        "locationsSearched": evidence
            .and_then(|files| files.summary.as_ref())
            .and_then(|summary| summary.location_count()),
        "topLocations": top,
        "failedLocations": evidence.map(ReportFiles::failed_locations),
        "files": files,
        "volume": volume.to_json(),
    })
}
