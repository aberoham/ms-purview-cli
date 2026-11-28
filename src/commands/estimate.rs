//! `purview estimate <case> <search>` (`docs/SPEC.md` section 3.5).
//!
//! Preflight is the action preflight of section 6.4 and the concurrency
//! check of section 6.7. After approval, one `POST …/estimateStatistics`;
//! then, unless `--no-wait`, the operation is polled to its end, and,
//! unless `--no-download`, its report zip is downloaded and read for the
//! collection check.

use std::io::Write;
use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::action::{
    active_operations, check_search, resume_check, started_since, ActionRun, Checked, Sent,
};
use crate::error::{PurviewError, Result};
use crate::graph::WriteResponse;
use crate::kql::GuardConfig;
use crate::model::requests::{EstimateRequest, IncludeQueryStats};
use crate::model::valid::{CaseKey, SearchKey};
use crate::model::wire::{OperationDetail, OperationRecord, OperationStatus};
use crate::poll::Timing;
use crate::report::estimate::{by_hits, Collection};
use crate::report::volume::{Volume, VolumeLimits, VolumeUse};
use crate::report::{EvidenceOf, ReportFiles, ReportLimits};
use crate::routes::{CaseId, OperationId, SearchId, WriteRoute};
use crate::safety::{
    After, Applied, Blocked, PlanInput, Planned, Preflight, Reconciled, WriteCommand, WritePlan,
    WriteSettings,
};

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

    fn volume_use(&self) -> VolumeUse {
        VolumeUse::All
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
        let active = active_operations(
            preflight.graph,
            case,
            &["estimateStatistics"],
            preflight.log,
        )
        .await?;
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
            Blocked::Concurrent(format!(
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
            ))
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
            let active = active_operations(
                preflight.graph,
                case,
                &["estimateStatistics"],
                preflight.log,
            )
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
        // Reconciliation looks for operations from just before the send:
        // after these reads, not when the plan was shown, since the prompt
        // or a slow read may have taken a long time.
        self.planned = Some((case, search, preflight.clock.now() - CLOCK_SKEW));
        Ok(())
    }

    async fn applied(&mut self, after: &mut After<'_>, response: WriteResponse) -> Result<Applied> {
        let Some((case, _, _)) = self.planned else {
            return Err(PurviewError::message("estimate was applied without a plan"));
        };
        let run = ActionRun {
            label: "estimate",
            noun: "an estimate",
            action: "estimateStatistics",
            evidence_of: EvidenceOf::Estimate,
            list_hint: "--action estimate",
            no_wait: self.flags.no_wait,
            no_download: self.flags.no_download,
            timing: self.flags.timing,
            out: self.flags.out.clone(),
            limits: self.limits,
        };
        let mut finished = match run.after_send(after, response, case).await? {
            Sent::Produced(produced) => return Ok(Applied::Produced(produced)),
            Sent::Submitted(operation) => {
                return Ok(Applied::result(json!({
                    "operationId": operation.to_string(),
                    "operationStatus": Value::Null,
                    "collection": Collection::Unchecked.as_str(),
                    "resume": resume_check(after, case, &operation),
                })))
            }
            Sent::Finished(finished) => finished,
        };
        let log = &mut after.session.env.stderr;
        let volume = volume_of(
            self.volume.unwrap_or_default(),
            &finished.record,
            finished.evidence.as_ref(),
            finished.collection,
        );
        for line in volume.warnings() {
            let _ = writeln!(log, "{line}");
        }
        finished.finish(log, self.flags.no_download, self.flags.strict);
        Ok(Applied::Result {
            result: result_value(
                &finished.operation,
                &finished.record,
                finished.collection,
                finished.evidence.as_ref(),
                finished.files,
                &volume,
            ),
            reasons: finished.reasons,
        })
    }

    async fn reconcile(&mut self, preflight: &mut Preflight<'_>) -> Result<Reconciled> {
        let Some((case, _, since)) = self.planned else {
            return Ok(Reconciled::default());
        };
        let (found, incomplete, failure) = started_since(
            preflight.graph,
            case,
            &["estimateStatistics"],
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

/// The volume check of a finished estimate (`docs/SPEC.md` section 6.9):
/// its counts, and the hits per location when the zip was read. The
/// counts of an estimate that failed, or whose status is not known, are
/// not used: every limit is unchecked.
fn volume_of(
    limits: VolumeLimits,
    record: &OperationRecord,
    evidence: Option<&ReportFiles>,
    collection: Collection,
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
        // A partial success may have left a location out of the files.
        record.status == OperationStatus::Succeeded && collection == Collection::Complete,
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
