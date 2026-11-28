//! `purview report <case> <search>` (`docs/SPEC.md` section 3.5).
//!
//! Preflight is the action preflight of section 6.4, the concurrency check
//! of section 6.7 and the size limit of section 6.9, against the search's
//! latest estimate. After approval, one `POST …/exportReport`; then, unless
//! `--no-wait`, the operation is polled to its end, and, unless
//! `--no-download`, its report zip is downloaded and its `Locations` file
//! read for the collection check.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::action::{
    active_operations, check_search, resume_check, started_since, ActionRun, Active, Checked, Sent,
    EXPORT_ACTIONS,
};
use crate::error::{PurviewError, Result};
use crate::graph::{GraphClient, WriteResponse};
use crate::kql::GuardConfig;
use crate::model::requests::{
    ExportReportRequest, ResponsiveLocations, SearchHits, TeamsConversations,
};
use crate::model::valid::{CaseKey, SearchKey, SearchRef};
use crate::model::wire::{Action, OperationRecord, OperationStatus, Source};
use crate::naming::{Naming, Values};
use crate::poll::Timing;
use crate::report::estimate::Collection;
use crate::report::volume::{grouped, size_text, size_texts, VolumeLimits, VolumeUse};
use crate::report::{EvidenceOf, ReportLimits};
use crate::routes::{CaseId, OperationId, Query, ReadRoute, SearchId, WriteRoute};
use crate::safety::{
    After, Applied, Blocked, PlanInput, Planned, Preflight, Reconciled, WriteCommand, WritePlan,
    WriteSettings,
};

/// How far before the POST reconciliation looks for new operations, for
/// clock differences.
const CLOCK_SKEW: chrono::Duration = chrono::Duration::minutes(5);
/// Candidates reconciliation reads one by one to tell a report from an
/// export (`docs/SPEC.md` section 6.7).
const RESOLVE_AT_MOST: usize = 10;
/// The rows per estimated item seen in item reports with Teams context on
/// (`docs/SPEC.md` section 6.6; Observed, one tenant).
const ROWS_PER_ITEM: (u64, u64) = (10, 37);

/// The flags of `report`, checked.
#[derive(Debug, Clone)]
pub struct ReportFlags {
    pub case: CaseKey,
    pub search: SearchKey,
    /// `--name`, else `naming.export_name`.
    pub name: Option<String>,
    /// `--no-teams-context`.
    pub no_teams_context: bool,
    /// `--allow-generic` with `--reason`.
    pub allow_generic: bool,
    /// `--allow-large` with `--reason`.
    pub allow_large: bool,
    /// `--reason`, for either override.
    pub reason: Option<String>,
    pub allow_concurrent: bool,
    pub no_wait: bool,
    pub no_download: bool,
    pub strict: bool,
    pub timing: Timing,
    pub out: Option<PathBuf>,
}

pub struct Report {
    flags: ReportFlags,
    naming: Option<Naming>,
    guard: Option<GuardConfig>,
    limits: Option<ReportLimits>,
    volume: Option<VolumeLimits>,
    /// `defaults.teams_context`, read before sign-in.
    teams_context_default: bool,
    /// What the plan sends to, and when preflight ended, for
    /// reconciliation.
    planned: Option<(CaseId, SearchId, DateTime<Utc>)>,
    /// The query, the verdict and the estimate the plan showed.
    shown: Option<Shown>,
}

#[derive(Debug, Clone)]
struct Shown {
    query: String,
    narrowed: bool,
    /// The latest estimate as the plan read it.
    basis: Basis,
    display_name: String,
    teams_context: bool,
}

/// `defaults.teams_context` in `config.json`: `true` when missing or
/// `null`; any other value that is not a boolean is an error naming the
/// key.
pub fn teams_context_setting(extra: &BTreeMap<String, Value>) -> Result<bool> {
    let defaults = match extra.get("defaults") {
        None | Some(Value::Null) => return Ok(true),
        Some(Value::Object(defaults)) => defaults,
        Some(_) => {
            return Err(PurviewError::message(
                "config.json: defaults must be an object",
            ))
        }
    };
    match defaults.get("teams_context") {
        None | Some(Value::Null) => Ok(true),
        Some(Value::Bool(on)) => Ok(*on),
        Some(_) => Err(PurviewError::message(
            "config.json: defaults.teams_context must be true or false",
        )),
    }
}

impl Report {
    pub fn new(flags: ReportFlags) -> Self {
        Self {
            flags,
            naming: None,
            guard: None,
            limits: None,
            volume: None,
            teams_context_default: true,
            planned: None,
            shown: None,
        }
    }

    fn teams_context(&self) -> bool {
        !self.flags.no_teams_context && self.teams_context_default
    }

    /// The reason the overrides given carry, for the plan and the
    /// operation's `description`.
    fn description(&self) -> Option<String> {
        let reason = self.flags.reason.as_deref()?;
        let flags: Vec<&str> = [
            (self.flags.allow_generic, "--allow-generic"),
            (self.flags.allow_large, "--allow-large"),
        ]
        .into_iter()
        .filter_map(|(given, flag)| given.then_some(flag))
        .collect();
        (!flags.is_empty()).then(|| format!("{}: {reason}", flags.join(" and ")))
    }
}

/// The search's latest estimate, as the size limit reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Basis {
    /// A finished estimate whose size can be compared.
    Sized {
        operation: String,
        items: Option<u64>,
        size: u64,
        /// A partial success: its size is at least this.
        partial: bool,
    },
    /// Why no size can be compared; `operation` when one was read.
    Unknown {
        operation: Option<String>,
        why: String,
    },
}

impl Basis {
    fn operation(&self) -> Option<&str> {
        match self {
            Self::Sized { operation, .. } => Some(operation),
            Self::Unknown { operation, .. } => operation.as_deref(),
        }
    }
}

/// `GET …/searches/{search}/lastEstimateStatisticsOperation` (Docs), read
/// as the basis of the size limit. An HTTP error is a basis that cannot
/// be compared, by its code and status only; an error with no answer from
/// Graph, such as a sign-in that cannot be refreshed, is the command's.
pub(crate) async fn latest_estimate(
    graph: &GraphClient,
    case: CaseId,
    search: &SearchRef,
    log: &mut (dyn Write + Send),
) -> Result<Basis> {
    let unknown = |operation: Option<String>, why: String| Basis::Unknown { operation, why };
    let value = match graph
        .get(
            &ReadRoute::LastEstimate(case, search.id),
            &Query::new(),
            log,
        )
        .await
    {
        Ok(value) => value,
        // An answer with no operation in it.
        Err(PurviewError::GraphBodyNotObject { status }) => {
            return Ok(unknown(
                None,
                format!("Graph's answer (HTTP {status}) holds no operation"),
            ))
        }
        Err(error) => {
            // Only Graph's own answer is a basis; a sign-in that could not
            // be refreshed, or no answer, is the command's error.
            let Some(status) = error.graph_status() else {
                return Err(error.context(format!(
                    "reading the latest estimate of search {}",
                    search.id
                )));
            };
            let (code, _) = error.metadata();
            return Ok(unknown(
                None,
                if status == 404 {
                    "Graph found no estimate of the search (HTTP 404)".into()
                } else {
                    format!("its latest estimate could not be read ({code}, HTTP {status})")
                },
            ));
        }
    };
    let Some(record) = OperationRecord::from_value(value) else {
        return Ok(unknown(None, "Graph's answer is not an operation".into()));
    };
    // Ids are checked: anything else is Graph's text.
    let operation = record
        .id
        .as_deref()
        .and_then(OperationId::parse)
        .map(|id| id.to_string());
    let detail = match (record.action.as_deref(), record.estimate_detail()) {
        (Some("estimateStatistics"), Some(detail)) => detail,
        _ => {
            return Ok(unknown(
                operation,
                "Graph's answer is not an estimate operation".into(),
            ))
        }
    };
    let partial = match record.status {
        OperationStatus::Succeeded => false,
        OperationStatus::PartiallySucceeded => true,
        OperationStatus::NotStarted | OperationStatus::Running => {
            return Ok(unknown(
                operation,
                "its latest estimate is not finished".into(),
            ))
        }
        _ => {
            return Ok(unknown(
                operation,
                "its latest estimate did not succeed".into(),
            ))
        }
    };
    // An estimate older than the search's last change may count another
    // query.
    match (
        record.created_date_time,
        search.record.last_modified_date_time,
    ) {
        (Some(created), Some(modified)) if modified <= created => {}
        (Some(_), Some(_)) => {
            return Ok(unknown(
                operation,
                "the search was changed after its latest estimate ran".into(),
            ))
        }
        _ => {
            return Ok(unknown(
                operation,
                "the times that show the estimate is newer than the search's last change are \
                 missing"
                    .into(),
            ))
        }
    }
    let Some(operation) = operation else {
        return Ok(unknown(
            None,
            "its latest estimate has no readable id".into(),
        ));
    };
    match detail.indexed_items_size {
        Some(size) => Ok(Basis::Sized {
            operation,
            items: detail.indexed_item_count,
            size,
            partial,
        }),
        None => Ok(unknown(
            Some(operation),
            "its latest estimate has no indexedItemsSize".into(),
        )),
    }
}

/// The size limit's verdict: a block without `--allow-large`, a warning
/// with it, and a line for the plan's preflight.
pub(crate) fn size_check(
    basis: &Basis,
    limit: u64,
    allow_large: bool,
    search: SearchId,
) -> (Option<Blocked>, Option<String>, String) {
    let limit_text = size_text(limit);
    let rerun = format!(
        "run 'purview estimate <case> {search}' for a current estimate, narrow the query, or pass \
         --allow-large --reason to collect it anyway"
    );
    match basis {
        Basis::Sized {
            operation,
            size,
            partial,
            ..
        } if *size > limit => {
            // Rounded alike, the two would read as equal.
            let (size_shown, limit_text) = size_texts(*size, limit);
            let message = format!(
                "the latest estimate of search {search} ({operation}) found {}{} of items, more \
                 than volume.max_export_size ({limit_text}), and a report or export collects \
                 more than the estimate counts; nothing was sent. Narrow the query, or pass \
                 --allow-large --reason to collect it anyway",
                if *partial { "at least " } else { "" },
                size_shown
            );
            let line = format!(
                "size: the latest estimate {operation} found {}{}, over volume.max_export_size \
                 ({limit_text})",
                if *partial { "at least " } else { "" },
                size_shown
            );
            if allow_large {
                (
                    None,
                    Some(format!(
                        "VOLUME: the latest estimate found {}{} of items, over \
                         volume.max_export_size ({limit_text}); --allow-large overrides it",
                        if *partial { "at least " } else { "" },
                        size_shown
                    )),
                    line,
                )
            } else {
                (Some(Blocked::TooLarge(message)), None, line)
            }
        }
        Basis::Sized {
            operation,
            size,
            partial: true,
            ..
        } => {
            // A partial success's size is only a lower bound.
            let why = format!(
                "its latest estimate ({operation}) only partly succeeded, so its {} is a lower \
                 bound",
                size_text(*size)
            );
            unknown_verdict(&why, &limit_text, &rerun, allow_large, search)
        }
        Basis::Sized {
            operation, size, ..
        } => (
            None,
            None,
            format!(
                "size: the latest estimate {operation} found {}, within volume.max_export_size \
                 ({limit_text})",
                size_text(*size)
            ),
        ),
        Basis::Unknown { why, .. } => {
            unknown_verdict(why, &limit_text, &rerun, allow_large, search)
        }
    }
}

fn unknown_verdict(
    why: &str,
    limit_text: &str,
    rerun: &str,
    allow_large: bool,
    search: SearchId,
) -> (Option<Blocked>, Option<String>, String) {
    let line = format!("size: not compared with volume.max_export_size ({limit_text}): {why}");
    if allow_large {
        (
            None,
            Some(format!(
                "VOLUME: the size was not compared with volume.max_export_size ({limit_text}): \
                 {why}; --allow-large overrides it"
            )),
            line,
        )
    } else {
        (
            Some(Blocked::VolumeUnchecked(format!(
                "the size of search {search} cannot be compared with volume.max_export_size \
                 ({limit_text}): {why}; nothing was sent. To go on, {rerun}"
            ))),
            None,
            line,
        )
    }
}

/// The row-count warning of section 6.6, with the estimate's count when
/// there is one.
fn row_warning(basis: &Basis, teams_context: bool) -> String {
    let (low, high) = ROWS_PER_ITEM;
    let items = match basis {
        Basis::Sized {
            items: Some(items), ..
        } => Some(*items),
        _ => None,
    };
    let counted = match items {
        Some(items) => format!(
            "; the latest estimate counted {} items, so the report may hold on the order of {} \
             to {} rows",
            grouped(items),
            grouped(items.saturating_mul(low)),
            grouped(items.saturating_mul(high))
        ),
        None => String::new(),
    };
    format!(
        "an item report can hold far more rows than the estimate counts: one tenant's reports{} \
         held about {low} to {high} rows per estimated item{counted}",
        if teams_context {
            " with Teams context on"
        } else {
            ", with Teams context on,"
        }
    )
}

fn concurrent_message(case: CaseId, active: &[Active]) -> String {
    format!(
        "case {case} has {} item report{} or export{} not yet finished that may be a duplicate \
         ({}); nothing was sent. Wait for {} with 'purview operation get {case} <op> --wait', or \
         pass --allow-concurrent to start another",
        active.len(),
        if active.len() == 1 { "" } else { "s" },
        if active.len() == 1 { "" } else { "s" },
        active
            .iter()
            .map(Active::describe)
            .collect::<Vec<_>>()
            .join("; "),
        if active.len() == 1 { "it" } else { "them" },
    )
}

#[async_trait]
impl WriteCommand for Report {
    fn check(&mut self, settings: &WriteSettings) -> Result<()> {
        self.naming = Some(settings.naming.clone());
        self.guard = Some(settings.guard.clone());
        self.limits = Some(settings.report);
        self.volume = Some(settings.volume);
        self.teams_context_default = settings.teams_context;
        Ok(())
    }

    fn downloads(&self) -> bool {
        !self.flags.no_download && !self.flags.no_wait
    }

    fn volume_use(&self) -> VolumeUse {
        VolumeUse::ExportSize
    }

    fn reads_teams_context(&self) -> bool {
        true
    }

    async fn plan(&mut self, preflight: &mut Preflight<'_>) -> Result<Planned> {
        let (Some(guard), Some(naming)) = (self.guard.clone(), self.naming.clone()) else {
            return Err(PurviewError::message("report ran without its settings"));
        };
        let generic_reason = self
            .flags
            .allow_generic
            .then_some(self.flags.reason.as_deref())
            .flatten();
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
            generic_reason,
            preflight.log,
        )
        .await?;
        let active =
            active_operations(preflight.graph, case, &EXPORT_ACTIONS, preflight.log).await?;
        let basis = latest_estimate(preflight.graph, case, &search, preflight.log).await?;
        let limit = self.volume.unwrap_or_default().max_export_size;
        let (size_block, size_warning, size_line) =
            size_check(&basis, limit, self.flags.allow_large, search.id);
        let teams_context = self.teams_context();
        let display_name = match &self.flags.name {
            Some(name) => name.clone(),
            None => naming.render(
                &naming.export_name,
                &Values {
                    topic: None,
                    requester: None,
                    user: &preflight.account.email,
                    query: Some(&query),
                    action: Some("report"),
                    now: Some(preflight.clock.now()),
                },
            )?,
        };
        super::check_sent_text("naming.export_name, rendered,", &display_name)?;
        if display_name.trim().is_empty() {
            return Err(PurviewError::message(
                "naming.export_name rendered an empty name; give --name or change the template",
            ));
        }
        let mut warnings = Vec::new();
        if !narrowed {
            warnings.push(format!(
                "the guard found the search's query not narrowed; --allow-generic overrides it, \
                 for this reason: {}",
                self.flags.reason.as_deref().unwrap_or_default()
            ));
        }
        warnings.extend(size_warning);
        warnings.push(row_warning(&basis, teams_context));
        if !teams_context {
            warnings.push(
                "Teams context is off: a report without additionalOptions has not been observed \
                 (experimental), and Teams hits come without the messages around them"
                    .into(),
            );
        }
        for operation in &active {
            warnings.push(format!(
                "item report or export {} in the case may be a duplicate: the operation list \
                 does not say which search an operation runs",
                operation.describe()
            ));
        }
        let concurrent = (!active.is_empty() && !self.flags.allow_concurrent)
            .then(|| Blocked::Concurrent(concurrent_message(case, &active)));
        let description = self.description();
        let body = serde_json::to_value(ExportReportRequest {
            display_name: &display_name,
            description: description.as_deref(),
            export_criteria: SearchHits,
            export_location: ResponsiveLocations,
            additional_options: teams_context.then_some(TeamsConversations),
        })?;
        self.planned = Some((case, search.id, preflight.clock.now() - CLOCK_SKEW));
        self.shown = Some(Shown {
            query: query.clone(),
            narrowed,
            basis: basis.clone(),
            display_name: display_name.clone(),
            teams_context,
        });
        Ok(Planned::Write(WritePlan::new(PlanInput {
            command: "report",
            account: preflight.account.email.clone(),
            tenant: preflight.account.tenant_id.clone(),
            route: WriteRoute::ExportReport(case, search.id),
            body,
            effects: vec![
                format!(
                    "Runs search {} over every mailbox in the tenant, and adds an item report \
                     operation and its report zip to case {case}: one row of metadata (sender, \
                     recipients, subject, dates, location) per item copy found.",
                    search.id
                ),
                "Collects no message bodies or attachments, changes no mailbox and places no \
                 hold."
                    .into(),
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
                Value::String(size_line),
                Value::String(if teams_context {
                    "Teams context: on (additionalOptions teamsAndYammerConversations)".into()
                } else {
                    "Teams context: off (experimental)".into()
                }),
                Value::String(if active.is_empty() {
                    "item reports or exports not yet finished in the case: none".into()
                } else {
                    format!(
                        "item reports or exports not yet finished in the case: {}",
                        active.len()
                    )
                }),
            ],
            // The size comes first: --allow-concurrent does not cover it.
            blocked: size_block.or(concurrent),
        })?))
    }

    /// The search again, by its id, as in preflight, and its latest
    /// estimate: each must be the one the plan showed.
    async fn recheck(&mut self, preflight: &mut Preflight<'_>) -> Result<()> {
        let (Some((case, search, _)), Some(shown), Some(guard)) =
            (self.planned, self.shown.clone(), self.guard.clone())
        else {
            return Err(PurviewError::message("report was approved without a plan"));
        };
        let changed = |what: &str| {
            PurviewError::SearchChanged(format!(
                "search {search} changed after the plan was shown ({what}); nothing was sent. Run \
                 the command again to see a new plan"
            ))
        };
        let generic_reason = self
            .flags
            .allow_generic
            .then_some(self.flags.reason.as_deref())
            .flatten();
        let again = check_search(
            preflight.graph,
            &CaseKey::Id(case),
            &SearchKey::Id(search),
            &guard,
            generic_reason,
            preflight.log,
        )
        .await
        .map_err(|error| {
            error.context(format!(
                "reading search {search} again after approval; nothing was sent"
            ))
        })?;
        if again.search.id != search || again.query != shown.query {
            return Err(changed("its query is not the one shown"));
        }
        if again.narrowed != shown.narrowed {
            return Err(changed("the guard's verdict is not the one shown"));
        }
        let basis = latest_estimate(preflight.graph, case, &again.search, preflight.log)
            .await
            .map_err(|error| {
                error.context(format!(
                    "reading the latest estimate of search {search} again after approval; \
                     nothing was sent"
                ))
            })?;
        let limit = self.volume.unwrap_or_default().max_export_size;
        if let (Some(blocked), _, _) = size_check(&basis, limit, self.flags.allow_large, search) {
            return Err(blocked.error());
        }
        // Another estimate, or the same one with another size, status or
        // verdict, is not the plan that was approved.
        if basis != shown.basis {
            return Err(changed("its latest estimate is not the one shown"));
        }
        if !self.flags.allow_concurrent {
            let active = active_operations(preflight.graph, case, &EXPORT_ACTIONS, preflight.log)
                .await
                .map_err(|error| {
                    error.context(format!(
                        "listing the operations of case {case} again after approval; \
                             nothing was sent"
                    ))
                })?;
            if !active.is_empty() {
                return Err(PurviewError::ConcurrentOperation(format!(
                    "an item report or export of case {case} was started after the plan was \
                     shown and may be a duplicate ({}); nothing was sent. Pass \
                     --allow-concurrent to start another",
                    active
                        .iter()
                        .map(Active::describe)
                        .collect::<Vec<_>>()
                        .join("; ")
                )));
            }
        }
        Ok(())
    }

    async fn applied(&mut self, after: &mut After<'_>, response: WriteResponse) -> Result<Applied> {
        let (Some((case, _, _)), Some(shown)) = (self.planned, self.shown.clone()) else {
            return Err(PurviewError::message("report was applied without a plan"));
        };
        let run = ActionRun {
            label: "report",
            noun: "an item report",
            action: "exportReport",
            evidence_of: EvidenceOf::Report,
            list_hint: "--action report --resolve",
            check_only: true,
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
                    "displayName": shown.display_name,
                    "teamsContext": shown.teams_context,
                    "resume": resume_check(after, case, &operation),
                })))
            }
            Sent::Finished(finished) => finished,
        };
        finished.finish(
            &mut after.session.env.stderr,
            self.flags.no_download,
            self.flags.strict,
        );
        Ok(Applied::Result {
            result: json!({
                "operationId": finished.operation.to_string(),
                "operationStatus": finished.record.status.as_str(),
                "collection": finished.collection.as_str(),
                "displayName": shown.display_name,
                "teamsContext": shown.teams_context,
                "estimateId": shown.basis.operation(),
                "locationsWithHits": finished
                    .evidence
                    .as_ref()
                    .and_then(|files| files.locations.as_ref())
                    .map(|locations| locations.rows.len()),
                "failedLocations": finished
                    .evidence
                    .as_ref()
                    .map(|files| files.failed_locations_of(EvidenceOf::Report)),
                "files": finished.files,
            }),
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
            &EXPORT_ACTIONS,
            since,
            preflight.account,
            preflight.log,
        )
        .await?;
        // The list shows reports and exports alike, so each candidate is
        // read on its own, up to a limit, for its true action.
        let mut candidates = Vec::new();
        let mut unresolved = 0usize;
        for (index, operation) in found.iter().enumerate() {
            let kind = match OperationId::parse(&operation.id) {
                Some(id) if index < RESOLVE_AT_MOST => preflight
                    .graph
                    .get(
                        &ReadRoute::Operation(case, id),
                        &Query::new(),
                        preflight.log,
                    )
                    .await
                    .ok()
                    .and_then(OperationRecord::from_value)
                    .map(|record| record.action(Source::Single)),
                _ => None,
            };
            let label = match kind {
                Some(Action::ExportReport) => "item report",
                Some(Action::ExportResult) => "export",
                _ => {
                    unresolved += 1;
                    "report or export"
                }
            };
            candidates.push(format!("{label} {} in case {case}", operation.describe()));
        }
        let mut notes = Vec::new();
        if candidates.is_empty() {
            notes.push(format!(
                "No item report or export started since the request was listed; Purview may not \
                 list a new operation at once, so run 'purview operation list {case} --action \
                 report --resolve' again before running the command again"
            ));
        }
        if unresolved > 0 {
            notes.push(format!(
                "{unresolved} candidate{} could not be read on {} own, so {} shown as \"report or \
                 export\"",
                if unresolved == 1 { "" } else { "s" },
                if unresolved == 1 { "its" } else { "their" },
                if unresolved == 1 { "it is" } else { "they are" },
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

#[cfg(test)]
mod tests {
    use super::*;

    const SEARCH: &str = "00000000-0000-4000-8000-000000000002";
    const GIB: u64 = 1 << 30;

    fn search() -> SearchId {
        SearchId::parse(SEARCH).unwrap()
    }

    fn sized(size: u64, partial: bool) -> Basis {
        Basis::Sized {
            operation: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001".into(),
            items: Some(120),
            size,
            partial,
        }
    }

    #[test]
    fn a_size_above_the_limit_blocks_and_one_equal_to_it_does_not() {
        let (blocked, warning, line) =
            size_check(&sized(10 * GIB + 1, false), 10 * GIB, false, search());
        assert!(matches!(blocked, Some(Blocked::TooLarge(_))), "{blocked:?}");
        assert!(warning.is_none());
        assert!(line.contains("over volume.max_export_size"), "{line}");
        let (blocked, warning, line) =
            size_check(&sized(10 * GIB, false), 10 * GIB, false, search());
        assert!(blocked.is_none() && warning.is_none(), "{blocked:?}");
        assert!(line.contains("within"), "{line}");
    }

    #[test]
    fn allow_large_turns_each_block_into_a_warning() {
        for basis in [
            sized(11 * GIB, false),
            sized(GIB, true),
            Basis::Unknown {
                operation: None,
                why: "Graph found no estimate of the search (HTTP 404)".into(),
            },
        ] {
            let (blocked, _, _) = size_check(&basis, 10 * GIB, false, search());
            assert!(blocked.is_some(), "{basis:?}");
            let (blocked, warning, _) = size_check(&basis, 10 * GIB, true, search());
            assert!(blocked.is_none(), "{basis:?}");
            assert!(warning.unwrap().starts_with("VOLUME:"), "{basis:?}");
        }
    }

    #[test]
    fn a_partial_estimate_below_the_limit_is_unchecked_and_above_it_too_large() {
        let (blocked, _, _) = size_check(&sized(GIB, true), 10 * GIB, false, search());
        assert!(
            matches!(blocked, Some(Blocked::VolumeUnchecked(_))),
            "{blocked:?}"
        );
        let (blocked, _, _) = size_check(&sized(11 * GIB, true), 10 * GIB, false, search());
        let Some(Blocked::TooLarge(message)) = blocked else {
            panic!("{blocked:?}");
        };
        assert!(message.contains("at least"), "{message}");
    }

    #[test]
    fn the_row_warning_gives_the_range_from_the_estimate() {
        let text = row_warning(&sized(GIB, false), true);
        assert!(text.contains("counted 120 items"), "{text}");
        assert!(text.contains("1,200 to 4,440 rows"), "{text}");
        let text = row_warning(
            &Basis::Unknown {
                operation: None,
                why: String::new(),
            },
            true,
        );
        assert!(!text.contains("counted"), "{text}");
    }

    #[test]
    fn teams_context_reads_a_boolean_and_refuses_anything_else() {
        let config =
            |value: Value| -> BTreeMap<String, Value> { serde_json::from_value(value).unwrap() };
        assert!(teams_context_setting(&config(json!({}))).unwrap());
        assert!(teams_context_setting(&config(json!({"defaults": null}))).unwrap());
        assert!(
            teams_context_setting(&config(json!({"defaults": {"teams_context": null}}))).unwrap()
        );
        assert!(
            !teams_context_setting(&config(json!({"defaults": {"teams_context": false}}))).unwrap()
        );
        let error = teams_context_setting(&config(json!({"defaults": {"teams_context": "no"}})))
            .unwrap_err()
            .to_string();
        assert!(error.contains("defaults.teams_context"), "{error}");
        assert!(!error.contains("\"no\""), "{error}");
        assert!(teams_context_setting(&config(json!({"defaults": 3}))).is_err());
    }
}
