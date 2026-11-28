//! `case list`, `case get` and `case create` (`docs/SPEC.md` section 3.5).

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;

use super::{
    candidates, case_status, check_sent_text, date_text, reconcile_notes, resolve_case, sent_text,
    shown_fields, shown_rows, split_by_name, time_text, unreadable_names, warn_incomplete,
    warn_unreadable, with_marker, Produced, Session,
};
use crate::config::AccountRecord;
use crate::error::{PurviewError, Result};
use crate::graph::WriteResponse;
use crate::model::requests::CreateCase;
use crate::model::valid::CaseKey;
use crate::model::wire::{identity, CaseRecord, CaseStatus};
use crate::naming::{Naming, Values};
use crate::output::{write_fields, write_rows, OutputFormat};
use crate::routes::{CaseId, Query, ReadRoute, WriteRoute};
use crate::safety::{
    After, Applied, PlanInput, Planned, Preflight, Reconciled, WriteCommand, WritePlan,
    WriteSettings,
};
use std::io::Write;
use std::time::Duration;

use serde_json::json;

use super::operation::shell_word;
use crate::poll::{elapsed_text, PollEnd, Poller, Timing};

/// `--status` of `case list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StatusFilter {
    Active,
    Closing,
    Closed,
    #[default]
    All,
}

impl StatusFilter {
    fn admits(self, status: &CaseStatus) -> bool {
        match self {
            Self::All => true,
            Self::Active => *status == CaseStatus::Active,
            Self::Closing => *status == CaseStatus::Closing,
            Self::Closed => *status == CaseStatus::Closed,
        }
    }
}

/// The filters of `case list`, already checked.
#[derive(Debug, Clone, Default)]
pub struct ListFilters {
    pub status: StatusFilter,
    /// A substring of the display name, matched ignoring case.
    pub name: Option<String>,
    /// Inclusive UTC dates.
    pub created_before: Option<NaiveDate>,
    pub created_after: Option<NaiveDate>,
    pub mine: bool,
}

pub const LIST_COLUMNS: &[&str] = &[
    "ID",
    "NAME",
    "STATUS",
    "CREATED",
    "AGE (DAYS)",
    "CREATED BY",
];

impl ListFilters {
    fn admits(&self, case: &CaseRecord, session: &Session<'_>) -> bool {
        if !self.status.admits(&case.status) {
            return false;
        }
        if let Some(wanted) = &self.name {
            let wanted = wanted.to_lowercase();
            if !case
                .display_name
                .as_deref()
                .is_some_and(|name| name.to_lowercase().contains(&wanted))
            {
                return false;
            }
        }
        if self.created_before.is_some() || self.created_after.is_some() {
            let Some(created) = case.created_date_time.map(|time| time.date_naive()) else {
                return false;
            };
            if self.created_before.is_some_and(|before| created > before)
                || self.created_after.is_some_and(|after| created < after)
            {
                return false;
            }
        }
        !self.mine || created_by_account(case, session)
    }
}

/// Whether the signed-in account created the case: `createdBy.user.id`
/// equals the stored object id, or, when the record has no id, its user
/// principal name equals the stored `upn` (or the account key when the
/// sign-in recorded no `upn`), ignoring case.
fn created_by_account(case: &CaseRecord, session: &Session<'_>) -> bool {
    created_by(case, &session.account)
}

/// `created_by_account`, for any stored account.
fn created_by(case: &CaseRecord, account: &AccountRecord) -> bool {
    let Some(creator) = case.created_by.as_ref() else {
        return false;
    };
    if let Some(id) = identity::user_id(creator) {
        return !account.oid.is_empty() && id.eq_ignore_ascii_case(&account.oid);
    }
    let stored = account
        .upn
        .as_deref()
        .filter(|upn| !upn.is_empty())
        .unwrap_or(&account.email);
    identity::upn(creator).is_some_and(|upn| upn.eq_ignore_ascii_case(stored))
}

/// `case list`: every case, filtered on the client.
pub async fn list(session: &mut Session<'_>, filters: &ListFilters) -> Result<Produced> {
    let listing = session
        .graph
        .list(&ReadRoute::Cases, &Query::new(), &mut session.env.stderr)
        .await?;
    warn_incomplete(&mut session.env.stderr, "case", &listing);
    let total = listing.items.len();
    let cases: Vec<CaseRecord> = listing
        .items
        .into_iter()
        .filter_map(CaseRecord::from_value)
        .collect();
    warn_unreadable(&mut session.env.stderr, "case", total - cases.len());
    // The observed tenant's case records carried no createdBy, in the list
    // or in a single read (Observed), so --mine can match nothing.
    if filters.mine && !cases.is_empty() && !cases.iter().any(|case| case.created_by.is_some()) {
        let _ = writeln!(
            session.env.stderr,
            "warning: none of the {} case records read carries createdBy, so --mine matches \
             none of them",
            cases.len()
        );
    }
    let cases: Vec<CaseRecord> = cases
        .into_iter()
        .filter(|case| filters.admits(case, session))
        .collect();
    let incomplete = cases
        .iter()
        .filter(|case| missing(&case.id) || missing(&case.display_name))
        .count();
    if incomplete > 0 {
        let _ = writeln!(
            session.env.stderr,
            "warning: {incomplete} cases have no id or no name{}",
            if session.output.format == OutputFormat::Json {
                ""
            } else {
                "; '?' stands in for it"
            }
        );
    }
    if session.output.format == OutputFormat::Json {
        let count = cases.len();
        let raw: Vec<Value> = cases.into_iter().map(|case| case.raw).collect();
        return Ok(Produced::success(Some(
            session
                .output
                .untrusted_json_value(Value::Array(raw), count, &session.env.redactor)?,
        )));
    }
    let now = session.env.clock.now();
    let rows: Vec<Vec<String>> = cases
        .iter()
        .map(|case| {
            vec![
                shown(&case.id),
                shown(&case.display_name),
                case.status.as_str().to_owned(),
                date_text(case.created_date_time),
                case.created_date_time
                    .map(|created| (now - created).num_days().max(0).to_string())
                    .unwrap_or_default(),
                identity::shown(case.created_by.as_ref()),
            ]
        })
        .collect();
    let rows = shown_rows(session, rows);
    write_rows(&mut session.env.stdout, session.output, LIST_COLUMNS, &rows)?;
    Ok(Produced::success(None))
}

fn missing(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(str::is_empty)
}

fn shown(value: &Option<String>) -> String {
    match value.as_deref() {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => "?".to_owned(),
    }
}

/// `case get`: the whole case. JSON keeps Graph's record as it came.
pub async fn get(session: &mut Session<'_>, key: &CaseKey) -> Result<Produced> {
    let case = resolve_case(&session.graph, key, &mut session.env.stderr).await?;
    if session.output.format == OutputFormat::Json {
        return Ok(Produced::success(Some(
            session
                .output
                .untrusted_json_value(case.record.raw, 1, &session.env.redactor)?,
        )));
    }
    let record = &case.record;
    let fields = shown_fields(
        session,
        vec![
            ("ID", case.id.to_string()),
            ("Name", shown(&record.display_name)),
            ("Status", record.status.as_str().to_owned()),
            (
                "Description",
                record.description.clone().unwrap_or_default(),
            ),
            (
                "External ID",
                record.external_id.clone().unwrap_or_default(),
            ),
            ("Created", time_text(record.created_date_time)),
            ("Created by", identity::shown(record.created_by.as_ref())),
            ("Last modified", time_text(record.last_modified_date_time)),
            (
                "Last modified by",
                identity::shown(record.last_modified_by.as_ref()),
            ),
            ("Closed", time_text(record.closed_date_time)),
            ("Closed by", identity::shown(record.closed_by.as_ref())),
        ],
    );
    write_fields(&mut session.env.stdout, &fields)?;
    Ok(Produced::success(None))
}

/// `case create` (`docs/SPEC.md` section 3.5): a new case, named by
/// `naming.case_name` unless `--name` is given. Preflight lists every case,
/// to the last page, and refuses a name that any case has, whatever its
/// status, because two cases with one name make every later lookup by that
/// name ambiguous. With `--reuse-existing`, a single active case with the
/// name is shown instead, and nothing is sent.
pub struct CaseCreate {
    topic: String,
    name: Option<String>,
    requester: Option<String>,
    description: Option<String>,
    reuse_existing: bool,
    now: DateTime<Utc>,
    naming: Option<Naming>,
    /// The display name in the plan, for reconciliation.
    planned_name: Option<String>,
}

/// The flags of `case create`, as given.
#[derive(Debug, Clone, Default)]
pub struct CaseCreateFlags {
    pub topic: String,
    pub name: Option<String>,
    pub requester: Option<String>,
    pub description: Option<String>,
    pub reuse_existing: bool,
}

impl CaseCreate {
    /// Checks the flags: each is trimmed, and blank text or text with a
    /// control or invisible character is refused. `now` gives
    /// `{yyyy_mm}`.
    pub fn new(flags: CaseCreateFlags, now: DateTime<Utc>) -> Result<Self> {
        let optional = |flag: &str, value: Option<String>| -> Result<Option<String>> {
            value.map(|value| sent_text(flag, &value)).transpose()
        };
        Ok(Self {
            topic: sent_text("--topic", &flags.topic)?,
            name: optional("--name", flags.name)?,
            requester: optional("--requester", flags.requester)?,
            description: optional("--description", flags.description)?,
            reuse_existing: flags.reuse_existing,
            now,
            naming: None,
            planned_name: None,
        })
    }

    /// The display name and description the case would get.
    fn names(&self, naming: &Naming, user: &str) -> Result<(String, String)> {
        let values = Values {
            topic: Some(&self.topic),
            requester: self.requester.as_deref(),
            user,
            query: None,
            action: None,
            now: Some(self.now),
        };
        let name = match &self.name {
            Some(name) => name.clone(),
            None => naming.render(&naming.case_name, &values)?,
        };
        let description = match &self.description {
            Some(description) => description.clone(),
            None => naming.render(&naming.case_description, &values)?,
        };
        if name.is_empty() {
            return Err(PurviewError::message(
                "config.json: naming.case_name renders an empty name",
            ));
        }
        check_sent_text("the case name from naming.case_name", &name)?;
        let description = with_marker(description, &naming.marker);
        check_sent_text(
            "the case description from naming.case_description",
            &description,
        )?;
        Ok((name, description))
    }
}

/// The cases whose display name is exactly `name`, and how many entries
/// have a name that cannot be read.
fn same_name(items: Vec<Value>, name: &str) -> (Vec<CaseRecord>, usize) {
    let (matches, unreadable) = split_by_name(items, name);
    (
        matches
            .into_iter()
            .filter_map(CaseRecord::from_value)
            .collect(),
        unreadable,
    )
}

/// `id (status, created date)` for each case, never its name.
fn case_candidates(cases: &[CaseRecord]) -> String {
    candidates(cases.iter().map(|case| {
        (
            case.id
                .as_deref()
                .and_then(CaseId::parse)
                .map(|id| id.to_string()),
            case_status(&case.status),
            case.created_date_time,
        )
    }))
}

#[async_trait]
impl WriteCommand for CaseCreate {
    fn check(&mut self, settings: &WriteSettings) -> Result<()> {
        self.naming = Some(settings.naming.clone());
        Ok(())
    }

    async fn plan(&mut self, preflight: &mut Preflight<'_>) -> Result<Planned> {
        let naming = self
            .naming
            .clone()
            .ok_or_else(|| PurviewError::message("case create ran without its settings"))?;
        let (name, description) = self.names(&naming, &preflight.account.email)?;
        let items = preflight
            .graph
            .list(&ReadRoute::Cases, &Query::new(), preflight.log)
            .await?
            .complete()
            .map_err(|error| error.context("checking whether a case has the name already"))?;
        let listed = items.len();
        let (matches, unreadable) = same_name(items, &name);
        if unreadable > 0 {
            return Err(unreadable_names("cases", unreadable));
        }
        match matches.as_slice() {
            [] => {}
            [only] if self.reuse_existing && only.status == CaseStatus::Active => {
                let case = crate::model::valid::CaseRef::new(only.clone())?;
                return Ok(Planned::Existing {
                    notice: format!(
                        "Reused: case {} is active and has the name; nothing was sent.",
                        case.id
                    ),
                    result: case.record.raw,
                });
            }
            several => {
                let reuse = if self.reuse_existing {
                    " --reuse-existing uses only a single active case with the name."
                } else if several.len() == 1 && several[0].status == CaseStatus::Active {
                    " Pass --reuse-existing to use that case."
                } else {
                    ""
                };
                return Err(PurviewError::CaseNameInUse(format!(
                    "{} with the name this case would get already exist{}, and two cases with \
                     one name make every later lookup by name ambiguous; nothing was sent: {}. \
                     Choose another --topic or --name.{reuse}",
                    if several.len() == 1 {
                        "a case".to_owned()
                    } else {
                        format!("{} cases", several.len())
                    },
                    if several.len() == 1 { "s" } else { "" },
                    case_candidates(several),
                )));
            }
        }
        let body = serde_json::to_value(CreateCase {
            display_name: &name,
            description: &description,
        })?;
        self.planned_name = Some(name);
        Ok(Planned::Write(WritePlan::new(PlanInput {
            command: "case create",
            account: preflight.account.email.clone(),
            tenant: preflight.account.tenant_id.clone(),
            route: WriteRoute::CreateCase,
            body,
            effects: vec![
                "Creates an eDiscovery case, visible to eDiscovery administrators in the tenant."
                    .into(),
                "Adds no custodians, data sources or holds.".into(),
            ],
            warnings: Vec::new(),
            preflight: vec![Value::String(format!(
                "cases listed: {listed}; none has this name"
            ))],
            blocked: None,
        })?))
    }

    async fn applied(&mut self, after: &mut After<'_>, response: WriteResponse) -> Result<Applied> {
        let log = &mut after.session.env.stderr;
        if response.status != 201 {
            let _ = writeln!(
                log,
                "warning: Graph answered HTTP {}, where 201 was observed",
                response.status
            );
        }
        let Some(body) = response.body else {
            let _ = writeln!(
                log,
                "warning: Graph's answer has no case record; 'purview case list --name <text>' \
                 finds the new case"
            );
            return Ok(Applied::result(Value::Null));
        };
        let record = CaseRecord::from_value(body.clone());
        match record.as_ref().map(|case| &case.status) {
            Some(CaseStatus::Active) => {}
            Some(status) => {
                let _ = writeln!(
                    log,
                    "warning: the new case's status is {}, where active was observed",
                    case_status(status)
                );
            }
            None => {}
        }
        if record
            .as_ref()
            .and_then(|case| case.id.as_deref())
            .and_then(CaseId::parse)
            .is_none()
        {
            let _ = writeln!(
                log,
                "warning: Graph's answer carries no valid case id; 'purview case list --name \
                 <text>' finds the new case"
            );
        }
        Ok(Applied::result(body))
    }

    async fn reconcile(&mut self, preflight: &mut Preflight<'_>) -> Result<Reconciled> {
        let Some(name) = self.planned_name.clone() else {
            return Ok(Reconciled::default());
        };
        let (listing, failure) = preflight
            .graph
            .list_partial(&ReadRoute::Cases, &Query::new(), preflight.log)
            .await?;
        let incomplete = failure.is_some() || listing.stopped.is_some();
        let (matches, unreadable) = same_name(listing.items, &name);
        let candidates: Vec<String> = matches
            .iter()
            .map(|case| format!("case {}", case_candidates(std::slice::from_ref(case))))
            .collect();
        Ok(Reconciled {
            notes: reconcile_notes(
                "case",
                candidates.is_empty(),
                incomplete,
                failure.as_ref(),
                unreadable,
                "purview case list".to_owned(),
            ),
            candidates,
        })
    }
}

/// The default deadline of `case close --wait` (`docs/SPEC.md` section 3.5).
pub const CLOSE_WAIT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// `case close` (`docs/SPEC.md` section 3.5): closes a case the tool made,
/// after showing that it has no custodians, data sources or holds. Every
/// preflight read must succeed and every list reach its last page; the
/// tool never changes a hold and never reopens a case.
pub struct CaseClose {
    key: CaseKey,
    any_case: bool,
    wait: Option<Timing>,
    marker: Option<String>,
    /// The case planned, for the recheck, the result and reconciliation.
    planned: Option<CaseId>,
}

impl CaseClose {
    /// `wait` is the `--wait` timing, or `None` to read the case once
    /// after the close.
    pub fn new(key: CaseKey, any_case: bool, wait: Option<Timing>) -> Self {
        Self {
            key,
            any_case,
            wait,
            marker: None,
            planned: None,
        }
    }
}

/// The three reads that show a case holds nothing, by the names Graph
/// gives them (Docs).
fn hold_reads(case: CaseId) -> [(&'static str, ReadRoute); 3] {
    [
        ("custodians", ReadRoute::Custodians(case)),
        (
            "noncustodialDataSources",
            ReadRoute::NoncustodialDataSources(case),
        ),
        ("legalHolds", ReadRoute::LegalHolds(case)),
    ]
}

/// The error's code and HTTP status, never its message, which may quote
/// tenant text: `GraphError, HTTP 403`.
fn failure_text(error: &PurviewError) -> String {
    let (code, status) = error.metadata();
    if status == 0 {
        code.to_owned()
    } else {
        format!("{code}, HTTP {status}")
    }
}

/// The precheck's refusal of `what` that failed. A broken sign-in keeps
/// its own error.
fn precheck_failed(what: &str, error: PurviewError) -> PurviewError {
    if matches!(error, PurviewError::TokenUnavailable(_)) {
        return error;
    }
    PurviewError::ClosePrecheckFailed(format!(
        "{what} failed ({}), so it cannot be shown that the case may be closed; nothing was sent",
        failure_text(&error)
    ))
}

/// How many entries each hold read lists, each read to its last page.
async fn hold_counts(
    preflight: &mut Preflight<'_>,
    case: CaseId,
) -> Result<Vec<(&'static str, usize)>> {
    let mut counts = Vec::new();
    for (name, route) in hold_reads(case) {
        let what = format!("reading the case's {name} to their end");
        // A paging link to any other collection is refused: the count must
        // be this case's.
        let items = preflight
            .graph
            .list_bound(&route, &Query::new(), preflight.log)
            .await
            .and_then(crate::graph::Listing::complete)
            .map_err(|error| precheck_failed(&what, error))?;
        counts.push((name, items.len()));
    }
    Ok(counts)
}

/// `CaseHasHolds` when any read listed an entry, with the counts.
fn refuse_holds(case: CaseId, counts: &[(&'static str, usize)]) -> Result<()> {
    if counts.iter().all(|(_, count)| *count == 0) {
        return Ok(());
    }
    Err(PurviewError::CaseHasHolds(format!(
        "case {case} has {}; nothing was sent. This tool never changes holds, custodians or \
         data sources; remove them in the Purview portal first if the case should be closed",
        counts
            .iter()
            .map(|(name, count)| format!("{count} {name}"))
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

/// How a case was shown to be one `case close` may close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ownership {
    Marked,
    CreatedByAccount,
    AnyCase,
}

impl Ownership {
    fn text(self) -> &'static str {
        match self {
            Self::Marked => "the description carries naming.marker",
            Self::CreatedByAccount => "the signed-in account created it",
            Self::AnyCase => "--any-case: not shown to be a case this tool made",
        }
    }
}

/// Step 2 of the preflight: the description carries `marker`, or the
/// signed-in account created the case, or `--any-case`.
fn ownership(
    case: &crate::model::valid::CaseRef,
    marker: &str,
    account: &AccountRecord,
    any_case: bool,
) -> Result<Ownership> {
    let marked = !marker.is_empty()
        && case
            .record
            .description
            .as_deref()
            .is_some_and(|description| description.contains(marker));
    if marked {
        Ok(Ownership::Marked)
    } else if created_by(&case.record, account) {
        Ok(Ownership::CreatedByAccount)
    } else if any_case {
        Ok(Ownership::AnyCase)
    } else {
        Err(PurviewError::ClosePrecheckFailed(format!(
            "case {} has no naming.marker in its description and was not created by the \
             signed-in account, so it is not shown to be a case this tool made; nothing was \
             sent. Pass --any-case to close a case made another way",
            case.id
        )))
    }
}

/// The case, which must be active.
async fn active_case(
    preflight: &mut Preflight<'_>,
    key: &CaseKey,
) -> Result<crate::model::valid::CaseRef> {
    let case = super::resolve_case(preflight.graph, key, preflight.log)
        .await
        .map_err(|error| match error {
            PurviewError::CaseNotFound(_) | PurviewError::AmbiguousCase(_) => error,
            other => precheck_failed("reading the case", other),
        })?;
    if case.record.status != CaseStatus::Active {
        return Err(PurviewError::ClosePrecheckFailed(format!(
            "case {} is {}, not active; nothing was sent",
            case.id,
            case_status(&case.record.status)
        )));
    }
    Ok(case)
}

#[async_trait]
impl WriteCommand for CaseClose {
    fn check(&mut self, settings: &WriteSettings) -> Result<()> {
        self.marker = Some(settings.naming.marker.clone());
        Ok(())
    }

    async fn plan(&mut self, preflight: &mut Preflight<'_>) -> Result<Planned> {
        let marker = self
            .marker
            .clone()
            .ok_or_else(|| PurviewError::message("case close ran without its settings"))?;
        let case = active_case(preflight, &self.key).await?;
        let ownership = ownership(&case, &marker, preflight.account, self.any_case)?;
        let counts = hold_counts(preflight, case.id).await?;
        refuse_holds(case.id, &counts)?;
        self.planned = Some(case.id);
        let name = case
            .record
            .display_name
            .clone()
            // A name the terminal would show as nothing is confirmed by the
            // case id.
            .filter(|name| !crate::output::sanitize(name).trim().is_empty())
            .unwrap_or_else(|| case.id.to_string());
        let mut lines = vec![
            Value::String(format!("case {} is active", case.id)),
            Value::String(format!("ownership: {}", ownership.text())),
        ];
        lines.extend(
            counts
                .iter()
                .map(|(name, count)| Value::String(format!("{name}: {count}, to the last page"))),
        );
        Ok(Planned::Write(
            WritePlan::new(PlanInput {
                command: "case close",
                account: preflight.account.email.clone(),
                tenant: preflight.account.tenant_id.clone(),
                route: WriteRoute::CloseCase(case.id),
                body: Value::Null,
                effects: vec![
                    format!(
                        "Closes case {}: its status becomes closing, then closed. This tool \
                         never reopens a case; reopening is done by hand in the Purview portal.",
                        case.id
                    ),
                    "Changes no hold, custodian or data source: the case has none.".into(),
                ],
                warnings: if ownership == Ownership::AnyCase {
                    vec!["--any-case: the case is not shown to be one this tool made".into()]
                } else {
                    Vec::new()
                },
                preflight: lines,
                blocked: None,
            })?
            .with_typed_confirmation(name),
        ))
    }

    /// The case is read again after approval: still active, and still with
    /// no holds, since the person may have taken a while to answer.
    async fn recheck(&mut self, preflight: &mut Preflight<'_>) -> Result<()> {
        let planned = self
            .planned
            .ok_or_else(|| PurviewError::message("case close ran without a plan"))?;
        let case = active_case(preflight, &CaseKey::Id(planned)).await?;
        let marker = self.marker.clone().unwrap_or_default();
        ownership(&case, &marker, preflight.account, self.any_case)?;
        let counts = hold_counts(preflight, case.id).await?;
        refuse_holds(case.id, &counts)
    }

    async fn applied(&mut self, after: &mut After<'_>, response: WriteResponse) -> Result<Applied> {
        let case = self
            .planned
            .ok_or_else(|| PurviewError::message("case close ran without a plan"))?;
        let session = &mut after.session;
        if response.status != 204 {
            let _ = writeln!(
                session.env.stderr,
                "warning: Graph answered HTTP {}, where 204 was observed",
                response.status
            );
        }
        let route = ReadRoute::Case(case);
        let Some(timing) = self.wait else {
            // One read, to show the status the close left.
            let read = session
                .graph
                .get(&route, &Query::new(), &mut session.env.stderr)
                .await
                .and_then(|body| case_as_read(body, case));
            return Ok(match read {
                Ok(record) => Applied::result(record.raw),
                Err(error) => {
                    let _ = writeln!(
                        session.env.stderr,
                        "warning: Graph accepted the close, but reading the case after it failed \
                         ({}); 'purview case get {case}' shows its status",
                        failure_text(&error)
                    );
                    Applied::result(Value::Null)
                }
            });
        };
        let started = session.env.clock.elapsed();
        let clock = session.env.clock.clone();
        let interrupt = session.env.interrupt.clone();
        let graph = session.graph.clone();
        let poller = Poller {
            graph: &graph,
            clock: clock.as_ref(),
            interrupt: interrupt.as_ref(),
            timing,
            not_found_grace: None,
        };
        let show_progress = session.env.stderr_is_terminal && !session.verbose;
        let shown_id = format!("{}…", &case.to_string()[..8]);
        let mut progress = |record: &CaseRecord, waited: Duration, log: &mut (dyn Write + Send)| {
            if show_progress {
                let _ = writeln!(
                    log,
                    "case {shown_id}: {} · {}",
                    crate::output::sanitize(record.status.as_str()),
                    elapsed_text(waited)
                );
            }
        };
        let end = poller
            .wait(&route, &mut session.env.stderr, &mut progress)
            .await?;
        let waited = clock.elapsed().saturating_sub(started);
        match end {
            PollEnd::Finished(record) => {
                let reasons = match &record.status {
                    CaseStatus::Closed => Vec::new(),
                    other => vec![json!({
                        "code": "UnknownStatus",
                        "message": format!(
                            "case {case} is {}, a status this tool does not know",
                            case_status(other)
                        ),
                    })],
                };
                Ok(Applied::Result {
                    result: record.raw,
                    reasons,
                })
            }
            PollEnd::TimedOut { last } => Ok(Applied::Produced(close_stopped(
                session, case, last, waited, false,
            ))),
            PollEnd::Interrupted { last } => Ok(Applied::Produced(close_stopped(
                session, case, last, waited, true,
            ))),
        }
    }

    /// After an unclear outcome, the case is read once and its status
    /// shown.
    async fn reconcile(&mut self, preflight: &mut Preflight<'_>) -> Result<Reconciled> {
        let Some(case) = self.planned else {
            return Ok(Reconciled::default());
        };
        let route = ReadRoute::Case(case);
        let read = preflight
            .graph
            .get(&route, &Query::new(), preflight.log)
            .await
            .and_then(|body| case_as_read(body, case));
        Ok(match read {
            Ok(record) => Reconciled {
                candidates: vec![format!("case {case}: {}", case_status(&record.status))],
                notes: vec![format!(
                    "'purview case get {case}' shows the case's status again"
                )],
            },
            Err(error) => Reconciled {
                candidates: Vec::new(),
                notes: vec![format!(
                    "reading case {case} failed ({}); 'purview case get {case}' shows whether it \
                     closed",
                    failure_text(&error)
                )],
            },
        })
    }
}

/// One read of the case after the close: it must be case `case`, but
/// may have no status, which the result then shows as Graph gave it. The
/// wait, by contrast, ends on a read with no status.
fn case_as_read(body: Value, case: CaseId) -> Result<CaseRecord> {
    let record = CaseRecord::from_value(body)
        .ok_or_else(|| PurviewError::message("Graph returned a case that is not an object"))?;
    let read = crate::model::valid::CaseRef::new(record)?;
    if read.id != case {
        return Err(PurviewError::message(format!(
            "Graph answered the read of case {case} with case {}",
            read.id
        )));
    }
    Ok(read.record)
}

/// The case-close document at the `--wait` deadline (exit 5) or after
/// Ctrl-C (exit 130), `docs/SPEC.md` section 3.3.
fn close_stopped(
    session: &mut Session<'_>,
    case: CaseId,
    last: Option<CaseRecord>,
    waited: Duration,
    interrupted: bool,
) -> Produced {
    // The status is Graph's text: shown as other tenant text is.
    let status = last
        .as_ref()
        .map(|record| crate::redact::shown(record.status.as_str(), &session.env.redactor));
    let closed = last
        .as_ref()
        .is_some_and(|record| record.status == CaseStatus::Closed);
    let account = shell_word(&session.account.email);
    let resume = vec![format!("purview --account={account} case get {case}")];
    let (exit_code, code, verb) = if interrupted {
        (130, "Interrupted", "interrupted")
    } else {
        (5, "WaitTimeout", "stopped waiting")
    };
    let message = if closed {
        format!("{verb} after {}", elapsed_text(waited))
    } else {
        format!(
            "{verb} after {}; the service carries on closing the case",
            elapsed_text(waited)
        )
    };
    if session.output.format == OutputFormat::Json {
        return Produced {
            exit_code,
            document: Some(json!({
                "caseId": case.to_string(),
                "caseStatus": status,
                "elapsedSeconds": waited.as_secs(),
                "resume": resume,
                "error": {"code": code, "status": 0, "message": message},
            })),
        };
    }
    let status = status
        .as_deref()
        .map(crate::output::sanitize)
        .unwrap_or_else(|| "not read yet".to_owned());
    let _ = writeln!(
        session.env.stderr,
        "{message}. Case {case} was {status}. Check it with: {}",
        crate::output::sanitize(&resume[0])
    );
    Produced {
        exit_code,
        document: None,
    }
}
