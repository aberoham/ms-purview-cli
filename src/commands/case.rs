//! `case list`, `case get` and `case create` (`docs/SPEC.md` section 3.5).

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use serde_json::Value;

use super::{
    candidates, case_status, check_sent_text, date_text, resolve_case, sent_text, shown_fields,
    shown_rows, time_text, warn_incomplete, warn_unreadable, with_marker, Produced, Session,
};
use crate::error::{PurviewError, Result};
use crate::graph::WriteResponse;
use crate::model::requests::CreateCase;
use crate::model::valid::CaseKey;
use crate::model::wire::{identity, CaseRecord, CaseStatus};
use crate::naming::{Naming, Values};
use crate::output::{write_fields, write_rows, OutputFormat};
use crate::routes::{CaseId, Query, ReadRoute, WriteRoute};
use crate::safety::{PlanInput, Planned, Preflight, WriteCommand, WritePlan, WriteSettings};
use std::io::Write;

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
    let Some(creator) = case.created_by.as_ref() else {
        return false;
    };
    if let Some(id) = identity::user_id(creator) {
        return !session.account.oid.is_empty() && id.eq_ignore_ascii_case(&session.account.oid);
    }
    let stored = session
        .account
        .upn
        .as_deref()
        .filter(|upn| !upn.is_empty())
        .unwrap_or(&session.account.email);
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

/// The cases whose display name is exactly `name`.
fn same_name(items: Vec<Value>, name: &str) -> Vec<CaseRecord> {
    items
        .into_iter()
        .filter_map(CaseRecord::from_value)
        .filter(|case| case.display_name.as_deref() == Some(name))
        .collect()
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
        let matches = same_name(items, &name);
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
        })?))
    }

    async fn applied(
        &mut self,
        preflight: &mut Preflight<'_>,
        response: WriteResponse,
    ) -> Result<Value> {
        if response.status != 201 {
            let _ = writeln!(
                preflight.log,
                "warning: Graph answered HTTP {}, where 201 was observed",
                response.status
            );
        }
        let Some(body) = response.body else {
            let _ = writeln!(
                preflight.log,
                "warning: Graph's answer has no case record; 'purview case list --name <text>' \
                 finds the new case"
            );
            return Ok(Value::Null);
        };
        let record = CaseRecord::from_value(body.clone());
        match record.as_ref().map(|case| &case.status) {
            Some(CaseStatus::Active) => {}
            Some(status) => {
                let _ = writeln!(
                    preflight.log,
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
                preflight.log,
                "warning: Graph's answer carries no valid case id; 'purview case list --name \
                 <text>' finds the new case"
            );
        }
        Ok(body)
    }

    async fn reconcile(&mut self, preflight: &mut Preflight<'_>) -> Result<Vec<String>> {
        let Some(name) = self.planned_name.clone() else {
            return Ok(Vec::new());
        };
        let listing = preflight
            .graph
            .list(&ReadRoute::Cases, &Query::new(), preflight.log)
            .await?;
        let incomplete = listing.stopped.is_some();
        let matches = same_name(listing.items, &name);
        let mut found: Vec<String> = matches
            .iter()
            .map(|case| format!("case {}", case_candidates(std::slice::from_ref(case))))
            .collect();
        if found.is_empty() {
            found.push(
                "no case with the name was listed; Purview may not list a new case at once, so \
                 check 'purview case list' again before running the command again"
                    .to_owned(),
            );
        }
        if incomplete {
            found.push("the case list stopped before its last page, so others may exist".into());
        }
        Ok(found)
    }
}
