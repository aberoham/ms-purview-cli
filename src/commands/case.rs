//! `case list` and `case get` (`docs/SPEC.md` section 3.5).

use chrono::NaiveDate;
use serde_json::Value;

use super::{
    date_text, resolve_case, shown_fields, shown_rows, time_text, warn_incomplete, warn_unreadable,
    Produced, Session,
};
use crate::error::Result;
use crate::model::valid::CaseKey;
use crate::model::wire::{identity, CaseRecord, CaseStatus};
use crate::output::{write_fields, write_rows, OutputFormat};
use crate::routes::{Query, ReadRoute};
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
    if filters.mine && !cases.iter().any(|case| case.created_by.is_some()) {
        let _ = writeln!(
            session.env.stderr,
            "warning: Graph's case records carry no createdBy, so --mine matches no case"
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
