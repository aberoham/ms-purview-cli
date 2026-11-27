//! The bodies of the commands that read Purview through Graph. `cli`
//! parses and checks the arguments, signs in, and hands each command a
//! `Session`; nothing here reads the process environment.

pub mod case;
pub mod download;
pub mod kql;
pub mod operation;
pub mod search;

use std::io::Write;
use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;

use crate::config::AccountRecord;
use crate::env::Env;
use crate::error::{PurviewError, Result};
use crate::graph::{GraphClient, ListStop, Listing, MAX_PAGES};
use crate::model::valid::{CaseKey, CaseRef, SearchKey, SearchRef};
use crate::model::wire::{CaseRecord, CaseStatus, SearchRecord};
use crate::output::OutputOptions;
use crate::routes::{CaseId, Query, ReadRoute, SearchId};

/// What a read command runs with: the streams, the output settings, the
/// Graph client and the account it acts as.
pub struct Session<'a> {
    pub env: &'a mut Env,
    pub output: &'a OutputOptions,
    pub graph: Arc<GraphClient>,
    pub account: AccountRecord,
    pub verbose: bool,
}

/// What a command produced: its exit code and the JSON document to print,
/// if any. `cli` prints the document.
#[derive(Debug, Clone, PartialEq)]
pub struct Produced {
    pub exit_code: i32,
    pub document: Option<Value>,
}

impl Produced {
    pub fn success(document: Option<Value>) -> Self {
        Self {
            exit_code: 0,
            document,
        }
    }
}

/// A timestamp as a table shows it: the UTC date.
pub fn date_text(time: Option<DateTime<Utc>>) -> String {
    time.map(|time| time.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// A timestamp as a record view shows it: UTC to the second.
pub fn time_text(time: Option<DateTime<Utc>>) -> String {
    time.map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_default()
}

/// Writes a warning when a list stopped before its last page. The list is
/// shown all the same.
pub fn warn_incomplete(log: &mut dyn Write, what: &str, listing: &Listing) {
    let reason = match listing.stopped {
        None => return,
        Some(ListStop::RepeatedLink) => "Graph's paging repeated a link".to_owned(),
        Some(ListStop::PageLimit) => format!("it did not end within {MAX_PAGES} pages"),
    };
    let _ = writeln!(
        log,
        "warning: the {what} list is incomplete: {reason}; {} entries are shown",
        listing.items.len()
    );
}

/// Writes a warning for list entries that are not JSON objects; they are
/// left out.
pub fn warn_unreadable(log: &mut dyn Write, what: &str, count: usize) {
    if count > 0 {
        let _ = writeln!(
            log,
            "warning: {count} {what} entries in Graph's list are not JSON objects and are not \
             shown"
        );
    }
}

/// The id of the case a `<case>` argument names, for a command that reads
/// below the case. An id is taken as given, with no read: a wrong one
/// fails with Graph's answer to the read that follows. A name is resolved
/// as in `resolve_case`.
pub async fn case_id(
    graph: &GraphClient,
    key: &CaseKey,
    log: &mut (dyn Write + Send),
) -> Result<CaseId> {
    match key {
        CaseKey::Id(id) => Ok(*id),
        CaseKey::Name(name) => match_case_name(graph, name, log).await,
    }
}

/// Text from the tenant as a human view shows it (`redact::shown`).
pub fn shown(session: &Session<'_>, text: &str) -> String {
    crate::redact::shown(text, &session.env.redactor)
}

/// Every value of a record view through `shown`.
pub fn shown_fields<'f>(
    session: &Session<'_>,
    fields: Vec<(&'f str, String)>,
) -> Vec<(&'f str, String)> {
    fields
        .into_iter()
        .map(|(label, value)| (label, shown(session, &value)))
        .collect()
}

/// Every cell of a table through `shown`.
pub fn shown_rows(session: &Session<'_>, rows: Vec<Vec<String>>) -> Vec<Vec<String>> {
    rows.into_iter()
        .map(|row| row.iter().map(|cell| shown(session, cell)).collect())
        .collect()
}

/// The case a `<case>` argument names, read from Graph. A name is first
/// matched exactly against every case, whatever its status, so the case
/// list must reach its last page; several matches fail with
/// `AmbiguousCase`, and a single match prints a notice on `log`. The case
/// is then read by its id, so a name gives the same record an id does.
pub async fn resolve_case(
    graph: &GraphClient,
    key: &CaseKey,
    log: &mut (dyn Write + Send),
) -> Result<CaseRef> {
    let id = case_id(graph, key, log).await?;
    let body = graph.get(&ReadRoute::Case(id), &Query::new(), log).await?;
    let record = CaseRecord::from_value(body)
        .ok_or_else(|| PurviewError::message("Graph returned a case that is not an object"))?;
    CaseRef::new(record)
}

async fn match_case_name(
    graph: &GraphClient,
    name: &str,
    log: &mut (dyn Write + Send),
) -> Result<CaseId> {
    let items = graph
        .list(&ReadRoute::Cases, &Query::new(), log)
        .await?
        .complete()
        .map_err(|error| error.context("matching the case name"))?;
    let matches: Vec<CaseRecord> = items
        .into_iter()
        .filter_map(CaseRecord::from_value)
        .filter(|case| case.display_name.as_deref() == Some(name))
        .collect();
    match matches.as_slice() {
        [] => Err(PurviewError::CaseNotFound(
            "no case has that display name, which must match exactly; 'purview case list --name \
             <text>' finds cases by part of their name"
                .to_owned(),
        )),
        [only] => {
            let case = CaseRef::new(only.clone())?;
            let _ = writeln!(log, "notice: matched case {} by its display name", case.id);
            Ok(case.id)
        }
        several => Err(PurviewError::AmbiguousCase(format!(
            "{} cases have that display name; pass the id of one: {}",
            several.len(),
            candidates(several.iter().map(|case| {
                (
                    case.id
                        .as_deref()
                        .and_then(CaseId::parse)
                        .map(|id| id.to_string()),
                    case_status(&case.status),
                    case.created_date_time,
                )
            }))
        ))),
    }
}

/// A case status for a diagnostic: one Graph documents, else `other`.
fn case_status(status: &CaseStatus) -> String {
    match status {
        CaseStatus::Active | CaseStatus::Closing | CaseStatus::Closed => status.as_str().to_owned(),
        CaseStatus::Missing => "?".to_owned(),
        CaseStatus::Other(_) => "other".to_owned(),
    }
}

/// The search a `<search>` argument names within the case, read from
/// Graph, by the same rules as `resolve_case`.
pub async fn resolve_search(
    graph: &GraphClient,
    case: CaseId,
    key: &SearchKey,
    log: &mut (dyn Write + Send),
) -> Result<SearchRef> {
    let id = match key {
        SearchKey::Id(id) => *id,
        SearchKey::Name(name) => match_search_name(graph, case, name, log).await?,
    };
    let body = graph
        .get(&ReadRoute::Search(case, id), &Query::new(), log)
        .await?;
    let record = SearchRecord::from_value(body)
        .ok_or_else(|| PurviewError::message("Graph returned a search that is not an object"))?;
    SearchRef::new(record)
}

async fn match_search_name(
    graph: &GraphClient,
    case: CaseId,
    name: &str,
    log: &mut (dyn Write + Send),
) -> Result<SearchId> {
    let items = graph
        .list(&ReadRoute::Searches(case), &Query::new(), log)
        .await?
        .complete()
        .map_err(|error| error.context("matching the search name"))?;
    let matches: Vec<SearchRecord> = items
        .into_iter()
        .filter_map(SearchRecord::from_value)
        .filter(|search| search.display_name.as_deref() == Some(name))
        .collect();
    match matches.as_slice() {
        [] => Err(PurviewError::SearchNotFound(format!(
            "no search in case {case} has that display name, which must match exactly; 'purview \
             search list {case}' lists them"
        ))),
        [only] => {
            let search = SearchRef::new(only.clone())?;
            let _ = writeln!(
                log,
                "notice: matched search {} by its display name",
                search.id
            );
            Ok(search.id)
        }
        several => Err(PurviewError::AmbiguousSearch(format!(
            "{} searches in case {case} have that display name; pass the id of one: {}",
            several.len(),
            candidates(several.iter().map(|search| {
                (
                    search
                        .id
                        .as_deref()
                        .and_then(SearchId::parse)
                        .map(|id| id.to_string()),
                    String::new(),
                    search.created_date_time,
                )
            }))
        ))),
    }
}

/// `id (status, created date)` for each match, never the name, which is
/// the same for all of them and is tenant text. Ids and statuses arrive
/// parsed or as `?`, so no tenant text reaches the message.
fn candidates(
    matches: impl Iterator<Item = (Option<String>, String, Option<DateTime<Utc>>)>,
) -> String {
    matches
        .map(|(id, status, created)| {
            let mut details = Vec::new();
            if !status.is_empty() {
                details.push(status);
            }
            let created = date_text(created);
            details.push(if created.is_empty() {
                "created ?".to_owned()
            } else {
                format!("created {created}")
            });
            format!("{} ({})", id.as_deref().unwrap_or("?"), details.join(", "))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Text cut to `limit` characters on a character boundary, with `…` in
/// place of the last when it was longer.
pub fn cut(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut kept: String = text.chars().take(limit.saturating_sub(1)).collect();
    kept.push('…');
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cut_keeps_whole_characters() {
        assert_eq!(cut("abc", 3), "abc");
        assert_eq!(cut("abcd", 3), "ab…");
        assert_eq!(cut("ééééé", 4), "ééé…");
    }

    #[test]
    fn candidates_name_ids_statuses_and_dates_only() {
        let created = DateTime::parse_from_rfc3339("2026-01-05T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let text = candidates(
            [
                (Some("a".to_owned()), "active".to_owned(), Some(created)),
                (None, "closed".to_owned(), None),
            ]
            .into_iter(),
        );
        assert_eq!(
            text,
            "a (active, created 2026-01-05); ? (closed, created ?)"
        );
    }
}
