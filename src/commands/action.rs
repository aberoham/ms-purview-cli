//! The preflight every action on a search runs (`docs/SPEC.md` sections
//! 6.4 and 6.7): the search's scope and sources, the guard on its current
//! query, and the case's active operations that may be duplicates.

use std::io::Write;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{case_id, resolve_search};
use crate::error::{PurviewError, Result};
use crate::graph::GraphClient;
use crate::kql::{enforce, GuardConfig, Override};
use crate::model::valid::{CaseKey, SearchKey, SearchRef};
use crate::model::wire::{OperationRecord, OperationStatus};
use crate::routes::{CaseId, OperationId, Query, ReadRoute, SearchSources};

/// The one scope an action may run on.
pub const ALL_TENANT_MAILBOXES: &str = "allTenantMailboxes";

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

/// The case's operations with `action` (`estimateStatistics`, or
/// `exportResult`, which the list shows for both reports and exports) that
/// are not known to be finished, read to the last page; an entry whose
/// action or status cannot be read is kept, since it cannot be ruled out. `$expand=search`
/// is refused (Observed), so they cannot be narrowed to the search.
pub async fn active_operations(
    graph: &GraphClient,
    case: CaseId,
    action: &str,
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
            .is_some_and(|found| found != action);
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

/// The operations with `action` that the signed-in account may have
/// started at or after `since`, for reconciliation (`docs/SPEC.md` section
/// 6.7): by `createdBy` when the record has it, else every one created
/// since then. Pages read before a failure are kept.
pub async fn started_since(
    graph: &GraphClient,
    case: CaseId,
    action: &str,
    since: DateTime<Utc>,
    account: &crate::config::AccountRecord,
    log: &mut (dyn Write + Send),
) -> (Vec<Active>, bool, Option<PurviewError>) {
    let (listing, failure) = graph
        .list_partial(&ReadRoute::Operations(case), &Query::new(), log)
        .await;
    let incomplete = failure.is_some() || listing.stopped.is_some();
    let mut found = Vec::new();
    for item in listing.items {
        let Some(record) = OperationRecord::from_value(item) else {
            continue;
        };
        if record.action.as_deref() != Some(action)
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
            status: record.status.as_str().to_owned(),
            created: record.created_date_time,
        });
    }
    (found, incomplete, failure)
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
