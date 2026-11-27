//! `search list`, `search get` and `search create` (`docs/SPEC.md`
//! section 3.5).

use std::io::Write;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{
    candidates, case_id, case_status, check_sent_text, cut, date_text, reconcile_notes,
    resolve_case, resolve_search, sent_text, shown, shown_fields, split_by_name, time_text,
    unreadable_names, warn_incomplete, warn_unreadable, with_marker, Produced, Session,
};
use crate::error::{PurviewError, Result};
use crate::graph::WriteResponse;
use crate::kql::{enforce, Override};
use crate::model::requests::{AllTenantMailboxes, CreateSearch};
use crate::model::valid::{CaseKey, SearchKey};
use crate::model::wire::{identity, CaseStatus, SearchRecord};
use crate::naming::{Naming, Values};
use crate::output::{sanitize, write_fields, write_rows, OutputFormat};
use crate::routes::{CaseId, Query, ReadRoute, SearchId, SearchSources, WriteRoute};
use crate::safety::{
    After, Applied, PlanInput, Planned, Preflight, Reconciled, WriteCommand, WritePlan,
    WriteSettings,
};

pub const LIST_COLUMNS: &[&str] = &["ID", "NAME", "SCOPE", "CREATED", "QUERY"];
/// The `QUERY` column's width; JSON keeps the whole query.
pub const QUERY_WIDTH: usize = 80;

/// The three source lists of a search, in the order they are shown, with
/// the key Graph gives each as a navigation property (Docs).
const SOURCES: [(SearchSources, &str, &str); 3] = [
    (
        SearchSources::Custodian,
        "custodianSources",
        "Custodian sources",
    ),
    (
        SearchSources::Noncustodial,
        "noncustodialSources",
        "Non-custodial sources",
    ),
    (
        SearchSources::Additional,
        "additionalSources",
        "Additional sources",
    ),
];

/// `search list <case>`.
pub async fn list(session: &mut Session<'_>, case: &CaseKey) -> Result<Produced> {
    let case = case_id(&session.graph, case, &mut session.env.stderr).await?;
    let listing = session
        .graph
        .list(
            &ReadRoute::Searches(case),
            &Query::new(),
            &mut session.env.stderr,
        )
        .await?;
    warn_incomplete(&mut session.env.stderr, "search", &listing);
    let total = listing.items.len();
    let searches: Vec<SearchRecord> = listing
        .items
        .into_iter()
        .filter_map(SearchRecord::from_value)
        .collect();
    warn_unreadable(&mut session.env.stderr, "search", total - searches.len());
    if session.output.format == OutputFormat::Json {
        let count = searches.len();
        let raw: Vec<Value> = searches.into_iter().map(|search| search.raw).collect();
        return Ok(Produced::success(Some(
            session
                .output
                .untrusted_json_value(Value::Array(raw), count, &session.env.redactor)?,
        )));
    }
    // Each cell goes through `shown` once. The query is redacted and
    // sanitised before it is cut, so that no part of a secret survives the
    // cut and the cut counts what the terminal shows; it is not redacted
    // again after the cut, which would misread a URL cut short.
    let rows: Vec<Vec<String>> = searches
        .iter()
        .map(|search| {
            vec![
                shown(session, search.id.as_deref().unwrap_or("?")),
                shown(
                    session,
                    search
                        .display_name
                        .as_deref()
                        .filter(|name| !name.is_empty())
                        .unwrap_or("?"),
                ),
                shown(
                    session,
                    search.data_source_scopes.as_deref().unwrap_or_default(),
                ),
                date_text(search.created_date_time),
                cut(
                    &sanitize(&shown(
                        session,
                        search.content_query.as_deref().unwrap_or_default(),
                    )),
                    QUERY_WIDTH,
                ),
            ]
        })
        .collect();
    write_rows(&mut session.env.stdout, session.output, LIST_COLUMNS, &rows)?;
    Ok(Produced::success(None))
}

/// `search get <case> <search>`: the search, and its custodian,
/// non-custodial and additional sources, which an action on the search
/// would also collect from (`docs/SPEC.md` section 6.4). The three source
/// lists are read at once. A source list that cannot be read, or that
/// stops before its last page, is a warning: the human view shows it as
/// unknown or as "N or more", and the JSON leaves it out rather than give
/// a partial list. A token that cannot be had is the command's error,
/// before any warning.
pub async fn get(
    session: &mut Session<'_>,
    case: &CaseKey,
    search: &SearchKey,
) -> Result<Produced> {
    let case = case_id(&session.graph, case, &mut session.env.stderr).await?;
    let search = resolve_search(&session.graph, case, search, &mut session.env.stderr).await?;
    let graph = &session.graph;
    let mut logs: [Vec<u8>; 3] = Default::default();
    let [first, second, third] = &mut logs;
    let route = |sources| ReadRoute::SearchSources(case, search.id, sources);
    let routes = [
        route(SOURCES[0].0),
        route(SOURCES[1].0),
        route(SOURCES[2].0),
    ];
    let query = Query::new();
    let (custodian, noncustodial, additional) = tokio::join!(
        graph.list(&routes[0], &query, first),
        graph.list(&routes[1], &query, second),
        graph.list(&routes[2], &query, third),
    );
    for log in &logs {
        session.env.stderr.write_all(log)?;
    }
    let mut reads = vec![custodian, noncustodial, additional];
    if let Some(position) = reads.iter().position(|read| {
        read.as_ref()
            .is_err_and(|error| error.is_token_unavailable())
    }) {
        reads.swap_remove(position)?;
    }
    let mut record = search.record.raw.clone();
    let mut counts: Vec<(&str, String)> = Vec::new();
    for ((_, key, label), read) in SOURCES.iter().zip(reads) {
        let listing = match read {
            Ok(listing) => listing,
            Err(error) => {
                if let Value::Object(object) = &mut record {
                    object.remove(*key);
                    object.remove(&format!("{key}@odata.context"));
                }
                let _ = writeln!(
                    session.env.stderr,
                    "warning: could not read the search's {key}: {}",
                    sanitize(&error.to_string())
                );
                counts.push((label, "unknown".to_owned()));
                continue;
            }
        };
        let complete = listing.stopped.is_none();
        warn_incomplete(&mut session.env.stderr, key, &listing);
        counts.push((
            label,
            format!(
                "{}{}",
                listing.items.len(),
                if complete { "" } else { " or more" }
            ),
        ));
        // The full read replaces any list Graph put on the record (it
        // carries additionalSources inline, Observed); an incomplete read
        // leaves no list, so the JSON never shows one that was not read to
        // its end.
        if let Value::Object(object) = &mut record {
            if complete {
                object.insert((*key).to_owned(), Value::Array(listing.items));
            } else {
                object.remove(*key);
                object.remove(&format!("{key}@odata.context"));
            }
        }
    }
    if session.output.format == OutputFormat::Json {
        return Ok(Produced::success(Some(
            session
                .output
                .untrusted_json_value(record, 1, &session.env.redactor)?,
        )));
    }
    let search = &search.record;
    let mut fields = vec![
        ("ID", search.id.clone().unwrap_or_default()),
        ("Case", case.to_string()),
        ("Name", search.display_name.clone().unwrap_or_default()),
        (
            "Description",
            search.description.clone().unwrap_or_default(),
        ),
        (
            "Scope",
            search
                .data_source_scopes
                .clone()
                .unwrap_or_else(|| "(not returned)".to_owned()),
        ),
        ("Created", time_text(search.created_date_time)),
        ("Created by", identity::shown(search.created_by.as_ref())),
        ("Last modified", time_text(search.last_modified_date_time)),
        (
            "Last modified by",
            identity::shown(search.last_modified_by.as_ref()),
        ),
    ];
    fields.extend(counts);
    fields.push(("Query", search.content_query.clone().unwrap_or_default()));
    let fields = shown_fields(session, fields);
    write_fields(&mut session.env.stdout, &fields)?;
    Ok(Produced::success(None))
}

/// `search create` (`docs/SPEC.md` section 3.5): a search over every
/// tenant mailbox in an active case. The query is built from the query
/// flags and put through the guard before sign-in; preflight reads the
/// case, lists its searches to the last page and refuses a name one of
/// them has.
pub struct SearchCreate {
    case: CaseKey,
    name: String,
    kql: String,
    description: Option<String>,
    /// `--reason` with `--allow-generic`.
    override_reason: Option<String>,
    now: DateTime<Utc>,
    naming: Option<Naming>,
    /// Whether the guard found the query narrowed; known after `check`.
    narrowed: Option<bool>,
    /// The case the plan writes to, for reconciliation.
    planned_case: Option<CaseId>,
}

/// The flags of `search create`, with the query already built.
#[derive(Debug, Clone)]
pub struct SearchCreateFlags {
    pub case: CaseKey,
    pub name: String,
    pub kql: String,
    pub description: Option<String>,
    /// `--allow-generic --reason TEXT`.
    pub override_reason: Option<String>,
}

impl SearchCreate {
    /// Checks the flags: the name, description and reason are trimmed,
    /// and blank text or text with a control or invisible character is
    /// refused. `now` gives the date variables of the naming templates.
    pub fn new(flags: SearchCreateFlags, now: DateTime<Utc>) -> Result<Self> {
        Ok(Self {
            case: flags.case,
            name: sent_text("--name", &flags.name)?,
            kql: flags.kql,
            description: flags
                .description
                .map(|description| sent_text("--description", &description))
                .transpose()?,
            override_reason: flags
                .override_reason
                .map(|reason| sent_text("--reason", &reason))
                .transpose()?,
            now,
            naming: None,
            narrowed: None,
            planned_case: None,
        })
    }

    /// The description the search would get: `--description`, or
    /// `naming.search_description`; then the override's reason, when the
    /// guard was overridden, and the marker.
    fn description(&self, naming: &Naming, user: &str, overridden: bool) -> Result<String> {
        let mut description = match &self.description {
            Some(description) => description.clone(),
            None => naming.render(
                &naming.search_description,
                &Values {
                    topic: None,
                    requester: None,
                    user,
                    query: Some(&self.kql),
                    action: None,
                    now: Some(self.now),
                },
            )?,
        };
        if overridden {
            if let Some(reason) = &self.override_reason {
                if !description.is_empty() {
                    description.push(' ');
                }
                description.push_str("Guard overridden with --allow-generic: ");
                description.push_str(reason);
            }
        }
        let description = with_marker(description, &naming.marker);
        check_sent_text(
            "the search description from naming.search_description",
            &description,
        )?;
        Ok(description)
    }
}

/// The searches whose display name is exactly `name`, and how many
/// entries have a name that cannot be read.
fn same_name(items: Vec<Value>, name: &str) -> (Vec<SearchRecord>, usize) {
    let (matches, unreadable) = split_by_name(items, name);
    (
        matches
            .into_iter()
            .filter_map(SearchRecord::from_value)
            .collect(),
        unreadable,
    )
}

/// `id (created date)` for each search, never its name.
fn search_candidates(searches: &[SearchRecord]) -> String {
    candidates(searches.iter().map(|search| {
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
}

#[async_trait]
impl WriteCommand for SearchCreate {
    /// The guard, with `guard` from `config.json`. A query that is not
    /// narrowed is refused unless `--allow-generic` gives a reason; a
    /// query outside the grammar is always refused.
    fn check(&mut self, settings: &WriteSettings) -> Result<()> {
        let allow = match &self.override_reason {
            Some(reason) => Override::AllowGeneric { reason },
            None => Override::None,
        };
        let analysis = enforce(&self.kql, &settings.guard, allow)?;
        self.narrowed = Some(analysis.narrowed);
        self.naming = Some(settings.naming.clone());
        Ok(())
    }

    async fn plan(&mut self, preflight: &mut Preflight<'_>) -> Result<Planned> {
        let (Some(naming), Some(narrowed)) = (self.naming.clone(), self.narrowed) else {
            return Err(PurviewError::message(
                "search create ran without its checks",
            ));
        };
        let description = self.description(&naming, &preflight.account.email, !narrowed)?;
        let case = resolve_case(preflight.graph, &self.case, preflight.log).await?;
        if case.record.status != CaseStatus::Active {
            return Err(PurviewError::CaseNotActive(format!(
                "case {} is {}, not active, and a search can be added only to an active case; \
                 nothing was sent",
                case.id,
                case_status(&case.record.status)
            )));
        }
        let items = preflight
            .graph
            .list(&ReadRoute::Searches(case.id), &Query::new(), preflight.log)
            .await?
            .complete()
            .map_err(|error| error.context("checking whether a search has the name already"))?;
        let listed = items.len();
        let (matches, unreadable) = same_name(items, &self.name);
        if unreadable > 0 {
            return Err(unreadable_names("searches", unreadable));
        }
        if !matches.is_empty() {
            return Err(PurviewError::SearchNameInUse(format!(
                "{} in case {} already {} the name given with --name; nothing was sent: {}. \
                 Choose another --name",
                if matches.len() == 1 {
                    "a search".to_owned()
                } else {
                    format!("{} searches", matches.len())
                },
                case.id,
                if matches.len() == 1 { "has" } else { "have" },
                search_candidates(&matches),
            )));
        }
        let body = serde_json::to_value(CreateSearch {
            display_name: &self.name,
            description: &description,
            content_query: &self.kql,
            data_source_scopes: AllTenantMailboxes,
        })?;
        self.planned_case = Some(case.id);
        let mut warnings = Vec::new();
        if !narrowed {
            warnings.push(
                "the guard found the query not narrowed; --allow-generic overrides it, and the \
                 reason is recorded in the search's description"
                    .to_owned(),
            );
        }
        Ok(Planned::Write(WritePlan::new(PlanInput {
            command: "search create",
            account: preflight.account.email.clone(),
            tenant: preflight.account.tenant_id.clone(),
            route: WriteRoute::CreateSearch(case.id),
            body,
            effects: vec![
                format!(
                    "Creates a search over all tenant mailboxes in case {}.",
                    case.id
                ),
                "Runs nothing: an estimate, report or export runs the search.".into(),
                "Adds no custodians, data sources or holds.".into(),
            ],
            warnings,
            preflight: vec![
                Value::String(format!("case {}: active", case.id)),
                Value::String(format!(
                    "searches listed in the case: {listed}; none has this name"
                )),
                Value::String(if narrowed {
                    "guard: the query is narrowed".to_owned()
                } else {
                    "guard: the query is not narrowed; overridden with --allow-generic".to_owned()
                }),
            ],
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
                "warning: Graph's answer has no search record; 'purview search list <case>' \
                 finds the new search"
            );
            return Ok(Applied::result(Value::Null));
        };
        let record = SearchRecord::from_value(body.clone());
        let check = |what: &str, echoed: Option<&str>, sent: &str, log: &mut dyn Write| {
            if echoed != Some(sent) {
                let _ = writeln!(
                    log,
                    "warning: Graph's answer {} {what} that differs from the one sent; check \
                     the search with 'purview search get' before running an action on it",
                    if echoed.is_some() { "has a" } else { "has no" },
                );
            }
        };
        check(
            "contentQuery",
            record.as_ref().and_then(|r| r.content_query.as_deref()),
            &self.kql,
            log,
        );
        check(
            "dataSourceScopes",
            record
                .as_ref()
                .and_then(|r| r.data_source_scopes.as_deref()),
            "allTenantMailboxes",
            log,
        );
        if record
            .as_ref()
            .and_then(|search| search.id.as_deref())
            .and_then(SearchId::parse)
            .is_none()
        {
            let _ = writeln!(
                log,
                "warning: Graph's answer carries no valid search id; 'purview search list \
                 <case>' finds the new search"
            );
        }
        Ok(Applied::result(body))
    }

    async fn reconcile(&mut self, preflight: &mut Preflight<'_>) -> Result<Reconciled> {
        let Some(case) = self.planned_case else {
            return Ok(Reconciled::default());
        };
        let (listing, failure) = preflight
            .graph
            .list_partial(&ReadRoute::Searches(case), &Query::new(), preflight.log)
            .await;
        let incomplete = failure.is_some() || listing.stopped.is_some();
        let (matches, unreadable) = same_name(listing.items, &self.name);
        let candidates: Vec<String> = matches
            .iter()
            .map(|search| {
                format!(
                    "search {} in case {case}",
                    search_candidates(std::slice::from_ref(search))
                )
            })
            .collect();
        Ok(Reconciled {
            notes: reconcile_notes(
                "search",
                candidates.is_empty(),
                incomplete,
                failure.as_ref(),
                unreadable,
                format!("purview search list {case}"),
            ),
            candidates,
        })
    }
}
