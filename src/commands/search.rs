//! `search list` and `search get` (`docs/SPEC.md` section 3.5).

use std::io::Write;

use serde_json::Value;

use super::{
    case_id, cut, date_text, resolve_search, shown, shown_fields, time_text, warn_incomplete,
    warn_unreadable, Produced, Session,
};
use crate::error::Result;
use crate::model::valid::{CaseKey, SearchKey};
use crate::model::wire::{identity, SearchRecord};
use crate::output::{sanitize, write_fields, write_rows, OutputFormat};
use crate::routes::{Query, ReadRoute, SearchSources};

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
        // Graph's own list wins if the record already carries one; a
        // null is taken as no list.
        if let (true, Value::Object(object)) = (complete, &mut record) {
            let slot = object.entry((*key).to_owned()).or_insert(Value::Null);
            if slot.is_null() {
                *slot = Value::Array(listing.items);
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
