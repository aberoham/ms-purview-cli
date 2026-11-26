//! Every method and path the tool may send to Microsoft Graph
//! (`docs/SPEC.md` section 4.3). Requests are built only from `ReadRoute`
//! and `WriteRoute`; no other code names a Graph path.
//!
//! Every read route is a `GET`. `WriteRoute` lists the six `POST`s the tool
//! can send, in `WriteRoute::ALL`. No other method exists in the crate, and
//! `tests/write_allow_list.rs` scans the source tree to keep it so. Adding a
//! write needs a reviewed design, a change to that test and an update to
//! `docs/safety.md`. No route adds custodians, data sources or holds.

use std::fmt;

use url::Url;
use uuid::Uuid;

use crate::error::{PurviewError, Result};

/// A case id: a globally unique identifier (GUID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaseId(Uuid);

/// A search id: a GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SearchId(Uuid);

/// An operation id: 32 hexadecimal characters with no hyphens (Observed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperationId(String);

/// A legal hold id, as Graph returns it. Its form is not observed, so any
/// text is accepted that addresses one path segment.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HoldId(String);

impl CaseId {
    /// The nil GUID, used only to spell the routes in `WriteRoute::ALL`.
    pub const NIL: Self = Self(Uuid::nil());

    pub fn parse(text: &str) -> Option<Self> {
        Uuid::parse_str(text.trim()).ok().map(Self)
    }
}

impl SearchId {
    /// The nil GUID, used only to spell the routes in `WriteRoute::ALL`.
    pub const NIL: Self = Self(Uuid::nil());

    pub fn parse(text: &str) -> Option<Self> {
        Uuid::parse_str(text.trim()).ok().map(Self)
    }
}

impl OperationId {
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        (text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| Self(text.to_ascii_lowercase()))
    }
}

impl HoldId {
    /// Refuses text that a URL path would read as navigation rather than as
    /// a segment.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        (!matches!(text, "" | "." | "..")).then(|| Self(text.to_owned()))
    }
}

impl fmt::Display for CaseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl fmt::Display for SearchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.hyphenated().fmt(formatter)
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Display for HoldId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

const CASES: [&str; 3] = ["security", "cases", "ediscoveryCases"];

/// The sources of a search that an action would also collect from
/// (`docs/SPEC.md` section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchSources {
    Custodian,
    Noncustodial,
    Additional,
}

impl SearchSources {
    fn segment(self) -> &'static str {
        match self {
            Self::Custodian => "custodianSources",
            Self::Noncustodial => "noncustodialSources",
            Self::Additional => "additionalSources",
        }
    }
}

/// The sources a legal hold covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldSources {
    User,
    Site,
}

impl HoldSources {
    fn segment(self) -> &'static str {
        match self {
            Self::User => "userSources",
            Self::Site => "siteSources",
        }
    }
}

/// Every Graph read. Each is a `GET`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadRoute {
    /// `/security/cases/ediscoveryCases`
    Cases,
    /// `…/{case}`
    Case(CaseId),
    /// `…/{case}/searches`
    Searches(CaseId),
    /// `…/{case}/searches/{search}`
    Search(CaseId, SearchId),
    /// `…/{case}/searches/{search}/custodianSources`, `noncustodialSources`
    /// or `additionalSources`
    SearchSources(CaseId, SearchId, SearchSources),
    /// `…/{case}/operations`
    Operations(CaseId),
    /// `…/{case}/operations/{op}`
    Operation(CaseId, OperationId),
    /// `…/{case}/custodians`
    Custodians(CaseId),
    /// `…/{case}/noncustodialDataSources`
    NoncustodialDataSources(CaseId),
    /// `…/{case}/legalHolds`
    LegalHolds(CaseId),
    /// `…/{case}/legalHolds/{hold}/userSources` or `siteSources`
    LegalHoldSources(CaseId, HoldId, HoldSources),
}

impl ReadRoute {
    /// The path segments below the Graph base, each encoded on its own when
    /// the URL is built.
    pub fn segments(&self) -> Vec<String> {
        let mut segments: Vec<String> = CASES.iter().map(|part| (*part).to_owned()).collect();
        let mut push =
            |parts: &[&str]| segments.extend(parts.iter().map(|part| (*part).to_owned()));
        match self {
            Self::Cases => {}
            Self::Case(case) => push(&[&case.to_string()]),
            Self::Searches(case) => push(&[&case.to_string(), "searches"]),
            Self::Search(case, search) => {
                push(&[&case.to_string(), "searches", &search.to_string()])
            }
            Self::SearchSources(case, search, sources) => push(&[
                &case.to_string(),
                "searches",
                &search.to_string(),
                sources.segment(),
            ]),
            Self::Operations(case) => push(&[&case.to_string(), "operations"]),
            Self::Operation(case, operation) => {
                push(&[&case.to_string(), "operations", &operation.to_string()])
            }
            Self::Custodians(case) => push(&[&case.to_string(), "custodians"]),
            Self::NoncustodialDataSources(case) => {
                push(&[&case.to_string(), "noncustodialDataSources"])
            }
            Self::LegalHolds(case) => push(&[&case.to_string(), "legalHolds"]),
            Self::LegalHoldSources(case, hold, sources) => push(&[
                &case.to_string(),
                "legalHolds",
                &hold.to_string(),
                sources.segment(),
            ]),
        }
        segments
    }
}

/// Every Purview write the tool can send. Each is a `POST`, and
/// `WriteRoute::ALL` lists one of each. The transport that sends them,
/// `GraphClient::send_write`, arrives with the first write command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRoute {
    /// `POST /security/cases/ediscoveryCases`
    CreateCase,
    /// `POST …/{case}/close`
    CloseCase(CaseId),
    /// `POST …/{case}/searches`
    CreateSearch(CaseId),
    /// `POST …/{case}/searches/{search}/estimateStatistics`
    EstimateStatistics(CaseId, SearchId),
    /// `POST …/{case}/searches/{search}/exportReport`
    ExportReport(CaseId, SearchId),
    /// `POST …/{case}/searches/{search}/exportResult`
    ExportResult(CaseId, SearchId),
}

impl WriteRoute {
    /// One of each variant, in the order of `docs/SPEC.md` section 4.3.
    pub const ALL: [WriteRoute; 6] = [
        Self::CreateCase,
        Self::CloseCase(CaseId::NIL),
        Self::CreateSearch(CaseId::NIL),
        Self::EstimateStatistics(CaseId::NIL, SearchId::NIL),
        Self::ExportReport(CaseId::NIL, SearchId::NIL),
        Self::ExportResult(CaseId::NIL, SearchId::NIL),
    ];

    /// The HTTP method: always `POST`.
    pub fn method(&self) -> &'static str {
        "POST"
    }

    /// The path below the Graph base, with `{case}` and `{search}` for the
    /// ids. The match is exhaustive, so a new variant must be spelled here.
    pub fn template(&self) -> &'static str {
        match self {
            Self::CreateCase => "/security/cases/ediscoveryCases",
            Self::CloseCase(_) => "/security/cases/ediscoveryCases/{case}/close",
            Self::CreateSearch(_) => "/security/cases/ediscoveryCases/{case}/searches",
            Self::EstimateStatistics(..) => {
                "/security/cases/ediscoveryCases/{case}/searches/{search}/estimateStatistics"
            }
            Self::ExportReport(..) => {
                "/security/cases/ediscoveryCases/{case}/searches/{search}/exportReport"
            }
            Self::ExportResult(..) => {
                "/security/cases/ediscoveryCases/{case}/searches/{search}/exportResult"
            }
        }
    }

    /// The path segments below the Graph base.
    pub fn segments(&self) -> Vec<String> {
        let (case, search) = match self {
            Self::CreateCase => (None, None),
            Self::CloseCase(case) | Self::CreateSearch(case) => (Some(case), None),
            Self::EstimateStatistics(case, search)
            | Self::ExportReport(case, search)
            | Self::ExportResult(case, search) => (Some(case), Some(search)),
        };
        self.template()
            .trim_start_matches('/')
            .split('/')
            .map(|part| match part {
                "{case}" => case.map(ToString::to_string).unwrap_or_default(),
                "{search}" => search.map(ToString::to_string).unwrap_or_default(),
                literal => literal.to_owned(),
            })
            .collect()
    }
}

/// An OData query option a read may carry. These are the keys
/// `redact::url` keeps, apart from `$skiptoken`, which only Graph's own
/// paging links carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryKey {
    Top,
    Select,
    Filter,
    Expand,
}

impl QueryKey {
    pub fn name(self) -> &'static str {
        match self {
            Self::Top => "$top",
            Self::Select => "$select",
            Self::Filter => "$filter",
            Self::Expand => "$expand",
        }
    }
}

/// The query options of one read, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query(Vec<(QueryKey, String)>);

impl Query {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: QueryKey, value: impl Into<String>) -> Self {
        self.0.push((key, value.into()));
        self
    }

    pub fn top(self, count: u32) -> Self {
        self.with(QueryKey::Top, count.to_string())
    }
}

/// The URL of `segments` below `base`, each segment percent-encoded on its
/// own, with `query` appended. A segment that would navigate (`.` or `..`)
/// or is empty is refused, so no id can address another path.
pub fn build_url(base: &Url, segments: &[String], query: &Query) -> Result<Url> {
    if let Some(bad) = segments
        .iter()
        .find(|segment| matches!(segment.as_str(), "" | "." | ".."))
    {
        return Err(PurviewError::message(format!(
            "refusing to build a Graph path with the segment {bad:?}"
        )));
    }
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|_| PurviewError::message("the Graph base URL cannot hold a path"))?
        .pop_if_empty()
        .extend(segments);
    url.set_query(None);
    url.set_fragment(None);
    if !query.0.is_empty() {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in &query.0 {
            pairs.append_pair(key.name(), value);
        }
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CASE: &str = "00000000-0000-4000-8000-000000000021";
    const SEARCH: &str = "00000000-0000-4000-8000-000000000022";

    fn base() -> Url {
        crate::origin::graph_base()
    }

    #[test]
    fn the_write_routes_are_exactly_the_six_posts() {
        let table: Vec<(&str, &str)> = WriteRoute::ALL
            .iter()
            .map(|route| (route.method(), route.template()))
            .collect();
        assert_eq!(
            table,
            [
                ("POST", "/security/cases/ediscoveryCases"),
                ("POST", "/security/cases/ediscoveryCases/{case}/close"),
                ("POST", "/security/cases/ediscoveryCases/{case}/searches"),
                (
                    "POST",
                    "/security/cases/ediscoveryCases/{case}/searches/{search}/estimateStatistics"
                ),
                (
                    "POST",
                    "/security/cases/ediscoveryCases/{case}/searches/{search}/exportReport"
                ),
                (
                    "POST",
                    "/security/cases/ediscoveryCases/{case}/searches/{search}/exportResult"
                ),
            ]
        );
    }

    /// Every variant appears in `ALL` exactly once. The match is
    /// exhaustive, so a new variant fails to compile here until it is
    /// given an index, and then fails this test until `ALL` lists it.
    #[test]
    fn all_lists_every_variant_once() {
        fn index(route: &WriteRoute) -> usize {
            match route {
                WriteRoute::CreateCase => 0,
                WriteRoute::CloseCase(_) => 1,
                WriteRoute::CreateSearch(_) => 2,
                WriteRoute::EstimateStatistics(..) => 3,
                WriteRoute::ExportReport(..) => 4,
                WriteRoute::ExportResult(..) => 5,
            }
        }
        let indices: Vec<usize> = WriteRoute::ALL.iter().map(index).collect();
        assert_eq!(indices, (0..WriteRoute::ALL.len()).collect::<Vec<_>>());
    }

    #[test]
    fn write_segments_fill_in_the_ids() {
        let case = CaseId::parse(CASE).unwrap();
        let search = SearchId::parse(SEARCH).unwrap();
        let url = build_url(
            &base(),
            &WriteRoute::EstimateStatistics(case, search).segments(),
            &Query::new(),
        )
        .unwrap();
        assert_eq!(
            url.as_str(),
            format!(
                "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/{CASE}/searches/\
                 {SEARCH}/estimateStatistics"
            )
        );
    }

    #[test]
    fn read_routes_build_their_paths_below_the_base() {
        let case = CaseId::parse(CASE).unwrap();
        let search = SearchId::parse(SEARCH).unwrap();
        let operation = OperationId::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAA0001").unwrap();
        let hold = HoldId::parse("hold 1/2").unwrap();
        let prefix = "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases";
        for (route, tail) in [
            (ReadRoute::Cases, String::new()),
            (ReadRoute::Case(case), format!("/{CASE}")),
            (ReadRoute::Searches(case), format!("/{CASE}/searches")),
            (
                ReadRoute::Search(case, search),
                format!("/{CASE}/searches/{SEARCH}"),
            ),
            (
                ReadRoute::SearchSources(case, search, SearchSources::Noncustodial),
                format!("/{CASE}/searches/{SEARCH}/noncustodialSources"),
            ),
            (ReadRoute::Operations(case), format!("/{CASE}/operations")),
            (
                ReadRoute::Operation(case, operation.clone()),
                format!("/{CASE}/operations/aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001"),
            ),
            (ReadRoute::Custodians(case), format!("/{CASE}/custodians")),
            (
                ReadRoute::NoncustodialDataSources(case),
                format!("/{CASE}/noncustodialDataSources"),
            ),
            (ReadRoute::LegalHolds(case), format!("/{CASE}/legalHolds")),
            (
                ReadRoute::LegalHoldSources(case, hold, HoldSources::Site),
                format!("/{CASE}/legalHolds/hold%201%2F2/siteSources"),
            ),
        ] {
            let url = build_url(&base(), &route.segments(), &Query::new()).unwrap();
            assert_eq!(url.as_str(), format!("{prefix}{tail}"), "{route:?}");
        }
    }

    #[test]
    fn query_options_are_encoded_and_navigation_segments_refused() {
        let url = build_url(
            &base(),
            &ReadRoute::Cases.segments(),
            &Query::new()
                .top(1)
                .with(QueryKey::Filter, "displayName eq 'a&b'"),
        )
        .unwrap();
        assert_eq!(
            url.query(),
            Some("%24top=1&%24filter=displayName+eq+%27a%26b%27")
        );
        for bad in ["", ".", ".."] {
            assert!(build_url(&base(), &[bad.to_owned()], &Query::new()).is_err());
        }
    }

    #[test]
    fn ids_are_validated() {
        assert!(CaseId::parse("not-a-guid").is_none());
        assert!(OperationId::parse(CASE).is_none());
        assert!(OperationId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaa000g").is_none());
        assert!(OperationId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaa00011").is_none());
        assert!(HoldId::parse("..").is_none());
        assert!(HoldId::parse(" ").is_none());
    }
}
