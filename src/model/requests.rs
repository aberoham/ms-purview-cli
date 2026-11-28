//! Request bodies (`docs/SPEC.md` section 7.5). Each write's body is one of
//! these types, so that what a command can send is fixed by the type: a
//! search's data source scope can only be every tenant mailbox.

use serde::{Serialize, Serializer};

/// Serialises only as `"allTenantMailboxes"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AllTenantMailboxes;

impl Serialize for AllTenantMailboxes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("allTenantMailboxes")
    }
}

/// `POST /security/cases/ediscoveryCases`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateCase<'a> {
    pub display_name: &'a str,
    pub description: &'a str,
}

/// `POST /security/cases/ediscoveryCases/{case}/searches`. It has no field
/// for custodians, non-custodial sources or any other scope.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSearch<'a> {
    pub display_name: &'a str,
    pub description: &'a str,
    pub content_query: &'a str,
    pub data_source_scopes: AllTenantMailboxes,
}

/// `POST …/searches/{search}/estimateStatistics`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EstimateRequest {
    /// Always `includeQueryStats`.
    pub statistics_options: IncludeQueryStats,
}

/// Serialises only as `"includeQueryStats"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IncludeQueryStats;

impl Serialize for IncludeQueryStats {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("includeQueryStats")
    }
}

/// `POST …/searches/{search}/exportReport` (`docs/SPEC.md` section 7.5):
/// every hit, from the locations with hits.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportReportRequest<'a> {
    pub display_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'a str>,
    pub export_criteria: SearchHits,
    pub export_location: ResponsiveLocations,
    /// `Some` by default; `None` under `--no-teams-context`, a body not
    /// yet observed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional_options: Option<TeamsConversations>,
}

/// Serialises only as `"searchHits"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SearchHits;

impl Serialize for SearchHits {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("searchHits")
    }
}

/// Serialises only as `"responsiveLocations"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResponsiveLocations;

impl Serialize for ResponsiveLocations {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("responsiveLocations")
    }
}

/// Serialises only as `"teamsAndYammerConversations"`: the conversation
/// around each Teams hit (`docs/SPEC.md` section 6.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TeamsConversations;

impl Serialize for TeamsConversations {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("teamsAndYammerConversations")
    }
}

/// `POST …/searches/{search}/exportResult` (`docs/SPEC.md` section 7.5):
/// every hit, from the locations with hits, as `.msg` files with the
/// item report beside them.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResultRequest<'a> {
    pub display_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'a str>,
    pub export_criteria: SearchHits,
    pub export_location: ResponsiveLocations,
    pub additional_options: ExportOptions,
    pub export_format: MsgFormat,
}

/// An export's `additionalOptions`: the report always, and the
/// conversation around each Teams hit unless `--no-teams-context`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportOptions {
    /// `teamsAndYammerConversations,includeReport` (Observed).
    TeamsAndReport,
    /// `includeReport`, not yet observed.
    ReportOnly,
}

impl Serialize for ExportOptions {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::TeamsAndReport => "teamsAndYammerConversations,includeReport",
            Self::ReportOnly => "includeReport",
        })
    }
}

/// Serialises only as `"msg"`: the format `export read` reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MsgFormat;

impl Serialize for MsgFormat {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("msg")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_export_body_is_the_observed_one_and_always_asks_for_the_report() {
        let body = serde_json::to_value(ExportResultRequest {
            display_name: "export 2026-03-14 0930Z",
            description: None,
            export_criteria: SearchHits,
            export_location: ResponsiveLocations,
            additional_options: ExportOptions::TeamsAndReport,
            export_format: MsgFormat,
        })
        .unwrap();
        assert_eq!(
            body,
            json!({
                "displayName": "export 2026-03-14 0930Z",
                "exportCriteria": "searchHits",
                "exportLocation": "responsiveLocations",
                "additionalOptions": "teamsAndYammerConversations,includeReport",
                "exportFormat": "msg",
            })
        );
        let body = serde_json::to_value(ExportResultRequest {
            display_name: "n",
            description: Some("why"),
            export_criteria: SearchHits,
            export_location: ResponsiveLocations,
            additional_options: ExportOptions::ReportOnly,
            export_format: MsgFormat,
        })
        .unwrap();
        assert_eq!(body["additionalOptions"], "includeReport");
        assert_eq!(body["description"], "why");
    }

    #[test]
    fn a_search_body_always_scopes_every_tenant_mailbox() {
        let body = serde_json::to_value(CreateSearch {
            display_name: "n",
            description: "d",
            content_query: "\"orders-api\"",
            data_source_scopes: AllTenantMailboxes,
        })
        .unwrap();
        assert_eq!(
            body,
            json!({
                "displayName": "n",
                "description": "d",
                "contentQuery": "\"orders-api\"",
                "dataSourceScopes": "allTenantMailboxes",
            })
        );
    }

    #[test]
    fn an_estimate_body_asks_for_query_statistics() {
        let body = serde_json::to_value(EstimateRequest {
            statistics_options: IncludeQueryStats,
        })
        .unwrap();
        assert_eq!(body, json!({"statisticsOptions": "includeQueryStats"}));
    }

    #[test]
    fn a_case_body_has_the_name_and_description_only() {
        let body = serde_json::to_value(CreateCase {
            display_name: "n",
            description: "d",
        })
        .unwrap();
        assert_eq!(body, json!({"displayName": "n", "description": "d"}));
    }

    #[test]
    fn a_report_body_is_the_observed_one_and_drops_only_what_is_absent() {
        let body = serde_json::to_value(ExportReportRequest {
            display_name: "report 2026-03-14 0930Z",
            description: None,
            export_criteria: SearchHits,
            export_location: ResponsiveLocations,
            additional_options: Some(TeamsConversations),
        })
        .unwrap();
        assert_eq!(
            body,
            json!({
                "displayName": "report 2026-03-14 0930Z",
                "exportCriteria": "searchHits",
                "exportLocation": "responsiveLocations",
                "additionalOptions": "teamsAndYammerConversations",
            })
        );
        let body = serde_json::to_value(ExportReportRequest {
            display_name: "n",
            description: Some("why"),
            export_criteria: SearchHits,
            export_location: ResponsiveLocations,
            additional_options: None,
        })
        .unwrap();
        assert_eq!(
            body,
            json!({
                "displayName": "n",
                "description": "why",
                "exportCriteria": "searchHits",
                "exportLocation": "responsiveLocations",
            })
        );
    }
}
