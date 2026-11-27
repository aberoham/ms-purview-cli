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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
