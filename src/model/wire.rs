//! Wire records: cases, searches and operations as Graph sends them
//! (`docs/SPEC.md` section 7).
//!
//! Every field is optional, and each is read from the JSON on its own: a
//! field that is absent, `null` or of an unexpected type becomes `None`,
//! so a sparse or changed response cannot fail a whole list. Each record
//! keeps the JSON it was read from in `raw`, for full views and `--json`.

use chrono::{DateTime, Datelike, Utc};
use serde_json::{Map, Value};

/// Graph's `@odata.type` for an estimate operation (Observed).
pub const ESTIMATE_OPERATION: &str = "#microsoft.graph.security.ediscoveryEstimateOperation";
/// Graph's `@odata.type` for an item report or export operation (Observed).
pub const EXPORT_OPERATION: &str = "#microsoft.graph.security.ediscoverySearchExportOperation";

fn field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

/// A string field; any other type is `None`.
fn text(object: &Map<String, Value>, key: &str) -> Option<String> {
    field(object, key)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// A Graph timestamp. `0001-01-01T00:00:00Z`, which Graph sends for an
/// operation that has not completed (Observed), an empty string and text
/// that does not parse are all `None`.
pub fn graph_time(value: Option<&Value>) -> Option<DateTime<Utc>> {
    let text = value?.as_str()?;
    DateTime::parse_from_rfc3339(text.trim())
        .ok()
        .map(|time| time.with_timezone(&Utc))
        .filter(|time| time.year() > 1)
}

/// How a number read as a count turned out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    /// Absent or `null`.
    Absent,
    /// A whole number of zero or more.
    Value(u64),
    /// A negative or fractional number, or another type: not a count.
    Invalid,
}

/// Reads a count. Negative and fractional numbers are `Invalid`, so the
/// caller can warn about them.
pub fn read_count(value: Option<&Value>) -> Count {
    match value {
        None | Some(Value::Null) => Count::Absent,
        Some(Value::Number(number)) => match number.as_u64() {
            Some(count) => Count::Value(count),
            None => Count::Invalid,
        },
        Some(_) => Count::Invalid,
    }
}

/// The status of a case.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CaseStatus {
    Active,
    Closing,
    Closed,
    /// No status in the record.
    #[default]
    Missing,
    /// Any other value Graph sends, such as `closedWithError`, kept as sent.
    Other(String),
}

impl CaseStatus {
    pub fn parse(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::Missing,
            Some("active") => Self::Active,
            Some("closing") => Self::Closing,
            Some("closed") => Self::Closed,
            Some(other) => Self::Other(other.to_owned()),
        }
    }

    /// The status as Graph spells it, or `?` when the record has none.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Missing => "?",
            Self::Other(other) => other,
        }
    }
}

/// An eDiscovery case.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct CaseRecord {
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub external_id: Option<String>,
    pub status: CaseStatus,
    pub created_date_time: Option<DateTime<Utc>>,
    pub last_modified_date_time: Option<DateTime<Utc>>,
    pub closed_date_time: Option<DateTime<Utc>>,
    /// Identity sets, kept as JSON so new fields survive; `identity` reads
    /// them.
    pub created_by: Option<Value>,
    pub last_modified_by: Option<Value>,
    pub closed_by: Option<Value>,
    pub raw: Value,
}

impl CaseRecord {
    /// The record in `value`, or `None` when it is not a JSON object.
    pub fn from_value(value: Value) -> Option<Self> {
        let object = value.as_object()?;
        Some(Self {
            id: text(object, "id"),
            display_name: text(object, "displayName"),
            description: text(object, "description"),
            external_id: text(object, "externalId"),
            status: CaseStatus::parse(field(object, "status").and_then(Value::as_str)),
            created_date_time: graph_time(field(object, "createdDateTime")),
            last_modified_date_time: graph_time(field(object, "lastModifiedDateTime")),
            closed_date_time: graph_time(field(object, "closedDateTime")),
            created_by: field(object, "createdBy").cloned(),
            last_modified_by: field(object, "lastModifiedBy").cloned(),
            closed_by: field(object, "closedBy").cloned(),
            raw: value,
        })
    }
}

/// A search in a case.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SearchRecord {
    pub id: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub content_query: Option<String>,
    /// A flags enumeration as comma-separated text, such as
    /// `allTenantMailboxes` (Docs).
    pub data_source_scopes: Option<String>,
    pub created_date_time: Option<DateTime<Utc>>,
    pub last_modified_date_time: Option<DateTime<Utc>>,
    pub created_by: Option<Value>,
    pub last_modified_by: Option<Value>,
    pub raw: Value,
}

impl SearchRecord {
    pub fn from_value(value: Value) -> Option<Self> {
        let object = value.as_object()?;
        Some(Self {
            id: text(object, "id"),
            display_name: text(object, "displayName"),
            description: text(object, "description"),
            content_query: text(object, "contentQuery"),
            data_source_scopes: text(object, "dataSourceScopes"),
            created_date_time: graph_time(field(object, "createdDateTime")),
            last_modified_date_time: graph_time(field(object, "lastModifiedDateTime")),
            created_by: field(object, "createdBy").cloned(),
            last_modified_by: field(object, "lastModifiedBy").cloned(),
            raw: value,
        })
    }
}

/// The status of an operation, from Graph's `caseOperationStatus` (Docs).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum OperationStatus {
    NotStarted,
    Running,
    Succeeded,
    PartiallySucceeded,
    Failed,
    SubmissionFailed,
    /// No status in the record.
    #[default]
    Missing,
    /// `unknownFutureValue` or any other value, kept as sent.
    Other(String),
}

impl OperationStatus {
    /// Every value Graph documents for `caseOperationStatus`, apart from
    /// `unknownFutureValue`.
    pub const KNOWN: [&'static str; 6] = [
        "notStarted",
        "running",
        "succeeded",
        "partiallySucceeded",
        "failed",
        "submissionFailed",
    ];

    pub fn parse(value: Option<&str>) -> Self {
        match value {
            None | Some("") => Self::Missing,
            Some("notStarted") => Self::NotStarted,
            Some("running") => Self::Running,
            Some("succeeded") => Self::Succeeded,
            Some("partiallySucceeded") => Self::PartiallySucceeded,
            Some("failed") => Self::Failed,
            Some("submissionFailed") => Self::SubmissionFailed,
            Some(other) => Self::Other(other.to_owned()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::NotStarted => "notStarted",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::PartiallySucceeded => "partiallySucceeded",
            Self::Failed => "failed",
            Self::SubmissionFailed => "submissionFailed",
            Self::Missing => "?",
            Self::Other(other) => other,
        }
    }

    /// Whether polling stops here. Only `notStarted` and `running`
    /// continue; a missing or unknown status stops (`docs/SPEC.md` section
    /// 4.6).
    pub fn is_terminal(&self) -> bool {
        !matches!(self, Self::NotStarted | Self::Running)
    }
}

/// Where an operation record came from. The list and a single GET
/// describe the same operation differently (Observed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    List,
    Single,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Single => "get",
        }
    }
}

/// What an operation did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Estimate,
    ExportReport,
    ExportResult,
    /// `exportResult` in the list, which is how the list shows both an
    /// item report and an export (Observed).
    ExportReportOrResult,
    Other(String),
}

impl Action {
    /// The name shown in tables: `estimate`, `report`, `export`,
    /// `exportResult?` for a list entry that could be either, or Graph's
    /// own value for any other action.
    pub fn label(&self) -> &str {
        match self {
            Self::Estimate => "estimate",
            Self::ExportReport => "report",
            Self::ExportResult => "export",
            Self::ExportReportOrResult => "exportResult?",
            Self::Other(other) => other,
        }
    }
}

/// `resultInfo`. Graph documents `code` and `subcode` as Int32 (Docs). A
/// member of another type is `None`, so an unexpected shape never hides
/// the operation; `raw` keeps it as sent.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ResultInfo {
    pub code: Option<i32>,
    pub subcode: Option<i32>,
    pub message: Option<String>,
    pub raw: Value,
}

impl ResultInfo {
    fn from_value(value: &Value) -> Option<Self> {
        let object = value.as_object()?;
        let int = |key: &str| {
            field(object, key)
                .and_then(Value::as_i64)
                .and_then(|value| i32::try_from(value).ok())
        };
        Some(Self {
            code: int("code"),
            subcode: int("subcode"),
            message: text(object, "message"),
            raw: value.clone(),
        })
    }

    /// One line for a person: the message, then the codes.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(message) = self.message.as_deref().filter(|text| !text.is_empty()) {
            parts.push(message.to_owned());
        }
        if let Some(code) = self.code {
            parts.push(format!("code {code}"));
        }
        if let Some(subcode) = self.subcode {
            parts.push(format!("subcode {subcode}"));
        }
        parts.join("; ")
    }
}

/// An operation: an estimate, an item report, an export or any other
/// action the case ran.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OperationRecord {
    pub odata_type: Option<String>,
    pub id: Option<String>,
    pub action: Option<String>,
    pub status: OperationStatus,
    pub percent_progress: Option<u64>,
    pub created_date_time: Option<DateTime<Utc>>,
    pub completed_date_time: Option<DateTime<Utc>>,
    pub created_by: Option<Value>,
    pub result_info: Option<ResultInfo>,
    /// Fields that held a number that is not a count, by name, for a
    /// warning.
    pub invalid_counts: Vec<String>,
    pub raw: Value,
}

impl OperationRecord {
    pub fn from_value(value: Value) -> Option<Self> {
        let object = value.as_object()?;
        let mut invalid_counts = Vec::new();
        let percent_progress = match read_count(field(object, "percentProgress")) {
            Count::Value(value) => Some(value),
            Count::Absent => None,
            Count::Invalid => {
                invalid_counts.push("percentProgress".to_owned());
                None
            }
        };
        let mut record = Self {
            odata_type: text(object, "@odata.type"),
            id: text(object, "id"),
            action: text(object, "action"),
            status: OperationStatus::parse(field(object, "status").and_then(Value::as_str)),
            percent_progress,
            created_date_time: graph_time(field(object, "createdDateTime")),
            completed_date_time: graph_time(field(object, "completedDateTime")),
            created_by: field(object, "createdBy").cloned(),
            result_info: field(object, "resultInfo").and_then(ResultInfo::from_value),
            invalid_counts,
            raw: Value::Null,
        };
        if let Some(detail) = detail_of(record.odata_type.as_deref(), object) {
            record.invalid_counts.extend(detail.invalid_counts());
        }
        record.raw = value;
        Some(record)
    }

    /// The action. The list shows an item report as `exportResult`
    /// (Observed), so only a single GET tells a report from an export.
    pub fn action(&self, source: Source) -> Action {
        match (self.action.as_deref().unwrap_or(""), source) {
            ("estimateStatistics", _) => Action::Estimate,
            ("exportReport", _) => Action::ExportReport,
            ("exportResult", Source::Single) => Action::ExportResult,
            ("exportResult", Source::List) => Action::ExportReportOrResult,
            (other, _) => Action::Other(other.to_owned()),
        }
    }

    /// The typed part, chosen by `@odata.type`, which single GETs carry
    /// (Observed). `None` when it is absent, as in list entries, or names
    /// another type.
    pub fn detail(&self) -> Option<OperationDetail> {
        detail_of(self.odata_type.as_deref(), self.raw.as_object()?)
    }
}

impl OperationRecord {
    /// The estimate detail of a record that is an estimate by its
    /// `@odata.type`, or that has no `@odata.type` and the action
    /// `estimateStatistics`: a search's `lastEstimateStatisticsOperation`
    /// answers without the type (Observed).
    pub fn estimate_detail(&self) -> Option<EstimateDetail> {
        let object = self.raw.as_object()?;
        match self.odata_type.as_deref() {
            Some(ESTIMATE_OPERATION) => Some(EstimateDetail::from_object(object)),
            None if self.action.as_deref() == Some("estimateStatistics") => {
                Some(EstimateDetail::from_object(object))
            }
            _ => None,
        }
    }
}

fn detail_of(odata_type: Option<&str>, object: &Map<String, Value>) -> Option<OperationDetail> {
    match odata_type? {
        ESTIMATE_OPERATION => Some(OperationDetail::Estimate(EstimateDetail::from_object(
            object,
        ))),
        EXPORT_OPERATION => Some(OperationDetail::SearchExport(ExportDetail::from_object(
            object,
        ))),
        _ => None,
    }
}

/// The typed part of a single operation GET.
#[derive(Debug, Clone, PartialEq)]
pub enum OperationDetail {
    Estimate(EstimateDetail),
    SearchExport(ExportDetail),
}

impl OperationDetail {
    pub fn files(&self) -> &[FileRecord] {
        match self {
            Self::Estimate(detail) => &detail.report_file_metadata,
            Self::SearchExport(detail) => &detail.export_file_metadata,
        }
    }

    fn invalid_counts(&self) -> Vec<String> {
        match self {
            Self::Estimate(detail) => detail.invalid_counts.clone(),
            Self::SearchExport(detail) => detail.invalid_counts.clone(),
        }
    }
}

/// A count field that keeps zero, with invalid values noted.
fn count_or_zero(object: &Map<String, Value>, key: &str, invalid: &mut Vec<String>) -> Option<u64> {
    match read_count(field(object, key)) {
        Count::Value(value) => Some(value),
        Count::Absent => None,
        Count::Invalid => {
            invalid.push(key.to_owned());
            None
        }
    }
}

/// The counts and report files of an estimate (Observed).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct EstimateDetail {
    pub indexed_item_count: Option<u64>,
    pub indexed_items_size: Option<u64>,
    pub unindexed_item_count: Option<u64>,
    pub unindexed_items_size: Option<u64>,
    /// Locations with hits (Observed meaning).
    pub mailbox_count: Option<u64>,
    pub site_count: Option<u64>,
    pub report_file_metadata: Vec<FileRecord>,
    invalid_counts: Vec<String>,
}

impl EstimateDetail {
    fn from_object(object: &Map<String, Value>) -> Self {
        let mut invalid = Vec::new();
        let mut detail = Self {
            indexed_item_count: count_or_zero(object, "indexedItemCount", &mut invalid),
            indexed_items_size: count_or_zero(object, "indexedItemsSize", &mut invalid),
            unindexed_item_count: count_or_zero(object, "unindexedItemCount", &mut invalid),
            unindexed_items_size: count_or_zero(object, "unindexedItemsSize", &mut invalid),
            mailbox_count: count_or_zero(object, "mailboxCount", &mut invalid),
            site_count: count_or_zero(object, "siteCount", &mut invalid),
            report_file_metadata: files(object, "reportFileMetadata", &mut invalid),
            invalid_counts: Vec::new(),
        };
        detail.invalid_counts = invalid;
        detail
    }
}

/// The settings and files of an item report or export (Observed).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ExportDetail {
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub export_criteria: Option<String>,
    pub export_location: Option<String>,
    pub additional_options: Option<String>,
    /// Shown, never used to decide the action: item reports carry `pst`
    /// too (Observed (trace)).
    pub export_format: Option<String>,
    pub export_file_metadata: Vec<FileRecord>,
    invalid_counts: Vec<String>,
}

impl ExportDetail {
    fn from_object(object: &Map<String, Value>) -> Self {
        let mut invalid = Vec::new();
        let files = files(object, "exportFileMetadata", &mut invalid);
        Self {
            display_name: text(object, "displayName"),
            description: text(object, "description"),
            export_criteria: text(object, "exportCriteria"),
            export_location: text(object, "exportLocation"),
            additional_options: text(object, "additionalOptions"),
            export_format: text(object, "exportFormat"),
            export_file_metadata: files,
            invalid_counts: invalid,
        }
    }
}

/// A file an operation produced.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FileRecord {
    pub file_name: Option<String>,
    /// `None` when absent or 0: an estimate's report file has `size: 0`
    /// although it is not empty (Observed).
    pub size: Option<u64>,
    /// Checked only when a download starts.
    pub download_url: Option<String>,
}

fn files(object: &Map<String, Value>, key: &str, invalid: &mut Vec<String>) -> Vec<FileRecord> {
    let Some(Value::Array(entries)) = field(object, key) else {
        return Vec::new();
    };
    entries
        .iter()
        .filter_map(Value::as_object)
        .map(|entry| FileRecord {
            file_name: text(entry, "fileName"),
            size: match read_count(field(entry, "size")) {
                Count::Value(0) | Count::Absent => None,
                Count::Value(size) => Some(size),
                Count::Invalid => {
                    invalid.push(format!("{key}.size"));
                    None
                }
            },
            download_url: text(entry, "downloadUrl"),
        })
        .collect()
}

/// Readers for Graph identity sets (`createdBy` and the like), which stay
/// JSON so that new fields survive into output.
pub mod identity {
    use serde_json::Value;

    fn user_field<'a>(identity: &'a Value, key: &str) -> Option<&'a str> {
        identity
            .get("user")?
            .get(key)?
            .as_str()
            .filter(|value| !value.is_empty())
    }

    /// `user.id`.
    pub fn user_id(identity: &Value) -> Option<&str> {
        user_field(identity, "id")
    }

    /// `user.userPrincipalName`.
    pub fn upn(identity: &Value) -> Option<&str> {
        user_field(identity, "userPrincipalName")
    }

    /// `user.displayName`, else `application.displayName`.
    pub fn display_name(identity: &Value) -> Option<&str> {
        user_field(identity, "displayName").or_else(|| {
            identity
                .get("application")?
                .get("displayName")?
                .as_str()
                .filter(|value| !value.is_empty())
        })
    }

    /// The name a table shows: the user principal name, else the display
    /// name, else empty.
    pub fn shown(identity: Option<&Value>) -> String {
        identity
            .and_then(|identity| upn(identity).or_else(|| display_name(identity)))
            .unwrap_or_default()
            .to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_placeholder_date_and_empty_text_are_none_and_seven_digit_fractions_parse() {
        assert_eq!(graph_time(Some(&json!("0001-01-01T00:00:00Z"))), None);
        assert_eq!(graph_time(Some(&json!(""))), None);
        assert_eq!(graph_time(Some(&json!("yesterday"))), None);
        assert_eq!(graph_time(Some(&json!(5))), None);
        let time = graph_time(Some(&json!("2026-01-05T09:00:00.1234567Z"))).unwrap();
        assert_eq!(time.to_rfc3339(), "2026-01-05T09:00:00.123456700+00:00");
    }

    #[test]
    fn counts_keep_zero_and_refuse_negative_and_fractional_values() {
        assert_eq!(read_count(Some(&json!(0))), Count::Value(0));
        assert_eq!(read_count(Some(&json!(12))), Count::Value(12));
        assert_eq!(read_count(Some(&json!(-1))), Count::Invalid);
        assert_eq!(read_count(Some(&json!(1.5))), Count::Invalid);
        assert_eq!(read_count(Some(&json!("3"))), Count::Invalid);
        assert_eq!(read_count(Some(&Value::Null)), Count::Absent);
        assert_eq!(read_count(None), Count::Absent);
    }

    #[test]
    fn a_sparse_or_odd_case_still_reads() {
        let case = CaseRecord::from_value(json!({
            "id": 7,
            "displayName": null,
            "status": "closedWithError",
            "createdBy": {"user": {"id": "u", "extra": {"kept": true}}},
            "futureField": [1, 2],
        }))
        .unwrap();
        assert_eq!(case.id, None);
        assert_eq!(case.display_name, None);
        assert_eq!(case.status, CaseStatus::Other("closedWithError".into()));
        assert_eq!(case.raw["futureField"], json!([1, 2]));
        assert_eq!(case.raw["createdBy"]["user"]["extra"]["kept"], true);
        assert_eq!(
            identity::user_id(case.created_by.as_ref().unwrap()),
            Some("u")
        );
        assert!(CaseRecord::from_value(json!("not an object")).is_none());
        assert_eq!(
            CaseRecord::from_value(json!({})).unwrap().status,
            CaseStatus::Missing
        );
    }

    #[test]
    fn the_list_cannot_tell_a_report_from_an_export_but_a_single_get_can() {
        let entry = OperationRecord::from_value(json!({"action": "exportResult"})).unwrap();
        assert_eq!(entry.action(Source::List), Action::ExportReportOrResult);
        assert_eq!(entry.action(Source::Single), Action::ExportResult);
        let report = OperationRecord::from_value(json!({
            "@odata.type": EXPORT_OPERATION,
            "action": "exportReport",
            "exportFormat": "pst",
        }))
        .unwrap();
        assert_eq!(report.action(Source::Single), Action::ExportReport);
        assert_eq!(report.action(Source::List), Action::ExportReport);
        let estimate =
            OperationRecord::from_value(json!({"action": "estimateStatistics"})).unwrap();
        assert_eq!(estimate.action(Source::List), Action::Estimate);
        let other = OperationRecord::from_value(json!({"action": "holdUpdate"})).unwrap();
        assert_eq!(
            other.action(Source::Single),
            Action::Other("holdUpdate".into())
        );
        assert_eq!(Action::ExportReportOrResult.label(), "exportResult?");
    }

    #[test]
    fn detail_follows_the_odata_type_and_is_none_without_it() {
        let body = json!({
            "@odata.type": ESTIMATE_OPERATION,
            "action": "estimateStatistics",
            "indexedItemCount": 0,
            "mailboxCount": 4,
            "reportFileMetadata": [{"fileName": "a.zip", "size": 0, "downloadUrl": null}],
        });
        let estimate = OperationRecord::from_value(body.clone()).unwrap();
        let Some(OperationDetail::Estimate(detail)) = estimate.detail() else {
            panic!("an estimate detail");
        };
        assert_eq!(detail.indexed_item_count, Some(0));
        assert_eq!(detail.mailbox_count, Some(4));
        assert_eq!(detail.report_file_metadata[0].size, None);
        assert_eq!(detail.report_file_metadata[0].download_url, None);
        let mut listed = body;
        listed.as_object_mut().unwrap().remove("@odata.type");
        assert_eq!(OperationRecord::from_value(listed).unwrap().detail(), None);
    }

    #[test]
    fn result_info_of_another_shape_keeps_the_operation() {
        let operation = OperationRecord::from_value(json!({
            "status": "failed",
            "resultInfo": {"code": "E42", "subcode": 3, "message": "the search failed"},
        }))
        .unwrap();
        let info = operation.result_info.unwrap();
        assert_eq!(info.code, None);
        assert_eq!(info.subcode, Some(3));
        assert_eq!(info.raw["code"], "E42");
        assert_eq!(info.summary(), "the search failed; subcode 3");
    }

    #[test]
    fn invalid_counts_are_noted_and_read_as_none() {
        let operation = OperationRecord::from_value(json!({
            "@odata.type": ESTIMATE_OPERATION,
            "percentProgress": 12.5,
            "indexedItemCount": -3,
            "reportFileMetadata": [{"fileName": "a.zip", "size": -1}],
        }))
        .unwrap();
        assert_eq!(operation.percent_progress, None);
        assert_eq!(
            operation.invalid_counts,
            [
                "percentProgress",
                "indexedItemCount",
                "reportFileMetadata.size"
            ]
        );
        let Some(OperationDetail::Estimate(detail)) = operation.detail() else {
            panic!("an estimate detail");
        };
        assert_eq!(detail.indexed_item_count, None);
    }

    #[test]
    fn statuses_continue_only_while_not_started_or_running() {
        for (text, terminal) in [
            ("notStarted", false),
            ("running", false),
            ("succeeded", true),
            ("partiallySucceeded", true),
            ("failed", true),
            ("submissionFailed", true),
            ("unknownFutureValue", true),
        ] {
            let status = OperationStatus::parse(Some(text));
            assert_eq!(status.is_terminal(), terminal, "{text}");
            assert_eq!(status.as_str(), text);
        }
        assert!(OperationStatus::parse(None).is_terminal());
    }

    #[test]
    fn identities_read_the_user_then_the_application() {
        let user =
            json!({"user": {"displayName": "Alex", "userPrincipalName": "alex@contoso.example"}});
        assert_eq!(identity::shown(Some(&user)), "alex@contoso.example");
        let app = json!({"application": {"displayName": "Purview app"}, "user": null});
        assert_eq!(identity::shown(Some(&app)), "Purview app");
        assert_eq!(identity::shown(None), "");
    }
}
