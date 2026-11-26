//! Validated inputs: what a command needs from an argument or a wire
//! record, with a targeted error when something is missing
//! (`docs/SPEC.md` sections 3.4 and 7.1).

use crate::error::{PurviewError, Result};
use crate::model::wire::{CaseRecord, OperationRecord, OperationStatus, SearchRecord};
use crate::output::sanitize;
use crate::routes::{CaseId, OperationId, SearchId};

/// A `<case>` argument: a case id, or else an exact display name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseKey {
    Id(CaseId),
    Name(String),
}

impl CaseKey {
    /// A GUID is an id; anything else is a display name, matched exactly.
    /// A blank argument is refused.
    pub fn parse(text: &str) -> Result<Self> {
        if text.trim().is_empty() {
            return Err(PurviewError::message(
                "<case> was given an empty value; pass a case id or its exact display name",
            ));
        }
        Ok(match CaseId::parse(text) {
            Some(id) => Self::Id(id),
            None => Self::Name(text.to_owned()),
        })
    }
}

/// A `<search>` argument: a search id, or else an exact display name
/// within the case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchKey {
    Id(SearchId),
    Name(String),
}

impl SearchKey {
    pub fn parse(text: &str) -> Result<Self> {
        if text.trim().is_empty() {
            return Err(PurviewError::message(
                "<search> was given an empty value; pass a search id or its exact display name",
            ));
        }
        Ok(match SearchId::parse(text) {
            Some(id) => Self::Id(id),
            None => Self::Name(text.to_owned()),
        })
    }
}

/// An `<op>` argument: 32 hexadecimal characters (Observed).
pub fn operation_id(text: &str) -> Result<OperationId> {
    OperationId::parse(text).ok_or_else(|| {
        PurviewError::message(format!(
            "{:?} is not an operation id: an operation id is 32 hexadecimal characters with no \
             hyphens",
            sanitize(text)
        ))
    })
}

/// A case record with a usable id.
#[derive(Debug, Clone, PartialEq)]
pub struct CaseRef {
    pub id: CaseId,
    pub record: CaseRecord,
}

impl CaseRef {
    pub fn new(record: CaseRecord) -> Result<Self> {
        let id = record
            .id
            .as_deref()
            .and_then(CaseId::parse)
            .ok_or_else(|| PurviewError::message("Graph returned a case without a valid id"))?;
        Ok(Self { id, record })
    }
}

/// A search record with a usable id.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchRef {
    pub id: SearchId,
    pub record: SearchRecord,
}

impl SearchRef {
    pub fn new(record: SearchRecord) -> Result<Self> {
        let id = record
            .id
            .as_deref()
            .and_then(SearchId::parse)
            .ok_or_else(|| PurviewError::message("Graph returned a search without a valid id"))?;
        Ok(Self { id, record })
    }
}

/// An operation that can be polled: it has a valid id and a status.
#[derive(Debug, Clone, PartialEq)]
pub struct PollTarget {
    pub id: OperationId,
    pub status: OperationStatus,
}

impl PollTarget {
    pub fn new(record: &OperationRecord) -> Result<Self> {
        let id = record
            .id
            .as_deref()
            .and_then(OperationId::parse)
            .ok_or_else(|| {
                PurviewError::message("Graph returned an operation without a valid id")
            })?;
        if record.status == OperationStatus::Missing {
            return Err(PurviewError::message(format!(
                "Graph returned operation {id} without a status"
            )));
        }
        Ok(Self {
            id,
            status: record.status.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_guid_is_an_id_and_anything_else_a_name() {
        assert_eq!(
            CaseKey::parse(" 00000000-0000-4000-8000-000000000031 ").unwrap(),
            CaseKey::Id(CaseId::parse("00000000-0000-4000-8000-000000000031").unwrap())
        );
        assert_eq!(
            CaseKey::parse("Orders review").unwrap(),
            CaseKey::Name("Orders review".into())
        );
        assert!(CaseKey::parse(" ").is_err());
        assert!(SearchKey::parse("").is_err());
        assert!(operation_id("00000000-0000-4000-8000-000000000031").is_err());
    }

    #[test]
    fn records_without_a_usable_id_or_status_are_refused() {
        let case = CaseRecord::from_value(json!({"id": "not-a-guid"})).unwrap();
        assert!(CaseRef::new(case).is_err());
        let operation =
            OperationRecord::from_value(json!({"id": "x", "status": "running"})).unwrap();
        assert!(PollTarget::new(&operation).is_err());
        let operation = OperationRecord::from_value(json!({
            "id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa0001",
        }))
        .unwrap();
        assert!(PollTarget::new(&operation).is_err());
    }
}
