//! The query builder behind the query flags (`docs/SPEC.md` section 3.5).
//!
//! It emits only the guard's subset, and its output goes through the same
//! parser as `--kql`, so both forms get the same verdict. The groups are
//! ANDed in a fixed order: terms, participants, `--since`, `--until`,
//! `--kind`, then each `--exclude-from`. A group of more than one value is
//! parenthesised.

use chrono::NaiveDate;

use super::classify::is_full_address;
use crate::error::{PurviewError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Email,
    Teams,
}

/// The query flags, as given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryFlags {
    pub terms: Vec<String>,
    pub participants: Vec<String>,
    pub since: Option<NaiveDate>,
    pub until: Option<NaiveDate>,
    pub kind: Option<Kind>,
    pub exclude_from: Vec<String>,
    /// `--kql`, which Clap keeps apart from every flag above.
    pub kql: Option<String>,
}

impl QueryFlags {
    fn is_empty(&self) -> bool {
        self.terms.is_empty()
            && self.participants.is_empty()
            && self.since.is_none()
            && self.until.is_none()
            && self.kind.is_none()
            && self.exclude_from.is_empty()
    }
}

/// Which of a repeated flag's values is meant, without repeating it.
fn ordinal(index: usize, count: usize) -> String {
    if count == 1 {
        String::new()
    } else {
        format!(" (value {} of {count})", index + 1)
    }
}

/// A full address for `flag`, trimmed. Diagnostics never repeat the value.
fn address(flag: &str, value: &str, index: usize, count: usize) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(PurviewError::message(format!(
            "{flag} was given an empty value{}",
            ordinal(index, count)
        )));
    }
    if !is_full_address(value) {
        return Err(PurviewError::message(format!(
            "{flag}{} needs a full address, such as alex@contoso.example: a local part, @ and a \
             domain, with no * and no quotes",
            ordinal(index, count)
        )));
    }
    Ok(value.to_owned())
}

fn group(parts: Vec<String>) -> String {
    if parts.len() == 1 {
        parts.into_iter().next().unwrap_or_default()
    } else {
        format!("({})", parts.join(" OR "))
    }
}

/// The KQL for the flags: `--kql` as given, or the built query.
pub fn build(flags: &QueryFlags) -> Result<String> {
    if let Some(kql) = &flags.kql {
        if kql.trim().is_empty() {
            return Err(PurviewError::message(
                "--kql was given an empty value; pass a query or leave the flag out",
            ));
        }
        return Ok(kql.clone());
    }
    if flags.is_empty() {
        return Err(PurviewError::message(
            "no query given: pass --term, --participant, --since, --until, --kind, \
             --exclude-from or --kql",
        ));
    }
    let mut groups = Vec::new();
    let count = flags.terms.len();
    if count > 0 {
        let terms = flags
            .terms
            .iter()
            .enumerate()
            .map(|(index, term)| {
                // Checked before trimming, which would remove a control
                // character at either end.
                if term
                    .chars()
                    .any(|character| character.is_control() || super::lexer::is_hidden(character))
                {
                    return Err(PurviewError::message(format!(
                        "--term{} contains a control or invisible character, such as a tab or a \
                         zero-width space",
                        ordinal(index, count)
                    )));
                }
                let term = term.trim();
                if term.is_empty() {
                    return Err(PurviewError::message(format!(
                        "--term was given an empty value{}",
                        ordinal(index, count)
                    )));
                }
                if term.contains('"') {
                    return Err(PurviewError::message(format!(
                        "--term{} contains a double quote (\"), which a quoted term cannot hold",
                        ordinal(index, count)
                    )));
                }
                if term.contains('*') {
                    return Err(PurviewError::message(format!(
                        "--term{} contains a *: a quoted term cannot hold a wildcard; use --kql \
                         with an unquoted word that ends in *",
                        ordinal(index, count)
                    )));
                }
                Ok(format!("\"{term}\""))
            })
            .collect::<Result<Vec<_>>>()?;
        groups.push(group(terms));
    }
    let count = flags.participants.len();
    if count > 0 {
        let participants = flags
            .participants
            .iter()
            .enumerate()
            .map(|(index, value)| {
                address("--participant", value, index, count)
                    .map(|address| format!("participants:{address}"))
            })
            .collect::<Result<Vec<_>>>()?;
        groups.push(group(participants));
    }
    if let (Some(since), Some(until)) = (flags.since, flags.until) {
        if since > until {
            return Err(PurviewError::message("--since is later than --until"));
        }
    }
    if let Some(since) = flags.since {
        groups.push(format!("sent>={}", since.format("%Y-%m-%d")));
    }
    if let Some(until) = flags.until {
        groups.push(format!("sent<={}", until.format("%Y-%m-%d")));
    }
    if let Some(kind) = flags.kind {
        groups.push(
            match kind {
                Kind::Email => "kind:email",
                Kind::Teams => "kind:microsoftteams",
            }
            .to_owned(),
        );
    }
    let count = flags.exclude_from.len();
    for (index, value) in flags.exclude_from.iter().enumerate() {
        groups.push(format!(
            "NOT from:{}",
            address("--exclude-from", value, index, count)?
        ));
    }
    Ok(groups.join(" AND "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(text: &str) -> NaiveDate {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn the_spec_example() {
        let flags = QueryFlags {
            terms: vec!["orders-api".into(), "orders_export_bucket".into()],
            participants: vec!["alex@contoso.example".into(), "sam@contoso.example".into()],
            since: Some(date("2025-01-01")),
            exclude_from: vec!["noreply@notify.example".into()],
            ..QueryFlags::default()
        };
        assert_eq!(
            build(&flags).unwrap(),
            "(\"orders-api\" OR \"orders_export_bucket\") AND (participants:alex@contoso.example \
             OR participants:sam@contoso.example) AND sent>=2025-01-01 AND NOT \
             from:noreply@notify.example"
        );
    }

    #[test]
    fn every_group_in_order() {
        let flags = QueryFlags {
            terms: vec![" retention ".into()],
            participants: vec!["alex@contoso.example".into()],
            since: Some(date("2025-01-01")),
            until: Some(date("2025-06-30")),
            kind: Some(Kind::Teams),
            exclude_from: vec!["a@fabrikam.example".into(), "b@fabrikam.example".into()],
            kql: None,
        };
        assert_eq!(
            build(&flags).unwrap(),
            "\"retention\" AND participants:alex@contoso.example AND sent>=2025-01-01 AND \
             sent<=2025-06-30 AND kind:microsoftteams AND NOT from:a@fabrikam.example AND NOT \
             from:b@fabrikam.example"
        );
        let email = QueryFlags {
            kind: Some(Kind::Email),
            ..QueryFlags::default()
        };
        assert_eq!(build(&email).unwrap(), "kind:email");
    }

    #[test]
    fn refusals_never_repeat_the_value() {
        let marker = "pasted-value-marker";
        for flags in [
            QueryFlags::default(),
            QueryFlags {
                kql: Some("  ".into()),
                ..QueryFlags::default()
            },
            QueryFlags {
                terms: vec![format!("{marker}\"")],
                ..QueryFlags::default()
            },
            QueryFlags {
                terms: vec![format!("{marker}*")],
                ..QueryFlags::default()
            },
            QueryFlags {
                terms: vec!["orders-api".into(), " ".into()],
                ..QueryFlags::default()
            },
            QueryFlags {
                participants: vec![format!("*@{marker}.example")],
                ..QueryFlags::default()
            },
            QueryFlags {
                participants: vec![format!("{marker}.example")],
                ..QueryFlags::default()
            },
            QueryFlags {
                exclude_from: vec![marker.to_owned()],
                ..QueryFlags::default()
            },
            QueryFlags {
                terms: vec![format!("{marker}\tx")],
                ..QueryFlags::default()
            },
            QueryFlags {
                terms: vec![format!("{marker}\u{200B}")],
                ..QueryFlags::default()
            },
            QueryFlags {
                since: Some(date("2025-02-01")),
                until: Some(date("2025-01-01")),
                ..QueryFlags::default()
            },
        ] {
            let error = build(&flags).expect_err(&format!("{flags:?}")).to_string();
            assert!(!error.contains(marker), "{error}");
        }
    }

    #[test]
    fn the_value_of_a_repeated_flag_is_named_by_position() {
        let flags = QueryFlags {
            participants: vec!["alex@contoso.example".into(), "contoso.example".into()],
            ..QueryFlags::default()
        };
        assert!(build(&flags)
            .unwrap_err()
            .to_string()
            .contains("(value 2 of 2)"));
    }

    #[test]
    fn raw_kql_is_kept_as_given() {
        let flags = QueryFlags {
            kql: Some(" a AND b ".into()),
            ..QueryFlags::default()
        };
        assert_eq!(build(&flags).unwrap(), " a AND b ");
    }
}
