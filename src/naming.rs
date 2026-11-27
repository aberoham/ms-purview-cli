//! The naming templates of `config.json` (`docs/SPEC.md` section 5.5):
//! `naming.case_name`, `naming.case_description`,
//! `naming.search_description` and `naming.export_name`, with
//! `naming.marker` as plain text. A template is text with `{variable}`
//! places; an unknown variable, or a `{` or `}` that is not part of one, is
//! an error when the configuration is read, before sign-in.

use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

use serde_json::Value;

use crate::error::{PurviewError, Result};

/// The variables a template may use.
pub const VARIABLES: &[&str] = &[
    "topic",
    "requester",
    "user",
    "query_summary",
    "yyyy_mm",
    "utc_date",
    "utc_hhmm",
    "action",
    "marker",
];

/// The characters of the query that `{query_summary}` keeps.
pub const QUERY_SUMMARY_CHARS: usize = 200;

pub const DEFAULT_CASE_NAME: &str = "Records research - {topic} {yyyy_mm}";
pub const DEFAULT_CASE_DESCRIPTION: &str =
    "Requested by {requester}. Tenant-wide mailbox search with no custodians or holds. {marker}";
pub const DEFAULT_SEARCH_DESCRIPTION: &str = "{query_summary} {marker}";
pub const DEFAULT_EXPORT_NAME: &str = "{action} {utc_date} {utc_hhmm}Z";
pub const DEFAULT_MARKER: &str = "[created-by:purview-cli]";

/// The naming settings, each checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Naming {
    pub case_name: Template,
    pub case_description: Template,
    pub search_description: Template,
    pub export_name: Template,
    pub marker: String,
}

/// One checked template, named after its setting for error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    setting: &'static str,
    parts: Vec<Part>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Text(String),
    Variable(&'static str),
}

/// The values a template is rendered with. `None` means the variable has
/// no value for this name, and a template that uses it is refused.
#[derive(Debug, Clone, Default)]
pub struct Values<'a> {
    pub topic: Option<&'a str>,
    /// `--requester`; `{requester}` falls back to `{user}` without it.
    pub requester: Option<&'a str>,
    /// The signed-in account.
    pub user: &'a str,
    /// The KQL, for `{query_summary}`.
    pub query: Option<&'a str>,
    /// `estimate`, `report` or `export`.
    pub action: Option<&'a str>,
    pub now: Option<DateTime<Utc>>,
}

impl Naming {
    /// The settings under `naming` in `config.json`, else the defaults. A
    /// missing or `null` object or key means the default; any other value
    /// that is not a string is an error.
    pub fn from_config(extra: &BTreeMap<String, Value>) -> Result<Self> {
        let naming = match extra.get("naming") {
            None | Some(Value::Null) => None,
            Some(Value::Object(naming)) => Some(naming),
            Some(_) => {
                return Err(PurviewError::message(
                    "config.json: naming must be an object",
                ))
            }
        };
        let text = |key: &'static str, default: &str| -> Result<String> {
            match naming.and_then(|naming| naming.get(key)) {
                None | Some(Value::Null) => Ok(default.to_owned()),
                Some(Value::String(text)) => Ok(text.clone()),
                Some(_) => Err(PurviewError::message(format!(
                    "config.json: naming.{key} must be a string"
                ))),
            }
        };
        let template = |key: &'static str, default: &str| -> Result<Template> {
            Template::parse(key, &text(key, default)?)
        };
        let marker = text("marker", DEFAULT_MARKER)?;
        if marker.chars().any(char::is_control) {
            return Err(PurviewError::message(
                "config.json: naming.marker must not hold control characters",
            ));
        }
        Ok(Self {
            case_name: template("case_name", DEFAULT_CASE_NAME)?,
            case_description: template("case_description", DEFAULT_CASE_DESCRIPTION)?,
            search_description: template("search_description", DEFAULT_SEARCH_DESCRIPTION)?,
            export_name: template("export_name", DEFAULT_EXPORT_NAME)?,
            marker,
        })
    }

    /// `template` with `values` and this marker.
    pub fn render(&self, template: &Template, values: &Values<'_>) -> Result<String> {
        template.render(values, &self.marker)
    }
}

impl Template {
    /// Splits `text` into text and `{variable}` places. Errors name the
    /// setting and, for an unknown variable, never repeat it: a pasted
    /// secret could sit there.
    pub fn parse(setting: &'static str, text: &str) -> Result<Self> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut rest = text;
        while let Some(index) = rest.find(['{', '}']) {
            literal.push_str(&rest[..index]);
            if rest[index..].starts_with('}') {
                return Err(PurviewError::message(format!(
                    "config.json: naming.{setting} has a '}}' that closes no variable"
                )));
            }
            let after = &rest[index + 1..];
            let Some(end) = after.find('}') else {
                return Err(PurviewError::message(format!(
                    "config.json: naming.{setting} has a '{{' that is not closed"
                )));
            };
            let name = &after[..end];
            let Some(known) = VARIABLES.iter().find(|known| **known == name) else {
                return Err(PurviewError::message(format!(
                    "config.json: naming.{setting} uses a variable that does not exist; the \
                     variables are {}",
                    VARIABLES
                        .iter()
                        .map(|name| format!("{{{name}}}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            };
            if !literal.is_empty() {
                parts.push(Part::Text(std::mem::take(&mut literal)));
            }
            parts.push(Part::Variable(known));
            rest = &after[end + 1..];
        }
        literal.push_str(rest);
        if !literal.is_empty() {
            parts.push(Part::Text(literal));
        }
        Ok(Self { setting, parts })
    }

    /// The rendered text. Where a variable is empty, a space on both sides
    /// of it would be left doubled, so one is dropped; the ends of the
    /// result are trimmed. Spaces anywhere else are kept as they are.
    pub fn render(&self, values: &Values<'_>, marker: &str) -> Result<String> {
        let mut out = String::new();
        let mut after_empty = false;
        for part in &self.parts {
            let piece = match part {
                Part::Text(text) => text.clone(),
                Part::Variable(name) => value_of(name, values, marker).ok_or_else(|| {
                    PurviewError::message(format!(
                        "config.json: naming.{} uses {{{name}}}, which has no value for this \
                         name",
                        self.setting
                    ))
                })?,
            };
            if piece.is_empty() {
                after_empty = true;
                continue;
            }
            if after_empty && out.ends_with(' ') && piece.starts_with(' ') {
                out.push_str(&piece[1..]);
            } else {
                out.push_str(&piece);
            }
            after_empty = false;
        }
        Ok(out.trim().to_owned())
    }
}

fn value_of(name: &str, values: &Values<'_>, marker: &str) -> Option<String> {
    let date = |format: &str| values.now.map(|now| now.format(format).to_string());
    match name {
        "topic" => values.topic.map(str::to_owned),
        "requester" => Some(values.requester.unwrap_or(values.user).to_owned()),
        "user" => Some(values.user.to_owned()),
        "query_summary" => values
            .query
            .map(|query| query.chars().take(QUERY_SUMMARY_CHARS).collect()),
        "yyyy_mm" => date("%Y-%m"),
        "utc_date" => date("%Y-%m-%d"),
        "utc_hhmm" => date("%H%M"),
        "action" => values.action.map(str::to_owned),
        "marker" => Some(marker.to_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn naming(config: Value) -> Result<Naming> {
        Naming::from_config(&config.as_object().unwrap().clone().into_iter().collect())
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-03-14T09:30:59Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn values() -> Values<'static> {
        Values {
            topic: Some("orders-api"),
            requester: None,
            user: "alex@contoso.example",
            query: Some("\"orders-api\""),
            action: Some("estimate"),
            now: Some(now()),
        }
    }

    #[test]
    fn the_defaults_render_as_documented() {
        let naming = naming(json!({})).unwrap();
        let values = values();
        assert_eq!(
            naming.render(&naming.case_name, &values).unwrap(),
            "Records research - orders-api 2026-03"
        );
        assert_eq!(
            naming.render(&naming.case_description, &values).unwrap(),
            "Requested by alex@contoso.example. Tenant-wide mailbox search with no custodians or \
             holds. [created-by:purview-cli]"
        );
        assert_eq!(
            naming.render(&naming.search_description, &values).unwrap(),
            "\"orders-api\" [created-by:purview-cli]"
        );
        assert_eq!(
            naming.render(&naming.export_name, &values).unwrap(),
            "estimate 2026-03-14 0930Z"
        );
    }

    #[test]
    fn each_variable_has_its_value() {
        let values = Values {
            requester: Some("sam@contoso.example"),
            ..values()
        };
        let cases = [
            ("{topic}", "orders-api"),
            ("{requester}", "sam@contoso.example"),
            ("{user}", "alex@contoso.example"),
            ("{query_summary}", "\"orders-api\""),
            ("{yyyy_mm}", "2026-03"),
            ("{utc_date}", "2026-03-14"),
            ("{utc_hhmm}", "0930"),
            ("{action}", "estimate"),
            ("{marker}", "m"),
        ];
        assert_eq!(cases.len(), VARIABLES.len());
        for (text, expected) in cases {
            let template = Template::parse("case_name", text).unwrap();
            assert_eq!(template.render(&values, "m").unwrap(), expected, "{text}");
        }
    }

    #[test]
    fn requester_falls_back_to_user() {
        let template = Template::parse("case_description", "{requester}").unwrap();
        assert_eq!(
            template.render(&values(), "m").unwrap(),
            "alex@contoso.example"
        );
    }

    #[test]
    fn the_query_summary_is_cut_on_a_character_boundary() {
        let query = "é".repeat(250);
        let template = Template::parse("search_description", "{query_summary}").unwrap();
        let values = Values {
            query: Some(&query),
            ..values()
        };
        let rendered = template.render(&values, "m").unwrap();
        assert_eq!(rendered.chars().count(), QUERY_SUMMARY_CHARS);
        assert!(rendered.chars().all(|character| character == 'é'));
    }

    #[test]
    fn unknown_variables_and_stray_braces_are_refused_when_read() {
        let secret = ["canary", "-secret-77"].concat();
        for text in [
            format!("{{{secret}}}"),
            "{Topic}".to_owned(),
            "{ topic }".to_owned(),
            "{}".to_owned(),
            "a {topic".to_owned(),
            "a } b".to_owned(),
            "{{topic}}".to_owned(),
        ] {
            let error = naming(json!({"naming": {"case_name": text}}))
                .unwrap_err()
                .to_string();
            assert!(error.contains("naming.case_name"), "{text}: {error}");
            assert!(!error.contains(&secret), "{error}");
        }
    }

    #[test]
    fn a_variable_with_no_value_for_the_name_is_refused() {
        let template = Template::parse("export_name", "{topic} x").unwrap();
        let values = Values {
            topic: None,
            ..values()
        };
        let error = template.render(&values, "m").unwrap_err().to_string();
        assert!(error.contains("naming.export_name uses {topic}"), "{error}");
    }

    #[test]
    fn settings_of_the_wrong_type_are_refused_and_null_means_default() {
        assert!(naming(json!({"naming": []})).is_err());
        assert!(naming(json!({"naming": {"case_name": 3}})).is_err());
        assert!(naming(json!({"naming": {"marker": false}})).is_err());
        assert!(naming(json!({"naming": {"marker": "a\u{7}"}})).is_err());
        let defaults = naming(json!({})).unwrap();
        assert_eq!(naming(json!({"naming": null})).unwrap(), defaults);
        assert_eq!(
            naming(json!({"naming": {"case_name": null, "marker": null}})).unwrap(),
            defaults
        );
        let custom = naming(json!({"naming": {"marker": "[m]"}})).unwrap();
        assert_eq!(custom.marker, "[m]");
    }

    #[test]
    fn an_empty_value_leaves_no_double_space_and_other_spaces_stay() {
        let template = Template::parse("case_name", " a {topic} b  c ").unwrap();
        let empty = Values {
            topic: Some(""),
            ..values()
        };
        assert_eq!(template.render(&empty, "m").unwrap(), "a b  c");
        let spaced = Values {
            topic: Some("x  y"),
            ..values()
        };
        assert_eq!(template.render(&spaced, "m").unwrap(), "a x  y b  c");
        let query = Template::parse("search_description", "{query_summary} {marker}").unwrap();
        let phrase = Values {
            query: Some("\"stock  report\""),
            ..values()
        };
        assert_eq!(query.render(&phrase, "m").unwrap(), "\"stock  report\" m");
    }
}
