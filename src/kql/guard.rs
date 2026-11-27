//! The narrowing verdict (`docs/SPEC.md` section 6.3): every branch of the
//! query that can match a message must be narrowed, by a positive specific
//! term or by a positive `participants:` restriction on a full address.
//!
//! The guard catches mistakes. It is not a security control: anyone with
//! the Purview role can use the portal.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use super::classify::{classify, Class, TermClass, TermLists};
use super::lexer::{KqlError, Restriction};
use super::parser::{parse, LeafKind, Node};
use crate::error::{PurviewError, Result};

/// `guard` in `config.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardConfig {
    pub lists: TermLists,
}

impl GuardConfig {
    /// Reads `guard.specific_terms` and `guard.generic_terms` from the
    /// keys `Config` keeps. A missing object or list, or `null`, is unset;
    /// any other value of the wrong type, or a blank entry, is an error.
    pub fn from_config(extra: &BTreeMap<String, Value>) -> Result<Self> {
        let guard = match extra.get("guard") {
            None | Some(Value::Null) => return Ok(Self::default()),
            Some(Value::Object(guard)) => guard,
            Some(_) => {
                return Err(PurviewError::message(
                    "config.json: guard must be an object",
                ))
            }
        };
        let list = |key: &str| -> Result<Vec<String>> {
            let refusal = || {
                PurviewError::message(format!(
                    "config.json: guard.{key} must be a list of non-blank strings"
                ))
            };
            match guard.get(key) {
                None | Some(Value::Null) => Ok(Vec::new()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| match item {
                        Value::String(text) if !text.trim().is_empty() => Ok(text.clone()),
                        _ => Err(refusal()),
                    })
                    .collect(),
                Some(_) => Err(refusal()),
            }
        };
        Ok(Self {
            lists: TermLists::new(&list("specific_terms")?, &list("generic_terms")?),
        })
    }
}

/// What the guard found in a query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Analysis {
    pub kql: String,
    pub narrowed: bool,
    /// The column of a branch that is not narrowed, when the query is not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unnarrowed_at: Option<usize>,
    pub leaves: Vec<LeafReport>,
}

/// One leaf of the query, as `purview kql` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LeafReport {
    pub column: usize,
    /// `term` for a phrase or word, otherwise the property name.
    pub field: &'static str,
    pub value: String,
    pub quoted: bool,
    /// Under a `NOT`, at any depth.
    pub negated: bool,
    /// `specific` or `generic` for text; `narrowing` or `not narrowing`
    /// for a restriction.
    pub class: &'static str,
    /// The number of the classification rule that decided, for text.
    pub rule: Option<u8>,
    pub reason: String,
    /// Each token's rule, for text that rule 1 did not decide whole.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<TokenReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenReport {
    pub token: String,
    pub class: Class,
    pub rule: u8,
}

/// The classification of every text leaf, worked out once.
struct Classified<'a> {
    lists: &'a TermLists,
}

impl Classified<'_> {
    fn text_class(&self, kind: &LeafKind) -> Option<TermClass> {
        match kind {
            LeafKind::Phrase(text)
            | LeafKind::Word(text)
            | LeafKind::Restriction(Restriction::Subject { value: text, .. }) => {
                Some(classify(text, self.lists))
            }
            LeafKind::Restriction(_) => None,
        }
    }

    /// `narrowed` of `docs/SPEC.md` section 6.3.
    fn narrowed(&self, node: &Node) -> bool {
        match node {
            Node::Leaf(leaf) => match &leaf.kind {
                LeafKind::Restriction(Restriction::Address { property, .. }) => {
                    *property == super::lexer::AddressProperty::Participants
                }
                LeafKind::Restriction(Restriction::Kind(_) | Restriction::Sent { .. }) => false,
                kind => self
                    .text_class(kind)
                    .is_some_and(|class| class.class == Class::Specific),
            },
            Node::Not { .. } => false,
            Node::And(children) => children.iter().any(|child| self.narrowed(child)),
            Node::Or(children) => children.iter().all(|child| self.narrowed(child)),
            Node::Group { inner, .. } => self.narrowed(inner),
        }
    }

    /// The column of a branch that is not narrowed, the smallest that
    /// explains the verdict: an OR's first such child, an AND none of whose
    /// children narrows, a NOT, or a leaf.
    fn unnarrowed_at(&self, node: &Node) -> Option<usize> {
        if self.narrowed(node) {
            return None;
        }
        match node {
            Node::Or(children) => children.iter().find_map(|child| self.unnarrowed_at(child)),
            Node::Group { inner, .. } => self.unnarrowed_at(inner),
            _ => Some(node.column()),
        }
    }

    fn leaves(&self, node: &Node, negated: bool, out: &mut Vec<LeafReport>) {
        match node {
            Node::Leaf(leaf) => out.push(self.report(leaf, negated)),
            Node::Not { inner, .. } => self.leaves(inner, true, out),
            Node::Group { inner, .. } => self.leaves(inner, negated, out),
            Node::And(children) | Node::Or(children) => {
                for child in children {
                    self.leaves(child, negated, out);
                }
            }
        }
    }

    fn report(&self, leaf: &super::parser::Leaf, negated: bool) -> LeafReport {
        let restriction = |field, value: String, class, reason: &str| LeafReport {
            column: leaf.column,
            field,
            value,
            quoted: false,
            negated,
            class,
            rule: None,
            reason: reason.to_owned(),
            tokens: Vec::new(),
        };
        let (field, text, quoted) = match &leaf.kind {
            LeafKind::Phrase(text) => ("term", text, true),
            LeafKind::Word(text) => ("term", text, false),
            LeafKind::Restriction(Restriction::Subject { value, quoted }) => {
                ("subject", value, *quoted)
            }
            LeafKind::Restriction(Restriction::Address { property, address }) => {
                return if *property == super::lexer::AddressProperty::Participants {
                    restriction(
                        property.name(),
                        address.clone(),
                        "narrowing",
                        "participants: on a full address",
                    )
                } else {
                    restriction(
                        property.name(),
                        address.clone(),
                        "not narrowing",
                        "only participants: narrows; write participants:x AND from:x",
                    )
                };
            }
            LeafKind::Restriction(Restriction::Kind(kind)) => {
                return restriction(
                    "kind",
                    kind.name().to_owned(),
                    "not narrowing",
                    "a filter on the kind of item",
                )
            }
            LeafKind::Restriction(Restriction::Sent { comparison, date }) => {
                return restriction(
                    "sent",
                    format!("{}{}", comparison.symbol(), date.format("%Y-%m-%d")),
                    "not narrowing",
                    "a filter on the date",
                )
            }
        };
        let class = classify(text, self.lists);
        let rule = class.deciding_rule();
        let reason = match rule {
            Some(rule) => rule.description().to_owned(),
            None => "no token is specific".to_owned(),
        };
        LeafReport {
            column: leaf.column,
            field,
            value: text.clone(),
            quoted,
            negated,
            class: class.class.name(),
            rule: rule.map(|rule| rule.number()),
            reason,
            tokens: class
                .tokens
                .iter()
                .map(|token| TokenReport {
                    token: token.token.clone(),
                    class: token.rule.class(),
                    rule: token.rule.number(),
                })
                .collect(),
        }
    }
}

impl From<KqlError> for PurviewError {
    fn from(error: KqlError) -> Self {
        Self::KqlNotUnderstood {
            column: error.column,
            reason: error.reason,
        }
    }
}

/// Parses `kql` and reports each leaf and the verdict. A query outside the
/// grammar is `KqlNotUnderstood`; a query that is not narrowed is still an
/// `Analysis`, with `narrowed` false.
pub fn analyse(kql: &str, config: &GuardConfig) -> Result<Analysis> {
    let root = parse(kql)?;
    let classified = Classified {
        lists: &config.lists,
    };
    let mut leaves = Vec::new();
    classified.leaves(&root, false, &mut leaves);
    Ok(Analysis {
        kql: kql.to_owned(),
        narrowed: classified.narrowed(&root),
        unnarrowed_at: classified.unnarrowed_at(&root),
        leaves,
    })
}

/// The refusal for a query that is not narrowed. It names the column of a
/// branch that is not, and never repeats the query's text.
pub fn generic_query(analysis: &Analysis) -> PurviewError {
    let place = analysis
        .unnarrowed_at
        .map(|column| format!("the branch at column {column}"))
        .unwrap_or_else(|| "a branch".to_owned());
    PurviewError::GenericQuery(format!(
        "the query is not narrowed: {place} can match messages without a specific term or a \
         participants: restriction on a full address. Add --participant, use a more specific \
         term, or add the term to guard.specific_terms in config.json; docs/safety.md explains \
         the rules"
    ))
}

/// The `--allow-generic` override of a write command: a non-blank reason
/// is required, and only a "not narrowed" verdict is overridden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Override<'a> {
    None,
    AllowGeneric { reason: &'a str },
}

/// The guard as a write command runs it: the analysis when the query is
/// narrowed or the override applies, otherwise the refusal. A parse error
/// is never overridden, and the reason is checked before the query.
pub fn enforce(kql: &str, config: &GuardConfig, allow: Override<'_>) -> Result<Analysis> {
    if let Override::AllowGeneric { reason } = allow {
        if reason.trim().is_empty() {
            return Err(PurviewError::message(
                "--allow-generic needs --reason with a reason that is not blank",
            ));
        }
    }
    let analysis = analyse(kql, config)?;
    match (analysis.narrowed, allow) {
        (true, _) | (false, Override::AllowGeneric { .. }) => Ok(analysis),
        (false, Override::None) => Err(generic_query(&analysis)),
    }
}
