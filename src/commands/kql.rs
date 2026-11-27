//! `purview kql`: the guard's verdict on a query, computed locally with no
//! sign-in (`docs/SPEC.md` section 3.5). It takes no override: it reports
//! what the guard would decide.

use std::io::Write;

use serde_json::Value;

use super::Produced;
use crate::env::Env;
use crate::error::Result;
use crate::kql::guard::{generic_query, LeafReport};
use crate::kql::{analyse, GuardConfig};
use crate::output::{
    error_value, sanitize, selected_indices, write_rows, OutputFormat, OutputOptions,
};

/// The table columns, which `--select` may name.
pub const COLUMNS: &[&str] = &["COLUMN", "FIELD", "VALUE", "NEGATED", "CLASS", "RULE"];

/// Checks `kql` and prints the report. A query outside the grammar is the
/// error `KqlNotUnderstood`. A query that is not narrowed exits 1 with
/// `GenericQuery` after the report: in a table, the report goes to stdout
/// and the error to stderr; under `--json` one document holds both, as
/// `{"analysis": …, "error": …}`, whatever `--results-only` says.
pub fn run(
    env: &mut Env,
    output: &OutputOptions,
    kql: &str,
    config: &GuardConfig,
) -> Result<Produced> {
    selected_indices(&output.select, COLUMNS)?;
    let analysis = analyse(kql, config)?;
    if output.format == OutputFormat::Json {
        // Every URL in the query keeps only what the trace keeps, as in
        // the human report: a pasted link can carry a signature.
        let mut report =
            crate::trace::redact_urls(&serde_json::to_value(&analysis)?, &env.redactor);
        if let Value::Object(object) = &mut report {
            object.insert(
                "kql".to_owned(),
                Value::String(redact_phrases(kql, |text| {
                    crate::redact::urls_in_text(text, &env.redactor)
                })),
            );
        }
        if analysis.narrowed {
            return Ok(Produced::success(Some(output.json_value(&report, 1)?)));
        }
        let mut document = error_value(&generic_query(&analysis));
        if let Value::Object(object) = &mut document {
            object.insert("analysis".to_owned(), report);
        }
        return Ok(Produced {
            exit_code: 1,
            document: Some(document),
        });
    }
    let rows: Vec<Vec<String>> = analysis
        .leaves
        .iter()
        .map(|leaf| row(leaf, &env.redactor))
        .collect();
    if output.format == OutputFormat::Table {
        writeln!(
            env.stdout,
            "kql: {}",
            sanitize(&redact_phrases(kql, |text| crate::redact::shown(
                text,
                &env.redactor
            )))
        )?;
    }
    write_rows(&mut env.stdout, output, COLUMNS, &rows)?;
    if output.format == OutputFormat::Table {
        writeln!(
            env.stdout,
            "verdict: {}",
            if analysis.narrowed {
                "narrowed"
            } else {
                "not narrowed"
            }
        )?;
    }
    if analysis.narrowed {
        Ok(Produced::success(None))
    } else {
        Err(generic_query(&analysis))
    }
}

/// A leaf as a table row. The value goes through `redact::shown`, as
/// tenant text does in every human view: a saved search's query is
/// tenant text.
fn row(leaf: &LeafReport, redactor: &crate::redact::Redactor) -> Vec<String> {
    let shown = crate::redact::shown(&leaf.value, redactor);
    let value = if leaf.quoted {
        format!("\"{shown}\"")
    } else {
        shown
    };
    let rule = match (leaf.rule, leaf.tokens.len()) {
        (Some(number), _) => format!("{number}: {}", leaf.reason),
        (None, 0) => leaf.reason.clone(),
        (None, _) => {
            let tokens: Vec<String> = leaf
                .tokens
                .iter()
                .map(|token| {
                    format!(
                        "{} {}",
                        crate::redact::shown(&token.token, redactor),
                        token.rule
                    )
                })
                .collect();
            format!("{} ({})", leaf.reason, tokens.join(", "))
        }
    };
    vec![
        leaf.column.to_string(),
        leaf.field.to_owned(),
        value,
        if leaf.negated { "yes" } else { "" }.to_owned(),
        leaf.class.to_owned(),
        rule,
    ]
}

/// `kql` with `redact` applied to the text inside each pair of quotes, and
/// the quotes and everything outside them kept. URL redaction in free text
/// runs to the next space, so applied to the whole query it would take a
/// closing quote with it. A URL can only stand in a phrase: a word cannot
/// hold `:`, so the rest of the query needs nothing redacted. The query
/// has parsed, so its quotes pair up and a phrase holds no quote.
fn redact_phrases(kql: &str, redact: impl Fn(&str) -> String) -> String {
    let mut out = String::with_capacity(kql.len());
    let mut parts = kql.split('"');
    if let Some(first) = parts.next() {
        out.push_str(first);
    }
    for (index, part) in parts.enumerate() {
        out.push('"');
        if index % 2 == 0 {
            out.push_str(&redact(part));
        } else {
            out.push_str(part);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::redact_phrases;

    #[test]
    fn only_phrase_text_is_redacted() {
        let shout = |text: &str| text.to_uppercase();
        assert_eq!(
            redact_phrases(r#"a1aa AND "x y" OR subject:"z" AND b2bb"#, shout),
            r#"a1aa AND "X Y" OR subject:"Z" AND b2bb"#
        );
        assert_eq!(redact_phrases("a1aa", shout), "a1aa");
    }
}
