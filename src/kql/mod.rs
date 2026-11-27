//! The guard against generic tenant-wide searches (`docs/SPEC.md`
//! section 6.3): a lexer and a recursive-descent parser for a small subset
//! of the Keyword Query Language (KQL), term and address classification,
//! the narrowing verdict, and the builder behind the query flags.
//!
//! `purview kql` runs it locally; the write commands of phase 2 run
//! `guard::enforce` before sign-in on a query from the command line.

pub mod build;
pub mod classify;
pub mod guard;
pub mod lexer;
pub mod parser;

pub use guard::{analyse, enforce, Analysis, GuardConfig, Override};

#[cfg(test)]
mod tests {
    use chrono::NaiveDate;

    use super::build::{build, Kind, QueryFlags};
    use super::classify::TermLists;
    use super::*;
    use crate::error::PurviewError;

    fn verdict(kql: &str) -> bool {
        analyse(kql, &GuardConfig::default())
            .unwrap_or_else(|error| panic!("{kql}: {error}"))
            .narrowed
    }

    fn not_understood(kql: &str) -> bool {
        matches!(
            analyse(kql, &GuardConfig::default()),
            Err(PurviewError::KqlNotUnderstood { .. })
        )
    }

    fn date(text: &str) -> Option<NaiveDate> {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").ok()
    }

    /// One table for both forms: the flags must build exactly the raw
    /// KQL, and both get the verdict.
    #[test]
    fn the_flags_and_raw_kql_get_the_same_verdicts() {
        let terms = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
        let cases: Vec<(QueryFlags, &str, bool)> = vec![
            (
                QueryFlags {
                    terms: terms(&["orders-api"]),
                    participants: terms(&["alex@contoso.example"]),
                    ..QueryFlags::default()
                },
                "\"orders-api\" AND participants:alex@contoso.example",
                true,
            ),
            (
                QueryFlags {
                    terms: terms(&["orders-api"]),
                    ..QueryFlags::default()
                },
                "\"orders-api\"",
                true,
            ),
            (
                QueryFlags {
                    terms: terms(&["retention"]),
                    ..QueryFlags::default()
                },
                "\"retention\"",
                false,
            ),
            (
                QueryFlags {
                    terms: terms(&["retention"]),
                    participants: terms(&["alex@contoso.example"]),
                    ..QueryFlags::default()
                },
                "\"retention\" AND participants:alex@contoso.example",
                true,
            ),
            (
                QueryFlags {
                    terms: terms(&["orders-api", "retention"]),
                    ..QueryFlags::default()
                },
                "(\"orders-api\" OR \"retention\")",
                false,
            ),
            (
                QueryFlags {
                    terms: terms(&["orders-api", "retention"]),
                    participants: terms(&["alex@contoso.example", "sam@contoso.example"]),
                    ..QueryFlags::default()
                },
                "(\"orders-api\" OR \"retention\") AND (participants:alex@contoso.example OR \
                 participants:sam@contoso.example)",
                true,
            ),
            (
                QueryFlags {
                    participants: terms(&["alex@contoso.example"]),
                    ..QueryFlags::default()
                },
                "participants:alex@contoso.example",
                true,
            ),
            (
                QueryFlags {
                    since: date("2025-01-01"),
                    until: date("2025-12-31"),
                    ..QueryFlags::default()
                },
                "sent>=2025-01-01 AND sent<=2025-12-31",
                false,
            ),
            (
                QueryFlags {
                    kind: Some(Kind::Email),
                    ..QueryFlags::default()
                },
                "kind:email",
                false,
            ),
            (
                QueryFlags {
                    kind: Some(Kind::Teams),
                    terms: terms(&["PagerDuty"]),
                    ..QueryFlags::default()
                },
                "\"PagerDuty\" AND kind:microsoftteams",
                true,
            ),
            (
                QueryFlags {
                    exclude_from: terms(&["noreply@notify.example"]),
                    ..QueryFlags::default()
                },
                "NOT from:noreply@notify.example",
                false,
            ),
            (
                QueryFlags {
                    terms: terms(&["follow-up meeting"]),
                    exclude_from: terms(&["noreply@notify.example"]),
                    ..QueryFlags::default()
                },
                "\"follow-up meeting\" AND NOT from:noreply@notify.example",
                false,
            ),
            (
                QueryFlags {
                    terms: terms(&["orders-api migration"]),
                    since: date("2025-01-01"),
                    kind: Some(Kind::Email),
                    exclude_from: terms(&["noreply@notify.example"]),
                    ..QueryFlags::default()
                },
                "\"orders-api migration\" AND sent>=2025-01-01 AND kind:email AND NOT \
                 from:noreply@notify.example",
                true,
            ),
        ];
        for (flags, raw, narrowed) in cases {
            let built = build(&flags).unwrap();
            assert_eq!(built, raw);
            assert_eq!(verdict(&built), narrowed, "{raw}");
            let raw_flags = QueryFlags {
                kql: Some(raw.to_owned()),
                ..QueryFlags::default()
            };
            assert_eq!(verdict(&build(&raw_flags).unwrap()), narrowed, "{raw}");
        }
    }

    #[test]
    fn every_grammar_production_is_accepted() {
        for kql in [
            "orders-api",
            "\"orders-api migration\"",
            "orders-api*",
            "a1aa OR b2bb",
            "a1aa AND b2bb",
            "NOT a1aa",
            "NOT NOT a1aa",
            "(a1aa)",
            "((a1aa OR b2bb) AND (c3cc OR NOT d4dd))",
            "participants:alex@contoso.example",
            "PARTICIPANTS:Alex@Contoso.example",
            "from:alex@contoso.example",
            "to:alex@contoso.example",
            "cc:alex@contoso.example",
            "bcc:alex@contoso.example",
            "subject:\"stock report\"",
            "subject:orders-api",
            "subject:orders-api*",
            "Subject:retention",
            "kind:email",
            "kind:microsoftteams",
            "sent>=2025-01-01",
            "sent<=2025-01-01",
            "Sent>=2025-01-01",
            "a1aa AND\tb2bb\nOR c3cc",
        ] {
            assert!(analyse(kql, &GuardConfig::default()).is_ok(), "{kql}");
        }
    }

    #[test]
    fn every_refused_construct_is_not_understood() {
        for kql in [
            // Juxtaposition.
            "orders-api retention",
            "\"stock\" \"report\"",
            "orders-api NOT retention",
            "(orders-api) retention",
            // Lower-case operators and NEAR.
            "orders-api and retention",
            "orders-api or retention",
            "not orders-api",
            "orders-api Or retention",
            "orders-api NEAR retention",
            "orders-api near retention",
            "orders-api ONEAR retention",
            "orders-api NEAR(3) retention",
            // Prefix operators.
            "-retention",
            "+retention",
            "orders-api AND -retention",
            // property:(…), unknown properties, comparisons.
            "participants:(alex@contoso.example OR sam@contoso.example)",
            "subject:(retention)",
            "body:\"stock report\"",
            "body:retention",
            "recipients:alex@contoso.example",
            "title:retention",
            "size>1000",
            "sent=2025-01-01",
            "sent>2025-01-01",
            "sent<2025-01-01",
            "sent:2025-01-01",
            "sent>=2025-01-01..2025-02-01",
            "subject=retention",
            // Wildcards.
            "ord*ers",
            "*orders",
            "orders**",
            "\"orders*\"",
            "participants:*@contoso.example",
            "participants:alex*@contoso.example",
            "from:*@contoso.example",
            // Addresses.
            "participants:contoso.example",
            "participants:@contoso.example",
            "participants:\"alex@contoso.example\"",
            "participants:alex",
            // Quotes and parentheses.
            "\"orders-api",
            "orders-api\"",
            "\"\"",
            "(orders-api",
            "orders-api)",
            "(orders-api))",
            "()",
            // Empty and dangling.
            "",
            " ",
            "orders-api AND",
            "OR orders-api",
            "NOT",
            // Other syntax.
            "orders-api~",
            "orders-api^2",
            "kind:sms",
            "1..5",
            "“orders-api”",
        ] {
            assert!(not_understood(kql), "{kql:?}");
        }
    }

    #[test]
    fn every_verdict_row() {
        // Specific phrase or word, and subject: with a specific value.
        assert!(verdict("\"orders-api migration\""));
        assert!(verdict("orders-api"));
        assert!(verdict("subject:orders-api"));
        assert!(verdict("subject:\"orders-api migration\""));
        // participants: with a valid address.
        assert!(verdict("participants:alex@contoso.example"));
        // Generic text, from:, to:, cc:, bcc:, kind:, sent.
        assert!(!verdict("\"retention\""));
        assert!(!verdict("retention"));
        assert!(!verdict("subject:retention"));
        assert!(!verdict("from:alex@contoso.example"));
        assert!(!verdict("to:alex@contoso.example"));
        assert!(!verdict("cc:alex@contoso.example"));
        assert!(!verdict("bcc:alex@contoso.example"));
        assert!(!verdict("kind:email"));
        assert!(!verdict("sent>=2025-01-01"));
        // NOT x, whatever x is.
        assert!(!verdict("NOT \"orders-api\""));
        assert!(!verdict("NOT participants:alex@contoso.example"));
        assert!(!verdict("NOT NOT \"orders-api\""));
        // AND: any child.
        assert!(verdict("retention AND participants:alex@contoso.example"));
        assert!(verdict("kind:email AND orders-api AND sent>=2025-01-01"));
        assert!(!verdict("retention AND kind:email AND sent>=2025-01-01"));
        // OR: every child.
        assert!(verdict("orders-api OR participants:alex@contoso.example"));
        assert!(!verdict("orders-api OR retention"));
        assert!(!verdict("participants:alex@contoso.example OR kind:email"));
        // Parentheses: the inner node.
        assert!(verdict("(orders-api)"));
        assert!(!verdict("(retention)"));
        // The section's examples.
        assert!(verdict(
            "\"retention\" AND participants:alex@contoso.example"
        ));
        assert!(!verdict(
            "(participants:alex@contoso.example OR kind:email) AND \"retention\""
        ));
    }

    #[test]
    fn the_unnarrowed_branch_is_located() {
        let at = |kql: &str| analyse(kql, &GuardConfig::default()).unwrap().unnarrowed_at;
        assert_eq!(at("orders-api"), None);
        assert_eq!(at("retention"), Some(1));
        assert_eq!(at("orders-api OR retention"), Some(15));
        assert_eq!(at("orders-api OR (retention AND kind:email)"), Some(16));
        assert_eq!(at("orders-api OR NOT svc2"), Some(15));
    }

    #[test]
    fn configured_terms_change_the_verdict() {
        let config = GuardConfig {
            lists: TermLists::new(&["Okta".to_owned()], &["orders-api".to_owned()]),
        };
        let narrowed = |kql: &str| analyse(kql, &config).unwrap().narrowed;
        assert!(narrowed("Okta"));
        assert!(narrowed("subject:okta"));
        assert!(!narrowed("\"orders-api\""));
        assert!(!verdict("Okta"));
    }

    /// Every guard bypass that the reviews of the first specification
    /// found, each refused.
    #[test]
    fn the_v1_bypasses_are_refused() {
        // Zero free-text terms passed vacuously.
        assert!(!verdict("kind:email"));
        assert!(!verdict("sent>=2020-01-01"));
        assert!(!verdict("NOT from:a@contoso.example"));
        // Content properties skipped classification.
        assert!(!verdict("subject:retention"));
        assert!(not_understood("body:\"stock report\""));
        // A negated specific term matched almost everything.
        assert!(!verdict("NOT \"orders-api\""));
        // Negated participants, and a participant in a mixed OR.
        assert!(!verdict("NOT participants:alex@contoso.example"));
        assert!(!verdict("NOT (participants:alex@contoso.example)"));
        assert!(!verdict(
            "(participants:alex@contoso.example OR kind:email) AND \"retention\""
        ));
        // A participant ORed with a generic term at the top.
        assert!(!verdict(
            "\"retention\" OR participants:alex@contoso.example"
        ));
        // Wildcard and bare-domain participants.
        assert!(not_understood("participants:*@contoso.example"));
        assert!(not_understood("participants:contoso.example"));
        // from:, to:, cc: and recipients: counted as narrowing.
        assert!(!verdict("retention AND from:alex@contoso.example"));
        assert!(!verdict("retention AND to:alex@contoso.example"));
        assert!(!verdict("retention AND cc:alex@contoso.example"));
        assert!(not_understood("recipients:alex@contoso.example"));
        // Heuristic false specifics.
        assert!(!verdict("\"CONTRACT\""));
        assert!(!verdict("\"RETENTION\""));
        assert!(!verdict("\"2025 contract\""));
        assert!(!verdict("\"follow-up meeting\""));
        // Plain multi-word phrases.
        assert!(!verdict("\"stock report\""));
        assert!(!verdict("\"retention policy\""));
        // A tokenizer could not see precedence, NOT scope or nesting.
        assert!(verdict(
            "orders-api OR retention AND participants:alex@contoso.example"
        ));
        assert!(!verdict(
            "retention AND participants:alex@contoso.example OR retention"
        ));
        assert!(!verdict("NOT orders-api AND NOT svc2-api"));
        assert!(!verdict("((orders-api OR (retention)))"));
        // Syntax KQL would read differently, refused outright.
        assert!(not_understood("orders-api retention"));
        assert!(not_understood("orders-api or retention"));
        assert!(not_understood("orders-api -retention"));
        assert!(not_understood("orders-api NEAR retention"));
        assert!(not_understood("participants:(alex@contoso.example)"));
        assert!(not_understood("ord*ers"));
        assert!(not_understood("\"orders-api"));
        assert!(not_understood("(orders-api"));
    }

    #[test]
    fn the_override_needs_a_reason_and_never_covers_a_parse_error() {
        let config = GuardConfig::default();
        let allow = |reason| Override::AllowGeneric { reason };
        assert!(enforce("orders-api", &config, Override::None).is_ok());
        assert!(matches!(
            enforce("retention", &config, Override::None),
            Err(PurviewError::GenericQuery(_))
        ));
        let overridden = enforce("retention", &config, allow("legal hold review")).unwrap();
        assert!(!overridden.narrowed);
        for reason in ["", "  \t"] {
            let error = enforce("retention", &config, allow(reason)).unwrap_err();
            assert_eq!(error.metadata().0, "CommandFailed");
            assert!(error.to_string().contains("--reason"));
            assert!(enforce("orders-api", &config, allow(reason)).is_err());
        }
        assert!(matches!(
            enforce("retention more", &config, allow("legal hold review")),
            Err(PurviewError::KqlNotUnderstood { .. })
        ));
    }

    #[test]
    fn the_refusal_names_a_column_and_never_the_query() {
        let analysis = analyse("orders-api OR secretword", &GuardConfig::default()).unwrap();
        let message = guard::generic_query(&analysis).to_string();
        assert!(message.contains("column 15"), "{message}");
        assert!(!message.contains("secretword"), "{message}");
        assert_eq!(
            guard::generic_query(&analysis).metadata(),
            ("GenericQuery", 0)
        );
    }

    #[test]
    fn guard_config_reads_the_lists_and_refuses_wrong_types() {
        let extra = |value: serde_json::Value| {
            value
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let config = GuardConfig::from_config(&extra(serde_json::json!({
            "guard": {"specific_terms": ["Okta"], "generic_terms": null}
        })))
        .unwrap();
        assert!(analyse("okta", &config).unwrap().narrowed);
        for value in [
            serde_json::json!({}),
            serde_json::json!({"guard": null}),
            serde_json::json!({"guard": {}}),
        ] {
            assert_eq!(
                GuardConfig::from_config(&extra(value)).unwrap(),
                GuardConfig::default()
            );
        }
        for value in [
            serde_json::json!({"guard": []}),
            serde_json::json!({"guard": {"specific_terms": "Okta"}}),
            serde_json::json!({"guard": {"generic_terms": [1]}}),
            serde_json::json!({"guard": {"specific_terms": [" "]}}),
        ] {
            assert!(GuardConfig::from_config(&extra(value)).is_err());
        }
    }
}
