//! Term and address classification (`docs/SPEC.md` section 6.3).
//!
//! A phrase or word is specific when at least one of its tokens is, and a
//! token is classified by the first of eight rules that matches. The rules
//! err towards "generic": a refused term can be added to
//! `guard.specific_terms` or searched with a participant.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// Common words that rule 6 would otherwise call specific, in trimmed lower
/// case. `docs/safety.md` reproduces this list; a test asserts the two are
/// identical. Changing it needs a test change and a `CHANGELOG.md` entry.
pub const BUILT_IN_GENERIC: &[&str] = &[
    "e-mail",
    "e-mails",
    "e-commerce",
    "e-learning",
    "e-signature",
    "e.g",
    "i.e",
    "etc",
    "a.m",
    "p.m",
    "n/a",
    "w/c",
    "and/or",
    "24/7",
    "sign-in",
    "sign-ins",
    "sign-on",
    "sign-up",
    "sign-out",
    "log-in",
    "log-on",
    "log-off",
    "opt-in",
    "opt-out",
    "follow-up",
    "follow-ups",
    "set-up",
    "check-in",
    "check-ins",
    "check-out",
    "roll-out",
    "hand-over",
    "hand-off",
    "add-on",
    "plug-in",
    "co-op",
    "co-operation",
    "co-ordinate",
    "co-ordination",
    "well-being",
    "ad-hoc",
    "up-to-date",
    "in-house",
    "on-site",
    "off-site",
    "on-call",
    "part-time",
    "full-time",
    "mid-year",
    "year-end",
    "month-end",
    "end-of-year",
    "end-of-month",
    "day-to-day",
    "one-to-one",
    "1-to-1",
    "face-to-face",
    "real-time",
    "long-term",
    "short-term",
    "high-level",
    "low-level",
    "top-level",
    "cross-team",
    "re-send",
    "re-sent",
    "re-run",
    "re-open",
    "pre-sales",
    "post-sales",
    "covid-19",
    "wi-fi",
];

/// The characters trimmed from each end of a token before it is classified.
const TRIMMED: &[char] = &['.', ',', ';', ':', '!', '?', '\'', '"', '(', ')'];

/// The address pattern of `docs/SPEC.md` section 6.3. It has no `*`, needs
/// a non-empty part before `@`, and needs a domain of at least two labels.
static ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9.!#$%&'+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
        .expect("the address pattern compiles")
});

/// Whether `address` is a full address that may narrow a query.
pub fn is_full_address(address: &str) -> bool {
    ADDRESS.is_match(address)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Class {
    Specific,
    Generic,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Self::Specific => "specific",
            Self::Generic => "generic",
        }
    }
}

/// The rule that decided a classification, numbered as in
/// `docs/SPEC.md` section 6.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// 1: the whole phrase is in `guard.generic_terms`.
    ConfiguredGeneric,
    /// 1: the whole phrase is in `guard.specific_terms`.
    ConfiguredSpecific,
    /// 2: the token is in the built-in generic list.
    BuiltInList,
    /// 3: the token is shorter than 4 characters.
    Short,
    /// 4: the token is digits only.
    DigitsOnly,
    /// 5: the token ends in `*` and its stem is shorter than 6 characters.
    ShortStem,
    /// 6: a letter plus punctuation from `- _ . / @ :` or a digit.
    Punctuated,
    /// 7: a lower-case letter and an upper-case letter after the first
    /// character.
    MixedCase,
    /// 8: none of the above.
    Plain,
}

impl Rule {
    pub fn number(self) -> u8 {
        match self {
            Self::ConfiguredGeneric | Self::ConfiguredSpecific => 1,
            Self::BuiltInList => 2,
            Self::Short => 3,
            Self::DigitsOnly => 4,
            Self::ShortStem => 5,
            Self::Punctuated => 6,
            Self::MixedCase => 7,
            Self::Plain => 8,
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::ConfiguredGeneric => "in guard.generic_terms",
            Self::ConfiguredSpecific => "in guard.specific_terms",
            Self::BuiltInList => "a common word on the built-in list",
            Self::Short => "shorter than 4 characters",
            Self::DigitsOnly => "digits only",
            Self::ShortStem => "a * stem shorter than 6 characters",
            Self::Punctuated => "a letter with a digit, or with - _ . / @ : between two characters",
            Self::MixedCase => "mixed case inside the word",
            Self::Plain => "an ordinary word",
        }
    }

    pub fn class(self) -> Class {
        match self {
            Self::ConfiguredSpecific | Self::Punctuated | Self::MixedCase => Class::Specific,
            _ => Class::Generic,
        }
    }
}

/// The configured term lists, compared ignoring case.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TermLists {
    specific: Vec<String>,
    generic: Vec<String>,
}

impl TermLists {
    pub fn new(specific: &[String], generic: &[String]) -> Self {
        let fold = |terms: &[String]| terms.iter().map(|term| fold(term)).collect();
        Self {
            specific: fold(specific),
            generic: fold(generic),
        }
    }
}

/// The form rule 1 compares: trimmed, lower case.
fn fold(text: &str) -> String {
    text.trim().to_lowercase()
}

/// One token's classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenClass {
    pub token: String,
    pub rule: Rule,
}

/// A phrase's or word's classification: the class, and either the rule-1
/// match for the whole text or one entry per token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermClass {
    pub class: Class,
    /// Set when rule 1 decided for the whole text.
    pub whole: Option<Rule>,
    pub tokens: Vec<TokenClass>,
}

impl TermClass {
    /// The rule that decided: rule 1, the first specific token's rule, or,
    /// for a generic text of one token, that token's rule. `None` for a
    /// generic text of several tokens, where every token's rule counts.
    pub fn deciding_rule(&self) -> Option<Rule> {
        if let Some(rule) = self.whole {
            return Some(rule);
        }
        if let Some(token) = self
            .tokens
            .iter()
            .find(|token| token.rule.class() == Class::Specific)
        {
            return Some(token.rule);
        }
        match self.tokens.as_slice() {
            [only] => Some(only.rule),
            _ => None,
        }
    }
}

/// Classifies a phrase, a word or a `subject:` value.
pub fn classify(text: &str, lists: &TermLists) -> TermClass {
    let whole = fold(text);
    // The generic list wins over the specific list.
    let configured = if lists.generic.contains(&whole) {
        Some(Rule::ConfiguredGeneric)
    } else if lists.specific.contains(&whole) {
        Some(Rule::ConfiguredSpecific)
    } else {
        None
    };
    if let Some(rule) = configured {
        return TermClass {
            class: rule.class(),
            whole: Some(rule),
            tokens: Vec::new(),
        };
    }
    let tokens: Vec<TokenClass> = text
        .split_whitespace()
        .map(|token| TokenClass {
            token: token.to_owned(),
            rule: classify_token(token),
        })
        .collect();
    let class = if tokens
        .iter()
        .any(|token| token.rule.class() == Class::Specific)
    {
        Class::Specific
    } else {
        Class::Generic
    };
    TermClass {
        class,
        whole: None,
        tokens,
    }
}

/// Rules 2 to 8 for one whitespace-separated token.
///
/// A digit is any character Unicode counts as numeric, as the lexer
/// accepts any alphanumeric character in a word.
pub fn classify_token(token: &str) -> Rule {
    let token = token.trim_matches(TRIMMED);
    if BUILT_IN_GENERIC.contains(&token.to_lowercase().as_str()) {
        return Rule::BuiltInList;
    }
    if token.chars().count() < 4 {
        return Rule::Short;
    }
    if token.chars().all(char::is_numeric) {
        return Rule::DigitsOnly;
    }
    // Rule 5 classifies the stem of a trailing `*` by the same rules, after
    // its own check of the stem's length.
    if let Some(stem) = token.strip_suffix('*') {
        let stem = stem.trim_matches(TRIMMED);
        if stem.chars().count() < 6 {
            return Rule::ShortStem;
        }
        return classify_token(stem);
    }
    let chars: Vec<char> = token.chars().collect();
    let has_letter = chars.iter().any(|character| character.is_alphabetic());
    let has_digit = chars.iter().any(|character| character.is_numeric());
    // A separator counts only between two letters or digits: KQL may read
    // it as a space (Docs), and `retention-` would then be `retention`.
    let joined = chars.windows(3).any(|window| {
        matches!(window[1], '-' | '_' | '.' | '/' | '@' | ':')
            && window[0].is_alphanumeric()
            && window[2].is_alphanumeric()
    });
    if has_letter && (has_digit || joined) {
        return Rule::Punctuated;
    }
    let has_lower = token.chars().any(char::is_lowercase);
    let upper_after_first = token.chars().skip(1).any(char::is_uppercase);
    if has_lower && upper_after_first {
        return Rule::MixedCase;
    }
    Rule::Plain
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_of(text: &str) -> Class {
        classify(text, &TermLists::default()).class
    }

    #[test]
    fn each_rule_with_its_examples() {
        for (token, rule) in [
            ("e-mail", Rule::BuiltInList),
            ("Sign-In", Rule::BuiltInList),
            ("e.g.", Rule::BuiltInList),
            ("(follow-up),", Rule::BuiltInList),
            ("api", Rule::Short),
            ("S3", Rule::Short),
            ("\"ab\"", Rule::Short),
            ("2025", Rule::DigitsOnly),
            ("12345678", Rule::DigitsOnly),
            ("order*", Rule::ShortStem),
            ("a*", Rule::Short),
            ("ab*", Rule::Short),
            ("abc*", Rule::ShortStem),
            ("retention-", Rule::Plain),
            ("\"retention-\"", Rule::Plain),
            ("retention_", Rule::Plain),
            ("retention/", Rule::Plain),
            ("-retention", Rule::Plain),
            ("retention--policy", Rule::Plain),
            ("svc٢", Rule::Punctuated),
            ("٢٠٢٥", Rule::DigitsOnly),
            ("svc2*", Rule::ShortStem),
            ("orders-api*", Rule::Punctuated),
            ("sign-in*", Rule::BuiltInList),
            ("retention*", Rule::Plain),
            ("orders-api", Rule::Punctuated),
            ("export_bucket", Rule::Punctuated),
            ("svc2", Rule::Punctuated),
            ("contoso.example", Rule::Punctuated),
            ("PagerDuty", Rule::MixedCase),
            ("GitHub", Rule::MixedCase),
            ("iPhone", Rule::MixedCase),
            ("RETENTION", Rule::Plain),
            ("Retention", Rule::Plain),
            ("retention", Rule::Plain),
            ("Okta", Rule::Plain),
            ("2025-01", Rule::Plain),
        ] {
            assert_eq!(classify_token(token), rule, "{token}");
        }
    }

    #[test]
    fn a_phrase_is_specific_when_one_token_is() {
        assert_eq!(class_of("orders-api migration"), Class::Specific);
        assert_eq!(class_of("2025 contract"), Class::Generic);
        assert_eq!(class_of("stock report"), Class::Generic);
        assert_eq!(class_of("follow-up meeting"), Class::Generic);
        assert_eq!(class_of("retention policy"), Class::Generic);
        assert_eq!(class_of("RETENTION"), Class::Generic);
        assert_eq!(class_of("PagerDuty"), Class::Specific);
    }

    #[test]
    fn configured_lists_match_the_whole_text_and_generic_wins() {
        let lists = TermLists::new(
            &[
                "Okta".to_owned(),
                " Stock Report ".to_owned(),
                "orders-api".to_owned(),
                "sign-in".to_owned(),
            ],
            &["orders-api".to_owned(), "PagerDuty".to_owned()],
        );
        let check = |text: &str, class: Class, whole: Option<Rule>| {
            let result = classify(text, &lists);
            assert_eq!((result.class, result.whole), (class, whole), "{text}");
        };
        check("okta", Class::Specific, Some(Rule::ConfiguredSpecific));
        check(
            "stock report",
            Class::Specific,
            Some(Rule::ConfiguredSpecific),
        );
        check("SIGN-IN", Class::Specific, Some(Rule::ConfiguredSpecific));
        // In both lists: generic.
        check("Orders-API", Class::Generic, Some(Rule::ConfiguredGeneric));
        // The generic list overrides rule 7.
        check("pagerduty", Class::Generic, Some(Rule::ConfiguredGeneric));
        // Rule 1 compares the whole text, not each token.
        check("okta rollout", Class::Generic, None);
        check("pagerduty incident", Class::Generic, None);
        check("PagerDuty incident", Class::Specific, None);
    }

    #[test]
    fn the_deciding_rule() {
        let lists = TermLists::default();
        assert_eq!(
            classify("follow-up orders-api", &lists).deciding_rule(),
            Some(Rule::Punctuated)
        );
        assert_eq!(
            classify("retention", &lists).deciding_rule(),
            Some(Rule::Plain)
        );
        assert_eq!(classify("stock report", &lists).deciding_rule(), None);
    }

    #[test]
    fn full_addresses() {
        for address in [
            "alex@contoso.example",
            "alex.smith+orders@mail.contoso.example",
            "o'neil@fabrikam.example",
            "a@b-c.example",
        ] {
            assert!(is_full_address(address), "{address}");
        }
        for address in [
            "contoso.example",
            "@contoso.example",
            "alex@",
            "alex@contoso",
            "*@contoso.example",
            "alex*@contoso.example",
            "alex@*.example",
            "\"alex@contoso.example\"",
            "alex@contoso..example",
            "alex@contoso.example.",
            "alex @contoso.example",
            "alex@contoso.example\n",
        ] {
            assert!(!is_full_address(address), "{address:?}");
        }
    }
}
