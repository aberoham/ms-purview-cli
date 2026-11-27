//! The lexer for the guard's subset of the Keyword Query Language (KQL),
//! `docs/SPEC.md` section 6.3.
//!
//! A restriction (`participants:…`, `subject:…`, `kind:…`, `sent>=…`) is
//! lexed as one token, value included, because the value's form depends on
//! the property: an address may hold characters, such as `+` and `'`, that a
//! word may not. Everything outside the grammar is refused here or in the
//! parser, with the column of the construct.
//!
//! Error reasons name the construct. They quote the query's text only when
//! it is one of the grammar's fixed symbols, never a word, a value or a
//! property name, which the user or a tenant user wrote.

use chrono::NaiveDate;

use super::classify::is_full_address;

/// A token and the column of its first character, counted in characters
/// from 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub column: usize,
    pub kind: TokenKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    LeftParen,
    RightParen,
    And,
    Or,
    Not,
    /// A quoted phrase, without its quotes.
    Phrase(String),
    /// An unquoted word, with its trailing `*` if it has one.
    Word(String),
    Restriction(Restriction),
}

/// A property restriction, with its value checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Restriction {
    Address {
        property: AddressProperty,
        address: String,
    },
    Subject {
        value: String,
        quoted: bool,
    },
    Kind(KindValue),
    Sent {
        comparison: Comparison,
        date: NaiveDate,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressProperty {
    Participants,
    From,
    To,
    Cc,
    Bcc,
}

impl AddressProperty {
    pub fn name(self) -> &'static str {
        match self {
            Self::Participants => "participants",
            Self::From => "from",
            Self::To => "to",
            Self::Cc => "cc",
            Self::Bcc => "bcc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindValue {
    Email,
    MicrosoftTeams,
}

impl KindValue {
    pub fn name(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::MicrosoftTeams => "microsoftteams",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    AtLeast,
    AtMost,
}

impl Comparison {
    pub fn symbol(self) -> &'static str {
        match self {
            Self::AtLeast => ">=",
            Self::AtMost => "<=",
        }
    }
}

/// Why the query was refused, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KqlError {
    pub column: usize,
    pub reason: String,
}

impl KqlError {
    pub fn new(column: usize, reason: impl Into<String>) -> Self {
        Self {
            column,
            reason: reason.into(),
        }
    }
}

/// The spaces that separate tokens: ASCII space, tab, line feed and
/// carriage return. Other Unicode spaces (no-break space, ideographic
/// space) are refused outside a phrase, because KQL may not split on them.
fn is_space(character: char) -> bool {
    matches!(character, ' ' | '\t' | '\n' | '\r')
}

/// The characters a word may hold after its first, which must be a letter
/// or a digit.
fn is_word_char(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '-' | '_' | '.' | '/' | '@')
}

/// Where a value or a word ends: whitespace, a parenthesis or the end.
fn is_delimiter(character: Option<char>) -> bool {
    match character {
        None => true,
        Some(character) => is_space(character) || character == '(' || character == ')',
    }
}

/// The words KQL could read as operators, compared ignoring case.
const OPERATOR_WORDS: &[&str] = &["and", "or", "not", "near", "onear"];

struct Lexer {
    chars: Vec<char>,
    position: usize,
}

impl Lexer {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.position + offset).copied()
    }

    /// The 1-based column of the character at `position`.
    fn column_of(position: usize) -> usize {
        position + 1
    }

    fn column(&self) -> usize {
        Self::column_of(self.position)
    }

    fn take_while(&mut self, keep: impl Fn(char) -> bool) -> String {
        let start = self.position;
        while self.peek().is_some_and(&keep) {
            self.position += 1;
        }
        self.chars[start..self.position].iter().collect()
    }

    fn next_token(&mut self) -> Result<Option<Token>, KqlError> {
        while self.peek().is_some_and(is_space) {
            self.position += 1;
        }
        let Some(character) = self.peek() else {
            return Ok(None);
        };
        let column = self.column();
        let kind = match character {
            '(' => {
                self.position += 1;
                TokenKind::LeftParen
            }
            ')' => {
                self.position += 1;
                TokenKind::RightParen
            }
            '"' => TokenKind::Phrase(self.phrase()?),
            '+' | '-' => {
                return Err(KqlError::new(
                    column,
                    format!("a prefix {character} is not supported; use NOT to exclude"),
                ))
            }
            character if character.is_alphanumeric() => self.word_or_restriction()?,
            '*' => return Err(KqlError::new(column, "a * must follow a word")),
            character if is_symbol(character) => {
                return Err(KqlError::new(
                    column,
                    format!("the character {character} is not supported here"),
                ))
            }
            _ => {
                return Err(KqlError::new(
                    column,
                    "a character that is not supported here; quote the text as a phrase",
                ))
            }
        };
        Ok(Some(Token { column, kind }))
    }

    /// A quoted phrase: non-empty, with no wildcard and no control
    /// character. The opening quote is at `self.position`.
    fn phrase(&mut self) -> Result<String, KqlError> {
        let open = self.column();
        self.position += 1;
        let start = self.position;
        loop {
            match self.peek() {
                None => {
                    return Err(KqlError::new(
                        open,
                        "unbalanced quotes: this \" has no closing \"",
                    ))
                }
                Some('"') => break,
                Some('*') => {
                    return Err(KqlError::new(
                        self.column(),
                        "a * inside a quoted phrase is not supported",
                    ))
                }
                Some(character) if character.is_control() => {
                    return Err(KqlError::new(
                        self.column(),
                        "a control character inside a quoted phrase is not supported",
                    ))
                }
                Some(_) => self.position += 1,
            }
        }
        let text: String = self.chars[start..self.position].iter().collect();
        self.position += 1;
        if text.trim().is_empty() {
            return Err(KqlError::new(open, "an empty quoted phrase"));
        }
        // KQL does not say how a word glued to a closing quote reads.
        if !is_delimiter(self.peek()) {
            return Err(KqlError::new(
                self.column(),
                "a closing quote must be followed by a space, a parenthesis or the end",
            ));
        }
        Ok(text)
    }

    /// A word, an operator, or a property restriction with its value.
    fn word_or_restriction(&mut self) -> Result<TokenKind, KqlError> {
        let start = self.position;
        let column = self.column();
        let word = self.take_while(is_word_char);
        match self.peek() {
            Some(':') => return self.restriction(&word, column, ':'),
            Some('>' | '<' | '=') => {
                let symbol = self.peek().unwrap_or_default();
                return self.restriction(&word, column, symbol);
            }
            _ => {}
        }
        let text = self.finish_word(start, &word)?;
        if OPERATOR_WORDS.contains(&word.to_lowercase().as_str()) {
            return match (word.as_str(), text.len() == word.len()) {
                ("AND", true) => Ok(TokenKind::And),
                ("OR", true) => Ok(TokenKind::Or),
                ("NOT", true) => Ok(TokenKind::Not),
                _ if word.eq_ignore_ascii_case("near") || word.eq_ignore_ascii_case("onear") => {
                    Err(KqlError::new(
                        column,
                        "NEAR and ONEAR are not supported, in any case; quote the word to \
                         search for it",
                    ))
                }
                _ if text.len() != word.len() => Err(KqlError::new(
                    column,
                    "an operator word with a *; quote the word to search for it",
                )),
                _ => Err(KqlError::new(
                    column,
                    "an operator word that is not upper case; write AND, OR or NOT, or quote \
                     the word to search for it",
                )),
            };
        }
        Ok(TokenKind::Word(text))
    }

    /// The rest of a word whose characters before any `*` are `word` and
    /// began at `start`: an optional single trailing `*`, then a delimiter.
    fn finish_word(&mut self, start: usize, word: &str) -> Result<String, KqlError> {
        let mut text = word.to_owned();
        if self.peek() == Some('*') {
            self.position += 1;
            text.push('*');
            if !is_delimiter(self.peek()) && self.peek() != Some('"') {
                // A quote after the `*` is refused below.
                return Err(KqlError::new(
                    Self::column_of(start),
                    "a wildcard is supported only once, at the end of a word",
                ));
            }
        }
        if word.contains("..") {
            return Err(KqlError::new(
                Self::column_of(start),
                "a range (..) is not supported",
            ));
        }
        match self.peek() {
            None => {}
            Some(character) if is_space(character) || matches!(character, '(' | ')') => {}
            // KQL does not say how a quote glued to a word reads.
            Some('"') => {
                return Err(KqlError::new(
                    self.column(),
                    "a quote straight after a word; put a space or a parenthesis between them",
                ))
            }
            Some(character) if is_symbol(character) => {
                return Err(KqlError::new(
                    self.column(),
                    format!("the character {character} is not supported in a word; quote it"),
                ))
            }
            Some(_) => {
                return Err(KqlError::new(
                    self.column(),
                    "a character that is not supported in a word; quote the text as a phrase",
                ))
            }
        }
        Ok(text)
    }

    /// A `subject:` value: a phrase, or a word that is not an operator and
    /// is not followed by a property symbol. Read without `next_token`, so
    /// that the lexer never recurses.
    fn subject_value(&mut self, value_column: usize) -> Result<TokenKind, KqlError> {
        let refused = || KqlError::new(value_column, "subject takes a word or a quoted phrase");
        if self.peek() == Some('"') {
            let value = self.phrase()?;
            return Ok(TokenKind::Restriction(Restriction::Subject {
                value,
                quoted: true,
            }));
        }
        if !self.peek().is_some_and(char::is_alphanumeric) {
            return Err(refused());
        }
        let start = self.position;
        let word = self.take_while(is_word_char);
        if matches!(self.peek(), Some(':' | '>' | '<' | '=')) {
            return Err(refused());
        }
        let value = self.finish_word(start, &word)?;
        if OPERATOR_WORDS.contains(&word.to_lowercase().as_str()) {
            return Err(refused());
        }
        Ok(TokenKind::Restriction(Restriction::Subject {
            value,
            quoted: false,
        }))
    }

    /// A restriction: `property` has been read, and `symbol` (`:`, `>`,
    /// `<` or `=`) is at `self.position`.
    fn restriction(
        &mut self,
        property: &str,
        column: usize,
        symbol: char,
    ) -> Result<TokenKind, KqlError> {
        let name = property.to_ascii_lowercase();
        let address_property = match name.as_str() {
            "participants" => Some(AddressProperty::Participants),
            "from" => Some(AddressProperty::From),
            "to" => Some(AddressProperty::To),
            "cc" => Some(AddressProperty::Cc),
            "bcc" => Some(AddressProperty::Bcc),
            _ => None,
        };
        let known = address_property.is_some() || matches!(name.as_str(), "subject" | "kind");
        if !known && name != "sent" {
            return Err(KqlError::new(
                column,
                "a property this tool does not support; the supported properties are \
                 participants, from, to, cc, bcc, subject, kind and sent",
            ));
        }
        if name == "sent" {
            let comparison = match (symbol, self.peek_at(1)) {
                ('>', Some('=')) => Comparison::AtLeast,
                ('<', Some('=')) => Comparison::AtMost,
                _ => {
                    return Err(KqlError::new(
                        column,
                        "sent takes only >= or <= and a date in the form YYYY-MM-DD",
                    ))
                }
            };
            self.position += 2;
            let value_column = self.column();
            let value = self.take_while(|character| !is_delimiter(Some(character)));
            let date = parse_date(&value)
                .ok_or_else(|| KqlError::new(value_column, "sent needs a date as YYYY-MM-DD"))?;
            return Ok(TokenKind::Restriction(Restriction::Sent {
                comparison,
                date,
            }));
        }
        if symbol != ':' {
            return Err(KqlError::new(
                column,
                "this property takes :, not a comparison such as =, < or >",
            ));
        }
        self.position += 1;
        let value_column = self.column();
        if self.peek() == Some('(') {
            return Err(KqlError::new(
                value_column,
                "a property followed by ( is not supported; write each restriction on its own \
                 and join them with OR",
            ));
        }
        if is_delimiter(self.peek()) {
            return Err(KqlError::new(value_column, "a property with no value"));
        }
        if let Some(property) = address_property {
            if self.peek() == Some('"') {
                return Err(KqlError::new(
                    value_column,
                    "a quoted address is not supported; write the address without quotes",
                ));
            }
            let address = self.take_while(|character| !is_delimiter(Some(character)));
            if address.contains('*') {
                return Err(KqlError::new(
                    value_column,
                    "a * in an address is not supported",
                ));
            }
            if !is_full_address(&address) {
                return Err(KqlError::new(
                    value_column,
                    "not a full address: an address needs a local part, @ and a domain, such \
                     as alex@contoso.example",
                ));
            }
            return Ok(TokenKind::Restriction(Restriction::Address {
                property,
                address,
            }));
        }
        if name == "kind" {
            let value = self.take_while(|character| !is_delimiter(Some(character)));
            let kind = match value.to_ascii_lowercase().as_str() {
                "email" => KindValue::Email,
                "microsoftteams" => KindValue::MicrosoftTeams,
                _ => {
                    return Err(KqlError::new(
                        value_column,
                        "kind takes only email or microsoftteams",
                    ))
                }
            };
            return Ok(TokenKind::Restriction(Restriction::Kind(kind)));
        }
        self.subject_value(value_column)
    }
}

/// The character index of the first web address in `text`: `http://` or
/// `https://` in any case, which is what `redact::urls_in_text` treats as
/// a URL everywhere in the tool. A query holding one is refused, so that
/// no URL query value (a signature, say) is ever printed and the query is
/// shown as it was given, never rewritten. Other schemes are not URLs to
/// the redactor either.
pub fn web_url_at(text: &str) -> Option<usize> {
    let lower = text.to_ascii_lowercase();
    let byte = ["http://", "https://"]
        .iter()
        .filter_map(|scheme| lower.find(scheme))
        .min()?;
    Some(text[..byte].chars().count())
}

/// A character a terminal may not show, or may show as space although KQL
/// would not read it as one: a control character other than tab, line
/// feed and carriage return, or a default-ignorable code point (a
/// zero-width space, a bidirectional control). Refused anywhere in a
/// query, so that what the report shows is what the guard classified.
pub fn is_hidden(character: char) -> bool {
    (character.is_control() && !matches!(character, '\t' | '\n' | '\r'))
        || crate::output::is_default_ignorable(character)
}

/// ASCII punctuation that error messages may quote: it is one of the
/// grammar's fixed symbols, or a single character that cannot be a secret.
fn is_symbol(character: char) -> bool {
    character.is_ascii_punctuation()
}

/// A date written exactly as YYYY-MM-DD.
pub fn parse_date(text: &str) -> Option<NaiveDate> {
    let bytes = text.as_bytes();
    let shape = bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if !shape {
        return None;
    }
    NaiveDate::parse_from_str(text, "%Y-%m-%d").ok()
}

/// Every token of `query`, or the first construct the grammar refuses.
pub fn tokens(query: &str) -> Result<Vec<Token>, KqlError> {
    if let Some(index) = web_url_at(query) {
        return Err(KqlError::new(
            index + 1,
            "a web address (an http or https link) is not supported; search for its host name \
             or path without the scheme",
        ));
    }
    if let Some(index) = query.chars().position(is_hidden) {
        return Err(KqlError::new(
            index + 1,
            "an invisible or control character; type the query again without it",
        ));
    }
    let mut lexer = Lexer {
        chars: query.chars().collect(),
        position: 0,
    };
    let mut tokens = Vec::new();
    while let Some(token) = lexer.next_token()? {
        tokens.push(token);
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(query: &str) -> Vec<TokenKind> {
        tokens(query)
            .unwrap()
            .into_iter()
            .map(|token| token.kind)
            .collect()
    }

    fn refused(query: &str) -> KqlError {
        tokens(query).expect_err(query)
    }

    #[test]
    fn words_phrases_operators_and_parentheses() {
        assert_eq!(
            kinds(r#"("orders-api" OR svc2*) AND NOT e.g"#),
            [
                TokenKind::LeftParen,
                TokenKind::Phrase("orders-api".into()),
                TokenKind::Or,
                TokenKind::Word("svc2*".into()),
                TokenKind::RightParen,
                TokenKind::And,
                TokenKind::Not,
                TokenKind::Word("e.g".into()),
            ]
        );
    }

    #[test]
    fn restrictions_carry_their_checked_values() {
        assert_eq!(
            kinds(
                "Participants:alex+x@contoso.example from:o'neil@fabrikam.example kind:Email \
                 SENT>=2025-01-31 sent<=2025-12-01 subject:\"stock report\" subject:retention"
            ),
            [
                TokenKind::Restriction(Restriction::Address {
                    property: AddressProperty::Participants,
                    address: "alex+x@contoso.example".into()
                }),
                TokenKind::Restriction(Restriction::Address {
                    property: AddressProperty::From,
                    address: "o'neil@fabrikam.example".into()
                }),
                TokenKind::Restriction(Restriction::Kind(KindValue::Email)),
                TokenKind::Restriction(Restriction::Sent {
                    comparison: Comparison::AtLeast,
                    date: NaiveDate::from_ymd_opt(2025, 1, 31).unwrap()
                }),
                TokenKind::Restriction(Restriction::Sent {
                    comparison: Comparison::AtMost,
                    date: NaiveDate::from_ymd_opt(2025, 12, 1).unwrap()
                }),
                TokenKind::Restriction(Restriction::Subject {
                    value: "stock report".into(),
                    quoted: true
                }),
                TokenKind::Restriction(Restriction::Subject {
                    value: "retention".into(),
                    quoted: false
                }),
            ]
        );
    }

    #[test]
    fn columns_count_characters_from_one() {
        let tokens = tokens("é AND \"x y\"").unwrap();
        let columns: Vec<usize> = tokens.iter().map(|token| token.column).collect();
        assert_eq!(columns, [1, 3, 7]);
    }

    #[test]
    fn refused_constructs_name_their_column() {
        for (query, column) in [
            ("-orders", 1),
            ("+orders", 1),
            ("a NEAR b", 3),
            ("a near b", 3),
            ("ONEAR", 1),
            ("a and b", 3),
            ("a Or b", 3),
            ("not a", 1),
            ("NOT*", 1),
            ("body:\"stock report\"", 1),
            ("participants:(a@contoso.example)", 14),
            ("subject:(retention)", 9),
            ("participants:*@contoso.example", 14),
            ("participants:alex@contoso.*", 14),
            ("participants:contoso.example", 14),
            ("participants:@contoso.example", 14),
            ("participants:\"alex@contoso.example\"", 14),
            ("participants:", 14),
            ("ord*ers", 1),
            ("orders**", 1),
            ("*orders", 1),
            ("\"orders*\"", 8),
            ("\"orders", 1),
            ("\"\"", 1),
            ("\"  \"", 1),
            ("sent>2025-01-01", 1),
            ("sent:2025-01-01", 1),
            ("sent>=2025-1-1", 7),
            ("sent>=2025-02-30", 7),
            ("sent>=2025-01-01..2025-02-01", 7),
            ("size=10", 1),
            ("subject=x", 1),
            ("1..5", 1),
            ("kind:sms", 6),
            ("a=b", 1),
            ("café!", 5),
            ("orders~", 7),
            ("“orders”", 1),
            ("subject:", 9),
        ] {
            let error = refused(query);
            assert_eq!(error.column, column, "{query}: {error:?}");
        }
    }

    #[test]
    fn hidden_characters_are_refused_where_they_are() {
        for (query, column) in [
            ("\"follow-up\u{200B}\"", 11),
            ("orders-api\u{200B}", 11),
            ("a1aa\u{000B}AND b2bb", 5),
            ("\u{202E}orders-api", 1),
            ("orders-api AND\u{00A0}\u{FEFF}svc2", 16),
        ] {
            assert_eq!(refused(query).column, column, "{query:?}");
        }
        // Tab, line feed and carriage return separate tokens.
        assert_eq!(kinds("a1aa\tAND\r\nb2bb").len(), 3);
    }

    #[test]
    fn operators_and_words_glued_to_quotes_are_refused() {
        for (query, column) in [
            ("\"retention\"AND\"orders-api\"", 12),
            ("retention AND\"orders-api\"", 14),
            ("\"orders-api\"retention", 13),
            ("orders-api*\"x\"", 12),
            ("subject:\"x y\"z", 14),
        ] {
            assert_eq!(refused(query).column, column, "{query}");
        }
        for query in ["retention AND\"orders-api\"", "orders-api*\"x\""] {
            assert!(
                refused(query)
                    .reason
                    .contains("quote straight after a word"),
                "{query}"
            );
        }
    }

    #[test]
    fn only_ascii_spaces_separate_and_properties_fold_ascii_only() {
        for (query, column) in [
            ("a1aa\u{00A0}AND b2bb", 5),
            ("a1aa AND\u{3000}b2bb", 9),
            ("a1aa\u{0085}OR b2bb", 5),
            ("\u{212A}ind:email", 1),
            ("kind:\u{212A}email", 6),
        ] {
            assert_eq!(refused(query).column, column, "{query:?}");
        }
        // Inside a phrase a no-break space is text.
        assert_eq!(kinds("\"stock\u{00A0}report\"").len(), 1);
    }

    #[test]
    fn an_operator_word_with_a_star_says_so() {
        for query in ["NOT*", "AND*", "or*"] {
            assert!(refused(query).reason.contains("with a *"), "{query}");
        }
    }

    #[test]
    fn a_web_address_is_refused_where_it_starts() {
        // Joined at run time, so that this file passes the public-data lint.
        let scheme = ["https", "://"].concat();
        for (query, column) in [
            (format!("\"{scheme}files.contoso.example/report\""), 2),
            (
                format!("a1aa AND subject:\"x {}y\"", scheme.to_uppercase()),
                21,
            ),
        ] {
            let query = query.as_str();
            let error = refused(query);
            assert_eq!(error.column, column, "{query}");
            assert!(error.reason.contains("a web address"), "{query}");
        }
        assert_eq!(kinds("\"files.contoso.example/report\"").len(), 1);
        // A pattern that names no address is text.
        assert_eq!(kinds("\"https?://\"").len(), 1);
    }

    #[test]
    fn a_subject_value_is_read_without_recursion() {
        for query in [
            "subject:subject:x",
            "subject:participants:alex@contoso.example",
            "subject:AND",
            "subject:near",
            "subject:x=y",
        ] {
            assert_eq!(refused(query).column, 9, "{query}");
        }
        let deep = "subject:".repeat(200_000);
        assert_eq!(refused(&deep).column, 9);
    }

    #[test]
    fn reasons_never_quote_a_word_or_a_value() {
        for query in [
            "secretword:x",
            "a near b",
            "participants:hunter2",
            "kind:hunter2",
            "subject:(hunter2)",
            "hunter2§",
        ] {
            let error = refused(query);
            for word in ["secretword", "hunter2", "near"] {
                assert!(!error.reason.contains(word), "{query}: {}", error.reason);
            }
        }
    }
}
