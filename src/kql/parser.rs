//! A recursive-descent parser for the guard's KQL subset
//! (`docs/SPEC.md` section 6.3):
//!
//! ```text
//! query   = or_expr EOF
//! or_expr = and_expr { "OR" and_expr }
//! and_expr= unary { "AND" unary }
//! unary   = "NOT" unary | primary
//! primary = "(" or_expr ")" | restriction | phrase | word
//! ```
//!
//! Two operands with no operator between them (juxtaposition) are
//! refused, as is nesting deeper than `MAX_DEPTH`.

use super::lexer::{tokens, KqlError, Restriction, Token, TokenKind};

/// The deepest nesting of parentheses and `NOT` the parser accepts, so that
/// a hostile query cannot exhaust the stack.
pub const MAX_DEPTH: usize = 64;

/// A node of the syntax tree. Every node knows the column it starts at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Leaf(Leaf),
    Not { column: usize, inner: Box<Node> },
    And(Vec<Node>),
    Or(Vec<Node>),
    Group { column: usize, inner: Box<Node> },
}

impl Node {
    pub fn column(&self) -> usize {
        match self {
            Self::Leaf(leaf) => leaf.column,
            Self::Not { column, .. } | Self::Group { column, .. } => *column,
            Self::And(children) | Self::Or(children) => children.first().map_or(1, Node::column),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leaf {
    pub column: usize,
    pub kind: LeafKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafKind {
    Phrase(String),
    Word(String),
    Restriction(Restriction),
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
    /// The column just past the query, for errors at its end.
    end: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.position)
    }

    fn peek_kind(&self) -> Option<&TokenKind> {
        self.peek().map(|token| &token.kind)
    }

    fn column(&self) -> usize {
        self.peek().map_or(self.end, |token| token.column)
    }

    fn or_expr(&mut self, depth: usize) -> Result<Node, KqlError> {
        let mut children = vec![self.and_expr(depth)?];
        while self.peek_kind() == Some(&TokenKind::Or) {
            self.position += 1;
            children.push(self.and_expr(depth)?);
        }
        Ok(if children.len() == 1 {
            children.remove(0)
        } else {
            Node::Or(children)
        })
    }

    fn and_expr(&mut self, depth: usize) -> Result<Node, KqlError> {
        let mut children = vec![self.unary(depth)?];
        loop {
            match self.peek_kind() {
                Some(TokenKind::And) => {
                    self.position += 1;
                    children.push(self.unary(depth)?);
                }
                None | Some(TokenKind::Or | TokenKind::RightParen) => break,
                Some(_) => {
                    return Err(KqlError::new(
                        self.column(),
                        "two operands with no operator between them; join them with AND or OR",
                    ))
                }
            }
        }
        Ok(if children.len() == 1 {
            children.remove(0)
        } else {
            Node::And(children)
        })
    }

    fn unary(&mut self, depth: usize) -> Result<Node, KqlError> {
        if self.peek_kind() == Some(&TokenKind::Not) {
            let column = self.column();
            let depth = deeper(depth, column)?;
            self.position += 1;
            let inner = self.unary(depth)?;
            return Ok(Node::Not {
                column,
                inner: Box::new(inner),
            });
        }
        self.primary(depth)
    }

    fn primary(&mut self, depth: usize) -> Result<Node, KqlError> {
        let column = self.column();
        let Some(token) = self.peek().cloned() else {
            return Err(KqlError::new(
                column,
                "the query ends where a term, phrase, restriction or ( was expected",
            ));
        };
        self.position += 1;
        let kind = match token.kind {
            TokenKind::LeftParen => {
                let depth = deeper(depth, column)?;
                let inner = self.or_expr(depth)?;
                if self.peek_kind() != Some(&TokenKind::RightParen) {
                    return Err(KqlError::new(
                        column,
                        "unbalanced parentheses: this ( has no closing )",
                    ));
                }
                self.position += 1;
                return Ok(Node::Group {
                    column,
                    inner: Box::new(inner),
                });
            }
            TokenKind::Phrase(text) => LeafKind::Phrase(text),
            TokenKind::Word(text) => LeafKind::Word(text),
            TokenKind::Restriction(restriction) => LeafKind::Restriction(restriction),
            TokenKind::RightParen => {
                return Err(KqlError::new(
                    column,
                    "a ) where a term, phrase, restriction or ( was expected",
                ))
            }
            TokenKind::And | TokenKind::Or => {
                return Err(KqlError::new(
                    column,
                    "an AND or OR where a term, phrase, restriction or ( was expected",
                ))
            }
            TokenKind::Not => unreachable!("unary reads NOT"),
        };
        Ok(Node::Leaf(Leaf { column, kind }))
    }
}

fn deeper(depth: usize, column: usize) -> Result<usize, KqlError> {
    if depth >= MAX_DEPTH {
        return Err(KqlError::new(
            column,
            format!("parentheses and NOT are nested more than {MAX_DEPTH} deep"),
        ));
    }
    Ok(depth + 1)
}

/// Parses `query`, or names the first construct the grammar refuses.
pub fn parse(query: &str) -> Result<Node, KqlError> {
    let tokens = tokens(query)?;
    let end = query.chars().count() + 1;
    if tokens.is_empty() {
        return Err(KqlError::new(1, "the query is empty"));
    }
    let mut parser = Parser {
        tokens,
        position: 0,
        end,
    };
    let node = parser.or_expr(0)?;
    if let Some(token) = parser.peek() {
        // `and_expr` stops only at OR, ) or the end, and `or_expr` consumes
        // every OR, so what is left is a ) with no (.
        return Err(KqlError::new(
            token.column,
            "unbalanced parentheses: this ) has no opening (",
        ));
    }
    Ok(node)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(column: usize, text: &str) -> Node {
        Node::Leaf(Leaf {
            column,
            kind: LeafKind::Word(text.into()),
        })
    }

    #[test]
    fn and_binds_tighter_than_or() {
        assert_eq!(
            parse("a1aa OR b2bb AND c3cc").unwrap(),
            Node::Or(vec![
                word(1, "a1aa"),
                Node::And(vec![word(9, "b2bb"), word(18, "c3cc")])
            ])
        );
    }

    #[test]
    fn not_applies_to_the_next_operand_and_groups_nest() {
        assert_eq!(
            parse("NOT NOT (a1aa OR b2bb) AND c3cc").unwrap(),
            Node::And(vec![
                Node::Not {
                    column: 1,
                    inner: Box::new(Node::Not {
                        column: 5,
                        inner: Box::new(Node::Group {
                            column: 9,
                            inner: Box::new(Node::Or(vec![word(10, "a1aa"), word(18, "b2bb")]))
                        })
                    })
                },
                word(28, "c3cc"),
            ])
        );
    }

    #[test]
    fn refusals_and_their_columns() {
        for (query, column) in [
            ("", 1),
            ("   ", 1),
            ("alpha beta", 7),
            ("\"stock\" \"report\"", 9),
            ("a1aa NOT b2bb", 6),
            ("(a1aa", 1),
            ("a1aa)", 5),
            ("((a1aa)", 1),
            ("()", 2),
            ("a1aa AND", 9),
            ("a1aa OR OR b2bb", 9),
            ("AND a1aa", 1),
            ("NOT", 4),
            ("a1aa (b2bb)", 6),
            ("participants:alex@contoso.example retention", 35),
        ] {
            let error = parse(query).expect_err(query);
            assert_eq!(error.column, column, "{query:?}: {error:?}");
        }
        for query in ["alpha beta", "a1aa NOT b2bb", "a1aa (b2bb)"] {
            let error = parse(query).unwrap_err();
            assert!(error.reason.contains("no operator"), "{query}: {error:?}");
        }
        for query in ["(a1aa", "a1aa)"] {
            let error = parse(query).unwrap_err();
            assert!(error.reason.contains("unbalanced"), "{query}: {error:?}");
        }
    }

    #[test]
    fn nesting_is_bounded() {
        let ok = format!("{}a1aa{}", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
        let deep = format!(
            "{}a1aa{}",
            "(".repeat(MAX_DEPTH + 1),
            ")".repeat(MAX_DEPTH + 1)
        );
        assert!(parse(&deep).unwrap_err().reason.contains("nested"));
        let nots = format!("{}a1aa", "NOT ".repeat(100_000));
        assert!(parse(&nots).unwrap_err().reason.contains("nested"));
        let parens = "(".repeat(100_000);
        assert!(parse(&parens).is_err());
    }
}
