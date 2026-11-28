//! Body selection (`docs/SPEC.md` section 4.11): the HTML body, decoded
//! with the item's code page, cleaned and converted to text; else the
//! plain-text body; else, for an item with only a compressed RTF body or
//! none, the reason there is no body.

use std::sync::LazyLock;

use encoding_rs::Encoding;
use regex::Regex;

/// The width the HTML is converted at: wide enough that no line of mail is
/// wrapped. `html2text` 0.17 lays text out to the width given and pads no
/// line to it (`pad_block_width` is off), so a large width costs nothing
/// for short lines (Derived from its source).
const TEXT_WIDTH: usize = 10_000;

/// The HTML property as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Html {
    /// Binary, in the item's code page (Observed: every exported mail item).
    Bytes(Vec<u8>),
    /// A UTF-16 string property.
    Text(String),
}

/// The body an item gives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Body {
    /// From `PidTagHtml`, as text.
    Html(String),
    /// From `PidTagBody`.
    Text(String),
    /// Only `PidTagRtfCompressed`, which is not decompressed yet.
    RtfOnly,
    /// A Teams system message with no body (Observed: `extract-msg` fails on
    /// these too).
    UnsupportedClass,
    /// An HTML body that could not be converted, and no plain-text body.
    Unconvertible,
    /// No body property at all.
    #[default]
    Missing,
}

impl Body {
    /// `bodySource`: `html` or `text`, else `None`.
    pub fn source(&self) -> Option<&'static str> {
        match self {
            Self::Html(_) => Some("html"),
            Self::Text(_) => Some("text"),
            _ => None,
        }
    }

    pub fn text(&self) -> Option<&str> {
        match self {
            Self::Html(text) | Self::Text(text) => Some(text),
            _ => None,
        }
    }

    /// `error` and `errorDetail` for an item without a body.
    pub fn error(&self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::RtfOnly => Some(("noBody", "compressed RTF only")),
            Self::UnsupportedClass => {
                Some(("unsupportedClass", "a Teams system message with no body"))
            }
            Self::Missing => Some(("noBody", "the item has no body property")),
            Self::Unconvertible => Some(("bodyDecode", "the HTML body could not be converted")),
            Self::Html(_) | Self::Text(_) => None,
        }
    }
}

/// Chooses the body: HTML converted to text, else plain text, else the
/// reason there is none. An HTML body that gives no text falls back to the
/// plain-text one.
pub fn select(
    html: Option<Html>,
    text: Option<String>,
    rtf: bool,
    internet_codepage: Option<u32>,
    class: Option<&str>,
) -> Body {
    if let Some(html) = html {
        let source = match html {
            Html::Bytes(bytes) => decode_codepage(&bytes, internet_codepage),
            Html::Text(text) => text,
        };
        match html_to_text(&source) {
            Some(converted) if !converted.trim().is_empty() => return Body::Html(converted),
            Some(_) => {}
            None => {
                // The plain-text body, when there is one, still serves.
                if let Some(text) = text.filter(|text| !text.trim().is_empty()) {
                    return Body::Text(text.replace("\r\n", "\n"));
                }
                return Body::Unconvertible;
            }
        }
    }
    if let Some(text) = text.filter(|text| !text.trim().is_empty()) {
        return Body::Text(text.replace("\r\n", "\n"));
    }
    if class.is_some_and(|class| {
        class
            .to_ascii_lowercase()
            .starts_with("ipm.skypeteams.systemmessage")
    }) {
        return Body::UnsupportedClass;
    }
    if rtf {
        return Body::RtfOnly;
    }
    Body::Missing
}

/// `bytes` in Windows code page `codepage` (default UTF-8), with invalid
/// sequences replaced. A code page this table does not know is read as
/// UTF-8.
pub fn decode_codepage(bytes: &[u8], codepage: Option<u32>) -> String {
    let encoding = codepage
        .and_then(encoding_for)
        .unwrap_or(encoding_rs::UTF_8);
    let (text, _, _) = encoding.decode(bytes);
    text.into_owned()
}

/// The `encoding_rs` encoding of a Windows code page identifier
/// (Docs: Microsoft's code page identifiers).
fn encoding_for(codepage: u32) -> Option<&'static Encoding> {
    let label = match codepage {
        65001 => "utf-8",
        10000 => "macintosh",
        10007 => "x-mac-cyrillic",
        1200 => "utf-16le",
        1201 => "utf-16be",
        20127 | 1252 | 28591 => "windows-1252",
        1250 => "windows-1250",
        1251 => "windows-1251",
        1253 => "windows-1253",
        1254 => "windows-1254",
        1255 => "windows-1255",
        1256 => "windows-1256",
        1257 => "windows-1257",
        1258 => "windows-1258",
        874 => "windows-874",
        866 => "ibm866",
        932 => "shift_jis",
        936 => "gbk",
        949 => "euc-kr",
        950 => "big5",
        20866 => "koi8-r",
        21866 => "koi8-u",
        50220..=50222 => "iso-2022-jp",
        51932 => "euc-jp",
        54936 => "gb18030",
        28592 => "iso-8859-2",
        28593 => "iso-8859-3",
        28594 => "iso-8859-4",
        28595 => "iso-8859-5",
        28596 => "iso-8859-6",
        28597 => "iso-8859-7",
        28598 => "iso-8859-8",
        28599 => "windows-1254",
        28603 => "iso-8859-13",
        28605 => "iso-8859-15",
        _ => return None,
    };
    Encoding::for_label(label.as_bytes())
}

/// The markers of Office's "downlevel-revealed" conditionals, whose content
/// is shown by every reader and is kept: `<!--[if !mso]><!-->` and
/// `<!--<![endif]-->`, and the bare `<![if …]>` and `<![endif]>`. They are
/// removed first, so that the hidden conditionals below cannot reach past
/// them.
static REVEALED_MARKERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)<!--\[if[^\]]*\]><!-->|<!--<!\[endif\]-->|<!\[(?:if[^\]]*|endif)\]>")
        .expect("a valid pattern")
});

/// Elements and comments removed before conversion: `<head>`, `<style>`
/// and `<script>` with their content, and Office's hidden conditional
/// comments (`<!--[if …]>…<![endif]-->`).
static REMOVED_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)<head\b.*?</head\s*>|<style\b.*?</style\s*>|<script\b.*?</script\s*>|<!--\[if.*?<!\[endif\]\s*-->",
    )
    .expect("a valid pattern")
});

/// Style rules for VML and Office namespaces that naive tag stripping
/// leaves behind as text: rules that set `behavior` (Observed for `v\:*`;
/// Assumption for the others, which share its origin). Ordinary CSS, such
/// as a `.shape` rule quoted in a message, is kept.
static VML_STYLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:[vowx]\\:\*|\.shape)\s*\{\s*behavior\s*:[^}]*\}").expect("a valid pattern")
});

/// A horizontal rule, which `html2text` 0.17 drops; it is kept as `---`.
static HR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<hr\b[^>]*>").expect("a valid pattern"));

/// A `colspan` or `rowspan` of more than two digits: `html2text` lays out
/// a cell per spanned slot, so a huge span is memory, not text.
static SPAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(colspan|rowspan)\s*=\s*["']?\s*\d{3,}["']?"#).expect("a valid pattern")
});

/// A URL's query or fragment. It is removed before conversion, because
/// `html2text` breaks a line longer than its width, and a query broken
/// across lines would escape the redaction that runs on the text after.
static URL_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(https?://[^\s"'<>?#]*)[?#][^\s"'<>]*"#).expect("a valid pattern")
});

/// The HTML as plain text: cleaned, converted with no decoration and no
/// link footnotes, then with VML leftovers and trailing spaces removed.
/// `None` when it cannot be converted, including a panic in the converter.
pub fn html_to_text(html: &str) -> Option<String> {
    let cleaned = REVEALED_MARKERS.replace_all(html, "");
    let cleaned = REMOVED_HTML.replace_all(&cleaned, "");
    let cleaned = VML_STYLE.replace_all(&cleaned, "");
    let cleaned = HR.replace_all(&cleaned, "<p>---</p>");
    let cleaned = SPAN.replace_all(&cleaned, "${1}=\"99\"");
    let cleaned = URL_QUERY.replace_all(&cleaned, "${1}");
    let cleaned = cleaned.into_owned();
    let text = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        html2text::config::plain_no_decorate()
            .allow_width_overflow()
            .string_from_read(cleaned.as_bytes(), TEXT_WIDTH)
    }))
    .ok()?
    .ok()?;
    let text = VML_STYLE.replace_all(&text, "");
    // A table's rules are drawn as wide as its widest cell, which at this
    // width can be a whole paragraph: each becomes a short one.
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .map(|line| if is_rule(line) { "---" } else { line })
        .collect();
    Some(lines.join("\n").trim().to_owned())
}

/// Whether `line` is only box-drawing or dash characters, and long.
fn is_rule(line: &str) -> bool {
    line.chars().count() > 3
        && line
            .chars()
            .all(|c| matches!(c, '─' | '━' | '═' | '-' | '_' | ' ' | '│' | '┼' | '┬' | '┴'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_is_preferred_and_cleaned() {
        let html = "<html><head><style>v\\:* {behavior:url(#default#VML);}\
                    p {margin:0}</style><title>t</title></head><body>\
                    <!--[if gte mso 9]><xml><o:shapedefaults/></xml><![endif]-->\
                    <p>Hello <b>there</b></p><p>Second line</p></body></html>";
        let body = select(
            Some(Html::Bytes(html.as_bytes().to_vec())),
            Some("plain".into()),
            true,
            Some(65001),
            Some("IPM.Note"),
        );
        let Body::Html(text) = body else {
            panic!("{body:?}")
        };
        assert!(text.contains("Hello there"), "{text}");
        assert!(text.contains("Second line"), "{text}");
        assert!(!text.contains("behavior"), "{text}");
        assert!(!text.contains("shapedefaults"), "{text}");
        assert!(!text.contains("margin"), "{text}");
    }

    #[test]
    fn vml_style_text_outside_a_style_element_is_removed() {
        let html = "<body><p>v\\:* {behavior:url(#default#VML);} o\\:* \
                    {behavior:url(#default#VML);} .shape {behavior:url(#default#VML);}\
                    Body text</p></body>";
        let text = html_to_text(html).unwrap();
        assert_eq!(text, "Body text");
    }

    #[test]
    fn entity_encoded_vml_style_text_is_removed_after_conversion() {
        // `v\:*` written with an entity only becomes the leftover once the
        // HTML is decoded.
        let text = html_to_text("<p>v&#92;:* {behavior:url(#default#VML);} Body text</p>").unwrap();
        assert_eq!(text, "Body text");
    }

    #[test]
    fn a_downlevel_revealed_conditional_keeps_its_text() {
        let html = "<p>before</p><!--[if !mso]><!--><p>visible to all</p><!--<![endif]-->\
                    <!--[if gte mso 9]><p>hidden</p><![endif]--><p>after</p>";
        let text = html_to_text(html).unwrap();
        assert!(text.contains("visible to all"), "{text}");
        assert!(!text.contains("hidden"), "{text}");
        assert!(text.contains("before") && text.contains("after"), "{text}");
    }

    #[test]
    fn ordinary_css_quoted_in_a_message_is_kept() {
        let text = html_to_text("<p>.shape { color: red; }</p>").unwrap();
        assert_eq!(text, ".shape { color: red; }");
    }

    #[test]
    fn a_url_query_is_removed_before_conversion() {
        let url = format!("https://portal.contoso.example/a?{}", "q".repeat(20_000));
        let text = html_to_text(&format!("<p>{url}</p>")).unwrap();
        assert!(!text.contains("qqqq"), "{}", text.len());
        assert!(text.contains("https://portal.contoso.example/a"), "{text}");
    }

    #[test]
    fn huge_table_spans_are_capped() {
        let html = "<table><tr><td colspan=\"4000000000\" rowspan=99999999>a</td></tr></table>";
        let text = html_to_text(html).unwrap();
        assert!(text.contains('a'), "{text}");
    }

    #[test]
    fn a_cp1252_html_body_decodes() {
        // "café – €5" in windows-1252.
        let bytes = b"<p>caf\xe9 \x96 \x805</p>".to_vec();
        let body = select(Some(Html::Bytes(bytes)), None, false, Some(1252), None);
        assert_eq!(body, Body::Html("café – €5".into()));
    }

    #[test]
    fn a_rule_is_drawn_short() {
        // A table's rules are as wide as its widest cell, which at this
        // width is a whole paragraph.
        let paragraph = "word ".repeat(400);
        let text = html_to_text(&format!(
            "<p>above</p><table><tr><td>{paragraph}</td></tr><tr><td>two</td></tr></table>\
             <hr><p>below</p>"
        ))
        .unwrap();
        assert!(
            text.lines()
                .filter(|line| !line.contains("word"))
                .all(|line| line.chars().count() < 20),
            "{text}"
        );
        assert!(text.contains("above") && text.contains("below"), "{text}");
        // The table's rules and the <hr> are kept, short.
        assert!(
            text.lines().filter(|line| *line == "---").count() >= 3,
            "{text}"
        );
    }

    #[test]
    fn a_long_line_is_not_wrapped() {
        let words = "word ".repeat(1_500);
        let text = html_to_text(&format!("<p>{words}</p>")).unwrap();
        assert_eq!(text.lines().count(), 1, "{}", text.len());
    }

    #[test]
    fn text_then_rtf_then_nothing() {
        assert_eq!(
            select(None, Some("a\r\nb".into()), true, None, None),
            Body::Text("a\nb".into())
        );
        assert_eq!(select(None, None, true, None, None), Body::RtfOnly);
        assert_eq!(select(None, None, false, None, None), Body::Missing);
        assert_eq!(
            select(
                None,
                None,
                false,
                None,
                Some("IPM.SkypeTeams.SystemMessage")
            ),
            Body::UnsupportedClass
        );
        // An HTML body with no text falls back to the plain one.
        assert_eq!(
            select(
                Some(Html::Text("<html><head></head></html>".into())),
                Some("plain".into()),
                false,
                None,
                None
            ),
            Body::Text("plain".into())
        );
    }

    #[test]
    fn an_unknown_code_page_reads_as_utf8() {
        assert_eq!(decode_codepage("é".as_bytes(), Some(99_999)), "é");
        assert_eq!(decode_codepage(b"\xe9", Some(28591)), "é");
    }
}
