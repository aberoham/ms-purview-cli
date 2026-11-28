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
        let converted = html_to_text(&source);
        if !converted.trim().is_empty() {
            return Body::Html(converted);
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
        50220 | 50221 | 50222 => "iso-2022-jp",
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

/// Elements and comments removed before conversion: `<head>`, `<style>`
/// and `<script>` with their content, and Office conditional comments.
static REMOVED_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)<head\b.*?</head\s*>|<style\b.*?</style\s*>|<script\b.*?</script\s*>|<!--\[if.*?<!\[endif\]\s*-->",
    )
    .expect("a valid pattern")
});

/// The markers of Office's "downlevel-revealed" conditionals, whose content
/// is kept.
static REVEALED_MARKERS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<!\[(?:if[^\]]*|endif)\]>").expect("a valid pattern"));

/// Style rules for VML and Office namespaces that naive tag stripping
/// leaves behind as text (Observed for `v\:*`; Assumption for the others,
/// which share its origin).
static VML_STYLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:[vowx]\\:\*|\.shape)\s*\{[^}]*\}").expect("a valid pattern")
});

/// The HTML as plain text: cleaned, converted with no decoration and no
/// link footnotes, then with VML leftovers and trailing spaces removed.
pub fn html_to_text(html: &str) -> String {
    let cleaned = REMOVED_HTML.replace_all(html, "");
    let cleaned = REVEALED_MARKERS.replace_all(&cleaned, "");
    let cleaned = VML_STYLE.replace_all(&cleaned, "");
    let text = html2text::config::plain_no_decorate()
        .allow_width_overflow()
        .string_from_read(cleaned.as_bytes(), TEXT_WIDTH)
        .unwrap_or_default();
    let text = VML_STYLE.replace_all(&text, "");
    // A rule (`<hr>`, a table border) is drawn across the whole width, so
    // at this width it would be thousands of characters: it becomes a
    // short one.
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .map(|line| if is_rule(line) { "---" } else { line })
        .collect();
    lines.join("\n").trim().to_owned()
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
        let text = html_to_text(html);
        assert_eq!(text, "Body text");
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
        let text = html_to_text("<p>above</p><hr><p>below</p>");
        assert!(text.lines().all(|line| line.chars().count() < 20), "{text}");
        assert!(text.contains("above") && text.contains("below"), "{text}");
    }

    #[test]
    fn a_long_line_is_not_wrapped() {
        let words = "word ".repeat(1_500);
        let text = html_to_text(&format!("<p>{words}</p>"));
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
