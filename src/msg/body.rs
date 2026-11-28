//! Body selection (`docs/SPEC.md` section 4.11): the HTML body, decoded
//! with the item's code page, cleaned and converted to text; else the
//! plain-text body; else, for an item with only a compressed RTF body or
//! none, the reason there is no body.

use std::sync::LazyLock;

use encoding_rs::Encoding;
use regex::Regex;

/// The least width the HTML is converted at. The width used is also more
/// than the HTML's length, so that no word, and so no URL, is ever broken
/// across lines: the URL redaction that runs on the text afterwards then
/// sees each URL whole. `html2text` 0.17 lays text out to the width given
/// and pads no line to it (`pad_block_width` is off, and raw mode draws no
/// table borders), so a large width costs nothing for short lines (Derived
/// from its source).
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

/// Elements removed with their content before conversion: `<head>`,
/// `<style>` and `<script>`. Office's conditional comments need nothing:
/// a hidden one (`<!--[if mso]>…<![endif]-->`) is one HTML comment, which
/// the parser drops, and the markers of a downlevel-revealed one
/// (`<!--[if !mso]><!-->`, `<![if …]>`) are comments around text that is
/// kept.
static REMOVED_HTML: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?is)<head(?:\s[^>]*)?>.*?</head\s*>|<style(?:\s[^>]*)?>.*?</style\s*>|<script(?:\s[^>]*)?>.*?</script\s*>",
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

/// A link's tags, removed and their text kept: `html2text` writes a link
/// as `[text]`, and a bracket run on to a URL hides its host from the
/// redaction after. The link's target is never shown.
static LINK_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<a(?:\s[^>]*)?>|</a\s*>").expect("a valid pattern"));

/// A horizontal rule, which `html2text` 0.17 drops; it is kept as `---`.
static HR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<hr\b[^>]*>").expect("a valid pattern"));

/// The HTML as plain text: cleaned, converted with no decoration and no
/// link footnotes, then with VML leftovers and trailing spaces removed.
/// `None` when it cannot be converted, including a panic in the converter.
pub fn html_to_text(html: &str) -> Option<String> {
    let cleaned = REMOVED_HTML.replace_all(html, "");
    let cleaned = VML_STYLE.replace_all(&cleaned, "");
    let cleaned = LINK_TAG.replace_all(&cleaned, "");
    let cleaned = HR.replace_all(&cleaned, "<p>---</p>");
    let cleaned = cleaned.into_owned();
    let width = TEXT_WIDTH.max(cleaned.len().saturating_add(1));
    let text = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Raw mode lays a table out as one column with a line per cell, and
        // draws no borders, so a table is never wider or longer than its
        // text (Derived from `html2text` 0.17's source and output).
        html2text::config::plain_no_decorate()
            .raw_mode(true)
            // Struck-through text stays plain: a combining stroke after each
            // character would hide a URL from the redaction after.
            .unicode_strikeout(false)
            .allow_width_overflow()
            .string_from_read(cleaned.as_bytes(), width)
    }))
    .ok()?
    .ok()?;
    let text = VML_STYLE.replace_all(&text, "");
    let lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    Some(lines.join("\n").trim().to_owned())
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
                    <!--[if !mso]><!-- --><p>spaced opener</p><!--<![endif]-->\
                    <p>between</p><![if !vml]><p>bare marker</p><![endif]>\
                    <!--[if gte mso 9]><p>hidden</p><![endif]--><p>after</p>";
        let text = html_to_text(html).unwrap();
        for kept in [
            "before",
            "visible to all",
            "spaced opener",
            "between",
            "bare marker",
            "after",
        ] {
            assert!(text.contains(kept), "{kept}: {text}");
        }
        assert!(!text.contains("hidden"), "{text}");
    }

    #[test]
    fn outlook_s_reply_divider_is_kept() {
        let divider = "_".repeat(32);
        let text = html_to_text(&format!("<p>reply</p><p>{divider}</p><p>quoted</p>")).unwrap();
        assert!(text.lines().any(|line| line == divider), "{text}");
    }

    #[test]
    fn ordinary_css_quoted_in_a_message_is_kept() {
        let text = html_to_text("<p>.shape { color: red; }</p>").unwrap();
        assert_eq!(text, ".shape { color: red; }");
    }

    #[test]
    fn a_url_longer_than_the_least_width_stays_on_one_line() {
        // A URL broken across lines would escape the redaction that runs on
        // the text afterwards.
        let url = format!("https://portal.contoso.example/a?{}", "q".repeat(20_000));
        let text = html_to_text(&format!("<p>See {url} now</p>")).unwrap();
        assert_eq!(text.lines().count(), 1, "{}", text.len());
        assert!(text.contains(&url), "{}", text.len());
    }

    #[test]
    fn struck_through_text_has_no_combining_strokes() {
        let text =
            html_to_text("<p><s>https://portal.contoso.example/a?x=1</s> <del>gone</del></p>")
                .unwrap();
        assert_eq!(text, "https://portal.contoso.example/a?x=1 gone");
    }

    #[test]
    fn a_link_is_its_text_with_no_brackets() {
        let text = html_to_text(
            "<p>See <a href=\"https://portal.contoso.example\">https://portal.contoso.example</a> \
             and <A HREF='https://portal.contoso.example/a?x=1'>the portal</A>.</p>",
        )
        .unwrap();
        assert_eq!(text, "See https://portal.contoso.example and the portal.");
    }

    #[test]
    fn an_element_named_like_head_is_not_removed() {
        // A forwarded message can hold a second document's `<head>` later.
        let text = html_to_text(
            "<p><head-line>kept</head-line></p><p>middle</p><head><title>t</title></head>\
             <p>after</p>",
        )
        .unwrap();
        for kept in ["kept", "middle", "after"] {
            assert!(text.contains(kept), "{kept}: {text}");
        }
    }

    #[test]
    fn text_after_a_link_is_kept() {
        let text =
            html_to_text("<p>https://portal.contoso.example/a?x=1&nbsp;before&nbsp;Friday</p>")
                .unwrap();
        assert!(text.ends_with("before\u{a0}Friday"), "{text}");
    }

    #[test]
    fn huge_table_spans_cost_nothing_in_raw_mode() {
        let html = "<table><tr><td colspan=\"4000000000\" rowspan=99999999>a</td></tr></table>";
        let text = html_to_text(html).unwrap();
        assert_eq!(text, "a");
    }

    #[test]
    fn span_attributes_written_as_text_are_kept() {
        let text = html_to_text("<p>Explain colspan=120 in this note.</p>").unwrap();
        assert_eq!(text, "Explain colspan=120 in this note.");
    }

    #[test]
    fn a_cp1252_html_body_decodes() {
        // "café – €5" in windows-1252.
        let bytes = b"<p>caf\xe9 \x96 \x805</p>".to_vec();
        let body = select(Some(Html::Bytes(bytes)), None, false, Some(1252), None);
        assert_eq!(body, Body::Html("café – €5".into()));
    }

    #[test]
    fn a_table_is_its_cells_and_a_rule_is_short() {
        // No border is drawn: a rule as wide as a cell, at this width a
        // whole paragraph, would repeat for every row.
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
        // The <hr> is kept, short; the table draws no rule.
        assert_eq!(
            text.lines().filter(|line| *line == "---").count(),
            1,
            "{text}"
        );
        assert!(text.contains("two"), "{text}");
        assert!(!text.contains('─') && !text.contains('│'), "{text}");
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
