//! The Redactor, which every output sink writes through.
//!
//! It holds every secret value the process has seen until the process
//! exits: access tokens of both kinds, refresh tokens (including ones
//! already superseded by rotation) and the device code. It replaces those
//! values, and any text matching the JSON Web Token (JWT) pattern
//! `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`, with `[redacted]`.

use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, RwLock};

use serde_json::Value;

/// What every redacted value becomes.
pub const REDACTED: &str = "[redacted]";

#[derive(Default)]
pub struct Redactor {
    secrets: RwLock<Vec<Box<[u8]>>>,
}

impl fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Redactor")
            .field("secrets", &self.secret_count())
            .finish()
    }
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a secret for the rest of the process's life. Nothing is
    /// ever unregistered. An empty value is ignored, because it would match
    /// everywhere. Output is redacted line by line (see `RedactingWriter`),
    /// so each line of a multi-line value is registered as well.
    pub fn register(&self, secret: &str) {
        let mut values: Vec<&str> = vec![secret];
        if secret.contains('\n') {
            values.extend(secret.split(['\r', '\n']));
        }
        let mut secrets = self
            .secrets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for value in values {
            if value.is_empty() || secrets.iter().any(|known| **known == *value.as_bytes()) {
                continue;
            }
            secrets.push(value.as_bytes().into());
        }
    }

    pub fn secret_count(&self) -> usize {
        self.read_secrets().len()
    }

    pub fn redact(&self, text: &str) -> String {
        // Replacing whole matches of valid UTF-8 or ASCII patterns with ASCII
        // keeps the text valid UTF-8; the lossy conversion never applies.
        String::from_utf8_lossy(&self.redact_bytes(text.as_bytes())).into_owned()
    }

    /// Whether `text` holds a registered secret or a JWT-shaped run.
    pub fn recognises(&self, text: &str) -> bool {
        !self.spans(text.as_bytes()).is_empty()
    }

    /// Redacts every string in a JSON value, object keys included, before
    /// it is serialised. Redacting serialised JSON would miss a secret that
    /// JSON escaping changed, and could break the document's syntax.
    pub fn redact_value(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.redact(text)),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| self.redact_value(item)).collect())
            }
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, item)| (self.redact(key), self.redact_value(item)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    /// Whether any string in a JSON value, object keys included, holds a
    /// registered secret or a JWT-shaped run.
    pub fn recognises_value(&self, value: &Value) -> bool {
        match value {
            Value::String(text) => self.recognises(text),
            Value::Array(items) => items.iter().any(|item| self.recognises_value(item)),
            Value::Object(map) => map
                .iter()
                .any(|(key, item)| self.recognises(key) || self.recognises_value(item)),
            _ => false,
        }
    }

    /// Replaces every registered secret and every JWT-shaped run. Matches
    /// are found on the original bytes and overlapping or adjacent matches
    /// are merged, so two secrets that share bytes are both removed whole.
    pub fn redact_bytes(&self, bytes: &[u8]) -> Vec<u8> {
        let spans = self.spans(bytes);
        if spans.is_empty() {
            return bytes.to_vec();
        }
        let mut output = Vec::with_capacity(bytes.len());
        let mut position = 0;
        for (start, end) in spans {
            output.extend_from_slice(&bytes[position..start]);
            output.extend_from_slice(REDACTED.as_bytes());
            position = end;
        }
        output.extend_from_slice(&bytes[position..]);
        output
    }

    /// Every match, sorted, with overlapping and adjacent spans merged.
    fn spans(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
        let mut spans = jwt_spans(bytes);
        for secret in self.read_secrets().iter() {
            spans.extend(occurrences(bytes, secret));
        }
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (start, end) in spans {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
    }

    /// Where the undecided tail of `bytes` begins: the earliest position
    /// from which the text could still become a match once more bytes
    /// arrive. That is the start of a registered secret's prefix or of a
    /// JWT that reaches the end, pulled back to the start of any match
    /// that runs into it. Text before this point can be written safely.
    fn hold_point(&self, bytes: &[u8]) -> usize {
        let length = bytes.len();
        let mut hold = jwt_open_start(bytes);
        for secret in self.read_secrets().iter() {
            for prefix in (1..secret.len().min(length + 1)).rev() {
                if bytes.ends_with(&secret[..prefix]) {
                    hold = hold.min(length - prefix);
                    break;
                }
            }
        }
        for (start, end) in self.spans(bytes).into_iter().rev() {
            if start < hold && end > hold {
                hold = start;
            }
        }
        hold
    }

    fn read_secrets(&self) -> std::sync::RwLockReadGuard<'_, Vec<Box<[u8]>>> {
        self.secrets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Every occurrence of `needle`, overlapping ones included, as byte spans.
fn occurrences(haystack: &[u8], needle: &[u8]) -> Vec<(usize, usize)> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(start, _)| (start, start + needle.len()))
        .collect()
}

fn is_jwt_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn skip_jwt_bytes(bytes: &[u8], from: usize) -> usize {
    bytes[from..]
        .iter()
        .position(|byte| !is_jwt_byte(*byte))
        .map_or(bytes.len(), |offset| from + offset)
}

/// The leftmost, longest matches of
/// `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`. The character class
/// excludes `.`, so a greedy scan gives the same matches as the regular
/// expression.
fn jwt_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    while start + 3 <= bytes.len() {
        if &bytes[start..start + 3] != b"eyJ" {
            start += 1;
            continue;
        }
        match jwt_end(bytes, start + 3) {
            Some(end) => {
                spans.push((start, end));
                start = end;
            }
            None => start += 1,
        }
    }
    spans
}

fn jwt_end(bytes: &[u8], after_prefix: usize) -> Option<usize> {
    let header_end = skip_jwt_bytes(bytes, after_prefix);
    if header_end == after_prefix || bytes.get(header_end) != Some(&b'.') {
        return None;
    }
    let payload_start = header_end + 1;
    let payload_end = skip_jwt_bytes(bytes, payload_start);
    if payload_end == payload_start || bytes.get(payload_end) != Some(&b'.') {
        return None;
    }
    Some(skip_jwt_bytes(bytes, payload_end + 1))
}

/// The start of a JWT that reaches the end of `bytes` and could still
/// grow, or of a partial `eyJ` prefix at the end; `bytes.len()` when there
/// is none.
fn jwt_open_start(bytes: &[u8]) -> usize {
    let tail = bytes
        .iter()
        .rposition(|byte| !(is_jwt_byte(*byte) || *byte == b'.'))
        .map_or(0, |position| position + 1);
    (tail..bytes.len())
        .find(|start| is_open_jwt(&bytes[*start..]))
        .unwrap_or(bytes.len())
}

/// Whether `text` is a prefix of some JWT match that could continue.
fn is_open_jwt(text: &[u8]) -> bool {
    if text.len() < 3 {
        return !text.is_empty() && b"eyJ".starts_with(text);
    }
    if &text[..3] != b"eyJ" {
        return false;
    }
    let mut dots = 0;
    let mut since_dot = 0;
    for byte in &text[3..] {
        if *byte == b'.' {
            // Each of the first two parts needs at least one character.
            if dots == 2 || since_dot == 0 {
                return false;
            }
            dots += 1;
            since_dot = 0;
        } else {
            since_dot += 1;
        }
    }
    true
}

/// A writer that redacts everything written through it before passing it
/// on. It holds bytes back until a line ends, so a secret split across two
/// `write` calls is still found. Neither secrets nor the JWT pattern span a
/// line break; a multi-line secret is registered line by line.
///
/// `flush` writes a partial line only up to the point where a match could
/// still begin, and keeps that tail for the next write. `finish` ends the
/// stream: it redacts and writes everything held. Call `finish` once at the
/// end and check its result; dropping the writer finishes it but discards
/// any error.
pub struct RedactingWriter {
    inner: Box<dyn Write + Send>,
    redactor: Arc<Redactor>,
    pending: Vec<u8>,
}

impl fmt::Debug for RedactingWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactingWriter")
            .field("pending_bytes", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl RedactingWriter {
    pub fn new(inner: Box<dyn Write + Send>, redactor: Arc<Redactor>) -> Self {
        Self {
            inner,
            redactor,
            pending: Vec::new(),
        }
    }

    fn write_complete_lines(&mut self) -> io::Result<()> {
        if let Some(last_newline) = self.pending.iter().rposition(|byte| *byte == b'\n') {
            let rest = self.pending.split_off(last_newline + 1);
            let lines = std::mem::replace(&mut self.pending, rest);
            self.inner.write_all(&self.redactor.redact_bytes(&lines))?;
        }
        Ok(())
    }
}

impl Write for RedactingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buffer);
        self.write_complete_lines()?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let hold = self.redactor.hold_point(&self.pending);
        if hold > 0 {
            let tail = self.pending.split_off(hold);
            let ready = std::mem::replace(&mut self.pending, tail);
            self.inner.write_all(&self.redactor.redact_bytes(&ready))?;
        }
        self.inner.flush()
    }
}

impl RedactingWriter {
    /// Ends the stream: redacts and writes every held byte, then flushes.
    pub fn finish(&mut self) -> io::Result<()> {
        if !self.pending.is_empty() {
            let rest = std::mem::take(&mut self.pending);
            self.inner.write_all(&self.redactor.redact_bytes(&rest))?;
        }
        self.inner.flush()
    }
}

impl Drop for RedactingWriter {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Built at run time so that no JWT-shaped literal sits in the source.
    fn jwt() -> String {
        [
            "eyJ",
            "hbGciOiJub25lIn0",
            ".",
            "eyJzdWIiOiJ4In0",
            ".",
            "c2ln",
        ]
        .concat()
    }

    #[test]
    fn a_registered_secret_is_replaced_everywhere() {
        let redactor = Redactor::new();
        redactor.register("canary-refresh-0001");
        assert_eq!(
            redactor.redact("a canary-refresh-0001 b canary-refresh-0001"),
            "a [redacted] b [redacted]"
        );
        assert_eq!(redactor.redact("nothing secret"), "nothing secret");
    }

    #[test]
    fn a_superseded_secret_stays_registered() {
        let redactor = Redactor::new();
        redactor.register("canary-refresh-old");
        redactor.register("canary-refresh-new");
        assert_eq!(
            redactor.redact("canary-refresh-old canary-refresh-new"),
            "[redacted] [redacted]"
        );
        assert_eq!(redactor.secret_count(), 2);
        redactor.register("canary-refresh-old");
        assert_eq!(redactor.secret_count(), 2);
    }

    #[test]
    fn an_empty_secret_is_ignored() {
        let redactor = Redactor::new();
        redactor.register("");
        assert_eq!(redactor.secret_count(), 0);
        assert_eq!(redactor.redact("text"), "text");
    }

    #[test]
    fn json_web_tokens_are_replaced_without_registration() {
        let redactor = Redactor::new();
        let token = jwt();
        assert_eq!(
            redactor.redact(&format!("Bearer {token} trailing")),
            "Bearer [redacted] trailing"
        );
        assert_eq!(redactor.redact(&format!("\"{token}\",")), "\"[redacted]\",");
        // The pattern has no leading boundary, as in the regular expression.
        assert_eq!(redactor.redact(&format!("x{token}")), "x[redacted]");
    }

    #[test]
    fn the_signature_part_of_a_jwt_may_be_empty() {
        let redactor = Redactor::new();
        assert_eq!(
            redactor.redact(&["eyJ", "abc.", "def.", " after"].concat()),
            "[redacted] after"
        );
    }

    #[test]
    fn text_that_only_starts_like_a_jwt_is_kept() {
        let redactor = Redactor::new();
        for text in [
            "eyJ",
            "eyJ.",
            "eyJabc",
            "eyJabc.",
            "eyJabc.def",
            "eyJabc..def",
            "eyJ.abc.def",
            "eyj-abc.def.ghi",
        ] {
            assert_eq!(redactor.redact(text), text, "{text}");
        }
    }

    #[test]
    fn two_jwts_side_by_side_are_both_replaced() {
        let redactor = Redactor::new();
        let token = jwt();
        assert_eq!(
            redactor.redact(&format!("{token} {token}")),
            "[redacted] [redacted]"
        );
    }

    #[test]
    fn overlapping_secrets_are_removed_whole() {
        let redactor = Redactor::new();
        redactor.register("abcdef");
        redactor.register("defghi");
        assert_eq!(redactor.redact("xx abcdefghi yy"), "xx [redacted] yy");
        redactor.register("cd");
        assert_eq!(redactor.redact("abcdef cd"), "[redacted] [redacted]");
    }

    #[test]
    fn non_ascii_text_around_a_secret_survives() {
        let redactor = Redactor::new();
        redactor.register("sécret-1");
        assert_eq!(
            redactor.redact("Zoë sécret-1 王小明"),
            "Zoë [redacted] 王小明"
        );
    }

    #[test]
    fn a_multi_line_secret_is_redacted_line_by_line_too() {
        let redactor = Redactor::new();
        redactor.register("first-line-secret\nsecond-line-secret");
        assert_eq!(redactor.redact("second-line-secret"), "[redacted]");
    }

    #[test]
    fn the_debug_form_shows_no_secret() {
        let redactor = Redactor::new();
        redactor.register("canary-access-0001");
        let shown = format!("{redactor:?}");
        assert!(!shown.contains("canary"), "{shown}");
        assert!(shown.contains("secrets: 1"), "{shown}");
    }

    #[derive(Clone, Default)]
    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Shared {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    #[test]
    fn the_writer_finds_a_secret_split_across_writes() {
        let redactor = Arc::new(Redactor::new());
        redactor.register("canary-download-0001");
        let sink = Shared::default();
        let mut writer = RedactingWriter::new(Box::new(sink.clone()), redactor);
        writer.write_all(b"token canary-down").unwrap();
        assert_eq!(sink.text(), "", "a partial line is held back");
        writer.write_all(b"load-0001 end\nnext ").unwrap();
        assert_eq!(sink.text(), "token [redacted] end\n");
        writer.write_all(b"canary-download-0001").unwrap();
        writer.finish().unwrap();
        assert_eq!(sink.text(), "token [redacted] end\nnext [redacted]");
    }

    fn writer_with(secrets: &[&str]) -> (RedactingWriter, Shared) {
        let redactor = Arc::new(Redactor::new());
        for secret in secrets {
            redactor.register(secret);
        }
        let sink = Shared::default();
        (RedactingWriter::new(Box::new(sink.clone()), redactor), sink)
    }

    #[test]
    fn a_flush_inside_a_secret_holds_back_its_start() {
        let (mut writer, sink) = writer_with(&["canary-download-0001"]);
        writer.write_all(b"a canary-dow").unwrap();
        writer.flush().unwrap();
        assert_eq!(sink.text(), "a ");
        writer.write_all(b"nload-0001 z").unwrap();
        writer.flush().unwrap();
        writer.finish().unwrap();
        assert_eq!(sink.text(), "a [redacted] z");
    }

    #[test]
    fn a_flush_inside_a_jwt_holds_back_its_start() {
        let token = jwt();
        for split in [
            1,
            2,
            3,
            8,
            token.find('.').unwrap() + 1,
            token.len() - 2,
            token.len(),
        ] {
            let (mut writer, sink) = writer_with(&[]);
            write!(writer, "x {}", &token[..split]).unwrap();
            writer.flush().unwrap();
            assert_eq!(sink.text(), "x ", "split at {split}");
            write!(writer, "{} y", &token[split..]).unwrap();
            writer.flush().unwrap();
            writer.finish().unwrap();
            assert_eq!(sink.text(), "x [redacted] y", "split at {split}");
        }
    }

    #[test]
    fn a_flush_across_the_lines_of_a_multi_line_secret_still_redacts() {
        let (mut writer, sink) = writer_with(&["line-one-secret\nline-two-secret"]);
        writer.write_all(b"line-one-se").unwrap();
        writer.flush().unwrap();
        writer.write_all(b"cret\nline-two").unwrap();
        writer.flush().unwrap();
        writer.write_all(b"-secret\n").unwrap();
        writer.finish().unwrap();
        assert_eq!(sink.text(), "[redacted]\n[redacted]\n");
    }

    #[test]
    fn a_flush_writes_text_that_cannot_start_a_match() {
        let (mut writer, sink) = writer_with(&["canary-0001"]);
        writer.write_all(b"progress 5% ok").unwrap();
        writer.flush().unwrap();
        assert_eq!(sink.text(), "progress 5% ok");
        writer.write_all(b" canary-0001").unwrap();
        writer.flush().unwrap();
        assert_eq!(sink.text(), "progress 5% ok [redacted]");
    }

    #[test]
    fn json_values_are_redacted_before_serialisation() {
        let redactor = Redactor::new();
        // JSON escaping changes these characters, so byte-level redaction of
        // the serialised text would not find the secret.
        redactor.register("se\"cr\\et-0001");
        let value = serde_json::json!({
            "token": "before se\"cr\\et-0001 after",
            "se\"cr\\et-0001": [1, {"nested": jwt()}],
        });
        let serialised = serde_json::to_string(&value).unwrap();
        assert_eq!(redactor.redact(&serialised).matches(REDACTED).count(), 1);
        let safe = redactor.redact_value(&value);
        let text = serde_json::to_string(&safe).unwrap();
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["token"], "before [redacted] after");
        assert_eq!(parsed[REDACTED][1]["nested"], REDACTED);
        assert!(!redactor.recognises_value(&safe));
        assert!(redactor.recognises_value(&value));
        assert!(redactor.recognises(&jwt()));
        assert!(!redactor.recognises("plain"));
    }

    #[test]
    fn the_writer_flushes_a_partial_line_when_dropped() {
        let redactor = Arc::new(Redactor::new());
        let sink = Shared::default();
        let token = jwt();
        {
            let mut writer = RedactingWriter::new(Box::new(sink.clone()), redactor);
            write!(writer, "no newline {token}").unwrap();
        }
        assert_eq!(sink.text(), "no newline [redacted]");
    }

    #[test]
    fn a_secret_registered_after_writer_creation_is_still_redacted() {
        let redactor = Arc::new(Redactor::new());
        let sink = Shared::default();
        let mut writer = RedactingWriter::new(Box::new(sink.clone()), redactor.clone());
        redactor.register("canary-access-0002");
        writeln!(writer, "canary-access-0002").unwrap();
        assert_eq!(sink.text(), "[redacted]\n");
    }
}
