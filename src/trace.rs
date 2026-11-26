//! `--trace DIR`: one JSON file per Graph exchange (`docs/SPEC.md` section
//! 4.9), for learning response shapes. Traces never become fixtures.
//!
//! - Request headers are never written, so no token reaches a trace.
//! - Of the response headers, only `KEPT_HEADERS` are written.
//! - Every URL, in the request, in a `location` header and in any string of
//!   a body, passes through `redact::url`.
//! - The whole record is redacted as a value, then checked again as bytes.
//! - Token endpoint exchanges are never traced: only `GraphClient` (and,
//!   later, the download client) records.
//! - New directories are created 0700 and files 0600 on Unix.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::SecondsFormat;
use serde_json::{json, Map, Value};
use url::Url;

use crate::env::Clock;
use crate::error::{PurviewError, Result};
use crate::output::sanitize;
use crate::redact::{self, Redactor};

/// The response headers a trace keeps.
pub const KEPT_HEADERS: &[&str] = &[
    "content-type",
    "content-length",
    "location",
    "retry-after",
    "request-id",
    "client-request-id",
    "date",
    "x-ms-ags-diagnostic",
];

/// The longest part of a trace file name taken from the URL's last path
/// segment.
const NAME_SEGMENT_CHARS: usize = 40;

/// A response, as a trace records it.
#[derive(Debug, Clone, Copy)]
pub struct TracedResponse<'a> {
    pub status: u16,
    pub headers: &'a reqwest::header::HeaderMap,
    pub body: &'a [u8],
}

/// One request and what came back: a response, or the error that took its
/// place.
#[derive(Debug, Clone, Copy)]
pub struct Exchange<'a> {
    pub method: &'a str,
    pub url: &'a Url,
    pub request_body: Option<&'a Value>,
    pub response: Option<TracedResponse<'a>>,
    pub error: Option<&'a str>,
}

/// Writes trace files into one directory.
pub struct TraceSink {
    dir: PathBuf,
    redactor: Arc<Redactor>,
    clock: Arc<dyn Clock>,
    /// The time stamp of the last file name, so names stay unique and in
    /// order when the clock does not move between two exchanges.
    last_nanos: Mutex<i64>,
}

impl std::fmt::Debug for TraceSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TraceSink")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

impl TraceSink {
    /// Opens `dir`, creating it and any missing parents with mode 0700 on
    /// Unix; an existing directory keeps its mode. A link or a
    /// non-directory at `dir` is refused. Warns on `warnings` that traces
    /// hold tenant data, and again when `dir` is inside a git work tree.
    pub fn open(
        dir: &Path,
        redactor: Arc<Redactor>,
        clock: Arc<dyn Clock>,
        warnings: &mut dyn Write,
    ) -> Result<Self> {
        let context = |error: PurviewError| {
            error.context(format!(
                "opening the trace directory {}",
                sanitize(&dir.display().to_string())
            ))
        };
        match std::fs::symlink_metadata(dir) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(context(PurviewError::message("it is a link")));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(context(PurviewError::message("it is not a directory")));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::config::ensure_private_dir(dir).map_err(context)?;
            }
            Err(error) => return Err(context(error.into())),
        }
        let shown = sanitize(&dir.display().to_string());
        writeln!(
            warnings,
            "warning: trace files hold tenant data (names, addresses, queries, case names); keep \
             {shown} out of version control"
        )?;
        if inside_git_work_tree(dir) {
            writeln!(
                warnings,
                "warning: the trace directory {shown} is inside a git work tree; add it to \
                 .gitignore or choose a directory outside the repository"
            )?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            redactor,
            clock,
            last_nanos: Mutex::new(i64::MIN),
        })
    }

    /// Writes one exchange to a new file and returns its path.
    pub fn record(&self, exchange: &Exchange<'_>) -> Result<PathBuf> {
        let now = self.clock.now();
        let nanos = {
            let mut last = self
                .last_nanos
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let nanos = now
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .max(last.saturating_add(1));
            *last = nanos;
            nanos
        };
        let mut record = Map::new();
        record.insert(
            "time".into(),
            Value::from(now.to_rfc3339_opts(SecondsFormat::Millis, true)),
        );
        record.insert(
            "request".into(),
            json!({
                "method": exchange.method,
                "url": redact::url(exchange.url),
                "body": exchange.request_body.map(redact_urls).unwrap_or(Value::Null),
            }),
        );
        record.insert(
            "response".into(),
            exchange.response.map_or(Value::Null, response_value),
        );
        if let Some(error) = exchange.error {
            record.insert("error".into(), Value::from(error));
        }
        let safe = self.redactor.redact_value(&Value::Object(record));
        let mut bytes = serde_json::to_vec_pretty(&safe)?;
        bytes.push(b'\n');
        // A match left outside a string (a number, say) cannot be removed
        // without breaking the JSON; a trace is for reading, so it is
        // removed anyway.
        if self.redactor.recognises_bytes(&bytes) {
            bytes = self.redactor.redact_bytes(&bytes);
        }
        let path = self
            .dir
            .join(file_name(nanos, exchange.method, exchange.url));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(path)
    }
}

/// `<unix-nanos>-<METHOD>-<last path segment, 40 chars>.json`, with every
/// character outside `[A-Za-z0-9._-]` replaced by `_`.
fn file_name(nanos: i64, method: &str, url: &Url) -> String {
    let segment = url
        .path_segments()
        .and_then(|mut segments| segments.rfind(|segment| !segment.is_empty()))
        .unwrap_or("root");
    let segment: String = segment.chars().take(NAME_SEGMENT_CHARS).collect();
    let clean = |text: &str| -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    format!("{nanos}-{}-{}.json", clean(method), clean(&segment))
}

fn response_value(response: TracedResponse<'_>) -> Value {
    let mut headers = Map::new();
    for name in KEPT_HEADERS {
        let values: Vec<String> = response
            .headers
            .get_all(*name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .map(|value| {
                if *name == "location" {
                    redact_url_text(value)
                } else {
                    value.to_owned()
                }
            })
            .collect();
        match values.as_slice() {
            [] => {}
            [one] => {
                headers.insert((*name).to_owned(), Value::from(one.clone()));
            }
            _ => {
                headers.insert((*name).to_owned(), Value::from(values));
            }
        }
    }
    let body = serde_json::from_slice::<Value>(response.body)
        .map(|value| redact_urls(&value))
        .unwrap_or(Value::Null);
    json!({
        "status": response.status,
        "headers": headers,
        "body": body,
        "bytes": response.body.len(),
    })
}

/// A copy of `value` with every string that is an absolute `http` or
/// `https` URL passed through `redact::url`, such as `downloadUrl` and
/// `@odata.nextLink`.
pub fn redact_urls(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_url_text(text)),
        Value::Array(items) => Value::Array(items.iter().map(redact_urls).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), redact_urls(item)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `text` through `redact::url` when it is an absolute `http` or `https`
/// URL; any other text unchanged.
fn redact_url_text(text: &str) -> String {
    let lower = text.get(..8).unwrap_or(text).to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return text.to_owned();
    }
    match Url::parse(text) {
        Ok(url) => redact::url(&url),
        // Not a URL the parser accepts, but it looked like one: keep none
        // of its query.
        Err(_) => text.split(['?', '#']).next().unwrap_or_default().to_owned(),
    }
}

/// Whether `dir`, or any directory above it, holds a `.git` entry.
fn inside_git_work_tree(dir: &Path) -> bool {
    let resolved = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    resolved
        .ancestors()
        .any(|ancestor| std::fs::symlink_metadata(ancestor.join(".git")).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::{test_epoch, ManualClock};
    use reqwest::header::{HeaderMap, HeaderValue};

    fn sink(dir: &Path) -> (TraceSink, Arc<Redactor>, Vec<u8>) {
        let redactor = Arc::new(Redactor::new());
        let mut warnings = Vec::new();
        let sink = TraceSink::open(
            dir,
            redactor.clone(),
            Arc::new(ManualClock::new(test_epoch())),
            &mut warnings,
        )
        .unwrap();
        (sink, redactor, warnings)
    }

    fn read(path: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn a_record_keeps_only_the_allowed_headers_and_redacts_urls_and_secrets() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("trace");
        let (sink, redactor, warnings) = sink(&dir);
        redactor.register("canary-graph-access-0001");
        let warnings = String::from_utf8(warnings).unwrap();
        assert!(
            warnings.starts_with("warning: trace files hold tenant data"),
            "{warnings}"
        );
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("content-type", "application/json"),
            ("request-id", "request-0001"),
            ("set-cookie", "canary-cookie-0001"),
            ("www-authenticate", "Bearer canary-graph-access-0001"),
            (
                "location",
                "https://graph.microsoft.com/v1.0/x?$top=1&sig=canary-sig-0001",
            ),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        let body = serde_json::to_vec(&json!({
            "value": [{
                "description": "canary-graph-access-0001",
                "downloadUrl": concat!(
                    "https://alpha.proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/x",
                    "?downloadType=Report&sig=canary-sig-0002",
                ),
            }],
        }))
        .unwrap();
        let url = Url::parse(
            "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases?$top=1&code=canary-code-0001",
        )
        .unwrap();
        let path = sink
            .record(&Exchange {
                method: "GET",
                url: &url,
                request_body: None,
                response: Some(TracedResponse {
                    status: 200,
                    headers: &headers,
                    body: &body,
                }),
                error: None,
            })
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("canary"), "{text}");
        let record = read(&path);
        assert_eq!(
            record["request"]["url"],
            "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases?%24top=1&code=REDACTED"
        );
        assert_eq!(record["request"]["body"], Value::Null);
        let kept: Vec<&String> = record["response"]["headers"]
            .as_object()
            .unwrap()
            .keys()
            .collect();
        assert_eq!(kept, ["content-type", "location", "request-id"]);
        assert_eq!(
            record["response"]["headers"]["location"],
            "https://graph.microsoft.com/v1.0/x?%24top=1&sig=REDACTED"
        );
        assert_eq!(
            record["response"]["body"]["value"][0]["description"],
            "[redacted]"
        );
        assert!(record["response"]["body"]["value"][0]["downloadUrl"]
            .as_str()
            .unwrap()
            .ends_with("?downloadType=Report&sig=REDACTED"));
        assert_eq!(record["response"]["bytes"], body.len());
        assert_eq!(record["time"], "2026-01-05T09:00:00.000Z");
    }

    #[test]
    fn file_names_are_unique_ordered_and_sanitised() {
        let root = tempfile::tempdir().unwrap();
        let (sink, _, _) = sink(root.path());
        let url = Url::parse(
            "https://graph.microsoft.com/v1.0/security/cases/ediscoveryCases/a%20b%3Fc%2F..d/",
        )
        .unwrap();
        let exchange = Exchange {
            method: "GET",
            url: &url,
            request_body: None,
            response: None,
            error: Some("the request timed out"),
        };
        let first = sink.record(&exchange).unwrap();
        let second = sink.record(&exchange).unwrap();
        let names: Vec<String> = [&first, &second]
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        let epoch = test_epoch().timestamp_nanos_opt().unwrap();
        assert_eq!(
            names,
            [
                format!("{epoch}-GET-a_20b_3Fc_2F..d.json"),
                format!("{}-GET-a_20b_3Fc_2F..d.json", epoch + 1),
            ]
        );
        assert_eq!(read(&first)["error"], "the request timed out");
        assert_eq!(read(&first)["response"], Value::Null);
        let long = Url::parse(&format!(
            "https://graph.microsoft.com/v1.0/{}",
            "x".repeat(60)
        ))
        .unwrap();
        assert_eq!(
            file_name(1, "GET", &long),
            format!("1-GET-{}.json", "x".repeat(40))
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_new_directory_is_0700_files_are_0600_and_a_link_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("a/trace");
        let (sink, _, _) = sink(&dir);
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        let url = Url::parse("https://graph.microsoft.com/v1.0/x").unwrap();
        let path = sink
            .record(&Exchange {
                method: "GET",
                url: &url,
                request_body: None,
                response: None,
                error: None,
            })
            .unwrap();
        assert_eq!(mode(&path), 0o600);
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&dir, &link).unwrap();
        let error = TraceSink::open(
            &link,
            Arc::new(Redactor::new()),
            Arc::new(ManualClock::new(test_epoch())),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("it is a link"), "{error}");
    }

    #[test]
    fn a_directory_inside_a_git_work_tree_gets_a_second_warning() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        let (_, _, warnings) = sink(&root.path().join("traces"));
        let warnings = String::from_utf8(warnings).unwrap();
        assert_eq!(warnings.lines().count(), 2, "{warnings}");
        assert!(warnings.contains("inside a git work tree"), "{warnings}");
    }
}
