//! `purview export read <items.zip>...` (`docs/SPEC.md` sections 3.5 and
//! 4.11), in its smallest form: local, no sign-in, one record per `.msg`
//! in each items zip, read in memory in central-directory order and never
//! extracted. Records are JSON Lines on stdout, or one JSON document with
//! `--json`; a terminal stdout is refused, because bodies are colleagues'
//! and outside senders' mail.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::commands::Produced;
use crate::env::Env;
use crate::error::{PurviewError, Result};
use crate::msg::{parse_msg, Mailbox, MsgItem};
use crate::output::OutputOptions;
use crate::redact::Redactor;
use crate::zipread::{read_error, ZipLimits, ZipReader, EXPORT_ZIP_ENTRIES, MAX_RATIO};

/// `--max-entry-bytes` by default: 64 MiB per `.msg`.
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 64 << 20;
/// `--max-body-chars` by default.
pub const DEFAULT_MAX_BODY_CHARS: usize = 200_000;
/// `--json` buffers every record; above this many it is refused.
pub const JSON_MAX_ITEMS: usize = 10_000;

/// The checked arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    pub zips: Vec<PathBuf>,
    pub max_entry_bytes: u64,
    pub max_body_chars: usize,
    pub json: bool,
}

/// What the run counted, for the stderr summary.
#[derive(Debug, Default)]
struct Tally {
    read: usize,
    failed: usize,
    by_class: BTreeMap<&'static str, (usize, usize)>,
    skipped: usize,
}

pub fn run(env: &mut Env, output: &OutputOptions, request: &ReadRequest) -> Result<Produced> {
    if env.stdout_is_terminal {
        return Err(PurviewError::message(
            "export read writes message bodies, which are colleagues' and outside senders' \
             mail, so it does not write them to a terminal; redirect standard output to a file \
             in the data directory",
        ));
    }
    let limits = ZipLimits {
        entries: EXPORT_ZIP_ENTRIES as usize,
        entry_bytes: request.max_entry_bytes,
        total_bytes: u64::MAX,
        ratio: MAX_RATIO,
    };
    // One marker id for a JSON Lines run, with its notice on stderr once;
    // a `--json` document carries its own marker and notice.
    let marker = if output.wrap_untrusted && !request.json {
        let id = crate::output::untrusted_id()?;
        let _ = writeln!(env.stderr, "{}", crate::output::untrusted_notice(&id));
        Some(id)
    } else {
        None
    };
    let mut tally = Tally::default();
    let mut buffered: Vec<Value> = Vec::new();
    for path in &request.zips {
        let part = part_name(path);
        // The path is the user's own argument and is not repeated.
        let mut zip = ZipReader::open(path, limits).map_err(|error| match error {
            PurviewError::Io(io) => {
                PurviewError::message(format!("an items zip given cannot be read: {}", io.kind()))
            }
            other => other,
        })?;
        let names: Vec<String> = zip.names().to_vec();
        for (index, name) in names.iter().enumerate() {
            if !name.to_ascii_lowercase().ends_with(".msg") {
                tally.skipped += 1;
                continue;
            }
            let record = read_item(&mut zip, index, name, &part, request, &env.redactor);
            let class = class_label(record["class"].as_str());
            let mut failed = !record["error"].is_null();
            if request.json {
                if buffered.len() == JSON_MAX_ITEMS {
                    return Err(PurviewError::message(format!(
                        "--json holds every record in memory and stops at {JSON_MAX_ITEMS}; \
                         use JSON Lines (the default) for larger exports"
                    )));
                }
                buffered.push(record);
            } else if !write_line(env, marker.as_deref(), record)? {
                failed = true;
            }
            let counts = tally.by_class.entry(class).or_default();
            counts.0 += 1;
            tally.read += 1;
            if failed {
                counts.1 += 1;
                tally.failed += 1;
            }
        }
    }
    summary(&mut env.stderr, &tally);
    let exit_code = if tally.failed > 0 { 4 } else { 0 };
    if request.json {
        let count = buffered.len();
        let document = output.untrusted_json_value(Value::Array(buffered), count, &env.redactor)?;
        return Ok(Produced {
            exit_code,
            document: Some(document),
        });
    }
    Ok(Produced {
        exit_code,
        document: None,
    })
}

/// The summary's label for an item class: one of the classes seen in
/// exports, or `other`, so that no text from an item reaches stderr and the
/// tally stays small.
fn class_label(class: Option<&str>) -> &'static str {
    const KNOWN: &[&str] = &[
        "IPM.Note",
        "IPM.Note.SMIME",
        "IPM.Note.SMIME.MultipartSigned",
        "IPM.Schedule.Meeting.Request",
        "IPM.Schedule.Meeting.Resp.Pos",
        "IPM.Schedule.Meeting.Resp.Neg",
        "IPM.Schedule.Meeting.Resp.Tent",
        "IPM.Schedule.Meeting.Canceled",
        "IPM.Appointment",
        "IPM.SkypeTeams.Message",
        "IPM.SkypeTeams.SystemMessage",
    ];
    match class {
        None => "(none)",
        Some(class) => KNOWN
            .iter()
            .find(|known| known.eq_ignore_ascii_case(class))
            .copied()
            .unwrap_or("other"),
    }
}

/// The zip's own file name, as `export index` matches parts by it.
fn part_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// One record: the item's fields, or its error.
fn read_item(
    zip: &mut ZipReader,
    index: usize,
    name: &str,
    part: &str,
    request: &ReadRequest,
    redactor: &Redactor,
) -> Value {
    let mut record = Map::new();
    record.insert("entry".into(), Value::String(name.to_owned()));
    record.insert("part".into(), Value::String(part.to_owned()));
    // An entry whose zip declares it larger than the limit is not read.
    if zip
        .declared_size(index)
        .is_some_and(|size| size > request.max_entry_bytes)
    {
        let detail = format!(
            "the zip declares the entry larger than {} bytes",
            request.max_entry_bytes
        );
        return failed(record, "entryTooLarge", &detail);
    }
    let bytes = zip.read_entry(index, |reader| {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).map_err(read_error)?;
        Ok(bytes)
    });
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(error) => {
            // Stopped by the per-entry limit (the zip understated the
            // size); a compression ratio refused, or anything else, is
            // unreadable.
            let limit = format!("more than {} bytes", request.max_entry_bytes);
            let too_large =
                matches!(&error, PurviewError::HostileZip(detail) if detail.ends_with(&limit));
            let code = if too_large {
                "entryTooLarge"
            } else {
                "entryUnreadable"
            };
            let detail = match error {
                PurviewError::HostileZip(detail) => detail,
                other => other.metadata().0.to_owned(),
            };
            return failed(record, code, &detail);
        }
    };
    let item = match parse_msg(&bytes) {
        Ok(item) => item,
        Err(error) => return failed(record, error.code(), error.detail()),
    };
    fill(&mut record, &item, request.max_body_chars, redactor);
    Value::Object(record)
}

fn failed(mut record: Map<String, Value>, code: &str, detail: &str) -> Value {
    record.insert("error".into(), Value::String(code.to_owned()));
    record.insert("errorDetail".into(), Value::String(detail.to_owned()));
    Value::Object(record)
}

fn mailbox(mailbox: &Mailbox) -> Value {
    json!({"name": mailbox.name, "address": mailbox.address})
}

fn fill(
    record: &mut Map<String, Value>,
    item: &MsgItem,
    max_body_chars: usize,
    redactor: &Redactor,
) {
    let time = |time: &Option<chrono::DateTime<chrono::Utc>>| {
        time.map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    };
    // Every URL in the body loses its query here, before the body is cut,
    // so that a query neither survives as an OData option of a body that
    // is one URL alone nor takes the place of text under the cap.
    let text = item
        .body
        .text()
        .map(|text| crate::redact::urls_in_free_text(text, redactor));
    let (body, truncated) = match text.as_deref() {
        Some(text) if text.chars().count() > max_body_chars => (
            Some(text.chars().take(max_body_chars).collect::<String>()),
            true,
        ),
        Some(text) => (Some(text.to_owned()), false),
        None => (None, false),
    };
    let (error, detail) = match item.body.error() {
        Some((code, detail)) => (Some(code), Some(detail)),
        None => (None, None),
    };
    for (key, value) in [
        ("class", json!(item.class)),
        ("subject", json!(item.subject)),
        ("conversationTopic", json!(item.conversation_topic)),
        ("internetMessageId", json!(item.internet_message_id)),
        ("from", item.from.as_ref().map_or(Value::Null, mailbox)),
        ("to", Value::Array(item.to.iter().map(mailbox).collect())),
        ("cc", Value::Array(item.cc.iter().map(mailbox).collect())),
        ("bcc", Value::Array(item.bcc.iter().map(mailbox).collect())),
        ("sent", json!(time(&item.sent))),
        ("received", json!(time(&item.received))),
        (
            "attachments",
            Value::Array(
                item.attachments
                    .iter()
                    .map(|attachment| json!({"name": attachment.name, "size": attachment.size}))
                    .collect(),
            ),
        ),
        ("body", json!(body)),
        ("bodySource", json!(item.body.source())),
        ("bodyTruncated", json!(truncated)),
        ("error", json!(error)),
        ("errorDetail", json!(detail)),
    ] {
        record.insert(key.into(), value);
    }
}

/// One JSON Lines record, prepared as every JSON document is: URLs
/// redacted, `--wrap-untrusted` applied, secrets redacted as values. A
/// record whose bytes still match a secret is replaced by its prepared
/// entry and part names and an error, so the line count still matches the
/// items. `false` when that happened.
fn write_line(env: &mut Env, marker: Option<&str>, record: Value) -> Result<bool> {
    let mut value = crate::trace::redact_urls(&record, &env.redactor);
    if let Some(id) = marker {
        crate::output::wrap_untrusted(&mut value, id);
    }
    let safe = env.redactor.redact_value(&value);
    let mut bytes = serde_json::to_vec(&safe)?;
    let mut written = true;
    if env.redactor.recognises_bytes(&bytes) {
        written = false;
        bytes = serde_json::to_vec(&json!({
            "entry": safe["entry"],
            "part": safe["part"],
            "error": "redactionFailed",
            "errorDetail": "the record held a secret that could not be removed, so it is not printed",
        }))?;
        if env.redactor.recognises_bytes(&bytes) {
            bytes = serde_json::to_vec(&json!({"error": "redactionFailed"}))?;
        }
    }
    bytes.push(b'\n');
    // `cli` reports a failed stdout itself, with its own prefix.
    env.stdout.write_all(&bytes)?;
    Ok(written)
}

fn summary(log: &mut dyn Write, tally: &Tally) {
    let _ = writeln!(
        log,
        "export read: {} item{} read, {} with an error{}",
        tally.read,
        if tally.read == 1 { "" } else { "s" },
        tally.failed,
        if tally.skipped > 0 {
            format!("; {} entries that are not .msg skipped", tally.skipped)
        } else {
            String::new()
        }
    );
    for (class, (read, failed)) in &tally.by_class {
        let _ = writeln!(log, "  {}: {read} read, {failed} with an error", class);
    }
}
