//! `purview parse items` in-process on item report zips written here from
//! synthetic rows. The command is local, so every `Env` keeps the
//! unreachable hosts of `Env::in_memory()`: a network call would fail it.

use std::io::Write;
use std::path::{Path, PathBuf};

use ms_purview_cli::cli::execute_with;
use ms_purview_cli::env::Env;
use serde_json::Value;

const HEADER: &str = "File ID,Status,Internet message ID,Immutable ID,Item class,Date,Sender,\
                      Subject/Title,Conversation name,Conversation type,Recipient count,\
                      Workload,Has attachment,Location ID,Location sub type";

const LOCATIONS: &str = "DataSourceName,DataSourceType,Location,LocationId,LocationType,\
                         LocationSubType,Count,Size,Status,ErrorWarning,Query\n";

/// A location id of the synthetic form.
fn location(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}

/// One CSV row: the columns a test varies, in header order.
#[allow(clippy::too_many_arguments)]
fn row(
    imid: &str,
    imm: &str,
    class: &str,
    date: &str,
    sender: &str,
    subject: &str,
    conversation: &str,
    loc: u32,
) -> String {
    format!(
        "1,Succeeded,{imid},{imm},{class},{date},\"{sender}\",\"{subject}\",\"{conversation}\",,1,Exchange,True,{},PrimaryMailBox\n",
        location(loc)
    )
}

/// Writes a zip with the given entries.
fn zip_of(dir: &Path, entries: &[(&str, String)]) -> PathBuf {
    let path = dir.join("report.zip");
    let mut writer = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(body.as_bytes()).unwrap();
    }
    writer.finish().unwrap();
    path
}

/// A report in two Items files, numbered so that a text sort would read
/// them the wrong way round: item m1 in three rows over two mailboxes, m2
/// once, a Teams message by Immutable ID twice, and one row with no id.
fn report(dir: &Path) -> PathBuf {
    let first = format!(
        "\u{feff}{HEADER}\n{}{}{}",
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-02 08:00:00Z",
            "Alex <alex@contoso.example>",
            "Orders",
            "",
            1
        ),
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-02 08:00:00Z",
            "Alex <alex@contoso.example>",
            "Orders",
            "",
            2
        ),
        row(
            "",
            "IMM3",
            "IPM.SkypeTeams.Message",
            "2026-07-03 12:00:00Z",
            "19:x@thread.v2",
            "",
            "Orders chat",
            1
        ),
    );
    let second = format!(
        "\u{feff}{HEADER}\n{}{}{}{}",
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-02 08:00:00Z",
            "Alex <alex@contoso.example>",
            "Orders",
            "",
            1
        ),
        row(
            "<m2@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-01 09:30:00Z",
            "bea@fabrikam.example",
            "Invoices",
            "",
            3
        ),
        row(
            "",
            "IMM3",
            "IPM.SkypeTeams.Message",
            "2026-07-03 12:00:00Z",
            "19:x@thread.v2",
            "",
            "Orders chat",
            2
        ),
        row(
            "",
            "",
            "IPM.Note",
            "2026-06-30 10:00:00Z",
            "carol@contoso.example",
            "No id",
            "",
            4
        ),
    );
    zip_of(
        dir,
        &[
            ("Items_10_2026-07-04.csv", second),
            ("Items_2_2026-07-04.csv", first),
            ("Locations-2026.csv", LOCATIONS.to_owned()),
        ],
    )
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    document: Option<Value>,
}

impl Run {
    fn lines(&self) -> Vec<Value> {
        self.stdout
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

async fn run(dir: &Path, args: &[&str]) -> Run {
    let (mut env, captured) = Env::in_memory();
    // No config.json: the default limits.
    env.config_dir = Some(dir.join("config"));
    let mut argv = vec!["purview"];
    argv.extend_from_slice(args);
    let outcome = execute_with(env, argv).await;
    Run {
        code: outcome.exit_code,
        stdout: captured.stdout.text(),
        stderr: captured.stderr.text(),
        document: outcome.stdout_value,
    }
}

#[tokio::test]
async fn unique_items_are_written_after_the_pass_by_date_with_copies_and_locations() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let run = run(dir.path(), &["parse", "items", zip.to_str().unwrap()]).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let lines = run.lines();
    let keys: Vec<&str> = lines.iter().map(|l| l["key"].as_str().unwrap()).collect();
    assert_eq!(keys.len(), 4, "{keys:?}");
    // By date: the hash-keyed row of 30 June, m2, m1, then the Teams item.
    assert_eq!(lines[0]["keyKind"], "hash");
    assert_eq!(
        &keys[1..],
        ["<m2@contoso.example>", "<m1@contoso.example>", "IMM3"]
    );
    let m1 = &lines[2];
    assert_eq!(m1["copies"], 3);
    assert_eq!(m1["locations"], 2);
    assert_eq!(m1["keyKind"], "internetMessageId");
    assert_eq!(m1["sender"], "Alex <alex@contoso.example>");
    assert_eq!(m1["senderDomain"], "contoso.example");
    assert_eq!(m1["date"], "2026-07-02T08:00:00Z");
    assert_eq!(m1["title"], "Orders");
    assert_eq!(m1["hasAttachment"], true);
    assert_eq!(m1["recipientCount"], 1);
    let teams = &lines[3];
    assert_eq!(teams["keyKind"], "immutableId");
    assert_eq!(teams["title"], "Orders chat");
    assert_eq!(teams["senderDomain"], Value::Null);
    assert_eq!(teams["copies"], 2);
    for key in [
        "key",
        "keyKind",
        "class",
        "date",
        "sender",
        "senderDomain",
        "recipientCount",
        "title",
        "conversationType",
        "workload",
        "copies",
        "locations",
        "hasAttachment",
        "immutableId",
        "internetMessageId",
    ] {
        assert!(m1.get(key).is_some(), "{key}");
    }
    assert!(run.stderr.contains("7 rows read from 2 Items files, 7 matched the filters; 4 unique items (1 keyed by a hash"), "{}", run.stderr);
    assert!(
        run.stderr.contains("warning: 1 matched row had neither"),
        "{}",
        run.stderr
    );
    assert!(run.document.is_none());
}

#[tokio::test]
async fn all_rows_writes_every_row_in_file_order() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let run = run(
        dir.path(),
        &["parse", "items", zip.to_str().unwrap(), "--all-rows"],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let lines = run.lines();
    assert_eq!(lines.len(), 7);
    // Items_2 before Items_10.
    assert_eq!(lines[2]["key"], "IMM3");
    assert_eq!(lines[4]["key"], "<m2@contoso.example>");
    assert_eq!(lines[0]["locationId"], location(1));
    assert!(lines[0].get("copies").is_none());
    assert!(run.stderr.contains("7 rows written"), "{}", run.stderr);
}

#[tokio::test]
async fn filters_apply_to_rows_before_they_are_counted() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let zip = zip.to_str().unwrap();
    let keys = |run: &Run| -> Vec<String> {
        run.lines()
            .iter()
            .map(|l| l["key"].as_str().unwrap().to_owned())
            .collect()
    };
    let run1 = run(
        dir.path(),
        &[
            "parse",
            "items",
            zip,
            "--since",
            "2026-07-02",
            "--until",
            "2026-07-02",
        ],
    )
    .await;
    assert_eq!(keys(&run1), ["<m1@contoso.example>"]);
    assert!(
        run1.stderr.contains("3 matched the filters"),
        "{}",
        run1.stderr
    );
    let run2 = run(
        dir.path(),
        &["parse", "items", zip, "--class", "ipm.skypeteams"],
    )
    .await;
    assert_eq!(keys(&run2), ["IMM3"]);
    let run3 = run(
        dir.path(),
        &[
            "parse",
            "items",
            zip,
            "--sender",
            "ALEX@contoso.example",
            "--sender",
            "bea@fabrikam.example",
        ],
    )
    .await;
    assert_eq!(
        keys(&run3),
        ["<m2@contoso.example>", "<m1@contoso.example>"]
    );
    let run4 = run(
        dir.path(),
        &[
            "parse",
            "items",
            zip,
            "--exclude-sender",
            "alex@contoso.example",
            "--subject-regex",
            "^Orders|Invoices",
        ],
    )
    .await;
    assert_eq!(keys(&run4), ["<m2@contoso.example>", "IMM3"]);
    let run5 = run(
        dir.path(),
        &["parse", "items", zip, "--workload", "sharepoint"],
    )
    .await;
    assert_eq!(run5.code, 0);
    assert!(run5.stdout.is_empty());
}

#[tokio::test]
async fn bad_flags_are_refused_before_the_zip_is_read_and_never_repeated() {
    let dir = tempfile::tempdir().unwrap();
    // No zip exists: each refusal must come before it is opened.
    let zip = dir.path().join("missing.zip");
    let zip = zip.to_str().unwrap();
    for (args, needle) in [
        (vec!["--sender", " "], "--sender"),
        (vec!["--class", ""], "--class"),
        (
            vec!["--subject-regex", "(secret-pattern"],
            "--subject-regex",
        ),
        (
            vec!["--since", "2026-07-03", "--until", "2026-07-02"],
            "--since is after --until",
        ),
        (vec!["--max-unique", "0"], "--max-unique"),
        (vec!["--jsonl"], "--jsonl and --json"),
    ] {
        let mut argv = vec!["--json", "parse", "items", zip];
        argv.extend(args.iter());
        let run = run(dir.path(), &argv).await;
        assert_eq!(run.code, 1, "{args:?}");
        let message = run.document.as_ref().unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(message.contains(needle), "{args:?}: {message}");
        assert!(!message.contains("secret-pattern"), "{message}");
        assert!(!message.contains("cannot be read"), "{args:?}: {message}");
    }
    // In JSON Lines mode the refusal goes to stderr, with stdout empty.
    let run = run(dir.path(), &["parse", "items", zip, "--force-buffer"]).await;
    assert_eq!(run.code, 1);
    assert!(run.stdout.is_empty());
    assert!(
        run.stderr.contains("--force-buffer goes with --json"),
        "{}",
        run.stderr
    );
}

#[tokio::test]
async fn the_subject_pattern_is_used_as_given_with_its_spaces() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let run = run(
        dir.path(),
        &[
            "parse",
            "items",
            zip.to_str().unwrap(),
            "--subject-regex",
            "^Orders ",
        ],
    )
    .await;
    let keys: Vec<Value> = run.lines().iter().map(|l| l["key"].clone()).collect();
    assert_eq!(keys, ["IMM3"]);
}

#[tokio::test]
async fn only_the_copies_that_pass_the_filters_are_counted() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!(
        "{HEADER}\n{}{}{}",
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-02 08:00:00Z",
            "a@contoso.example",
            "S",
            "",
            1
        ),
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-05 08:00:00Z",
            "a@contoso.example",
            "S",
            "",
            2
        ),
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-05 08:00:00Z",
            "b@contoso.example",
            "S",
            "",
            3
        ),
    );
    let zip = zip_of(dir.path(), &[("Items_0_2026.csv", body)]);
    let run = run(
        dir.path(),
        &[
            "parse",
            "items",
            zip.to_str().unwrap(),
            "--since",
            "2026-07-05",
            "--exclude-sender",
            "b@contoso.example",
        ],
    )
    .await;
    let lines = run.lines();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["copies"], 1);
    assert_eq!(lines[0]["locations"], 1);
    assert_eq!(lines[0]["date"], "2026-07-05T08:00:00Z");
}

/// A configuration directory holding `config`, private as the tool keeps
/// it.
fn with_config(dir: &Path, config: &str) {
    let dir = dir.join("config");
    std::fs::create_dir(&dir).unwrap();
    std::fs::write(dir.join("config.json"), config).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            dir.join("config.json"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
}

#[tokio::test]
async fn a_failure_while_rows_stream_leaves_only_records_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    with_config(
        dir.path(),
        r#"{"limits": {"csv_max_record_bytes": "1KiB"}}"#,
    );
    let big = "x".repeat(4096);
    let body = format!(
        "{HEADER}\n{}{}",
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-02 08:00:00Z",
            "a@contoso.example",
            "S",
            "",
            1
        ),
        row(
            "<m2@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-02 08:00:00Z",
            "a@contoso.example",
            &big,
            "",
            1
        ),
    );
    let zip = zip_of(dir.path(), &[("Items_0_2026.csv", body)]);
    let run = run(
        dir.path(),
        &["parse", "items", zip.to_str().unwrap(), "--all-rows"],
    )
    .await;
    assert_eq!(run.code, 1);
    assert_eq!(run.lines().len(), 1);
    assert!(run.document.is_none());
    assert!(run.stderr.contains("Error: "), "{}", run.stderr);
    assert!(!run.stderr.contains("xxxx"), "{}", run.stderr);
}

#[tokio::test]
async fn json_is_one_document() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let zip = zip.to_str().unwrap();
    let run1 = run(dir.path(), &["--json", "parse", "items", zip]).await;
    assert_eq!(run1.code, 0, "{}", run1.stderr);
    let document = run1.document.unwrap();
    assert_eq!(document["count"], 4);
    assert_eq!(document["results"][2]["copies"], 3);
    let run2 = run(dir.path(), &["parse", "items", zip, "--jsonl"]).await;
    assert!(run2.document.is_none());
    assert_eq!(run2.lines().len(), 4);
}

/// A report with `n` rows of distinct items, in one file.
fn wide(dir: &Path, n: usize) -> PathBuf {
    let mut body = format!("{HEADER}\n");
    for i in 0..n {
        body.push_str(&row(
            &format!("<m{i}@contoso.example>"),
            "",
            "IPM.Note",
            "2026-07-01 08:00:00Z",
            "alex@contoso.example",
            "S",
            "",
            (i % 50) as u32,
        ));
    }
    zip_of(dir, &[("Items_0_2026.csv", body)])
}

#[tokio::test]
async fn json_above_ten_thousand_records_needs_force_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let zip = wide(dir.path(), 10_001);
    let zip = zip.to_str().unwrap();
    for extra in [&[][..], &["--all-rows"][..]] {
        let mut argv = vec!["--json", "parse", "items", zip];
        argv.extend_from_slice(extra);
        let refused = run(dir.path(), &argv).await;
        assert_eq!(refused.code, 1, "{extra:?}");
        assert!(refused.document.unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--force-buffer"));
        argv.push("--force-buffer");
        let forced = run(dir.path(), &argv).await;
        assert_eq!(forced.code, 0, "{extra:?}: {}", forced.stderr);
        assert_eq!(forced.document.unwrap()["count"], 10_001);
    }
    // Past the limit the pass stops with the --json refusal, before
    // --max-unique is reached.
    let dir = tempfile::tempdir().unwrap();
    let zip = wide(dir.path(), 10_010);
    let early = run(
        dir.path(),
        &[
            "--json",
            "parse",
            "items",
            zip.to_str().unwrap(),
            "--max-unique",
            "10005",
        ],
    )
    .await;
    let message = early.document.unwrap()["error"].clone();
    assert_eq!(message["code"], "CommandFailed", "{message}");
    assert!(
        message["message"]
            .as_str()
            .unwrap()
            .contains("--force-buffer"),
        "{message}"
    );
    // Exactly at the limit is accepted.
    let dir = tempfile::tempdir().unwrap();
    let zip = wide(dir.path(), 10_000);
    let at = run(
        dir.path(),
        &["--json", "parse", "items", zip.to_str().unwrap()],
    )
    .await;
    assert_eq!(at.code, 0);
}

#[tokio::test]
async fn max_unique_stops_the_pass_with_nothing_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let zip = zip.to_str().unwrap();
    let run1 = run(dir.path(), &["parse", "items", zip, "--max-unique", "3"]).await;
    assert_eq!(run1.code, 1);
    assert!(run1.stdout.is_empty());
    assert!(run1.stderr.contains("--max-unique"), "{}", run1.stderr);
    let run2 = run(
        dir.path(),
        &["--json", "parse", "items", zip, "--max-unique", "3"],
    )
    .await;
    assert_eq!(run2.document.unwrap()["error"]["code"], "TooManyUnique");
    // Exactly the number of unique items is allowed.
    let run3 = run(dir.path(), &["parse", "items", zip, "--max-unique", "4"]).await;
    assert_eq!(run3.code, 0, "{}", run3.stderr);
    // --all-rows keeps no map, so the limit does not apply.
    let run4 = run(
        dir.path(),
        &["parse", "items", zip, "--max-unique", "1", "--all-rows"],
    )
    .await;
    assert_eq!(run4.code, 0, "{}", run4.stderr);
}

#[tokio::test]
async fn a_zip_that_is_not_an_item_report_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_of(
        dir.path(),
        &[
            ("Locations-1.csv", LOCATIONS.to_owned()),
            ("Statistics-1.csv", "x\n".to_owned()),
        ],
    );
    let run = run(
        dir.path(),
        &["--json", "parse", "items", zip.to_str().unwrap()],
    )
    .await;
    assert_eq!(run.code, 1);
    assert_eq!(run.document.unwrap()["error"]["code"], "NotAReportZip");
}

#[tokio::test]
async fn missing_id_columns_are_named_and_every_row_is_keyed_by_hash() {
    let dir = tempfile::tempdir().unwrap();
    let body = "Item class,Date,Sender,Subject/Title\n\
                IPM.Note,2026-07-01 08:00:00Z,a@contoso.example,One\n\
                IPM.Note,2026-07-01 08:00:00Z,a@contoso.example,One\n\
                IPM.Note,not a date,a@contoso.example,Two\n";
    let zip = zip_of(dir.path(), &[("Items_0_2026.csv", body.to_owned())]);
    let run = run(dir.path(), &["parse", "items", zip.to_str().unwrap()]).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let lines = run.lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["copies"], 2);
    assert_eq!(lines[1]["date"], Value::Null);
    assert!(
        run.stderr
            .contains("columns missing from the report's Items files: "),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("Internet message ID"), "{}", run.stderr);
    assert!(
        run.stderr
            .contains("1 row had a Date that could not be read"),
        "{}",
        run.stderr
    );
    // Field text never reaches the summary.
    assert!(!run.stderr.contains("a@contoso.example"), "{}", run.stderr);
}

#[tokio::test]
async fn wrap_untrusted_wraps_the_title_key_and_sender() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let run = run(
        dir.path(),
        &["--wrap-untrusted", "parse", "items", zip.to_str().unwrap()],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let m1 = &run.lines()[2];
    for key in [
        "title",
        "key",
        "sender",
        "senderDomain",
        "internetMessageId",
        "class",
    ] {
        assert!(
            m1[key].as_str().unwrap().starts_with("[UNTRUSTED:"),
            "{key}: {m1}"
        );
    }
    assert_eq!(m1["keyKind"], "internetMessageId");
}

/// The acceptance timing of `docs/SPEC.md` section 11: 200,000 rows in
/// under 10 seconds. Run with `cargo test --release --test items --
/// --ignored`.
#[tokio::test]
#[ignore]
async fn two_hundred_thousand_rows_in_under_ten_seconds() {
    let dir = tempfile::tempdir().unwrap();
    // About 12 copies per unique item, over 3 files.
    let mut files = Vec::new();
    for part in 0..3 {
        let mut body = format!("{HEADER}\n");
        for i in (part..200_000).step_by(3) {
            let item = i / 12;
            body.push_str(&row(
                &format!("<m{item}@contoso.example>"),
                "",
                "IPM.Note",
                "2026-07-01 08:00:00Z",
                "alex@contoso.example",
                "Weekly orders report",
                "",
                (i % 400) as u32,
            ));
        }
        files.push((format!("Items_{part}_2026.csv"), body));
    }
    let entries: Vec<(&str, String)> = files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
    let zip = zip_of(dir.path(), &entries);
    let started = std::time::Instant::now();
    let run = run(dir.path(), &["parse", "items", zip.to_str().unwrap()]).await;
    let elapsed = started.elapsed();
    assert_eq!(run.code, 0, "{}", run.stderr);
    assert_eq!(run.stdout.lines().count(), 200_000_usize.div_ceil(12));
    assert!(elapsed.as_secs_f64() < 10.0, "{elapsed:?}");
}
