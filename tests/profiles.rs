//! `purview parse profile` in-process on item report zips written here from
//! synthetic rows. The command is local, so every `Env` keeps the
//! unreachable hosts of `Env::in_memory()`: a network call would fail it.

use std::io::Write;
use std::path::{Path, PathBuf};

use ms_purview_cli::cli::execute_with;
use ms_purview_cli::env::Env;
use serde_json::{json, Value};

const HEADER: &str = "Internet message ID,Immutable ID,Item class,Date,Sender,Subject/Title,\
                      Conversation name,Conversation type,Recipient count,Workload,\
                      Has attachment,Location ID";

/// The aliases and internal domains the tests use: an old domain renamed,
/// and a second internal domain.
const IDENTITY: &str = r#"{"identity": {
    "internal_domains": ["contoso.example", "EU.contoso.example"],
    "domain_aliases": {"old.contoso.example": "contoso.example"}
}}"#;

/// One CSV row.
#[allow(clippy::too_many_arguments)] // One argument per column a test varies.
fn row(
    imid: &str,
    imm: &str,
    class: &str,
    date: &str,
    sender: &str,
    conversation: &str,
    location: u32,
) -> String {
    format!(
        "{imid},{imm},{class},{date},\"{sender}\",,\"{conversation}\",,1,Exchange,False,\
         00000000-0000-4000-8000-{location:012}\n"
    )
}

/// Nine unique items in twelve rows:
/// - m1, mail from alex@contoso.example, in three mailboxes;
/// - m2, from the same person under the old domain, the same ISO week;
/// - m3, from alex at the second internal domain, the next week;
/// - m4, from alex at an outside domain, in August;
/// - IMM5, a Teams message whose sender is a thread id, twice;
/// - IMM6, a Teams message from bea in the same chat;
/// - IMM7, a Teams system message with no sender and no conversation name;
/// - a Teams file with no id and no date, keyed by hash, which is not a
///   Teams message;
/// - IMM9, a Teams file whose sender is a list of addresses.
fn report(dir: &Path) -> PathBuf {
    let rows = [
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-06 08:00:00Z",
            "Alex <alex@contoso.example>",
            "",
            1,
        ),
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-06 08:00:00Z",
            "Alex <alex@contoso.example>",
            "",
            2,
        ),
        row(
            "<m1@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-06 08:00:00Z",
            "Alex <alex@contoso.example>",
            "",
            3,
        ),
        row(
            "<m2@contoso.example>",
            "",
            "IPM.Note",
            "2026-07-12 23:59:59Z",
            "ALEX@old.contoso.example",
            "",
            1,
        ),
        row(
            "<m3@eu.contoso.example>",
            "",
            "IPM.Note",
            "2026-07-13 00:00:00Z",
            "alex@eu.contoso.example",
            "",
            1,
        ),
        row(
            "<m4@fabrikam.example>",
            "",
            "IPM.Note",
            "2026-08-01 10:00:00Z",
            "alex@fabrikam.example",
            "",
            1,
        ),
        row(
            "",
            "IMM5",
            "IPM.SkypeTeams.Message",
            "2026-07-07 09:00:00Z",
            "19:x@thread.v2",
            "Orders chat",
            1,
        ),
        row(
            "",
            "IMM5",
            "IPM.SkypeTeams.Message",
            "2026-07-07 09:00:00Z",
            "19:x@thread.v2",
            "Orders chat",
            2,
        ),
        row(
            "",
            "IMM6",
            "IPM.SkypeTeams.Message",
            "2026-07-07 09:05:00Z",
            "Bea <bea@contoso.example>",
            "Orders chat",
            1,
        ),
        row(
            "",
            "IMM7",
            "ipm.skypeteams.systemmessage",
            "2026-07-08 09:00:00Z",
            "",
            "",
            1,
        ),
        row(
            "",
            "",
            "IPM.File.TeamsConversation",
            "",
            "carol@contoso.example",
            "Orders chat",
            1,
        ),
        // A Teams file whose Sender lists addresses, cut short (Observed).
        row(
            "",
            "IMM9",
            "IPM.File.TeamsConversation",
            "2026-07-09 09:00:00Z",
            "alex@contoso.example; bea@contoso.example; carol@fabrik",
            "Orders chat",
            1,
        ),
    ];
    zip_of(
        dir,
        &[(
            "Items_1_2026-08-02.csv",
            format!("{HEADER}\n{}", rows.concat()),
        )],
    )
}

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

fn with_config(dir: &Path, config: &str) {
    let dir = dir.join("config");
    std::fs::create_dir_all(&dir).unwrap();
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

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
    document: Option<Value>,
}

impl Run {
    /// The profile, from `{"results": …, "count": 1}`.
    fn profile(&self) -> &Value {
        let document = self.document.as_ref().expect("a JSON document");
        assert_eq!(document["count"], 1, "{document}");
        &document["results"]
    }

    fn message(&self) -> String {
        self.document.as_ref().unwrap()["error"]["message"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

async fn run(dir: &Path, args: &[&str]) -> Run {
    let (mut env, captured) = Env::in_memory();
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

/// `(name, items)` pairs of a top list, by the name's key.
fn pairs(list: &Value, key: &str) -> Vec<(String, u64)> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry[key].as_str().unwrap_or("<null>").to_owned(),
                entry["items"].as_u64().unwrap(),
            )
        })
        .collect()
}

fn owned(list: &[(&str, u64)]) -> Vec<(String, u64)> {
    list.iter()
        .map(|(name, count)| ((*name).to_owned(), *count))
        .collect()
}

#[tokio::test]
async fn the_profile_counts_unique_items_by_class_sender_domain_conversation_and_week() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    with_config(dir.path(), IDENTITY);
    let run = run(
        dir.path(),
        &[
            "--json",
            "parse",
            "profile",
            zip.to_str().unwrap(),
            "--bucket",
            "week",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let profile = run.profile();
    assert_eq!(profile["items"], 9);
    assert_eq!(profile["hashKeyed"], 1);
    assert_eq!(profile["copies"]["rows"], 12);
    assert_eq!(profile["copies"]["max"], 3);
    let mean = profile["copies"]["mean"].as_f64().unwrap();
    assert!((mean - 12.0 / 9.0).abs() < 1e-9, "{mean}");
    assert_eq!(
        pairs(&profile["classes"], "class"),
        owned(&[
            ("IPM.Note", 4),
            ("IPM.File.TeamsConversation", 2),
            ("IPM.SkypeTeams.Message", 2),
            ("ipm.skypeteams.systemmessage", 1),
        ])
    );
    assert_eq!(
        pairs(&profile["workloads"], "workload"),
        owned(&[("Exchange", 9)])
    );
    // The old domain is the new one; the second internal domain and the
    // outside one stay apart without --merge-local-part. The thread id and
    // the empty sender and the list of addresses are never a person.
    let senders = &profile["senders"];
    assert_eq!(senders["distinct"], 5);
    assert_eq!(senders["teamsThread"], 1);
    assert_eq!(senders["addressLists"], 1);
    assert_eq!(senders["none"], 1);
    assert_eq!(
        pairs(&senders["top"], "sender"),
        owned(&[
            ("alex@contoso.example", 2),
            ("alex@eu.contoso.example", 1),
            ("alex@fabrikam.example", 1),
            ("bea@contoso.example", 1),
            ("carol@contoso.example", 1),
        ])
    );
    assert_eq!(senders["top"][0]["addresses"], 2);
    assert_eq!(profile["senderDomains"]["distinct"], 3);
    assert_eq!(
        pairs(&profile["senderDomains"]["top"], "senderDomain"),
        owned(&[
            ("contoso.example", 4),
            ("eu.contoso.example", 1),
            ("fabrikam.example", 1),
        ])
    );
    // Teams messages only, by class prefix in any case; the Teams file's
    // conversation name is not counted.
    let teams = &profile["teamsConversations"];
    assert_eq!(teams["items"], 3);
    assert_eq!(teams["distinct"], 1);
    assert_eq!(teams["unnamed"], 1);
    assert_eq!(
        pairs(&teams["top"], "conversationName"),
        owned(&[("Orders chat", 2)])
    );
    // ISO weeks from Monday, UTC: Sunday 23:59:59 is the week before the
    // Monday at midnight.
    let histogram = &profile["histogram"];
    assert_eq!(histogram["bucket"], "week");
    assert_eq!(histogram["undated"], 1);
    assert_eq!(
        pairs(&histogram["buckets"], "start"),
        owned(&[("2026-07-06", 6), ("2026-07-13", 1), ("2026-07-27", 1)])
    );
    assert_eq!(
        profile["options"],
        json!({"top": 20, "bucket": "week", "mergeLocalPart": false})
    );
    assert!(
        run.stderr.starts_with(
            "parse profile: 12 rows read from 1 Items file, 12 matched the filters; 9 unique \
             items (1 keyed by a hash of their fields)"
        ),
        "{}",
        run.stderr
    );
}

#[tokio::test]
async fn merge_local_part_merges_only_within_internal_domains() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    with_config(dir.path(), IDENTITY);
    let run = run(
        dir.path(),
        &[
            "--json",
            "parse",
            "profile",
            zip.to_str().unwrap(),
            "--merge-local-part",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let senders = &run.profile()["senders"];
    assert_eq!(senders["distinct"], 4);
    // Shown as the address most of its items came under.
    assert_eq!(
        pairs(&senders["top"], "sender"),
        owned(&[
            ("alex@contoso.example", 3),
            ("alex@fabrikam.example", 1),
            ("bea@contoso.example", 1),
            ("carol@contoso.example", 1),
        ])
    );
    assert_eq!(senders["top"][0]["addresses"], 3);
    assert_eq!(senders["top"][1]["addresses"], 1);
    // Domains are not merged.
    assert_eq!(run.profile()["senderDomains"]["distinct"], 3);
}

#[tokio::test]
async fn without_identity_settings_domains_are_as_given_and_merging_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let zip = zip.to_str().unwrap();
    let run = run(dir.path(), &["--json", "parse", "profile", zip]).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let profile = run.profile();
    assert_eq!(profile["senders"]["distinct"], 6);
    assert_eq!(profile["senderDomains"]["distinct"], 4);
    let refused = self::run(
        dir.path(),
        &["--json", "parse", "profile", zip, "--merge-local-part"],
    )
    .await;
    assert_eq!(refused.code, 1);
    assert!(
        refused.message().contains("identity.internal_domains"),
        "{}",
        refused.message()
    );
}

#[tokio::test]
async fn filters_apply_to_rows_before_they_are_counted() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let zip = zip.to_str().unwrap();
    let teams = run(
        dir.path(),
        &[
            "--json",
            "parse",
            "profile",
            zip,
            "--class",
            "ipm.skypeteams.",
        ],
    )
    .await;
    assert_eq!(teams.code, 0, "{}", teams.stderr);
    assert_eq!(teams.profile()["items"], 3);
    assert_eq!(teams.profile()["copies"]["rows"], 4);
    // A date filter leaves out the undated item.
    let later = run(
        dir.path(),
        &["--json", "parse", "profile", zip, "--since", "2026-07-13"],
    )
    .await;
    assert_eq!(later.profile()["items"], 2);
    assert_eq!(later.profile()["histogram"]["undated"], 0);
    let one = run(
        dir.path(),
        &[
            "--json",
            "parse",
            "profile",
            zip,
            "--sender",
            "Bea <BEA@contoso.example>",
        ],
    )
    .await;
    assert_eq!(one.profile()["items"], 1);
    assert_eq!(one.profile()["teamsConversations"]["items"], 1);
}

#[tokio::test]
async fn top_comes_from_the_flag_then_defaults_top() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let zip = zip.to_str().unwrap();
    with_config(dir.path(), r#"{"defaults": {"top": 2}}"#);
    let run = run(dir.path(), &["--json", "parse", "profile", zip]).await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let profile = run.profile();
    assert_eq!(profile["senders"]["top"].as_array().unwrap().len(), 2);
    assert_eq!(profile["senderDomains"]["top"].as_array().unwrap().len(), 2);
    // Every class is listed, whatever the top.
    assert_eq!(profile["classes"].as_array().unwrap().len(), 4);
    let flag = self::run(
        dir.path(),
        &["--json", "parse", "profile", zip, "--top", "1"],
    )
    .await;
    assert_eq!(
        flag.profile()["senders"]["top"].as_array().unwrap().len(),
        1
    );
    assert_eq!(flag.profile()["options"]["top"], 1);
}

#[tokio::test]
async fn bad_flags_and_settings_are_refused_before_the_zip_is_read_and_never_repeated() {
    let dir = tempfile::tempdir().unwrap();
    // No zip exists: each refusal must come before it is opened.
    let zip = dir.path().join("missing.zip");
    let zip = zip.to_str().unwrap();
    for (args, needle) in [
        (vec!["--top", "0"], "--top must be above zero"),
        (vec!["--sender", " "], "--sender"),
        (vec!["--max-unique", "0"], "--max-unique"),
        (vec!["--select", "SECRET-COLUMN"], "--select"),
    ] {
        let mut argv = vec!["--json", "parse", "profile", zip];
        argv.extend(args.iter());
        let run = run(dir.path(), &argv).await;
        assert_eq!(run.code, 1, "{args:?}");
        let message = run.message();
        assert!(message.contains(needle), "{args:?}: {message}");
        assert!(!message.contains("SECRET"), "{args:?}: {message}");
        assert!(!message.contains("cannot be read"), "{args:?}: {message}");
    }
    for (config, needle) in [
        (r#"{"identity": []}"#, "identity must be an object"),
        (
            r#"{"identity": {"internal_domains": "secret.example"}}"#,
            "identity.internal_domains",
        ),
        (
            r#"{"identity": {"internal_domains": ["alex@secret.example"]}}"#,
            "identity.internal_domains",
        ),
        (
            r#"{"identity": {"domain_aliases": {"secret.example": 3}}}"#,
            "identity.domain_aliases",
        ),
        (
            r#"{"identity": {"domain_aliases": {"a.secret.example": "b.secret.example", "b.secret.example": "c.secret.example"}}}"#,
            "mapped again",
        ),
        (r#"{"defaults": {"top": 0}}"#, "defaults.top"),
        (r#"{"defaults": {"top": "secret"}}"#, "defaults.top"),
    ] {
        let config_dir = tempfile::tempdir().unwrap();
        with_config(config_dir.path(), config);
        let run = run(config_dir.path(), &["--json", "parse", "profile", zip]).await;
        assert_eq!(run.code, 1, "{config}");
        let message = run.message();
        assert!(message.contains(needle), "{config}: {message}");
        assert!(!message.contains("secret"), "{config}: {message}");
    }
    // --top makes defaults.top unread.
    let config_dir = tempfile::tempdir().unwrap();
    with_config(config_dir.path(), r#"{"defaults": {"top": "x"}}"#);
    let report_dir = tempfile::tempdir().unwrap();
    let real = report(report_dir.path());
    let run = run(
        config_dir.path(),
        &[
            "--json",
            "parse",
            "profile",
            real.to_str().unwrap(),
            "--top",
            "3",
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{:?}", run.document);
}

#[tokio::test]
async fn the_table_has_a_section_name_and_count_per_row() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let run = run(
        dir.path(),
        &["--plain", "parse", "profile", zip.to_str().unwrap()],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let lines: Vec<&str> = run.stdout.lines().collect();
    for expected in [
        "items\tunique\t9",
        "copies\tmean\t1.33",
        "class\tIPM.Note\t4",
        "sender\t(Teams thread)\t1",
        "sender\t(address list)\t1",
        "sender\t(none)\t1",
        "conversation\tOrders chat\t2",
        "conversation\t(unnamed)\t1",
        "month\t2026-07-01\t7",
        "month\t2026-08-01\t1",
        "month\t(undated)\t1",
    ] {
        assert!(lines.contains(&expected), "{expected}: {}", run.stdout);
    }
    let selected = self::run(
        dir.path(),
        &[
            "--plain",
            "--select",
            "SECTION,COUNT",
            "parse",
            "profile",
            zip.to_str().unwrap(),
        ],
    )
    .await;
    assert!(
        selected.stdout.lines().any(|line| line == "items\t9"),
        "{}",
        selected.stdout
    );
}

#[tokio::test]
async fn wrap_untrusted_wraps_senders_domains_classes_and_conversation_names() {
    let dir = tempfile::tempdir().unwrap();
    let zip = report(dir.path());
    let run = run(
        dir.path(),
        &[
            "--json",
            "--wrap-untrusted",
            "parse",
            "profile",
            zip.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(run.code, 0, "{}", run.stderr);
    let profile = run.profile();
    for value in [
        &profile["senders"]["top"][0]["sender"],
        &profile["senderDomains"]["top"][0]["senderDomain"],
        &profile["classes"][0]["class"],
        &profile["teamsConversations"]["top"][0]["conversationName"],
    ] {
        assert!(
            value.as_str().unwrap().starts_with("[UNTRUSTED:"),
            "{value}"
        );
    }
}

#[tokio::test]
async fn a_zip_that_is_not_an_item_report_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let zip = zip_of(dir.path(), &[("Statistics-1.csv", "a\n1\n".to_owned())]);
    let run = run(
        dir.path(),
        &["--json", "parse", "profile", zip.to_str().unwrap()],
    )
    .await;
    assert_eq!(run.code, 1);
    assert_eq!(
        run.document.as_ref().unwrap()["error"]["code"],
        "NotAReportZip"
    );
}

#[tokio::test]
async fn a_long_name_is_cut_in_the_table_and_kept_whole_in_json() {
    let dir = tempfile::tempdir().unwrap();
    let name = "x".repeat(100);
    let zip = zip_of(
        dir.path(),
        &[(
            "Items_1_2026-08-02.csv",
            format!(
                "{HEADER}\n{}",
                row(
                    "",
                    "IMM1",
                    "IPM.SkypeTeams.Message",
                    "2026-07-07 09:00:00Z",
                    "bea@contoso.example",
                    &name,
                    1
                )
            ),
        )],
    );
    let zip = zip.to_str().unwrap();
    let table = run(dir.path(), &["--plain", "parse", "profile", zip]).await;
    let cut = format!("conversation\t{}…\t1", "x".repeat(79));
    assert!(
        table.stdout.lines().any(|line| line == cut),
        "{}",
        table.stdout
    );
    let json = run(dir.path(), &["--json", "parse", "profile", zip]).await;
    assert_eq!(
        json.profile()["teamsConversations"]["top"][0]["conversationName"],
        name.as_str()
    );
}
