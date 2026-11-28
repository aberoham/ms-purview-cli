//! The `.msg` reader (`docs/SPEC.md` section 8.7) on `.msg` files made by
//! `msggen`, and `purview export read` in-process on zips of them. Every
//! value is synthetic.

mod support;

use ms_purview_cli::msg::body::Body;
use ms_purview_cli::msg::parse_msg;
use serde_json::Value;
use support::msggen::{attachment, items_zip, recipient, Message, Value as P};
use support::*;

const HTML: u16 = 0x1013;
const BODY: u16 = 0x1000;
const RTF: u16 = 0x1009;
const CODEPAGE: u16 = 0x3FDE;

fn html_note() -> Message {
    Message::note("Orders API cut-over").with(
        HTML,
        P::Binary(b"<html><body><p>Moving <b>orders-api</b> on Monday.</p></body></html>".to_vec()),
    )
}

#[test]
fn an_html_only_note_reads_with_its_headers_and_html_body() {
    let mut message = html_note();
    message
        .recipients
        .push(recipient("Kim Example", "kim@fabrikam.example", 2));
    message
        .recipients
        .push(recipient("Lee Example", "lee@contoso.example", 3));
    message
        .attachments
        .push(attachment("plan.xlsx", &[7_u8; 1234]));
    let item = parse_msg(&message.build()).unwrap();
    assert_eq!(item.class.as_deref(), Some("IPM.Note"));
    assert_eq!(item.subject.as_deref(), Some("Orders API cut-over"));
    let from = item.from.unwrap();
    assert_eq!(from.name.as_deref(), Some("Alex Example"));
    assert_eq!(from.address.as_deref(), Some("alex@contoso.example"));
    assert_eq!(item.to.len(), 1);
    assert_eq!(item.to[0].address.as_deref(), Some("sam@contoso.example"));
    assert_eq!(item.cc[0].address.as_deref(), Some("kim@fabrikam.example"));
    assert_eq!(item.bcc[0].address.as_deref(), Some("lee@contoso.example"));
    assert_eq!(item.sent.unwrap().to_rfc3339(), "2026-01-05T09:00:00+00:00");
    assert_eq!(item.attachments[0].name.as_deref(), Some("plan.xlsx"));
    assert_eq!(item.attachments[0].size, Some(1234));
    assert_eq!(item.body, Body::Html("Moving orders-api on Monday.".into()));
}

#[test]
fn a_text_only_note_reads_its_text_body() {
    let message = Message::note("Plain").with(BODY, P::Unicode("Line one\r\nLine two".into()));
    let item = parse_msg(&message.build()).unwrap();
    assert_eq!(item.body, Body::Text("Line one\nLine two".into()));
}

#[test]
fn an_rtf_only_note_has_no_body() {
    let message = Message::note("Rich").with(RTF, P::Binary(vec![1, 2, 3, 4]));
    let item = parse_msg(&message.build()).unwrap();
    assert_eq!(item.body, Body::RtfOnly);
    assert_eq!(item.body.error(), Some(("noBody", "compressed RTF only")));
}

#[test]
fn a_cp1252_html_body_decodes_with_the_internet_code_page() {
    let message = Message::note("Café")
        .with(HTML, P::Binary(b"<p>caf\xe9 \x805</p>".to_vec()))
        .with(CODEPAGE, P::Long(1252));
    let item = parse_msg(&message.build()).unwrap();
    assert_eq!(item.body, Body::Html("café €5".into()));
}

#[test]
fn vml_leftovers_never_reach_the_body() {
    let html = "<html><head><style>v\\:* {behavior:url(#default#VML);}</style></head><body>\
                <!--[if gte vml 1]><v:shapedefaults v:ext=\"edit\"/><![endif]-->\
                <p>o\\:* {behavior:url(#default#VML);} Real text</p></body></html>";
    let message = Message::note("VML").with(HTML, P::Binary(html.as_bytes().to_vec()));
    let item = parse_msg(&message.build()).unwrap();
    let text = item.body.text().unwrap().to_owned();
    assert_eq!(text, "Real text");
}

#[test]
fn a_teams_system_message_without_a_body_is_unsupported_class() {
    let message = Message::note("").with(0x001A, P::Unicode("IPM.SkypeTeams.SystemMessage".into()));
    // The later class value wins: properties are written in order.
    let mut message = message;
    message.props.0.retain(|(id, value)| {
        !(*id == 0x001A && matches!(value, P::Unicode(class) if class == "IPM.Note"))
    });
    let item = parse_msg(&message.build()).unwrap();
    assert_eq!(item.body, Body::UnsupportedClass);
}

#[test]
fn an_8_bit_subject_decodes_with_the_message_code_page() {
    let mut message = Message::note("x");
    message.props.0.retain(|(id, _)| *id != 0x0037);
    let message = message
        .with(0x0037, P::String8(b"Gr\xfc\xdfe\0".to_vec()))
        .with(0x3FFD, P::Long(1252));
    let item = parse_msg(&message.build()).unwrap();
    assert_eq!(item.subject.as_deref(), Some("Grüße"));
}

#[test]
fn bytes_that_are_not_a_container_are_cfb_invalid() {
    let error = parse_msg(b"PK\x03\x04 not a compound file").unwrap_err();
    assert_eq!(error.code(), "cfbInvalid");
}

/// Writes `zip` under the harness root and returns its path.
fn write_zip(harness: &Harness, name: &str, zip: Vec<u8>) -> String {
    let path = harness.root.path().join(name);
    std::fs::write(&path, zip).unwrap();
    path.to_string_lossy().into_owned()
}

fn lines(run: &Run) -> Vec<Value> {
    run.stdout()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn export_read_writes_one_json_line_per_msg_in_zip_order() {
    let harness = Harness::new().await;
    let zip = items_zip(&[
        ("Exchange/Items/aaaa.msg", html_note().build()),
        ("Exchange/Items/readme.txt", b"not a message".to_vec()),
        (
            "Exchange/Items/bbbb.msg",
            Message::note("Second")
                .with(BODY, P::Unicode("Text".into()))
                .build(),
        ),
    ]);
    let path = write_zip(&harness, "Items.1.001.export.zip", zip);
    let run = harness.run(&["export", "read", &path]).await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let records = lines(&run);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["entry"], "Exchange/Items/aaaa.msg");
    assert_eq!(records[0]["part"], "Items.1.001.export.zip");
    assert_eq!(records[0]["bodySource"], "html");
    assert_eq!(records[0]["body"], "Moving orders-api on Monday.");
    assert_eq!(records[0]["from"]["address"], "alex@contoso.example");
    assert_eq!(records[0]["sent"], "2026-01-05T09:00:00Z");
    assert_eq!(records[0]["error"], Value::Null);
    assert_eq!(records[1]["subject"], "Second");
    assert_eq!(records[1]["bodySource"], "text");
    let stderr = run.stderr();
    assert!(stderr.contains("2 items read, 0 with an error"), "{stderr}");
    assert!(
        stderr.contains("1 entries that are not .msg skipped"),
        "{stderr}"
    );
}

#[tokio::test]
async fn an_item_with_an_error_gets_a_record_and_the_run_exits_4() {
    let harness = Harness::new().await;
    let zip = items_zip(&[
        ("Exchange/Items/broken.msg", b"not a compound file".to_vec()),
        (
            "Exchange/Items/rtf.msg",
            Message::note("Rich").with(RTF, P::Binary(vec![1])).build(),
        ),
        ("Exchange/Items/good.msg", html_note().build()),
    ]);
    let path = write_zip(&harness, "Items.1.001.export.zip", zip);
    let run = harness.run(&["export", "read", &path]).await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stderr());
    let records = lines(&run);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["error"], "cfbInvalid");
    assert_eq!(records[1]["error"], "noBody");
    assert_eq!(records[1]["errorDetail"], "compressed RTF only");
    assert_eq!(records[2]["error"], Value::Null);
}

#[tokio::test]
async fn an_entry_over_the_limit_is_entry_too_large_and_the_rest_are_read() {
    let harness = Harness::new().await;
    let mut big = html_note();
    big.attachments
        .push(attachment("big.bin", &vec![1_u8; 20_000]));
    let zip = items_zip(&[
        ("Exchange/Items/big.msg", big.build()),
        ("Exchange/Items/small.msg", html_note().build()),
    ]);
    let path = write_zip(&harness, "Items.1.001.export.zip", zip);
    let small = html_note().build().len();
    let limit = format!("{}", small + 100);
    let run = harness
        .run(&["export", "read", &path, "--max-entry-bytes", &limit])
        .await;
    assert_eq!(run.outcome.exit_code, 4, "{}", run.stderr());
    let records = lines(&run);
    assert_eq!(records[0]["error"], "entryTooLarge");
    assert_eq!(records[1]["error"], Value::Null);
}

#[tokio::test]
async fn a_long_body_is_cut_and_marked() {
    let harness = Harness::new().await;
    let message = Message::note("Long").with(BODY, P::Unicode("é".repeat(50)));
    let path = write_zip(
        &harness,
        "Items.1.001.export.zip",
        items_zip(&[("Exchange/Items/a.msg", message.build())]),
    );
    let run = harness
        .run(&["export", "read", &path, "--max-body-chars", "10"])
        .await;
    let records = lines(&run);
    assert_eq!(records[0]["body"], "é".repeat(10));
    assert_eq!(records[0]["bodyTruncated"], true);
}

#[tokio::test]
async fn a_terminal_stdout_is_refused_before_anything_is_read() {
    let harness = Harness::new().await;
    let path = write_zip(
        &harness,
        "Items.1.001.export.zip",
        items_zip(&[("Exchange/Items/a.msg", html_note().build())]),
    );
    let run = harness
        .run_with(&["export", "read", &path], |env, _| {
            env.stdout_is_terminal = true;
        })
        .await;
    assert_eq!(run.outcome.exit_code, 1);
    assert!(run.stdout().is_empty());
    assert!(
        run.stderr().contains("does not write them to a terminal"),
        "{}",
        run.stderr()
    );
    assert!(!run.stderr().contains("orders-api"));
}

#[tokio::test]
async fn json_gives_one_document_and_wrap_untrusted_marks_the_message() {
    let harness = Harness::new().await;
    let path = write_zip(
        &harness,
        "Items.1.001.export.zip",
        items_zip(&[("Exchange/Items/a.msg", html_note().build())]),
    );
    let run = harness
        .run(&["export", "read", &path, "--json", "--wrap-untrusted"])
        .await;
    assert_eq!(run.outcome.exit_code, 0, "{}", run.stderr());
    let document = run.json();
    assert_eq!(document["count"], 1);
    let record = &document["results"][0];
    for key in ["subject", "body"] {
        let text = record[key].as_str().unwrap();
        assert!(text.starts_with("[UNTRUSTED:"), "{key}: {text}");
    }
    assert!(record["from"]["address"]
        .as_str()
        .unwrap()
        .starts_with("[UNTRUSTED:"));
    assert!(document["untrustedNotice"].is_string());

    // JSON Lines: one marker for the run, the notice on stderr.
    let run = harness
        .run(&["export", "read", &path, "--wrap-untrusted"])
        .await;
    let records = lines(&run);
    assert!(records[0]["body"]
        .as_str()
        .unwrap()
        .starts_with("[UNTRUSTED:"));
    assert!(run.stderr().contains("SECURITY NOTICE"), "{}", run.stderr());
}

#[tokio::test]
async fn a_url_in_a_body_keeps_only_scheme_host_and_path() {
    let harness = Harness::new().await;
    let html = "<p>See https://portal.contoso.example/orders?token=abc123secret now</p>";
    let message = Message::note("Link").with(HTML, P::Binary(html.as_bytes().to_vec()));
    let path = write_zip(
        &harness,
        "Items.1.001.export.zip",
        items_zip(&[("Exchange/Items/a.msg", message.build())]),
    );
    let run = harness.run(&["export", "read", &path]).await;
    let body = lines(&run)[0]["body"].as_str().unwrap().to_owned();
    assert!(!body.contains("abc123secret"), "{body}");
    assert!(body.contains("portal.contoso.example/orders"), "{body}");
}
