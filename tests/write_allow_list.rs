//! The write allow list (`AGENTS.md`, `docs/SPEC.md` section 4.3): the
//! only Graph writes are the six POSTs in `routes::WriteRoute::ALL`, and no
//! other HTTP write method exists anywhere in the crate. This test scans
//! `src/` and `build.rs` for them. Adding a write needs a reviewed design,
//! a change to this test and an update to `docs/safety.md`.
//!
//! A POST is sent from two places only: `GraphClient::send_write`, which
//! takes an approved plan, and the identity platform's token and
//! device-code endpoints in `auth.rs`.
//!
//! The forbidden words are joined from pieces at run time, so this file
//! could be scanned too without finding itself.

use std::path::{Path, PathBuf};

/// The HTTP methods that may not appear, as whole upper-case words: in
/// code (`Method::…`), in strings and in comments alike.
fn forbidden_words() -> Vec<String> {
    vec![
        ["PAT", "CH"].concat(),
        ["P", "UT"].concat(),
        ["DEL", "ETE"].concat(),
    ]
}

/// Calls that would send one of those methods, or a method chosen at run
/// time.
fn forbidden_calls() -> Vec<String> {
    vec![
        [".pat", "ch("].concat(),
        [".p", "ut("].concat(),
        [".requ", "est("].concat(),
        ["Method::from_", "bytes"].concat(),
        ["Method::from_", "str"].concat(),
        ["Method::try_", "from"].concat(),
    ]
}

/// `.delete(` is also the credential store's method, so it is refused
/// only in a file that talks HTTP.
fn forbidden_http_calls() -> Vec<String> {
    vec![[".del", "ete("].concat()]
}

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    file: String,
    line: usize,
    what: String,
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Whether `word` occurs in `line` with no letter, digit or `_` on either
/// side.
fn has_word(line: &str, word: &str) -> bool {
    let bytes = line.as_bytes();
    line.match_indices(word).any(|(start, _)| {
        let end = start + word.len();
        (start == 0 || !is_word_byte(bytes[start - 1]))
            && (end == bytes.len() || !is_word_byte(bytes[end]))
    })
}

fn scan(file: &str, text: &str) -> Vec<Finding> {
    let speaks_http = text.contains("reqwest");
    let mut findings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let mut found = |what: &str| {
            findings.push(Finding {
                file: file.to_owned(),
                line: index + 1,
                what: what.to_owned(),
            })
        };
        for word in forbidden_words() {
            if has_word(line, &word) {
                found(&word);
            }
        }
        for call in forbidden_calls() {
            if line.contains(&call) {
                found(&call);
            }
        }
        if speaks_http {
            for call in forbidden_http_calls() {
                if line.contains(&call) {
                    found(&call);
                }
            }
        }
    }
    findings
}

fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn the_crate_holds_no_http_write_method_but_post() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("build.rs")];
    rust_files(&root.join("src"), &mut files);
    assert!(files.len() > 10, "{files:?}");
    let mut findings = Vec::new();
    for path in &files {
        let text = std::fs::read_to_string(path).unwrap();
        let name = path.strip_prefix(root).unwrap().display().to_string();
        findings.extend(scan(&name, &text));
    }
    assert!(findings.is_empty(), "{findings:#?}");
}

#[test]
fn the_scan_finds_each_forbidden_form() {
    let samples = [
        (
            format!("let m = reqwest::Method::{};", forbidden_words()[0]),
            1,
        ),
        (format!("// sends a {} request", forbidden_words()[1]), 1),
        (format!("\"{}\"", forbidden_words()[2]), 1),
        (format!("client{}url)", forbidden_calls()[0]), 1),
        (format!("client{}url)", forbidden_calls()[1]), 1),
        (format!("client{}m, url)", forbidden_calls()[2]), 1),
        (format!("{}(b\"X\")", forbidden_calls()[3]), 1),
        (
            format!("use reqwest;\nclient{}url)", forbidden_http_calls()[0]),
            1,
        ),
    ];
    for (text, expected) in samples {
        assert_eq!(scan("sample.rs", &text).len(), expected, "{text}");
    }
    // Not methods: other words that contain the letters, and the store's
    // delete in a file that sends no HTTP.
    for text in [
        format!("OUT{} IN{}", forbidden_words()[1], forbidden_words()[1]),
        format!("{}_X", forbidden_words()[2]),
        format!("store{}key)", forbidden_http_calls()[0]),
        "client.get(url).send()".to_owned(),
        "client.post(url)".to_owned(),
    ] {
        assert!(scan("sample.rs", &text).is_empty(), "{text}");
    }
}

/// The files and the number of lines in each that build an HTTP POST
/// with reqwest's `.post(`. Calls of the identity client's own `post`
/// wrapper (`self.post(`) are not requests built here.
fn post_builders(root: &Path) -> Vec<(String, usize)> {
    let mut files = vec![root.join("build.rs")];
    rust_files(&root.join("src"), &mut files);
    let call = [".po", "st("].concat();
    let wrapper = ["self.po", "st("].concat();
    let mut found: Vec<(String, usize)> = files
        .iter()
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).unwrap();
            let count = text
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .filter(|line| line.contains(&call) && !line.contains(&wrapper))
                .count();
            (count > 0).then(|| {
                (
                    path.strip_prefix(root).unwrap().display().to_string(),
                    count,
                )
            })
        })
        .collect();
    found.sort();
    found
}

#[test]
fn a_post_is_built_only_in_send_write_and_the_token_client() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let separator = std::path::MAIN_SEPARATOR.to_string();
    assert_eq!(
        post_builders(root),
        [
            (["src", "auth.rs"].join(&separator), 1),
            (["src", "graph.rs"].join(&separator), 1),
        ]
    );
    // In graph.rs, the one POST is inside send_write.
    let graph = std::fs::read_to_string(root.join("src").join("graph.rs")).unwrap();
    let start = graph.find("pub async fn send_write(").unwrap();
    let end = start + graph[start..].find("\n    }\n").unwrap();
    assert!(graph[start..end].contains(&[".po", "st("].concat()));
}
