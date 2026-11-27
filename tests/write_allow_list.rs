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
        // A request built by hand and sent with `execute`.
        ["Request::", "new"].concat(),
        ["from_pa", "rts("].concat(),
        [".exec", "ute("].concat(),
        ["Method::PO", "ST"].concat(),
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
        // A Windows checkout may have CRLF endings; the checks read LF.
        let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
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

/// The part of a source file that is not its unit-test module: everything
/// before `#[cfg(test)]` followed by `mod tests`, at the start of a line.
/// A `#[cfg(test)]` on anything else, such as one statement, is scanned.
fn production_code(text: &str) -> &str {
    let marker = "#[cfg(test)]\nmod tests";
    if text.starts_with(marker) {
        return "";
    }
    match text.find(&format!("\n{marker}")) {
        Some(index) => &text[..index + 1],
        None => text,
    }
}

/// The name of the function whose signature comes last before `at`.
fn enclosing_function(code: &str, at: usize) -> Option<String> {
    let before = &code[..at];
    let start = before.rfind("fn ")? + 3;
    let name: String = before[start..]
        .chars()
        .take_while(|character| character.is_alphanumeric() || *character == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// The functions allowed to build an HTTP POST with reqwest's `.post(`,
/// by file: `GraphClient::send_write`, and the identity client's `post`.
fn allowed_posts() -> Vec<(&'static str, String)> {
    vec![
        ("auth.rs", ["async fn po", "st("].concat()),
        ("graph.rs", ["pub(crate) async fn send_wr", "ite("].concat()),
    ]
}

/// Where `text` builds a POST outside the function allowed in `file`, or
/// builds more than one. A call of the identity client's own wrapper,
/// `self.post(`, is not a request built here, and is allowed only in
/// `auth.rs`.
fn misplaced_posts(file: &str, text: &str) -> Vec<String> {
    let call = [".po", "st("].concat();
    let code = production_code(text);
    let allowed = allowed_posts()
        .into_iter()
        .find(|(name, _)| file.ends_with(name))
        .map(|(_, function)| function);
    // The span of the allowed function: from its signature to the first
    // line that closes a method body at its indentation.
    let span = allowed.as_ref().and_then(|function| {
        let start = code.find(function.as_str())?;
        let end = start + code[start..].find("\n    }\n")?;
        Some(start..end)
    });
    let mut problems = Vec::new();
    let mut inside = 0;
    let mut offset = 0;
    for line in code.split_inclusive('\n') {
        let start = offset;
        offset += line.len();
        if line.trim_start().starts_with("//") {
            continue;
        }
        // Each call on the line counts, not the line.
        for (column, _) in line.match_indices(&call) {
            let at = start + column;
            let is_wrapper = column >= 4 && line[..column].ends_with("self");
            if is_wrapper && file.ends_with("auth.rs") {
                continue;
            }
            match &span {
                Some(span) if span.contains(&at) => inside += 1,
                _ => problems.push(format!("{file}: a POST at byte {at}")),
            }
        }
    }
    if inside > 1 {
        problems.push(format!("{file}: {inside} POSTs in the allowed function"));
    }
    problems
}

#[test]
fn a_post_is_built_only_in_send_write_and_the_token_client() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![root.join("build.rs")];
    rust_files(&root.join("src"), &mut files);
    let mut problems = Vec::new();
    let mut found = 0;
    for path in &files {
        // A Windows checkout may have CRLF endings; the checks read LF.
        let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let name = path.strip_prefix(root).unwrap().display().to_string();
        problems.extend(misplaced_posts(&name, &text));
        if allowed_posts().iter().any(|(file, _)| name.ends_with(file)) {
            found += 1;
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(found, 2);
}

#[test]
fn the_post_check_finds_a_post_in_the_wrong_place() {
    let post = [".po", "st("].concat();
    let send = ["pub(crate) async fn send_wr", "ite("].concat();
    let wrapper = ["self.po", "st("].concat();
    let good = format!("impl X {{\n    {send}) {{\n        c{post}u);\n    }}\n}}\n");
    assert!(misplaced_posts("src/graph.rs", &good).is_empty());
    for (file, text) in [
        // In another function of an allowed file.
        (
            "src/graph.rs",
            format!("{good}impl Y {{\n    fn other() {{\n        c{post}u);\n    }}\n}}\n"),
        ),
        // Twice in the allowed function.
        (
            "src/graph.rs",
            format!(
                "impl X {{\n    {send}) {{\n        c{post}u);\n        c{post}v);\n    }}\n}}\n"
            ),
        ),
        // In a file with no allowed function.
        ("src/download.rs", format!("fn f() {{ c{post}u); }}\n")),
        // The wrapper's spelling outside auth.rs.
        ("src/download.rs", format!("fn f() {{ {wrapper}u); }}\n")),
        // Two on one line in the allowed function.
        (
            "src/graph.rs",
            format!("impl X {{\n    {send}) {{\n        c{post}u); c{post}v);\n    }}\n}}\n"),
        ),
        // After a #[cfg(test)] that guards one statement, not the tests.
        (
            "src/config.rs",
            format!("fn f() {{\n    #[cfg(test)]\n    let a = 1;\n}}\nfn g() {{ c{post}u); }}\n"),
        ),
    ] {
        assert!(!misplaced_posts(file, &text).is_empty(), "{file}: {text}");
    }
}

/// Every call of the function `name` outside unit-test modules, as (file,
/// enclosing function), one entry per call. `name(` must not follow a
/// letter, digit or `_`, so a method call, an imported name and a path such
/// as `GraphClient::name(` all count; its own `fn name(` does not.
fn callers(root: &Path, name: &str) -> Vec<(String, String)> {
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut found = Vec::new();
    for path in &files {
        // A Windows checkout may have CRLF endings; the checks read LF.
        let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let code = production_code(&text);
        let file = path.strip_prefix(root).unwrap().display().to_string();
        let mut offset = 0;
        for line in code.split_inclusive('\n') {
            let start = offset;
            offset += line.len();
            if line.trim_start().starts_with("//") {
                continue;
            }
            for (column, _) in line.match_indices(&format!("{name}(")) {
                let after_word = column > 0 && is_word_byte(line.as_bytes()[column - 1]);
                if after_word || line[..column].ends_with("fn ") {
                    continue;
                }
                let function = enclosing_function(code, start + column).unwrap_or_default();
                found.push((file.clone(), function));
            }
        }
    }
    found.sort();
    found
}

#[test]
fn only_the_write_runner_decides_and_sends() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runner = (
        ["src", "cli.rs"].join(std::path::MAIN_SEPARATOR_STR),
        "run_write".to_owned(),
    );
    assert_eq!(
        callers(root, &["dec", "ide"].concat()),
        std::slice::from_ref(&runner)
    );
    assert_eq!(
        callers(root, &["send_wr", "ite"].concat()),
        std::slice::from_ref(&runner)
    );
    let safety = ["src", "safety.rs"].join(std::path::MAIN_SEPARATOR_STR);
    assert!(callers(root, &["appr", "ove"].concat())
        .iter()
        .all(|(file, function)| *file == safety && function == "decide"));
}

#[test]
fn the_scanner_reads_past_a_statement_level_cfg_test() {
    let text = "fn a() {\n    #[cfg(test)]\n    let x = 1;\n}\nfn b() {}\n#[cfg(test)]\nmod tests {\n    fn c() {}\n}\n";
    let code = production_code(text);
    assert!(code.contains("fn b()"));
    assert!(!code.contains("fn c()"));
    assert_eq!(
        enclosing_function(code, code.find("fn b").unwrap() + 6).as_deref(),
        Some("b")
    );
}

/// What `production_code` relies on, in every source file: a unit-test
/// module is the last item of its file (after it, only its own indented
/// lines, blank lines and its closing brace), and none is declared as a
/// separate file with `mod tests;`. Also, the protected functions are not
/// imported under another name, which `callers` could not follow.
fn layout_problems(file: &str, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let marker = "#[cfg(test)]\nmod tests";
    if let Some(index) = text.find(marker) {
        let rest = &text[index + marker.len()..];
        if rest.trim_start().starts_with(';') {
            problems.push(format!("{file}: mod tests is declared in another file"));
        }
        let after_open = rest
            .split_once('\n')
            .map(|(_, tail)| tail)
            .unwrap_or_default();
        for line in after_open.lines() {
            let column_zero = !line.is_empty() && !line.starts_with([' ', '\t']);
            if column_zero && line != "}" {
                problems.push(format!("{file}: an item follows the test module"));
                break;
            }
        }
    }
    let code = production_code(text);
    for name in [
        ["dec", "ide"].concat(),
        ["send_wr", "ite"].concat(),
        ["appr", "ove"].concat(),
    ] {
        if code.contains(&format!("{name} as ")) {
            problems.push(format!("{file}: {name} is imported under another name"));
        }
    }
    problems
}

#[test]
fn test_modules_end_their_files_and_protected_names_are_not_renamed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut problems = Vec::new();
    for path in &files {
        // A Windows checkout may have CRLF endings; the checks read LF.
        let text = std::fs::read_to_string(path).unwrap().replace("\r\n", "\n");
        let name = path.strip_prefix(root).unwrap().display().to_string();
        problems.extend(layout_problems(&name, &text));
    }
    assert!(problems.is_empty(), "{problems:#?}");
    let marker = "#[cfg(test)]\nmod tests";
    for sample in [
        format!("fn a() {{}}\n{marker} {{\n    fn t() {{}}\n}}\nfn after() {{}}\n"),
        format!("fn a() {{}}\n{marker};\n"),
        format!("use crate::safety::{} as d;\n", ["dec", "ide"].concat()),
    ] {
        assert!(!layout_problems("src/x.rs", &sample).is_empty(), "{sample}");
    }
    let good = format!("fn a() {{}}\n{marker} {{\n    fn t() {{}}\n\n}}\n");
    assert!(layout_problems("src/x.rs", &good).is_empty());
}
