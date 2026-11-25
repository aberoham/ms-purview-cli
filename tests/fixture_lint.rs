//! The public-data lint. This is a public repository, so tracked text may
//! hold only synthetic data and well-known Microsoft constants. The lint
//! scans `tests/`, `docs/`, `contrib/`, `src/`, `README.md`, `SKILL.md`,
//! `AGENTS.md` and `CHANGELOG.md`, and fails on:
//!
//! - a globally unique identifier (GUID) that is neither synthetic
//!   (`00000000-0000-4000-8000-0000000000NN`) nor an allowed Microsoft
//!   constant;
//! - an email address outside `*.example`;
//! - a URL whose host and path are not an allowed pair;
//! - a `docs/reviews/` directory, or an absolute path into a home directory
//!   (private notes and prototypes live there);
//! - any term in the file named by `PURVIEW_LINT_DENYLIST`, when that
//!   variable is set. The file lives outside the repository and lists
//!   private names a maintainer wants kept out, one per line.
//!
//! Test inputs that must fail the lint are assembled at run time, so this
//! file passes its own scan.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCANNED_DIRECTORIES: &[&str] = &["tests/", "docs/", "contrib/", "src/"];
const SCANNED_FILES: &[&str] = &["README.md", "SKILL.md", "AGENTS.md", "CHANGELOG.md"];

/// Microsoft constants that may appear: the zero role id, the Microsoft
/// Graph and Purview eDiscovery application ids, and published delegated
/// scope ids.
const ALLOWED_GUIDS: &[&str] = &[
    "00000000-0000-0000-0000-000000000000", // default application role
    "00000003-0000-0000-c000-000000000000", // Microsoft Graph application
    "b26e684c-5068-4120-a679-64a5d2c909d9", // Purview eDiscovery application
    "c78f9c7e-bb5c-4125-b69a-5594d2f4ffc2", // eDiscovery.Download.Read
    "acb8f680-0834-4146-b69e-4ab1b39745ad", // eDiscovery.ReadWrite.All
    "99201db3-7652-4d5a-809a-bdb94f85fe3c", // eDiscovery.Read.All
    "37f7f235-527c-4136-accd-4a02d197296e", // openid
    "14dad69e-099b-42c9-810b-d002981feec1", // profile
    "7427e0e9-2fba-42fe-b0c0-848c9e6a8182", // offline_access
];

/// Domains of Teams thread identifiers, which look like addresses but name
/// no person or organisation.
const THREAD_DOMAINS: &[&str] = &["thread.v2", "thread.skype", "thread.tacv2"];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    file: String,
    line: usize,
    rule: &'static str,
    text: String,
}

#[test]
fn public_files_hold_only_synthetic_data() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = scanned_files(root);
    assert!(
        files.iter().any(|file| file == "docs/SPEC.md"),
        "the lint found none of the files it should scan: {files:?}"
    );
    let denylist = load_denylist();
    let mut findings = Vec::new();
    if root.join("docs/reviews").exists() {
        findings.push(Finding {
            file: "docs/reviews/".into(),
            line: 0,
            rule: "review history is private and must stay outside the published tree",
            text: String::new(),
        });
    }
    for file in &files {
        if file.starts_with("docs/reviews/") {
            findings.push(Finding {
                file: file.clone(),
                line: 0,
                rule: "review history is private and must stay outside the published tree",
                text: String::new(),
            });
            continue;
        }
        let Ok(bytes) = std::fs::read(root.join(file)) else {
            continue; // listed but deleted in the working tree
        };
        let text = String::from_utf8_lossy(&bytes);
        findings.extend(scan_text(file, &text, &denylist));
    }
    findings.sort();
    assert!(
        findings.is_empty(),
        "public-data lint: {} finding(s)\n{}",
        findings.len(),
        findings
            .iter()
            .map(|finding| format!(
                "  {}:{}: {}: {}",
                finding.file, finding.line, finding.rule, finding.text
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Tracked files, plus untracked files git does not ignore, so a new file
/// is checked before it is committed. Without git, the scanned paths are
/// walked instead.
fn scanned_files(root: &Path) -> Vec<String> {
    let listed = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            output
                .stdout
                .split(|byte| *byte == 0)
                .filter(|name| !name.is_empty())
                .map(|name| String::from_utf8_lossy(name).replace('\\', "/"))
                .collect::<BTreeSet<_>>()
        });
    let all = listed.unwrap_or_else(|| walk(root));
    all.into_iter().filter(|file| is_scanned(file)).collect()
}

fn is_scanned(file: &str) -> bool {
    SCANNED_FILES.contains(&file)
        || SCANNED_DIRECTORIES
            .iter()
            .any(|directory| file.starts_with(directory))
}

fn walk(root: &Path) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "target" || relative == ".git" {
                continue;
            }
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(path),
                Ok(kind) if kind.is_file() => {
                    found.insert(relative);
                }
                _ => {}
            }
        }
    }
    found
}

fn load_denylist() -> Vec<String> {
    let Some(path) = std::env::var_os("PURVIEW_LINT_DENYLIST").filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };
    let contents = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("PURVIEW_LINT_DENYLIST names a file that cannot be read: {error}")
    });
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_lowercase)
        .collect()
}

fn scan_text(file: &str, text: &str, denylist: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let mut found = |rule: &'static str, value: String| {
            findings.push(Finding {
                file: file.to_owned(),
                line: index + 1,
                rule,
                text: value,
            });
        };
        for guid in guids(line) {
            if !guid_allowed(&guid) {
                found("GUID is neither synthetic nor an allowed constant", guid);
            }
        }
        for address in email_addresses(line) {
            if !email_allowed(&address) {
                found("email address outside *.example", address);
            }
        }
        for url in urls(line) {
            if !url_allowed(&url) {
                found("URL host and path are not an allowed pair", url);
            }
        }
        for path in home_paths(line) {
            found("absolute path into a home directory", path);
        }
        let lower = line.to_lowercase();
        for (number, term) in denylist.iter().enumerate() {
            if lower.contains(term.as_str()) {
                // The term itself is private, so only its position is shown.
                found(
                    "term from PURVIEW_LINT_DENYLIST",
                    format!("term {}", number + 1),
                );
            }
        }
    }
    findings
}

// GUIDs.

fn guids(line: &str) -> Vec<String> {
    const SHAPE: [usize; 5] = [8, 4, 4, 4, 12];
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut start = 0;
    while start + 36 <= bytes.len() {
        let boundary_before =
            start == 0 || !(bytes[start - 1].is_ascii_hexdigit() || bytes[start - 1] == b'-');
        let boundary_after = bytes
            .get(start + 36)
            .is_none_or(|byte| !byte.is_ascii_hexdigit());
        let mut position = start;
        let mut shaped = true;
        for (group, length) in SHAPE.iter().enumerate() {
            if group > 0 {
                shaped &= bytes[position] == b'-';
                position += 1;
            }
            shaped &= bytes[position..position + length]
                .iter()
                .all(u8::is_ascii_hexdigit);
            position += length;
        }
        if shaped && boundary_before && boundary_after {
            found.push(line[start..start + 36].to_owned());
            start += 36;
        } else {
            start += 1;
        }
    }
    found
}

fn guid_allowed(guid: &str) -> bool {
    let lower = guid.to_ascii_lowercase();
    let synthetic = lower
        .strip_prefix("00000000-0000-4000-8000-0000000000")
        .is_some_and(|tail| tail.len() == 2);
    synthetic || ALLOWED_GUIDS.contains(&lower.as_str())
}

// Email addresses.

fn is_local_part_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}

fn is_domain_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn email_addresses(line: &str) -> Vec<String> {
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    for (at, _) in line.match_indices('@') {
        let mut start = at;
        while start > 0 && is_local_part_byte(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = at + 1;
        while end < bytes.len() && is_domain_byte(bytes[end]) {
            end += 1;
        }
        let local = line[start..at].trim_start_matches('.');
        let domain = line[at + 1..end].trim_end_matches(['.', '-']);
        if local.is_empty() || !domain.contains('.') {
            continue;
        }
        let top_level = domain.rsplit('.').next().unwrap_or_default();
        if top_level.len() < 2 || !top_level.bytes().all(|byte| byte.is_ascii_alphabetic()) {
            continue;
        }
        found.push(format!("{local}@{domain}"));
    }
    found
}

fn email_allowed(address: &str) -> bool {
    let domain = address
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_ascii_lowercase())
        .unwrap_or_default();
    domain == "example" || domain.ends_with(".example") || THREAD_DOMAINS.contains(&domain.as_str())
}

// URLs.

fn urls(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut search = 0;
    while let Some(offset) = lower[search..].find("http") {
        let start = search + offset;
        let rest = &lower[start..];
        let scheme_length = if rest.starts_with("https://") {
            8
        } else if rest.starts_with("http://") {
            7
        } else {
            search = start + 4;
            continue;
        };
        let end = line[start + scheme_length..]
            .find(|character: char| {
                character.is_whitespace()
                    || matches!(
                        character,
                        '"' | '\''
                            | '<'
                            | '>'
                            | '`'
                            | '('
                            | ')'
                            | '['
                            | ']'
                            | '{'
                            | '}'
                            | '\\'
                            | '|'
                    )
            })
            .map_or(line.len(), |offset| start + scheme_length + offset);
        let url = line[start..end].trim_end_matches(['.', ',', ';', ':', '!', '?', '*']);
        found.push(url.to_owned());
        search = end.max(start + scheme_length);
    }
    found
}

/// Splits a URL into its lower-cased host and its path.
fn host_and_path(url: &str) -> (String, String) {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host_port.split(':').next().unwrap_or_default();
    let rest = &after_scheme[authority_end..];
    let path = rest.split(['?', '#']).next().unwrap_or_default();
    (
        host.trim_end_matches('.').to_ascii_lowercase(),
        path.to_owned(),
    )
}

fn is_proxy_host(host: &str) -> bool {
    host.strip_suffix(".proxyservice.ediscovery.svc.cloud.microsoft")
        .is_some_and(|region| {
            !region.is_empty()
                && region
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// A delegated permission written as a Graph resource URI, such as
/// `/eDiscovery.ReadWrite.All`, or `/.default`.
fn is_scope_path(path: &str) -> bool {
    let Some(scope) = path.strip_prefix('/') else {
        return false;
    };
    scope == ".default"
        || (scope.contains('.')
            && !scope.starts_with('.')
            && !scope.ends_with('.')
            && scope.split('.').all(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphabetic())
            }))
}

fn url_allowed(url: &str) -> bool {
    let (host, path) = host_and_path(url);
    if host.is_empty() || host.contains(['$', '%']) {
        return true; // a template, such as https://<host>/ or ${HOST}
    }
    if host == "localhost" || host == "127.0.0.1" || host == "example" || host.ends_with(".example")
    {
        return true;
    }
    match host.as_str() {
        "graph.microsoft.com" => {
            path.is_empty()
                || path == "/"
                || path == "/v1.0"
                || path.starts_with("/v1.0/")
                || is_scope_path(&path)
        }
        "login.microsoftonline.com" | "learn.microsoft.com" | "aka.ms" => true,
        "github.com" => path == "/aberoham" || path.starts_with("/aberoham/"),
        "img.shields.io" => path.starts_with("/github/") && path.contains("/aberoham/"),
        _ if is_proxy_host(&host) => path.starts_with("/ediscovery/api/proxy/"),
        _ => false,
    }
}

// Home directories.

fn home_paths(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for prefix in ["/Users/", "/home/", "C:\\Users\\", "c:\\users\\"] {
        for (start, _) in line.match_indices(prefix) {
            let after = &line[start + prefix.len()..];
            let name: String = after
                .chars()
                .take_while(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
                })
                .collect();
            if !name.is_empty() {
                found.push(format!("{prefix}{name}"));
            }
        }
    }
    found
}

// Tests of the lint itself. Inputs that must be refused are joined from
// pieces, so the literal text of this file stays clean.

fn join(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn synthetic_and_constant_guids_pass_and_others_fail() {
    assert!(guid_allowed("00000000-0000-4000-8000-000000000001"));
    assert!(guid_allowed("00000000-0000-4000-8000-0000000000AB"));
    assert!(guid_allowed("B26E684C-5068-4120-A679-64A5D2C909D9"));
    let real_looking = join(&["3f2a9c1e", "-7b4d-4e0a-9c8f-", "1a2b3c4d5e6f"]);
    assert!(!guid_allowed(&real_looking));
    let near_synthetic = join(&["00000000-0000-4000-8000-", "000000000123"]);
    assert!(!guid_allowed(&near_synthetic));
    let findings = scan_text("x", &format!("id: {real_looking}."), &[]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].text, real_looking);
}

#[test]
fn guid_detection_needs_the_whole_shape_and_boundaries() {
    assert_eq!(
        guids("00000000-0000-4000-8000-000000000001"),
        ["00000000-0000-4000-8000-000000000001"]
    );
    assert!(guids("00000000-0000-4000-8000-00000000000").is_empty());
    assert!(guids("a00000000-0000-4000-8000-000000000001").is_empty());
    assert!(guids("00000000-0000-4000-8000-000000000001f").is_empty());
    assert!(guids("0000000-0000-4000-8000-000000000001").is_empty());
}

#[test]
fn only_example_addresses_pass() {
    assert!(email_addresses("alex@contoso.example")
        .iter()
        .all(|a| email_allowed(a)));
    assert!(email_addresses("<sam@fabrikam.example>")
        .iter()
        .all(|a| email_allowed(a)));
    let outside = join(&["alex", "@", "contoso.com"]);
    assert_eq!(
        email_addresses(&format!("mail {outside}, please")),
        [outside.as_str()]
    );
    assert!(!email_allowed(&outside));
    let lookalike = join(&["alex", "@", "contoso.example.net"]);
    assert!(!email_allowed(&lookalike));
    let thread = join(&["19:abc", "@", "thread.v2"]);
    assert!(email_addresses(&thread).iter().all(|a| email_allowed(a)));
}

#[test]
fn things_with_an_at_sign_that_are_not_addresses_are_ignored() {
    for text in [
        "\"@odata.nextLink\"",
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "crate@1.2.3",
        "user@localhost",
        "@ alone",
    ] {
        assert!(email_addresses(text).is_empty(), "{text}");
    }
}

#[test]
fn urls_pass_only_on_allowed_host_and_path_pairs() {
    let url = |rest: &str| join(&["https", "://", rest]);
    for allowed in [
        "graph.microsoft.com/v1.0/security/cases/ediscoveryCases",
        "graph.microsoft.com:443",
        "graph.microsoft.com/eDiscovery.ReadWrite.All",
        "graph.microsoft.com/.default",
        "login.microsoftonline.com/organizations/oauth2/v2.0/token",
        "eur.proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/exportaedblobFileResult",
        "learn.microsoft.com/graph/api/resources/ediscovery-ediscoverycase",
        "aka.ms/anything",
        "github.com/aberoham/ms-purview-cli",
        "img.shields.io/github/actions/workflow/status/aberoham/ms-purview-cli/ci.yml",
        "contoso.example/path",
        "localhost:8400/callback",
        "127.0.0.1/x",
    ] {
        assert!(url_allowed(&url(allowed)), "{allowed}");
    }
    for refused in [
        "graph.microsoft.com/beta/security/cases",
        "graph.microsoft.com/v1.0.evil",
        "github.com/someone-else/repo",
        "img.shields.io/badge/x",
        "eur.proxyservice.ediscovery.svc.cloud.microsoft/other",
        "proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/x",
        "a.b.proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/x",
        "contoso.com/",
        "example.com/",
        "graph.microsoft.com.evil.test/v1.0/",
    ] {
        assert!(!url_allowed(&url(refused)), "{refused}");
    }
    let with_user_information = url(&join(&["user", "@", "contoso.com.evil.test/"]));
    assert!(!url_allowed(&with_user_information));
}

#[test]
fn urls_are_cut_at_markdown_and_quote_boundaries() {
    let text = join(&[
        "[docs](",
        "https",
        "://github.com/aberoham/ms-purview-cli). and \"",
        "http",
        "://localhost/callback\"",
    ]);
    assert_eq!(
        urls(&text),
        [
            join(&["https", "://github.com/aberoham/ms-purview-cli"]),
            join(&["http", "://localhost/callback"]),
        ]
    );
    let bare = join(&["see ", "HTTPS", "://contoso.com"]);
    let found = urls(&bare);
    assert_eq!(found.len(), 1);
    assert!(!url_allowed(&found[0]));
}

#[test]
fn placeholders_are_not_urls_to_check() {
    let url = |rest: &str| join(&["https", "://", rest]);
    assert!(url_allowed(&url("")));
    assert!(url_allowed(&url("${HOST}/x")));
}

#[test]
fn home_directory_paths_are_refused_but_placeholders_pass() {
    let path = join(&["/", "Users", "/", "someone", "/notes.md"]);
    assert_eq!(home_paths(&path), [join(&["/", "Users", "/", "someone"])]);
    assert!(home_paths("/Users/<you>/Library").is_empty());
    let linux = join(&["/", "home", "/", "dev/proto.py"]);
    assert_eq!(home_paths(&linux).len(), 1);
}

#[test]
fn denylist_terms_match_case_insensitively_and_are_not_echoed() {
    let term = join(&["private", "-name"]);
    let findings = scan_text("x", "a PRIVATE-NAME b", &[term]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].text, "term 1");
}

#[test]
fn review_history_paths_are_in_scope() {
    assert!(is_scanned("docs/reviews/round-1.md"));
    assert!(is_scanned("tests/fixtures/graph/cases-list.json"));
    assert!(is_scanned("README.md"));
    assert!(!is_scanned("target/debug/x"));
    assert!(!is_scanned("Cargo.toml"));
}
