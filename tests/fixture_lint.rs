//! The public-data lint. This is a public repository, so tracked text may
//! hold only synthetic data and well-known Microsoft constants. The lint
//! scans `tests/`, `docs/`, `contrib/`, `src/`, `.github/ISSUE_TEMPLATE/`,
//! `README.md`, `SKILL.md`, `AGENTS.md`, `CHANGELOG.md`, `CONTRIBUTING.md`
//! and `SECURITY.md`, and fails on:
//!
//! - a globally unique identifier (GUID) that is neither synthetic
//!   (`00000000-0000-4000-8000-0000000000NN`) nor an allowed Microsoft
//!   constant;
//! - an email address outside `*.example`, internationalised ones included;
//! - a URL whose normalised host and path are not an allowed pair;
//! - a `docs/reviews/` directory, or an absolute path into a home directory
//!   (private notes and prototypes live there), in Unix or Windows form;
//! - a file that cannot be read as UTF-8 text;
//! - any term in the file named by `PURVIEW_LINT_DENYLIST`, when that
//!   variable is set. The file lives outside the repository and lists
//!   private names and path fragments a maintainer wants kept out, one per
//!   line; blank lines and lines starting with `#` are skipped.
//!
//! Each line is scanned as written, with JSON-escaped slashes undone, and
//! percent-decoded. The report names the file, line, column and rule, never
//! the matched value: the value is the private data the lint exists to keep
//! out of public CI logs. A file path that contains a deny-list term is
//! withheld too.
//!
//! Test inputs that must fail the lint are assembled at run time, so this
//! file passes its own scan.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCANNED_DIRECTORIES: &[&str] = &[
    "tests/",
    "docs/",
    "contrib/",
    "src/",
    ".github/ISSUE_TEMPLATE/",
];
const SCANNED_FILES: &[&str] = &[
    "README.md",
    "SKILL.md",
    "AGENTS.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
];

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

/// URL schemes the lint recognises.
const SCHEMES: &[&str] = &["https://", "http://", "wss://", "ws://"];

const RULE_GUID: &str = "GUID is neither synthetic nor an allowed constant";
const RULE_EMAIL: &str = "email address outside *.example";
const RULE_URL: &str = "URL host and path are not an allowed pair";
const RULE_HOME: &str = "absolute path into a home directory";
const RULE_DENY: &str = "term from PURVIEW_LINT_DENYLIST";
const RULE_REVIEWS: &str = "review history is private and must stay outside the published tree";
const RULE_UNREADABLE: &str = "file could not be read; the lint fails closed";
const RULE_NOT_UTF8: &str = "file is not UTF-8 text; the lint cannot check it";
const RULE_PRIVATE_PATH: &str =
    "file path holds data the lint refuses (a deny-list term, GUID, address, URL or home path)";

/// One finding. `value` is kept for de-duplication and tests and is never
/// rendered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    file: String,
    line: usize,
    /// 1-based character column in the line as written; 0 when the match
    /// was found only after decoding.
    column: usize,
    rule: &'static str,
    variant: &'static str,
    detail: String,
    value: String,
}

/// A deny-list term with its line number in the deny-list file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DenyTerm {
    line: usize,
    term: String,
}

#[test]
fn public_files_hold_only_synthetic_data() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = scanned_files(root);
    assert!(
        files.iter().any(|file| file == "docs/SPEC.md"),
        "the lint found none of the files it should scan"
    );
    let denylist = load_denylist();
    let findings = lint_files(root, &files, &denylist);
    assert!(findings.is_empty(), "{}", render(&findings, &denylist));
}

/// The production scan: the `docs/reviews/` check, then for each file its
/// path and its contents.
fn lint_files(root: &Path, files: &[String], denylist: &[DenyTerm]) -> Vec<Finding> {
    let mut findings = Vec::new();
    if root.join("docs/reviews").exists() {
        findings.push(file_finding("docs/reviews/", RULE_REVIEWS));
    }
    for file in files {
        if file.starts_with("docs/reviews/") {
            findings.push(file_finding(file, RULE_REVIEWS));
            continue;
        }
        if path_is_private(file, denylist) {
            findings.push(file_finding(file, RULE_PRIVATE_PATH));
        }
        match read_for_scan(&root.join(file)) {
            Ok(Some(text)) => findings.extend(scan_text(file, &text, denylist)),
            Ok(None) => {} // listed by git but deleted in the working tree
            Err(rule) => findings.push(file_finding(file, rule)),
        }
    }
    findings
}

fn file_finding(file: &str, rule: &'static str) -> Finding {
    Finding {
        file: file.to_owned(),
        line: 0,
        column: 0,
        rule,
        variant: "",
        detail: String::new(),
        value: String::new(),
    }
}

/// Reads a file as UTF-8 text. A missing file is `Ok(None)`; any other
/// failure is an error, so the lint never passes a file it did not read.
fn read_for_scan(path: &Path) -> Result<Option<String>, &'static str> {
    match std::fs::read(path) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| RULE_NOT_UTF8),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(RULE_UNREADABLE),
    }
}

/// Whether a file path itself holds something the lint refuses: a
/// deny-list term, or a match for any built-in rule. Such a path is a
/// finding of its own and is never shown.
fn path_is_private(file: &str, denylist: &[DenyTerm]) -> bool {
    !scan_text(file, file, denylist).is_empty()
}

/// The failure report: file, line, column and rule, never the matched
/// value, and no path that holds refused data.
fn render(findings: &[Finding], denylist: &[DenyTerm]) -> String {
    let mut sorted = findings.to_vec();
    sorted.sort();
    sorted.dedup();
    let lines: Vec<String> = sorted
        .iter()
        .map(|finding| {
            let file = if path_is_private(&finding.file, denylist) {
                "[path withheld: it holds data the lint refuses]".to_owned()
            } else {
                finding.file.clone()
            };
            let place = match (finding.line, finding.column) {
                (0, _) => file,
                (line, 0) => format!("{file}:{line}"),
                (line, column) => format!("{file}:{line}:{column}"),
            };
            format!(
                "  {place}: {}{}{}",
                finding.rule, finding.detail, finding.variant
            )
        })
        .collect();
    format!(
        "public-data lint: {} finding(s). Matched values are not shown; open each \
         location to see them.\n{}",
        lines.len(),
        lines.join("\n")
    )
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
        let entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|_| panic!("the lint could not list a directory; it fails closed"));
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|_| panic!("the lint could not list a directory entry"));
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
                _ => {
                    found.insert(relative);
                }
            }
        }
    }
    found
}

fn load_denylist() -> Vec<DenyTerm> {
    let Some(path) = std::env::var_os("PURVIEW_LINT_DENYLIST").filter(|value| !value.is_empty())
    else {
        return Vec::new();
    };
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("PURVIEW_LINT_DENYLIST names a file that cannot be read"));
    parse_denylist(&contents)
}

/// Terms, lower-cased, each with its 1-based line in the deny-list file.
fn parse_denylist(contents: &str) -> Vec<DenyTerm> {
    contents
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(line, term)| DenyTerm {
            line,
            term: term.to_lowercase(),
        })
        .collect()
}

/// The forms of a line the lint scans: as written, with JSON's `\/`
/// undone, and percent-decoded.
fn variants(line: &str) -> Vec<(&'static str, String)> {
    let mut forms = vec![("", line.to_owned())];
    if line.contains("\\/") {
        forms.push((" (in JSON-escaped text)", line.replace("\\/", "/")));
    }
    if line.contains('%') {
        let decoded = percent_decode_lossy(line);
        if decoded != line {
            forms.push((" (in percent-decoded text)", decoded.clone()));
            if decoded.contains('%') {
                let twice = percent_decode_lossy(&decoded);
                if twice != decoded {
                    forms.push((" (in percent-decoded text)", twice));
                }
            }
        }
    }
    forms
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                output.push(high * 16 + low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    output
}

fn percent_decode_lossy(text: &str) -> String {
    String::from_utf8_lossy(&percent_decode(text)).into_owned()
}

fn scan_text(file: &str, text: &str, denylist: &[DenyTerm]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let mut seen: BTreeSet<(&'static str, String)> = BTreeSet::new();
        for (variant, form) in variants(line) {
            let raw = variant.is_empty();
            let mut found = |rule: &'static str, start: usize, value: String, detail: String| {
                if !seen.insert((rule, value.clone())) {
                    return;
                }
                findings.push(Finding {
                    file: file.to_owned(),
                    line: index + 1,
                    column: if raw {
                        form[..start].chars().count() + 1
                    } else {
                        0
                    },
                    rule,
                    variant,
                    detail,
                    value,
                });
            };
            for (start, guid) in guids(&form) {
                if !guid_allowed(&guid) {
                    found(RULE_GUID, start, guid, String::new());
                }
            }
            for (start, address) in email_addresses(&form) {
                if !email_allowed(&address) {
                    found(RULE_EMAIL, start, address, String::new());
                }
            }
            for (start, url) in urls(&form) {
                if let UrlMatch::Url(url) = url {
                    if !url_allowed(&url) {
                        found(RULE_URL, start, url, String::new());
                    }
                }
            }
            for (start, path) in home_paths(&form) {
                found(RULE_HOME, start, path, String::new());
            }
            let lower = form.to_lowercase();
            for deny in denylist {
                if let Some(start) = lower.find(&deny.term) {
                    // `lower` can differ in length from `form`; the column is
                    // approximate for non-ASCII text.
                    let start = form.char_indices().nth(lower[..start].chars().count());
                    found(
                        RULE_DENY,
                        start.map_or(0, |(byte, _)| byte),
                        deny.term.clone(),
                        format!(" (deny-list line {})", deny.line),
                    );
                }
            }
        }
    }
    findings
}

// GUIDs.

/// GUID-shaped runs. Any character except a hex digit delimits one, so a
/// GUID inside `Reports-<guid>-x.zip` is found.
fn guids(line: &str) -> Vec<(usize, String)> {
    const SHAPE: [usize; 5] = [8, 4, 4, 4, 12];
    let bytes = line.as_bytes();
    let mut found = Vec::new();
    let mut start = 0;
    while start + 36 <= bytes.len() {
        let boundary_before = start == 0 || !bytes[start - 1].is_ascii_hexdigit();
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
            found.push((start, line[start..start + 36].to_owned()));
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

fn is_local_part_char(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '.' | '_' | '%' | '+' | '-')
}

fn is_domain_char(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '.' | '-')
}

/// Address-shaped runs around `@` or the full-width `＠`. Non-ASCII local
/// parts and domains count, so internationalised addresses are checked.
fn email_addresses(line: &str) -> Vec<(usize, String)> {
    let characters: Vec<(usize, char)> = line.char_indices().collect();
    let mut found = Vec::new();
    for (position, &(_, character)) in characters.iter().enumerate() {
        if character != '@' && character != '\u{FF20}' {
            continue;
        }
        let mut first = position;
        while first > 0 && is_local_part_char(characters[first - 1].1) {
            first -= 1;
        }
        let mut last = position + 1;
        while last < characters.len() && is_domain_char(characters[last].1) {
            last += 1;
        }
        while first < position && characters[first].1 == '.' {
            first += 1;
        }
        let local: String = characters[first..position]
            .iter()
            .map(|(_, character)| *character)
            .collect();
        let domain: String = characters[position + 1..last]
            .iter()
            .map(|(_, character)| *character)
            .collect::<String>()
            .trim_end_matches(['.', '-'])
            .to_owned();
        if local.is_empty() || !domain.contains('.') {
            continue;
        }
        let top_level = domain.rsplit('.').next().unwrap_or_default();
        if top_level.chars().count() < 2 || !top_level.chars().any(char::is_alphabetic) {
            continue;
        }
        found.push((characters[first].0, format!("{local}@{domain}")));
    }
    found
}

fn email_allowed(address: &str) -> bool {
    let domain = address
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_lowercase())
        .unwrap_or_default();
    domain == "example"
        || (domain.ends_with(".example") && domain.is_ascii())
        || THREAD_DOMAINS.contains(&domain.as_str())
}

// URLs.

#[derive(Debug, Clone, PartialEq, Eq)]
enum UrlMatch {
    /// A documented placeholder such as `https://<host>/` or
    /// `https://${HOST}/`.
    Placeholder,
    Url(String),
}

fn is_url_stop(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '"' | '\'' | '<' | '>' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        )
}

/// Every URL in the line, nested ones in a query or fragment included,
/// since the search resumes right after each scheme.
fn urls(line: &str) -> Vec<(usize, UrlMatch)> {
    let lower = line.to_ascii_lowercase();
    let mut found = Vec::new();
    let mut search = 0;
    while search < lower.len() {
        let next = SCHEMES
            .iter()
            .filter_map(|scheme| {
                lower[search..]
                    .find(scheme)
                    .map(|offset| (search + offset, scheme.len()))
            })
            .min();
        let Some((start, scheme_length)) = next else {
            break;
        };
        let after = &line[start + scheme_length..];
        if after.is_empty()
            || after.starts_with(['<', '{'])
            || after.starts_with("${")
            || (after.starts_with(is_url_stop) && !after.starts_with('['))
        {
            found.push((start, UrlMatch::Placeholder));
        } else {
            // A bracketed IPv6 host is a host, not a template: read past it.
            let skip = if after.starts_with('[') {
                after.find(']').map_or(after.len(), |close| close + 1)
            } else {
                0
            };
            let end = after[skip..]
                .find(is_url_stop)
                .map_or(line.len(), |offset| start + scheme_length + skip + offset);
            let url = line[start..end].trim_end_matches(['.', ',', ';', ':', '!', '?', '*']);
            found.push((start, UrlMatch::Url(url.to_owned())));
        }
        search = start + scheme_length;
    }
    found
}

/// A URL's lower-cased host and its normalised path segments, or `None`
/// when either cannot be read safely: a host with characters outside
/// `[a-z0-9.-]` (including `%`, `$` and non-ASCII), a non-numeric port, a
/// path that does not percent-decode to UTF-8, or a `..` above the root.
fn host_and_segments(url: &str) -> Option<(String, Vec<String>)> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority_end = after_scheme
        .find(['/', '?', '#', '\\'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (host, port) = match host_port.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (host_port, None),
    };
    if port.is_some_and(|port| !port.is_empty() && !port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    {
        return None;
    }
    let rest = &after_scheme[authority_end..];
    let raw_path = rest.split(['?', '#']).next().unwrap_or_default();
    let decoded = String::from_utf8(percent_decode(raw_path)).ok()?;
    if decoded.contains('%') {
        return None; // encoded twice
    }
    let mut segments: Vec<String> = Vec::new();
    for segment in decoded.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other.to_owned()),
        }
    }
    Some((host, segments))
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
/// `eDiscovery.ReadWrite.All`, or `.default`.
fn is_scope_segment(scope: &str) -> bool {
    scope == ".default"
        || (scope.contains('.')
            && scope.split('.').all(|part| {
                !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_alphabetic())
            }))
}

/// The repositories whose Shields badges may appear, as exact
/// (owner, repository) pairs.
const SHIELDS_REPOSITORIES: &[(&str, &str)] =
    &[("aberoham", "ms-purview-cli"), ("aberoham", "ms-entra-cli")];

/// A Shields `/github/…` badge passes only when an allowed owner and its
/// repository appear as consecutive path segments. Route words are not
/// parsed; any other badge is refused.
fn is_own_shields_badge(segments: &[String]) -> bool {
    segments.first().map(String::as_str) == Some("github")
        && segments[1..].windows(2).any(|pair| {
            SHIELDS_REPOSITORIES.iter().any(|(owner, repository)| {
                pair[0].eq_ignore_ascii_case(owner) && pair[1].eq_ignore_ascii_case(repository)
            })
        })
}

fn url_allowed(url: &str) -> bool {
    let Some((host, segments)) = host_and_segments(url) else {
        return false;
    };
    let first = |name: &str| {
        segments
            .first()
            .is_some_and(|segment| segment.eq_ignore_ascii_case(name))
    };
    if host == "localhost" || host == "127.0.0.1" || host == "example" || host.ends_with(".example")
    {
        return true;
    }
    match host.as_str() {
        "graph.microsoft.com" => {
            segments.is_empty()
                || segments[0] == "v1.0"
                || (segments.len() == 1 && is_scope_segment(&segments[0]))
        }
        "login.microsoftonline.com" | "learn.microsoft.com" | "aka.ms" => true,
        "github.com" => first("aberoham"),
        "img.shields.io" => is_own_shields_badge(&segments),
        // Apple's public Developer ID G2 intermediate, which the release
        // signer imports (docs/macos-signing.md). Only that one file.
        "www.apple.com" => segments == ["certificateauthority", "DeveloperIDG2CA.cer"],
        _ if is_proxy_host(&host) => {
            segments.len() > 3
                && segments[0] == "ediscovery"
                && segments[1] == "api"
                && segments[2] == "proxy"
        }
        _ => false,
    }
}

// Home directories.

fn is_name_char(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '.' | '_' | '-')
}

fn name_after(text: &str) -> Option<String> {
    let name: String = text.chars().take_while(|c| is_name_char(*c)).collect();
    (!name.is_empty()).then_some(name)
}

/// Absolute paths into a home directory: `/Users/<name>` and
/// `/home/<name>`, and `X:\Users\<name>` in any case, with any drive
/// letter, with `/`, `\` or an escaped `\\` as separator. A placeholder such
/// as `/Users/<you>` passes.
fn home_paths(line: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for prefix in ["/Users/", "/home/"] {
        for (start, _) in line.match_indices(prefix) {
            if let Some(name) = name_after(&line[start + prefix.len()..]) {
                found.push((start, format!("{prefix}{name}")));
            }
        }
    }
    let bytes = line.as_bytes();
    for (start, _) in line.match_indices(':') {
        if start == 0 || !bytes[start - 1].is_ascii_alphabetic() {
            continue;
        }
        if start >= 2 && bytes[start - 2].is_ascii_alphanumeric() {
            continue; // part of a longer word, such as `https:`
        }
        let mut rest = &line[start + 1..];
        let separator = |text: &str| -> Option<usize> {
            if text.starts_with("\\\\") {
                Some(2)
            } else if text.starts_with(['\\', '/']) {
                Some(1)
            } else {
                None
            }
        };
        let Some(skip) = separator(rest) else {
            continue;
        };
        rest = &rest[skip..];
        if !rest
            .as_bytes()
            .get(..5)
            .is_some_and(|word| word.eq_ignore_ascii_case(b"users"))
        {
            continue;
        }
        rest = &rest[5..]; // the five bytes are ASCII, so this is a boundary
        let Some(skip) = separator(rest) else {
            continue;
        };
        if let Some(name) = name_after(&rest[skip..]) {
            found.push((start - 1, format!("users path {name}")));
        }
    }
    found
}

// Tests of the lint itself. Inputs that must be refused are joined from
// pieces, so the literal text of this file stays clean.

fn join(parts: &[&str]) -> String {
    parts.concat()
}

fn values(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.value.as_str()).collect()
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
}

#[test]
fn guid_detection_needs_the_whole_shape_and_a_non_hex_boundary() {
    let guid = "00000000-0000-4000-8000-000000000001";
    assert_eq!(guids(guid), [(0, guid.to_owned())]);
    assert!(guids("00000000-0000-4000-8000-00000000000").is_empty());
    assert!(guids("a00000000-0000-4000-8000-000000000001").is_empty());
    assert!(guids("00000000-0000-4000-8000-000000000001f").is_empty());
    assert!(guids("0000000-0000-4000-8000-000000000001").is_empty());
    let real = join(&["3f2a9c1e", "-7b4d-4e0a-9c8f-", "1a2b3c4d5e6f"]);
    for text in [
        join(&["case-", &real]),
        join(&["Reports-", &real, "-x.zip"]),
        join(&["{", &real, "}"]),
        join(&["id_", &real]),
    ] {
        assert_eq!(
            values(&scan_text("f", &text, &[])),
            [real.as_str()],
            "{text}"
        );
    }
}

#[test]
fn addresses_are_extracted_exactly_and_only_example_passes() {
    assert_eq!(
        email_addresses("to alex@contoso.example."),
        [(3, "alex@contoso.example".to_owned())]
    );
    let outside = join(&["alex", "@", "contoso.com"]);
    assert_eq!(
        email_addresses(&format!("mail {outside}, please")),
        [(5, outside.clone())]
    );
    assert!(!email_allowed(&outside));
    assert!(email_allowed("sam@fabrikam.example"));
    assert!(email_allowed("SAM@FABRIKAM.EXAMPLE"));
    let lookalike = join(&["alex", "@", "contoso.example.net"]);
    assert!(!email_allowed(&lookalike));
    let thread = join(&["19:abc", "@", "thread.v2"]);
    assert_eq!(
        email_addresses(&thread),
        [(3, join(&["abc", "@", "thread.v2"]))]
    );
    assert!(email_allowed(&join(&["abc", "@", "thread.v2"])));
}

#[test]
fn internationalised_and_encoded_addresses_are_checked() {
    let idn = join(&["josé", "@", "bücher.de"]);
    assert_eq!(values(&scan_text("f", &idn, &[])), [idn.as_str()]);
    let wide = join(&["alex", "\u{FF20}", "contoso.com"]);
    assert_eq!(scan_text("f", &wide, &[]).len(), 1);
    let encoded = join(&["mailto:alex", "%40", "contoso.com"]);
    let findings = scan_text("f", &encoded, &[]);
    assert_eq!(
        values(&findings),
        [join(&["alex", "@", "contoso.com"]).as_str()]
    );
    assert_eq!(findings[0].column, 0);
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
        "www.apple.com/certificateauthority/DeveloperIDG2CA.cer",
        "github.com/aberoham/ms-purview-cli",
        "github.com/Aberoham/ms-purview-cli",
        "img.shields.io/github/actions/workflow/status/aberoham/ms-purview-cli/ci.yml",
        "contoso.example/path",
        "localhost:8400/callback",
        "127.0.0.1/x",
    ] {
        assert!(url_allowed(&url(allowed)), "{allowed}");
    }
    for allowed in [
        "img.shields.io/github/v/release/aberoham/ms-purview-cli",
        "img.shields.io/github/license/aberoham/ms-purview-cli",
        "img.shields.io/github/commit-activity/m/aberoham/ms-purview-cli",
        "img.shields.io/github/actions/workflow/status/aberoham/ms-entra-cli/ci.yml",
    ] {
        assert!(url_allowed(&url(allowed)), "{allowed}");
    }
    for refused in [
        "graph.microsoft.com/beta/security/cases",
        "graph.microsoft.com/v1.0.evil",
        "graph.microsoft.com/v1.0/../beta/security",
        "graph.microsoft.com/v1.0/%2e%2e/beta",
        "graph.microsoft.com/v1.0%2f..%2fbeta",
        "graph.microsoft.com/v1.0/%252e%252e/beta",
        "graph.microsoft.com/..",
        "github.com/someone-else/repo",
        "www.apple.com/",
        "www.apple.com/certificateauthority/",
        "www.apple.com/certificateauthority/AppleWWDRCAG3.cer",
        "www.apple.com/certificateauthority/DeveloperIDG2CA.cer/x",
        "apple.com/certificateauthority/DeveloperIDG2CA.cer",
        "github.com/aberoham/../someone-else",
        "img.shields.io/badge/x",
        "img.shields.io/github/stars/other-owner/aberoham",
        "img.shields.io/github/actions/workflow/status/status/aberoham/ci.yml",
        "img.shields.io/github/downloads/actions/aberoham/total",
        "img.shields.io/github/license/aberoham",
        "img.shields.io/github/license/aberoham/other-repository",
        "img.shields.io/badge/aberoham/ms-purview-cli",
        "[::1]/x",
        "[2001:db8::1]:8443/x",
        "eur.proxyservice.ediscovery.svc.cloud.microsoft/other",
        "proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/x",
        "a.b.proxyservice.ediscovery.svc.cloud.microsoft/ediscovery/api/proxy/x",
        "contoso.com/",
        "example.com/",
        "graph.microsoft.com.evil.test/v1.0/",
        "intranet$corp.test/",
        "intranet%2ecorp.test/",
        "bücher.de/",
        "graph.microsoft.com:x443/v1.0/",
    ] {
        assert!(!url_allowed(&url(refused)), "{refused}");
    }
    let with_user_information = url(&join(&["user", "@", "contoso.com.evil.test/"]));
    assert!(!url_allowed(&with_user_information));
}

#[test]
fn urls_are_cut_at_markdown_and_quote_boundaries_and_nested_ones_are_found() {
    let text = join(&[
        "[docs](",
        "https",
        "://github.com/aberoham/ms-purview-cli). and \"",
        "http",
        "://localhost/callback\"",
    ]);
    let found: Vec<UrlMatch> = urls(&text).into_iter().map(|(_, url)| url).collect();
    assert_eq!(
        found,
        [
            UrlMatch::Url(join(&["https", "://github.com/aberoham/ms-purview-cli"])),
            UrlMatch::Url(join(&["http", "://localhost/callback"])),
        ]
    );
    let nested = join(&[
        "https",
        "://login.microsoftonline.com/x?redirect=",
        "https",
        "://intranet.corp.test/y",
    ]);
    let findings = scan_text("f", &nested, &[]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule, RULE_URL);
    let escaped = join(&["\"", "https", ":\\/\\/intranet.corp.test\\/y\""]);
    assert_eq!(scan_text("f", &escaped, &[]).len(), 1);
    let encoded = join(&[
        "https",
        "://aka.ms/x?u=",
        "https",
        "%3A%2F%2Fintranet.corp.test%2Fy",
    ]);
    assert_eq!(scan_text("f", &encoded, &[]).len(), 1);
}

#[test]
fn only_documented_placeholders_skip_the_url_check() {
    for rest in ["<host>/x", "{host}/x", "${HOST}/x", ""] {
        let line = join(&["https", "://", rest]);
        assert_eq!(urls(&line), [(0, UrlMatch::Placeholder)], "{rest}");
    }
    for rest in ["$HOST/x", "%HOST%/x"] {
        let line = join(&["https", "://", rest]);
        assert_eq!(scan_text("f", &line, &[]).len(), 1, "{rest}");
    }
}

#[test]
fn home_directory_paths_are_refused_in_every_form() {
    let refused = [
        join(&["/", "Users", "/", "someone", "/notes.md"]),
        join(&["/", "home", "/", "dev/proto.py"]),
        join(&["C", ":\\", "Users", "\\", "someone"]),
        join(&["\"C", ":\\\\", "Users", "\\\\", "someone\""]),
        join(&["c", ":/", "users", "/", "someone"]),
        join(&["D", ":\\", "USERS", "\\", "someone"]),
        join(&["/", "Users", "/", "zoë/x"]),
    ];
    for text in &refused {
        assert_eq!(home_paths(text).len(), 1, "{text}");
        assert_eq!(scan_text("f", text, &[]).len(), 1, "{text}");
    }
    for text in [
        "/Users/<you>/Library",
        "/home/$USER/x",
        "C:\\Users\\<you>",
        "https://example/x",
        "%USERPROFILE%\\x",
    ] {
        assert!(home_paths(text).is_empty(), "{text}");
    }
}

#[test]
fn a_bracketed_host_is_checked_not_skipped() {
    let line = join(&["see ", "https", "://[2001:db8::1]/x"]);
    assert_eq!(urls(&line).len(), 1);
    assert!(matches!(urls(&line)[0].1, UrlMatch::Url(_)));
    assert_eq!(scan_text("f", &line, &[]).len(), 1);
}

#[test]
fn multibyte_text_after_a_drive_letter_does_not_panic() {
    for text in [
        join(&["D", ":/abcdé/fixture"]),
        join(&["D", ":\\é", "users"]),
        join(&["x", ":/", "usé"]),
    ] {
        assert!(home_paths(&text).is_empty(), "{text}");
        assert!(scan_text("f", &text, &[]).is_empty(), "{text}");
    }
    let named = join(&["D", ":/", "Users", "/", "zoë"]);
    assert!(!home_paths(&named).is_empty());
}

/// A file whose name holds refused data and whose contents are clean is
/// still a finding, through the production scan loop.
#[test]
fn a_refused_file_name_with_clean_contents_fails_the_scan() {
    let dir = tempfile::tempdir().unwrap();
    let guid = join(&["3f2a9c1e", "-7b4d-4e0a-9c8f-", "1a2b3c4d5e6f"]);
    let name = join(&["fixture-", &guid, ".json"]);
    std::fs::write(dir.path().join(&name), "{}").unwrap();
    std::fs::write(dir.path().join("clean.json"), "{}").unwrap();
    let findings = lint_files(dir.path(), &[name, "clean.json".to_owned()], &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule, RULE_PRIVATE_PATH);
    assert!(!render(&findings, &[]).contains(&guid));
}

/// With no deny list, a file whose name holds a value a built-in rule
/// refuses is reported without showing the name.
#[test]
fn a_path_holding_refused_data_is_withheld_with_an_empty_deny_list() {
    let guid = join(&["3f2a9c1e", "-7b4d-4e0a-9c8f-", "1a2b3c4d5e6f"]);
    let address = join(&["alex", "@", "contoso.com"]);
    for name in [
        join(&["tests/fixtures/", &guid, ".json"]),
        join(&["docs/", &address, ".md"]),
    ] {
        assert!(path_is_private(&name, &[]));
        let mut findings = scan_text(&name, &join(&["id ", &guid, "\n"]), &[]);
        findings.push(file_finding(&name, RULE_PRIVATE_PATH));
        let report = render(&findings, &[]);
        assert!(!report.contains(&guid), "{report}");
        assert!(!report.contains(&address), "{report}");
        assert!(report.contains("[path withheld"), "{report}");
    }
    assert!(!path_is_private(
        "tests/fixtures/graph/cases-list.json",
        &[]
    ));
}

#[test]
fn deny_list_terms_keep_their_file_line_numbers() {
    let parsed = parse_denylist(&join(&[
        "# private terms\n\n",
        "First-Term\n",
        "  \n",
        "second\n",
    ]));
    assert_eq!(
        parsed,
        [
            DenyTerm {
                line: 3,
                term: "first-term".into()
            },
            DenyTerm {
                line: 5,
                term: "second".into()
            },
        ]
    );
}

/// A complete file with several rules firing on one line: the rendered
/// report names locations and rules and never a matched value, a deny-list
/// term, or a path that contains one.
#[test]
fn the_report_never_shows_matched_values_or_deny_list_terms() {
    let term = join(&["private", "-name"]);
    let address = join(&["alex", "@", "private-name.test"]);
    let guid = join(&["3f2a9c1e", "-7b4d-4e0a-9c8f-", "1a2b3c4d5e6f"]);
    let url = join(&["https", "://private-name.test/notes"]);
    let home = join(&["/", "Users", "/", "private-name"]);
    let file = join(&[
        "line one is clean\n",
        "see ",
        &address,
        " and ",
        &guid,
        " at ",
        &url,
        " in ",
        &home,
        "\n",
    ]);
    let denylist = parse_denylist(&join(&["# comment\n", &term, "\n"]));
    let path = join(&["docs/", &term, ".md"]);
    let mut findings = scan_text(&path, &file, &denylist);
    let rules: BTreeSet<&str> = findings.iter().map(|f| f.rule).collect();
    assert_eq!(
        rules,
        BTreeSet::from([RULE_EMAIL, RULE_GUID, RULE_URL, RULE_HOME, RULE_DENY])
    );
    assert!(findings.iter().all(|f| f.line == 2));
    findings.push(file_finding(&path, RULE_PRIVATE_PATH));
    let report = render(&findings, &denylist);
    for secret in [&term, &address, &guid, &url, &home, &path] {
        assert!(
            !report.to_lowercase().contains(&secret.to_lowercase()),
            "{report}"
        );
    }
    assert!(report.contains("deny-list line 2"), "{report}");
    assert!(report.contains("[path withheld"), "{report}");
    assert!(report.contains(":2:5: email address"), "{report}");
}

#[test]
fn unreadable_and_non_utf8_files_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("binary.json");
    std::fs::write(&binary, [0xff, 0xfe, 0x00, 0x41]).unwrap();
    assert_eq!(read_for_scan(&binary), Err(RULE_NOT_UTF8));
    assert_eq!(read_for_scan(dir.path()), Err(RULE_UNREADABLE));
    assert_eq!(read_for_scan(&dir.path().join("missing")), Ok(None));
    let text = dir.path().join("text.md");
    std::fs::write(&text, "fine").unwrap();
    assert_eq!(read_for_scan(&text), Ok(Some("fine".into())));
}

#[test]
fn review_history_paths_are_in_scope() {
    assert!(is_scanned("docs/reviews/round-1.md"));
    assert!(is_scanned("tests/fixtures/graph/cases-list.json"));
    assert!(is_scanned("README.md"));
    assert!(!is_scanned("target/debug/x"));
    assert!(!is_scanned("Cargo.toml"));
}
