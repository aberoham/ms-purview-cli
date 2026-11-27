//! Local file names for server file names (`docs/SPEC.md` section 4.7.1).
//!
//! Server file names embed case, search and export names (Observed), so
//! they can be long and hold any character. A local name:
//!
//! - keeps the extension (`.zip`);
//! - has `/ \ < > : " | ? *`, control characters, and leading or trailing
//!   dots and spaces of the stem replaced with `_`;
//! - gets `_` before a Windows reserved name;
//! - fits `MAX_NAME_BYTES`, the stem cut on a character boundary and
//!   followed by `~` and 8 hexadecimal characters of the SHA-256 of the
//!   original name when it is cut;
//! - is a single normal path component.
//!
//! Two files of one operation whose names map to the same local name
//! (compared without regard to case, as on the default macOS and Windows
//! file systems) both get the hash suffix.

use std::collections::HashMap;
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

/// The longest local file name, in bytes.
pub const MAX_NAME_BYTES: usize = 200;

/// The longest extension kept apart from the stem, the dot included.
const MAX_EXTENSION_BYTES: usize = 16;

/// `~` and 8 hexadecimal characters.
const SUFFIX_BYTES: usize = 9;

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// The local names for one operation's server names, in the same order.
/// `None` for a name that cannot be made into a local one: two files with
/// the very same server name, which no suffix can tell apart.
pub fn local_names(originals: &[&str]) -> Vec<Option<String>> {
    let plain: Vec<String> = originals
        .iter()
        .map(|name| local_name(name, false))
        .collect();
    let mut seen: HashMap<String, usize> = HashMap::new();
    for name in &plain {
        *seen.entry(name.to_lowercase()).or_default() += 1;
    }
    let mut exact: HashMap<&str, usize> = HashMap::new();
    for original in originals {
        *exact.entry(original).or_default() += 1;
    }
    originals
        .iter()
        .zip(plain)
        .map(|(original, name)| {
            if exact.get(original).copied().unwrap_or(0) > 1 {
                None
            } else if seen.get(&name.to_lowercase()).copied().unwrap_or(0) > 1 {
                Some(local_name(original, true))
            } else {
                Some(name)
            }
        })
        .collect()
}

/// The local name for one server name; `suffixed` adds the hash suffix
/// whether or not the name was cut.
pub fn local_name(original: &str, suffixed: bool) -> String {
    let (stem, extension) = split(original);
    let mut stem: String = stem.chars().map(replace).collect();
    let extension: String = extension.chars().map(replace).collect();
    stem = edge_dots_and_spaces(&stem);
    if stem.is_empty() {
        stem.push('_');
    }
    if is_reserved(&stem) {
        stem.insert(0, '_');
    }
    let cut = stem.len() + extension.len() > MAX_NAME_BYTES;
    if cut || suffixed {
        let room = MAX_NAME_BYTES - extension.len() - SUFFIX_BYTES;
        let mut end = room.min(stem.len());
        while !stem.is_char_boundary(end) {
            end -= 1;
        }
        stem.truncate(end);
        stem.push('~');
        stem.push_str(&short_hash(original));
    }
    let name = format!("{stem}{extension}");
    debug_assert!(is_single_component(&name));
    name
}

/// Whether `name` is one normal path component: no separator, no `.` or
/// `..`, no root or prefix.
pub fn is_single_component(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(part)), None) if part == name
    ) && !name.contains(['/', '\\'])
}

/// The stem and the extension, dot included. The extension is the part
/// after the last dot when it is short and alphanumeric (`.zip`, `.csv`);
/// otherwise the whole name is the stem.
fn split(original: &str) -> (&str, &str) {
    match original.rfind('.') {
        Some(dot) if dot > 0 => {
            let extension = &original[dot..];
            if extension.len() > 1
                && extension.len() <= MAX_EXTENSION_BYTES
                && extension[1..].chars().all(|c| c.is_ascii_alphanumeric())
            {
                (&original[..dot], extension)
            } else {
                (original, "")
            }
        }
        _ => (original, ""),
    }
}

fn replace(c: char) -> char {
    if matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*') || c.is_control() {
        '_'
    } else {
        c
    }
}

/// Leading and trailing dots and spaces become `_`, one for one.
fn edge_dots_and_spaces(stem: &str) -> String {
    let edge = |c: char| c == '.' || c == ' ';
    let leading = stem.chars().take_while(|c| edge(*c)).count();
    let total = stem.chars().count();
    if leading == total {
        return "_".repeat(total);
    }
    let trailing = stem.chars().rev().take_while(|c| edge(*c)).count();
    stem.chars()
        .enumerate()
        .map(|(index, c)| {
            if index < leading || index >= total - trailing {
                '_'
            } else {
                c
            }
        })
        .collect()
}

/// A Windows reserved device name, which Windows also reads in `CON.txt`
/// and `con .zip`: the part before the first dot, without trailing spaces,
/// in any case.
fn is_reserved(stem: &str) -> bool {
    let base = stem.split('.').next().unwrap_or(stem).trim_end_matches(' ');
    RESERVED
        .iter()
        .any(|reserved| base.eq_ignore_ascii_case(reserved))
}

fn short_hash(original: &str) -> String {
    let digest = Sha256::digest(original.as_bytes());
    digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_name_is_kept() {
        assert_eq!(
            local_name("Estimate report - Orders 2026.zip", false),
            "Estimate report - Orders 2026.zip"
        );
    }

    #[test]
    fn windows_characters_and_control_characters_are_replaced() {
        assert_eq!(
            local_name("a/b\\c<d>e:f\"g|h?i*j\u{7}k.zip", false),
            "a_b_c_d_e_f_g_h_i_j_k.zip"
        );
    }

    #[test]
    fn leading_and_trailing_dots_and_spaces_are_replaced() {
        assert_eq!(local_name("..hidden.zip", false), "__hidden.zip");
        assert_eq!(local_name(" name .zip", false), "_name_.zip");
        assert_eq!(local_name("..", false), "__");
        assert_eq!(local_name(".", false), "_");
        assert_eq!(local_name("", false), "_");
        assert_eq!(local_name("name.", false), "name_");
    }

    #[test]
    fn reserved_names_get_a_prefix() {
        assert_eq!(local_name("CON.zip", false), "_CON.zip");
        assert_eq!(local_name("lpt9.zip", false), "_lpt9.zip");
        assert_eq!(local_name("com1.tar.zip", false), "_com1.tar.zip");
        assert_eq!(local_name("CONSOLE.zip", false), "CONSOLE.zip");
    }

    #[test]
    fn a_long_name_is_cut_on_a_character_boundary_and_keeps_its_extension() {
        let original = format!("{}.zip", "é".repeat(300));
        let name = local_name(&original, false);
        assert!(name.len() <= MAX_NAME_BYTES, "{}", name.len());
        assert!(name.ends_with(&format!("~{}.zip", short_hash(&original))));
        // Two-byte characters: the cut never splits one.
        assert!(name.starts_with("éé"));
        let exact = format!("{}.zip", "a".repeat(MAX_NAME_BYTES - 4));
        assert_eq!(local_name(&exact, false), exact);
        let over = format!("{}.zip", "a".repeat(MAX_NAME_BYTES - 3));
        assert_eq!(local_name(&over, false).len(), MAX_NAME_BYTES);
    }

    #[test]
    fn an_odd_extension_stays_in_the_stem() {
        assert_eq!(local_name("report.2026 final", false), "report.2026 final");
        assert_eq!(local_name("x.a b", false), "x.a b");
    }

    #[test]
    fn colliding_names_both_get_the_suffix_and_identical_ones_are_refused() {
        let names = local_names(&["a:b.zip", "a?b.zip", "A_B.zip", "c.zip"]);
        let suffixed: Vec<&String> = names.iter().take(3).map(|n| n.as_ref().unwrap()).collect();
        assert!(suffixed
            .iter()
            .all(|name| name.starts_with("a_b~") || name.starts_with("A_B~")));
        assert_ne!(suffixed[0], suffixed[1]);
        assert_eq!(names[3].as_deref(), Some("c.zip"));
        let same = local_names(&["x.zip", "x.zip", "y.zip"]);
        assert_eq!(same, vec![None, None, Some("y.zip".to_owned())]);
    }

    #[test]
    fn every_result_is_one_normal_component() {
        for original in [
            "../../etc/passwd",
            "a/../b",
            "C:\\x",
            "\\\\server\\share",
            "..\\..",
        ] {
            let name = local_name(original, false);
            assert!(is_single_component(&name), "{name}");
        }
        assert!(!is_single_component("a/b"));
        assert!(!is_single_component(".."));
    }
}
