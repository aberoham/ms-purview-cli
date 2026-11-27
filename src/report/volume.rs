//! The volume warning of `estimate`: `volume` in `config.json`
//! (`docs/SPEC.md` section 6.9).
//!
//! An estimate whose counts pass a limit is reported, on stderr and as
//! `volume` in the result, so that a person decides before a report or an
//! export collects it. The defaults, and their evidence:
//!
//! - `warn_hits`, 5,000 estimated items: the working threshold that a team
//!   running subject access requests reported on issue #15 (Assumption for
//!   other tenants).
//! - `warn_hits_per_location`, 1,000 hits in one location: one mailbox
//!   holding that many hits usually means the query matches a person's
//!   own name or address (Assumption).
//! - `max_export_size`, 10 GiB of `indexedItemsSize`: the size threshold
//!   of the same report. An export held items on the order of gigabytes
//!   for a few thousand items (Observed), and, with Teams context on,
//!   about four times the estimated count (Observed, one run), so an
//!   export can be several times larger than this size.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::estimate::Locations;
use crate::error::{PurviewError, Result};

pub const DEFAULT_WARN_HITS: u64 = 5_000;
pub const DEFAULT_WARN_HITS_PER_LOCATION: u64 = 1_000;
pub const DEFAULT_MAX_EXPORT_SIZE: u64 = 10 << 30;

/// The limits, from `config.json`'s `volume`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeLimits {
    pub warn_hits: u64,
    pub warn_hits_per_location: u64,
    pub max_export_size: u64,
}

impl Default for VolumeLimits {
    fn default() -> Self {
        Self {
            warn_hits: DEFAULT_WARN_HITS,
            warn_hits_per_location: DEFAULT_WARN_HITS_PER_LOCATION,
            max_export_size: DEFAULT_MAX_EXPORT_SIZE,
        }
    }
}

impl VolumeLimits {
    /// Reads `volume`. A missing or `null` object or key keeps the
    /// default; any other value of the wrong type is an error, which names
    /// the key and never repeats the value.
    pub fn from_config(extra: &BTreeMap<String, Value>) -> Result<Self> {
        let volume = match extra.get("volume") {
            None | Some(Value::Null) => return Ok(Self::default()),
            Some(Value::Object(volume)) => volume,
            Some(_) => {
                return Err(PurviewError::message(
                    "config.json: volume must be an object",
                ))
            }
        };
        let get = |key: &str| volume.get(key).filter(|value| !value.is_null());
        let count = |key: &str, default: u64| -> Result<u64> {
            match get(key) {
                None => Ok(default),
                Some(value) => value.as_u64().filter(|count| *count > 0).ok_or_else(|| {
                    PurviewError::message(format!(
                        "config.json: volume.{key} must be a positive whole number"
                    ))
                }),
            }
        };
        let max_export_size = match get("max_export_size") {
            None => DEFAULT_MAX_EXPORT_SIZE,
            Some(value) => value
                .as_str()
                .and_then(crate::download::parse_size)
                .ok_or_else(|| {
                    PurviewError::message(
                        "config.json: volume.max_export_size must be a size such as 10GiB",
                    )
                })?,
        };
        Ok(Self {
            warn_hits: count("warn_hits", DEFAULT_WARN_HITS)?,
            warn_hits_per_location: count(
                "warn_hits_per_location",
                DEFAULT_WARN_HITS_PER_LOCATION,
            )?,
            max_export_size,
        })
    }
}

/// One limit that the estimate passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Over {
    /// The key under `volume`.
    pub setting: &'static str,
    /// The estimate's value: items, the largest location's hits, or bytes.
    pub value: u64,
    pub limit: u64,
    /// For `warn_hits_per_location`, how many locations passed it.
    pub locations: Option<usize>,
}

/// What the volume check found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Volume {
    pub limits: Option<VolumeLimits>,
    pub over: Vec<Over>,
    /// The keys that could not be checked in full, for want of a count.
    /// A limit can be both passed and unchecked: some locations' hits
    /// passed it, and others' could not be read.
    pub unchecked: Vec<&'static str>,
}

impl Volume {
    /// Checks the estimate's item count and size, and the hits of each
    /// row of `Locations-*.csv` when the zip was read. `duplicated` says
    /// the zip held a second Locations file, which was not read.
    pub fn check(
        limits: VolumeLimits,
        items: Option<u64>,
        size: Option<u64>,
        locations: Option<&Locations>,
        duplicated: bool,
    ) -> Self {
        let mut volume = Self {
            limits: Some(limits),
            ..Self::default()
        };
        match items {
            Some(items) if items > limits.warn_hits => volume.over.push(Over {
                setting: "warn_hits",
                value: items,
                limit: limits.warn_hits,
                locations: None,
            }),
            Some(_) => {}
            None => volume.unchecked.push("warn_hits"),
        }
        match locations {
            Some(locations) => {
                let over: Vec<u64> = locations
                    .rows
                    .iter()
                    .filter_map(|row| row.count)
                    .filter(|count| *count > limits.warn_hits_per_location)
                    .collect();
                if let Some(largest) = over.iter().max() {
                    volume.over.push(Over {
                        setting: "warn_hits_per_location",
                        value: *largest,
                        limit: limits.warn_hits_per_location,
                        locations: Some(over.len()),
                    });
                }
                // A location whose hits are not known, such as a failed
                // one, a row without a location, a file without `Count`,
                // or a second file, may pass the limit unseen.
                if duplicated
                    || locations.missing_columns.contains(&"Count")
                    || locations.unusable_rows > 0
                    || locations.rows.iter().any(|row| row.count.is_none())
                {
                    volume.unchecked.push("warn_hits_per_location");
                }
            }
            None => volume.unchecked.push("warn_hits_per_location"),
        }
        match size {
            Some(size) if size > limits.max_export_size => volume.over.push(Over {
                setting: "max_export_size",
                value: size,
                limit: limits.max_export_size,
                locations: None,
            }),
            Some(_) => {}
            None => volume.unchecked.push("max_export_size"),
        }
        volume
    }

    pub fn exceeded(&self) -> bool {
        !self.over.is_empty()
    }

    /// `volume` in the estimate's result.
    pub fn to_json(&self) -> Value {
        let limits = self.limits.unwrap_or_default();
        json!({
            "exceeded": self.exceeded(),
            "limits": {
                "warn_hits": limits.warn_hits,
                "warn_hits_per_location": limits.warn_hits_per_location,
                "max_export_size": limits.max_export_size,
            },
            "over": self.over.iter().map(|over| {
                let mut entry = json!({
                    "setting": format!("volume.{}", over.setting),
                    "value": over.value,
                    "limit": over.limit,
                });
                if let Some(locations) = over.locations {
                    entry["locations"] = json!(locations);
                }
                entry
            }).collect::<Vec<_>>(),
            "unchecked": self.unchecked.iter().map(|key| format!("volume.{key}")).collect::<Vec<_>>(),
        })
    }

    /// The stderr lines: one per limit passed, then what to do. Empty when
    /// no limit was passed.
    pub fn warnings(&self) -> Vec<String> {
        if self.over.is_empty() {
            return Vec::new();
        }
        let mut lines: Vec<String> = self
            .over
            .iter()
            .map(|over| match over.setting {
                "warn_hits" => format!(
                    "warning: VOLUME: the estimate found {} items, more than volume.warn_hits ({})",
                    grouped(over.value),
                    grouped(over.limit)
                ),
                "warn_hits_per_location" => {
                    let locations = over.locations.unwrap_or(1);
                    format!(
                        "warning: VOLUME: {locations} location{} more than \
                         volume.warn_hits_per_location ({}) hits; the largest has {}",
                        if locations == 1 { " has" } else { "s have" },
                        grouped(over.limit),
                        grouped(over.value)
                    )
                }
                _ => {
                    let (mut value, mut limit) = (size_text(over.value), size_text(over.limit));
                    // Rounded alike, they would read as equal.
                    if value == limit {
                        value = format!("{} bytes", grouped(over.value));
                        limit = format!("{} bytes", grouped(over.limit));
                    }
                    format!(
                        "warning: VOLUME: the estimate's indexed size is {value}, more than \
                         volume.max_export_size ({limit}); with Teams context an export can be \
                         several times larger"
                    )
                }
            })
            .collect();
        lines.push(
            "warning: VOLUME: a report or export of this search would be hard to work with; \
             narrow the query, or confirm the scope with whoever asked for it, before going \
             further. The limits are under volume in config.json"
                .into(),
        );
        lines
    }
}

/// `12345` as `12,345`.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Bytes in the largest binary unit that keeps one or more whole units,
/// with one decimal place.
fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1 << 10 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::estimate::LocationRow;

    fn row(count: Option<u64>) -> LocationRow {
        LocationRow {
            location: "alex@contoso.example".into(),
            location_id: None,
            location_type: None,
            sub_type: None,
            count,
            size: None,
            status: Some("Succeeded".into()),
            error_warning: None,
        }
    }

    fn config(value: Value) -> BTreeMap<String, Value> {
        BTreeMap::from([("volume".to_owned(), value)])
    }

    #[test]
    fn defaults_apply_when_volume_or_a_key_is_missing_or_null() {
        let defaults = VolumeLimits::default();
        assert_eq!(
            VolumeLimits::from_config(&BTreeMap::new()).unwrap(),
            defaults
        );
        assert_eq!(
            VolumeLimits::from_config(&config(Value::Null)).unwrap(),
            defaults
        );
        assert_eq!(
            VolumeLimits::from_config(&config(json!({"warn_hits": null}))).unwrap(),
            defaults
        );
        assert_eq!(defaults.max_export_size, 10 * 1024 * 1024 * 1024);
    }

    #[test]
    fn values_are_read_and_bad_ones_refused_without_repeating_them() {
        let limits = VolumeLimits::from_config(&config(json!({
            "warn_hits": 200,
            "warn_hits_per_location": 50,
            "max_export_size": "2GiB",
        })))
        .unwrap();
        assert_eq!(
            limits,
            VolumeLimits {
                warn_hits: 200,
                warn_hits_per_location: 50,
                max_export_size: 2 << 30,
            }
        );
        for (bad, key) in [
            (json!({"warn_hits": 0}), "volume.warn_hits"),
            (json!({"warn_hits": "secret-value"}), "volume.warn_hits"),
            (
                json!({"warn_hits_per_location": 1.5}),
                "volume.warn_hits_per_location",
            ),
            (
                json!({"max_export_size": "secret-value"}),
                "volume.max_export_size",
            ),
            (json!({"max_export_size": 10}), "volume.max_export_size"),
            (json!("secret-value"), "volume must be an object"),
        ] {
            let message = VolumeLimits::from_config(&config(bad))
                .unwrap_err()
                .to_string();
            assert!(message.contains(key), "{message}");
            assert!(!message.contains("secret-value"), "{message}");
        }
    }

    #[test]
    fn each_limit_is_passed_only_above_it() {
        let limits = VolumeLimits {
            warn_hits: 10,
            warn_hits_per_location: 5,
            max_export_size: 100,
        };
        let at = Locations {
            rows: vec![row(Some(5)), row(None)],
            ..Locations::default()
        };
        let quiet = Volume::check(limits, Some(10), Some(100), Some(&at), false);
        assert!(!quiet.exceeded());
        // The row without a count leaves the per-location check unchecked.
        assert_eq!(quiet.unchecked, vec!["warn_hits_per_location"]);
        assert!(quiet.warnings().is_empty());
        let counted = Locations {
            rows: vec![row(Some(5))],
            ..Locations::default()
        };
        let quiet = Volume::check(limits, Some(10), Some(100), Some(&counted), false);
        assert!(quiet.unchecked.is_empty());

        let above = Locations {
            rows: vec![row(Some(6)), row(Some(9)), row(Some(2))],
            ..Locations::default()
        };
        let loud = Volume::check(limits, Some(11), Some(101), Some(&above), false);
        assert!(loud.exceeded());
        assert_eq!(
            loud.over,
            vec![
                Over {
                    setting: "warn_hits",
                    value: 11,
                    limit: 10,
                    locations: None
                },
                Over {
                    setting: "warn_hits_per_location",
                    value: 9,
                    limit: 5,
                    locations: Some(2),
                },
                Over {
                    setting: "max_export_size",
                    value: 101,
                    limit: 100,
                    locations: None
                },
            ]
        );
        let warnings = loud.warnings();
        assert_eq!(warnings.len(), 4);
        assert!(
            warnings[1].contains("2 locations have more than"),
            "{}",
            warnings[1]
        );
        assert!(warnings[3].contains("narrow the query"));
        let value = loud.to_json();
        assert_eq!(value["exceeded"], true);
        assert_eq!(value["over"][1]["setting"], "volume.warn_hits_per_location");
        assert_eq!(value["over"][1]["locations"], 2);
        assert!(value["over"][0].get("locations").is_none());
    }

    #[test]
    fn missing_counts_are_unchecked_not_passed() {
        let volume = Volume::check(VolumeLimits::default(), None, None, None, false);
        assert!(!volume.exceeded());
        assert_eq!(
            volume.to_json()["unchecked"],
            json!([
                "volume.warn_hits",
                "volume.warn_hits_per_location",
                "volume.max_export_size"
            ])
        );
    }

    #[test]
    fn locations_whose_hits_are_not_all_known_are_unchecked_but_still_passed() {
        let limits = VolumeLimits {
            warn_hits: 100,
            warn_hits_per_location: 5,
            max_export_size: 100,
        };
        let one_over = || Locations {
            rows: vec![row(Some(9))],
            ..Locations::default()
        };
        let cases: [(Locations, bool); 4] = [
            (one_over(), true),
            (
                Locations {
                    missing_columns: vec!["Count"],
                    ..one_over()
                },
                false,
            ),
            (
                Locations {
                    unusable_rows: 1,
                    ..one_over()
                },
                false,
            ),
            (
                Locations {
                    rows: vec![row(Some(9)), row(None)],
                    ..Locations::default()
                },
                false,
            ),
        ];
        for (locations, duplicated) in cases {
            let volume = Volume::check(limits, Some(1), Some(1), Some(&locations), duplicated);
            assert_eq!(
                volume.unchecked,
                vec!["warn_hits_per_location"],
                "{locations:?}"
            );
            assert_eq!(volume.over.len(), 1);
            assert!(volume.warnings()[0].contains("1 location has more than"));
        }
    }

    #[test]
    fn a_size_just_over_the_limit_is_shown_in_bytes() {
        let limits = VolumeLimits::default();
        let volume = Volume::check(limits, None, Some((10 << 30) + 1), None, false);
        let line = &volume.warnings()[0];
        assert!(
            line.contains(
                "is 10,737,418,241 bytes, more than volume.max_export_size (10,737,418,240 bytes)"
            ),
            "{line}"
        );
        let volume = Volume::check(limits, None, Some(12 << 30), None, false);
        assert!(volume.warnings()[0]
            .contains("is 12.0 GiB, more than volume.max_export_size (10.0 GiB)"));
    }

    #[test]
    fn numbers_are_shown_grouped_and_sizes_in_binary_units() {
        assert_eq!(grouped(5), "5");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
        assert_eq!(size_text(512), "512 B");
        assert_eq!(size_text(10 << 30), "10.0 GiB");
        assert_eq!(size_text(1536), "1.5 KiB");
    }
}
