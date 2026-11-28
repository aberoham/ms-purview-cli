//! The item report reader of `docs/SPEC.md` section 4.8, "Items and
//! deduplication": the `Items_N_*.csv` files of an item report zip, read
//! in order of `N` one record at a time, the rows that pass the filters,
//! and their aggregation into unique items.
//!
//! An item report has one row per copy of an item in each mailbox, 162
//! columns and no body text (Observed). Only the columns below are read,
//! by name.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::csvread::{byte_field, Table};
use super::{Kind, ReportLimits};
use crate::error::{PurviewError, Result};
use crate::zipread::ZipReader;

/// `--max-unique` by default.
pub const DEFAULT_MAX_UNIQUE: usize = 2_000_000;

/// The columns read, by their header names (Observed).
const COLUMNS: [&str; 12] = [
    "Internet message ID",
    "Immutable ID",
    "Item class",
    "Date",
    "Sender",
    "Subject/Title",
    "Conversation name",
    "Conversation type",
    "Recipient count",
    "Workload",
    "Has attachment",
    "Location ID",
];

/// The index of each of `COLUMNS` in one file.
#[derive(Debug, Clone, Copy)]
struct Columns {
    internet_message_id: Option<usize>,
    immutable_id: Option<usize>,
    class: Option<usize>,
    date: Option<usize>,
    sender: Option<usize>,
    subject: Option<usize>,
    conversation_name: Option<usize>,
    conversation_type: Option<usize>,
    recipient_count: Option<usize>,
    workload: Option<usize>,
    has_attachment: Option<usize>,
    location_id: Option<usize>,
}

impl Columns {
    fn of(indexes: &[Option<usize>]) -> Self {
        Self {
            internet_message_id: indexes[0],
            immutable_id: indexes[1],
            class: indexes[2],
            date: indexes[3],
            sender: indexes[4],
            subject: indexes[5],
            conversation_name: indexes[6],
            conversation_type: indexes[7],
            recipient_count: indexes[8],
            workload: indexes[9],
            has_attachment: indexes[10],
            location_id: indexes[11],
        }
    }
}

/// The fields of one row that a unique item keeps (`docs/SPEC.md` section
/// 7.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlimItem {
    pub class: Option<String>,
    pub date: Option<DateTime<Utc>>,
    pub sender: Option<String>,
    /// `Subject/Title`, or `Conversation name` when that is empty, as for
    /// Teams messages (Observed).
    pub title: Option<String>,
    /// `Conversation name`, which names a Teams chat or channel (Observed).
    pub conversation_name: Option<String>,
    pub conversation_type: Option<String>,
    pub recipient_count: Option<u32>,
    pub workload: Option<String>,
    pub has_attachment: Option<bool>,
    pub internet_message_id: Option<String>,
    pub immutable_id: Option<String>,
}

/// What a unique item is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KeyKind {
    InternetMessageId,
    ImmutableId,
    /// A SHA-256 of `Item class`, `Date`, `Sender`, `Subject/Title` and
    /// `Conversation name` (`hash_key`), for a row with neither id.
    Hash,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InternetMessageId => "internetMessageId",
            Self::ImmutableId => "immutableId",
            Self::Hash => "hash",
        }
    }
}

/// One row, read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemRow {
    pub item: SlimItem,
    pub key: String,
    pub kind: KeyKind,
    /// `Location ID`: the mailbox this copy is in.
    pub location: Option<String>,
    /// `Subject/Title` and `Conversation name` as given, for the subject
    /// filter.
    subject: Option<String>,
    conversation_name: Option<String>,
    /// A `Date` was given and could not be read.
    pub date_unreadable: bool,
}

impl ItemRow {
    fn read(record: &csv::ByteRecord, columns: &Columns) -> Self {
        let get = |index| byte_field(record, index);
        let class = get(columns.class);
        let date_text = get(columns.date);
        let date = date_text.as_deref().and_then(parse_date);
        let sender = get(columns.sender);
        let subject = get(columns.subject);
        let conversation_name = get(columns.conversation_name);
        let internet_message_id = get(columns.internet_message_id);
        let immutable_id = get(columns.immutable_id);
        let (key, kind) = if let Some(id) = &internet_message_id {
            (id.clone(), KeyKind::InternetMessageId)
        } else if let Some(id) = &immutable_id {
            (id.clone(), KeyKind::ImmutableId)
        } else {
            (
                hash_key(&[&class, &date_text, &sender, &subject, &conversation_name]),
                KeyKind::Hash,
            )
        };
        let item = SlimItem {
            class,
            date,
            sender,
            title: subject.clone().or_else(|| conversation_name.clone()),
            conversation_name: conversation_name.clone(),
            conversation_type: get(columns.conversation_type),
            recipient_count: get(columns.recipient_count).and_then(|text| text.parse().ok()),
            workload: get(columns.workload),
            has_attachment: get(columns.has_attachment).and_then(|text| {
                if text.eq_ignore_ascii_case("true") {
                    Some(true)
                } else if text.eq_ignore_ascii_case("false") {
                    Some(false)
                } else {
                    None
                }
            }),
            internet_message_id,
            immutable_id,
        };
        Self {
            item,
            key,
            kind,
            location: get(columns.location_id),
            subject,
            conversation_name,
            date_unreadable: date_text.is_some() && date.is_none(),
        }
    }

    /// The row as an `--all-rows` record.
    pub fn record(&self) -> Value {
        let mut record = item_record(&self.key, self.kind, &self.item);
        record["locationId"] = json!(self.location);
        record
    }
}

/// The SHA-256, in hex, of the fields as a compact JSON array of strings,
/// an empty field as `""`: unlike joined text, no field's content can move
/// into the next (`docs/SPEC.md` section 4.8).
fn hash_key(fields: &[&Option<String>]) -> String {
    let fields: Vec<&str> = fields
        .iter()
        .map(|field| field.as_deref().unwrap_or_default())
        .collect();
    let bytes = serde_json::to_vec(&fields).expect("strings serialise");
    crate::download::hex(&Sha256::digest(&bytes))
}

/// `Date` as written in item reports, `2024-06-03 08:15:00Z` (format
/// Observed), or RFC 3339.
fn parse_date(text: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(text, "%Y-%m-%d %H:%M:%SZ")
        .map(|time| time.and_utc())
        .ok()
        .or_else(|| {
            DateTime::parse_from_rfc3339(text)
                .ok()
                .map(|time| time.with_timezone(&Utc))
        })
}

/// A sender's address, lowercased: the text between `<` and `>` of
/// `Name <addr>`, else the whole text.
pub fn sender_address(sender: &str) -> String {
    let text = sender.trim();
    let inner = match (text.rfind('<'), text.ends_with('>')) {
        (Some(start), true) => &text[start + 1..text.len() - 1],
        _ => text,
    };
    inner.trim().to_lowercase()
}

/// Whether a sender's address, as `sender_address` gives it, is a Teams
/// thread id (`19:…@thread.v2`), which names a chat, not a person
/// (Observed).
pub fn is_thread_id(address: &str) -> bool {
    address.starts_with("19:")
}

/// Whether a sender's address, as `sender_address` gives it, is a list of
/// addresses separated by `;`, as Teams file items have, cut at 255
/// characters (Observed), which names no one sender.
pub fn is_address_list(address: &str) -> bool {
    address.contains(';')
}

/// The domain of a sender's address, or `None` when it has none, is a
/// Teams thread id (`19:…@thread.v2`) or is a list of addresses, which
/// name no person (Observed).
pub fn sender_domain(sender: &str) -> Option<String> {
    let address = sender_address(sender);
    if is_thread_id(&address) || is_address_list(&address) {
        return None;
    }
    address
        .rsplit_once('@')
        .map(|(_, domain)| domain.to_owned())
        .filter(|domain| !domain.is_empty())
}

/// The fields every record shares.
fn item_record(key: &str, kind: KeyKind, item: &SlimItem) -> Value {
    json!({
        "key": key,
        "keyKind": kind.as_str(),
        "class": item.class,
        "date": item.date.map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)),
        "sender": item.sender,
        "senderDomain": item.sender.as_deref().and_then(sender_domain),
        "recipientCount": item.recipient_count,
        "title": item.title,
        "conversationType": item.conversation_type,
        "workload": item.workload,
        "hasAttachment": item.has_attachment,
        "immutableId": item.immutable_id,
        "internetMessageId": item.internet_message_id,
    })
}

/// The filters of `parse items` (`docs/SPEC.md` section 3.5). Rows that
/// fail them are not counted as copies.
#[derive(Debug, Clone, Default)]
pub struct Filters {
    /// On `Date`, from the start of this day, UTC.
    pub since: Option<NaiveDate>,
    /// On `Date`, to the end of this day, UTC.
    pub until: Option<NaiveDate>,
    /// On `Subject/Title` or `Conversation name`.
    pub subject: Option<Regex>,
    /// A prefix of `Item class`, lowercased; compared ignoring case.
    pub class_prefix: Option<String>,
    /// Sender addresses as `sender_address` gives them; a row must match
    /// one.
    pub senders: Vec<String>,
    /// Sender addresses as `sender_address` gives them; a row matching one
    /// is left out.
    pub exclude_senders: Vec<String>,
    /// `Workload`, lowercased; compared ignoring case.
    pub workload: Option<String>,
}

impl Filters {
    pub fn matches(&self, row: &ItemRow) -> bool {
        let item = &row.item;
        if self.since.is_some() || self.until.is_some() {
            let Some(day) = item.date.map(|date| date.date_naive()) else {
                return false;
            };
            if self.since.is_some_and(|since| day < since)
                || self.until.is_some_and(|until| day > until)
            {
                return false;
            }
        }
        if let Some(pattern) = &self.subject {
            let hit = [&row.subject, &row.conversation_name]
                .iter()
                .any(|text| text.as_deref().is_some_and(|text| pattern.is_match(text)));
            if !hit {
                return false;
            }
        }
        if let Some(prefix) = &self.class_prefix {
            let hit = item
                .class
                .as_deref()
                .is_some_and(|class| class.to_lowercase().starts_with(prefix.as_str()));
            if !hit {
                return false;
            }
        }
        let address = item.sender.as_deref().map(sender_address);
        if !self.senders.is_empty()
            && !address
                .as_ref()
                .is_some_and(|address| self.senders.contains(address))
        {
            return false;
        }
        if address
            .as_ref()
            .is_some_and(|address| self.exclude_senders.contains(address))
        {
            return false;
        }
        if let Some(workload) = &self.workload {
            if !item
                .workload
                .as_deref()
                .is_some_and(|value| value.to_lowercase() == *workload)
            {
                return false;
            }
        }
        true
    }
}

/// What a pass counted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Tally {
    /// `Items_N_*.csv` files read.
    pub files: usize,
    pub rows: u64,
    /// Rows that passed the filters.
    pub matched: u64,
    /// Matched rows keyed by hash.
    pub hash_rows: u64,
    /// Rows whose `Date` could not be read.
    pub unreadable_dates: u64,
    /// Columns missing from at least one file.
    pub missing_columns: BTreeSet<&'static str>,
}

/// Reads every row of the item report zip at `path`, in order of the
/// files' `N` and then of the rows, giving each that passes `filters` to
/// `each`.
pub fn read(
    path: &Path,
    limits: ReportLimits,
    filters: &Filters,
    mut each: impl FnMut(ItemRow) -> Result<()>,
) -> Result<Tally> {
    let mut zip = ZipReader::open(path, limits.zip)?;
    if Kind::of(zip.names()) != Kind::ItemReport {
        return Err(PurviewError::NotAReportZip(
            "the zip has no Items_N_*.csv, or is an export package, so it is not an item report \
             zip"
            .into(),
        ));
    }
    let mut tally = Tally::default();
    for index in item_files(zip.names()) {
        tally.files += 1;
        zip.read_entry(index, |reader| {
            let mut table = Table::new(reader, "Items", limits.record_bytes)?;
            let (indexes, missing) = table.index(&COLUMNS);
            tally.missing_columns.extend(missing);
            let columns = Columns::of(&indexes);
            let mut record = csv::ByteRecord::new();
            while table.next_record(&mut record)? {
                tally.rows += 1;
                let row = ItemRow::read(&record, &columns);
                if row.date_unreadable {
                    tally.unreadable_dates += 1;
                }
                if !filters.matches(&row) {
                    continue;
                }
                tally.matched += 1;
                if row.kind == KeyKind::Hash {
                    tally.hash_rows += 1;
                }
                each(row)?;
            }
            Ok(())
        })?;
    }
    Ok(tally)
}

/// The indexes of the `Items_N_*.csv` entries, by `N` as a number, then by
/// name.
fn item_files(names: &[String]) -> Vec<usize> {
    // By the number's digits without leading zeros: shorter is smaller,
    // and digits of one length compare as text, at any length.
    let mut files: Vec<(usize, &str, &str, usize)> = names
        .iter()
        .enumerate()
        .filter_map(|(index, name)| {
            let base = name.rsplit('/').next().unwrap_or(name);
            let digits = super::items_file_number(base)?.trim_start_matches('0');
            Some((digits.len(), digits, base, index))
        })
        .collect();
    files.sort();
    files.into_iter().map(|(_, _, _, index)| index).collect()
}

/// One unique item: the first row's fields, the rows counted, and the
/// distinct locations they are in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UniqueAgg {
    pub first: SlimItem,
    pub kind: KeyKind,
    pub copies: u64,
    /// Interned `Location ID`s; sorted and distinct up to `distinct`, and
    /// after `finish`.
    locations: Vec<u32>,
    distinct: usize,
}

impl UniqueAgg {
    /// The number of distinct locations; exact after `Dedup::finish`.
    pub fn location_count(&self) -> usize {
        self.locations.len()
    }

    /// Adds a location, sorting and removing repeats whenever the list has
    /// doubled since the last time, so that the time spent stays
    /// proportional to the copies and the memory to twice the distinct
    /// locations.
    fn add_location(&mut self, location: u32) {
        self.locations.push(location);
        if self.locations.len() >= 2 * self.distinct.max(8) {
            self.compact();
        }
    }

    fn compact(&mut self) {
        self.locations.sort_unstable();
        self.locations.dedup();
        self.distinct = self.locations.len();
    }
}

/// The unique items of a pass, keyed as section 4.8 says.
#[derive(Debug)]
pub struct Dedup {
    /// By kind and key, so that an Internet message ID and an Immutable
    /// ID with the same text stay two items.
    items: HashMap<(KeyKind, Box<str>), UniqueAgg>,
    locations: HashMap<Box<str>, u32>,
    max_unique: usize,
    hash_keys: usize,
}

impl Dedup {
    pub fn new(max_unique: usize) -> Self {
        Self {
            items: HashMap::new(),
            locations: HashMap::new(),
            max_unique,
            hash_keys: 0,
        }
    }

    /// Unique items keyed by hash.
    pub fn hash_keys(&self) -> usize {
        self.hash_keys
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Counts `row` as a copy of its item. A new item past `max_unique` is
    /// `TooManyUnique`.
    pub fn add(&mut self, row: ItemRow) -> Result<()> {
        let location = row
            .location
            .as_deref()
            .map(|id| self.intern(id))
            .transpose()?;
        let key = (row.kind, row.key.into_boxed_str());
        let agg = match self.items.get_mut(&key) {
            Some(agg) => agg,
            None => {
                if self.items.len() >= self.max_unique {
                    return Err(PurviewError::TooManyUnique(self.max_unique));
                }
                if row.kind == KeyKind::Hash {
                    self.hash_keys += 1;
                }
                self.items.entry(key).or_insert(UniqueAgg {
                    first: row.item,
                    kind: row.kind,
                    copies: 0,
                    locations: Vec::new(),
                    distinct: 0,
                })
            }
        };
        agg.copies = agg.copies.saturating_add(1);
        if let Some(location) = location {
            agg.add_location(location);
        }
        Ok(())
    }

    fn intern(&mut self, id: &str) -> Result<u32> {
        if let Some(index) = self.locations.get(id) {
            return Ok(*index);
        }
        // Past the index range, distinct locations would be counted as one.
        let index = u32::try_from(self.locations.len()).map_err(|_| {
            PurviewError::message("the report names more distinct locations than can be counted")
        })?;
        self.locations.insert(id.into(), index);
        Ok(index)
    }

    /// The unique items, by date (items without one last), then key.
    pub fn finish(self) -> Vec<(Box<str>, UniqueAgg)> {
        let mut items: Vec<(Box<str>, UniqueAgg)> = self
            .items
            .into_iter()
            .map(|((_, key), mut agg)| {
                agg.compact();
                (key, agg)
            })
            .collect();
        items.sort_by(|(a_key, a), (b_key, b)| {
            (a.first.date.is_none(), a.first.date, a_key, a.kind).cmp(&(
                b.first.date.is_none(),
                b.first.date,
                b_key,
                b.kind,
            ))
        });
        items
    }
}

/// A unique item as a record.
pub fn unique_record(key: &str, agg: &UniqueAgg) -> Value {
    let mut record = item_record(key, agg.kind, &agg.first);
    record["copies"] = json!(agg.copies);
    record["locations"] = json!(agg.location_count());
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "Internet message ID,Immutable ID,Item class,Date,Sender,\
                          Subject/Title,Conversation name,Conversation type,Recipient count,\
                          Workload,Has attachment,Location ID";

    fn rows(text: &str) -> Vec<ItemRow> {
        let mut table = Table::new(
            text.as_bytes(),
            "Items",
            super::super::csvread::DEFAULT_RECORD_BYTES,
        )
        .unwrap();
        let (indexes, _) = table.index(&COLUMNS);
        let columns = Columns::of(&indexes);
        let mut record = csv::ByteRecord::new();
        let mut out = Vec::new();
        while table.next_record(&mut record).unwrap() {
            out.push(ItemRow::read(&record, &columns));
        }
        out
    }

    fn one(line: &str) -> ItemRow {
        rows(&format!("{HEADER}\n{line}\n")).remove(0)
    }

    #[test]
    fn the_key_prefers_the_internet_message_id_then_the_immutable_id_then_a_hash() {
        let row = one("<m1@contoso.example>,IMM1,IPM.Note,2026-07-01 08:15:00Z,a@contoso.example,S,,,1,Exchange,True,L1");
        assert_eq!(row.key, "<m1@contoso.example>");
        assert_eq!(row.kind, KeyKind::InternetMessageId);
        let row =
            one(",IMM1,IPM.Note,2026-07-01 08:15:00Z,a@contoso.example,S,,,1,Exchange,True,L1");
        assert_eq!(row.key, "IMM1");
        assert_eq!(row.kind, KeyKind::ImmutableId);
        let row = one(",,IPM.Note,2026-07-01 08:15:00Z,a@contoso.example,S,C,,1,Exchange,True,L1");
        assert_eq!(row.kind, KeyKind::Hash);
        let expected = crate::download::hex(&Sha256::digest(
            br#"["IPM.Note","2026-07-01 08:15:00Z","a@contoso.example","S","C"]"#,
        ));
        assert_eq!(row.key, expected);
        // A separator inside a field cannot make two items one.
        let a = one(",,IPM.Note,2026-07-01 08:15:00Z,a@contoso.example,A|B,C,,1,Exchange,True,L1");
        let b = one(",,IPM.Note,2026-07-01 08:15:00Z,a@contoso.example,A,B|C,,1,Exchange,True,L1");
        assert_ne!(a.key, b.key);
    }

    #[test]
    fn fields_are_read_and_teams_messages_take_their_conversation_name() {
        let row = one(",IMM2,IPM.SkypeTeams.Message,2026-07-02 09:00:00Z,\"Alex <ALEX@Contoso.example>\",,Orders chat,Group,3,Exchange,false,L2");
        let item = &row.item;
        assert_eq!(item.title.as_deref(), Some("Orders chat"));
        assert_eq!(item.recipient_count, Some(3));
        assert_eq!(item.has_attachment, Some(false));
        assert_eq!(item.conversation_type.as_deref(), Some("Group"));
        assert_eq!(item.date.unwrap().to_rfc3339(), "2026-07-02T09:00:00+00:00");
        assert_eq!(row.location.as_deref(), Some("L2"));
        let record = row.record();
        assert_eq!(record["senderDomain"], "contoso.example");
        assert_eq!(record["date"], "2026-07-02T09:00:00Z");
        assert_eq!(record["locationId"], "L2");
    }

    #[test]
    fn fractions_of_a_second_are_kept() {
        let row =
            one(",IMM5,IPM.Note,2026-07-02T09:00:00.5Z,a@contoso.example,S,,,1,Exchange,True,L1");
        assert_eq!(row.record()["date"], "2026-07-02T09:00:00.500Z");
    }

    #[test]
    fn an_unreadable_date_is_none_and_counted() {
        let row = one(",IMM3,IPM.Note,yesterday,a@contoso.example,S,,,x,Exchange,maybe,L1");
        assert!(row.item.date.is_none());
        assert!(row.date_unreadable);
        assert_eq!(row.item.recipient_count, None);
        assert_eq!(row.item.has_attachment, None);
    }

    #[test]
    fn sender_addresses_and_domains() {
        assert_eq!(
            sender_address("Alex <ALEX@Contoso.example>"),
            "alex@contoso.example"
        );
        assert_eq!(sender_address(" b@fabrikam.example "), "b@fabrikam.example");
        assert_eq!(
            sender_domain("b@fabrikam.example").as_deref(),
            Some("fabrikam.example")
        );
        assert_eq!(sender_domain("19:abc@thread.v2"), None);
        assert_eq!(sender_domain("Alex Example"), None);
        // A list of addresses, as Teams file items have (Observed).
        assert_eq!(sender_domain("a@contoso.example; b@fabrik"), None);
    }

    fn filtered(filters: &Filters) -> Vec<String> {
        rows(&format!(
            "{HEADER}\n\
             <m1@contoso.example>,,IPM.Note,2026-07-01 00:00:00Z,a@contoso.example,Orders,,,1,Exchange,True,L1\n\
             <m2@contoso.example>,,IPM.Note.SMIME,2026-07-02 23:59:59Z,Bea <b@fabrikam.example>,Invoices,,,1,Exchange,True,L1\n\
             ,IMM3,IPM.SkypeTeams.Message,2026-07-03 12:00:00Z,19:x@thread.v2,,Orders chat,Group,2,Exchange,False,L2\n\
             ,IMM4,IPM.Note,,c@contoso.example,Orders,,,1,SharePoint,False,L3\n"
        ))
        .into_iter()
        .filter(|row| filters.matches(row))
        .map(|row| row.key)
        .collect()
    }

    #[test]
    fn date_filters_are_inclusive_days_and_drop_rows_without_a_date() {
        let day = |text| NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap();
        let filters = Filters {
            since: Some(day("2026-07-01")),
            until: Some(day("2026-07-02")),
            ..Filters::default()
        };
        assert_eq!(
            filtered(&filters),
            vec!["<m1@contoso.example>", "<m2@contoso.example>"]
        );
        let filters = Filters {
            since: Some(day("2026-07-03")),
            ..Filters::default()
        };
        assert_eq!(filtered(&filters), vec!["IMM3"]);
    }

    #[test]
    fn the_subject_filter_reads_the_subject_or_the_conversation_name() {
        let filters = Filters {
            subject: Some(Regex::new("^Orders").unwrap()),
            ..Filters::default()
        };
        assert_eq!(
            filtered(&filters),
            vec!["<m1@contoso.example>", "IMM3", "IMM4"]
        );
    }

    #[test]
    fn case_is_ignored_beyond_ascii() {
        let row = one(",IMM9,IPM.Équipe,,a@contoso.example,S,,,1,Équipe,True,L1");
        let filters = Filters {
            class_prefix: Some("ipm.équipe".into()),
            workload: Some("équipe".into()),
            ..Filters::default()
        };
        assert!(filters.matches(&row));
    }

    #[test]
    fn class_sender_and_workload_filters() {
        let filters = Filters {
            class_prefix: Some("ipm.note".into()),
            ..Filters::default()
        };
        assert_eq!(
            filtered(&filters),
            vec!["<m1@contoso.example>", "<m2@contoso.example>", "IMM4"]
        );
        let filters = Filters {
            senders: vec!["b@fabrikam.example".into()],
            ..Filters::default()
        };
        assert_eq!(filtered(&filters), vec!["<m2@contoso.example>"]);
        let filters = Filters {
            exclude_senders: vec!["a@contoso.example".into(), "c@contoso.example".into()],
            ..Filters::default()
        };
        assert_eq!(filtered(&filters), vec!["<m2@contoso.example>", "IMM3"]);
        let filters = Filters {
            workload: Some("sharepoint".into()),
            ..Filters::default()
        };
        assert_eq!(filtered(&filters), vec!["IMM4"]);
    }

    #[test]
    fn copies_and_distinct_locations_are_counted_per_item() {
        let all = rows(&format!(
            "{HEADER}\n\
             <m1@contoso.example>,,IPM.Note,2026-07-02 08:00:00Z,a@contoso.example,S,,,1,Exchange,True,L1\n\
             <m1@contoso.example>,,IPM.Note,2026-07-02 08:00:00Z,a@contoso.example,S,,,1,Exchange,True,L2\n\
             <m1@contoso.example>,,IPM.Note,2026-07-02 08:00:00Z,a@contoso.example,S,,,1,Exchange,True,L1\n\
             ,,IPM.Note,2026-07-01 08:00:00Z,a@contoso.example,T,,,1,Exchange,True,\n"
        ));
        let mut dedup = Dedup::new(10);
        for row in all {
            dedup.add(row).unwrap();
        }
        assert_eq!(dedup.hash_keys(), 1);
        let items = dedup.finish();
        assert_eq!(items.len(), 2);
        // By date: the hash-keyed item of 1 July first.
        assert_eq!(items[0].1.kind, KeyKind::Hash);
        assert_eq!(items[0].1.copies, 1);
        assert_eq!(items[0].1.location_count(), 0);
        assert_eq!(&*items[1].0, "<m1@contoso.example>");
        assert_eq!(items[1].1.copies, 3);
        assert_eq!(items[1].1.location_count(), 2);
        let record = unique_record(&items[1].0, &items[1].1);
        assert_eq!(record["copies"], 3);
        assert_eq!(record["locations"], 2);
    }

    #[test]
    fn many_locations_in_any_order_are_counted_once_each() {
        let mut dedup = Dedup::new(10);
        let mut text = format!("{HEADER}\n");
        for round in 0..3 {
            for n in 0..100 {
                let n = if round == 1 { 99 - n } else { n };
                text.push_str(&format!(
                    ",IMM1,IPM.Note,,a@contoso.example,S,,,1,Exchange,True,L{n}\n"
                ));
            }
        }
        for row in rows(&text) {
            dedup.add(row).unwrap();
        }
        let items = dedup.finish();
        assert_eq!(items[0].1.copies, 300);
        assert_eq!(items[0].1.location_count(), 100);
    }

    #[test]
    fn the_same_text_as_two_kinds_of_key_is_two_items() {
        let mut dedup = Dedup::new(10);
        for row in rows(&format!(
            "{HEADER}\nSAME,,IPM.Note,,a@contoso.example,S,,,1,Exchange,True,L1\n\
             ,SAME,IPM.Note,,a@contoso.example,T,,,1,Exchange,True,L2\n"
        )) {
            dedup.add(row).unwrap();
        }
        let items = dedup.finish();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].1.kind, KeyKind::InternetMessageId);
        assert_eq!(items[1].1.kind, KeyKind::ImmutableId);
    }

    #[test]
    fn a_new_item_past_max_unique_is_refused_and_a_copy_is_not() {
        let all = rows(&format!(
            "{HEADER}\n\
             ,IMM1,IPM.Note,,a@contoso.example,S,,,1,Exchange,True,L1\n\
             ,IMM1,IPM.Note,,a@contoso.example,S,,,1,Exchange,True,L2\n\
             ,IMM2,IPM.Note,,a@contoso.example,S,,,1,Exchange,True,L1\n"
        ));
        let mut dedup = Dedup::new(1);
        let mut all = all.into_iter();
        dedup.add(all.next().unwrap()).unwrap();
        dedup.add(all.next().unwrap()).unwrap();
        let error = dedup.add(all.next().unwrap()).unwrap_err();
        assert_eq!(error.metadata().0, "TooManyUnique");
    }

    #[test]
    fn item_files_are_ordered_by_their_number() {
        let names: Vec<String> = [
            "Items_10_2026.csv",
            "Locations-1.csv",
            "Items_2_2026.csv",
            "x/Items_0_2026.CSV",
            "Items_a_2026.csv",
            "Items_100000000000000000000_2026.csv",
            "Items_20000000000000000000_2026.csv",
            "Items_003_2026.csv",
        ]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
        assert_eq!(item_files(&names), vec![3, 2, 7, 0, 6, 5]);
    }
}
