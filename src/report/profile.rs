//! The profile of an item report (`docs/SPEC.md` section 4.8, "Profile"):
//! counts over its unique items by class, workload, sender, sender domain,
//! Teams conversation and date, and the copies per item.
//!
//! Every count is of unique items, as `items::Dedup` makes them, after the
//! filters. Senders are normalised through the `identity` section of
//! `config.json` (`Identity`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use chrono::{Datelike, Days, NaiveDate};
use serde_json::{json, Value};

use super::items::{self, Dedup, Filters, SlimItem, Tally, UniqueAgg};
use super::ReportLimits;
use crate::error::{PurviewError, Result};

/// The length of the top lists when neither `--top` nor `defaults.top` is
/// given (`docs/SPEC.md` section 5.5).
pub const DEFAULT_TOP: usize = 20;

/// The `Item class` prefix of Teams messages, compared ignoring ASCII case:
/// `IPM.SkypeTeams.Message` and `IPM.SkypeTeams.SystemMessage` (Observed).
/// Their `Workload` is `Exchange`, as for mail (Observed), so the class is
/// what tells them apart.
const TEAMS_CLASS_PREFIX: &str = "ipm.skypeteams.";

/// The histogram's bucket, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bucket {
    Day,
    /// An ISO 8601 week, from Monday.
    Week,
    Month,
}

impl Bucket {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
        }
    }

    /// The first day of the bucket that holds `date`.
    fn start(self, date: NaiveDate) -> NaiveDate {
        match self {
            Self::Day => date,
            Self::Week => date
                .checked_sub_days(Days::new(date.weekday().num_days_from_monday().into()))
                // Only the first days of the calendar have no Monday
                // before them; they keep their own day.
                .unwrap_or(date),
            Self::Month => date.with_day(1).unwrap_or(date),
        }
    }
}

/// How the profile is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// The length of the sender, domain and conversation lists.
    pub top: usize,
    pub bucket: Bucket,
    /// `--merge-local-part`: senders in `identity.internal_domains` with one
    /// local part are one sender.
    pub merge_local_part: bool,
}

/// The `identity` section of `config.json`, checked, with every domain
/// lowercased.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// After `domain_aliases`.
    internal_domains: BTreeSet<String>,
    domain_aliases: BTreeMap<String, String>,
}

/// A domain as `identity` may give it: lowercased, with no `@`, space or
/// control character.
fn domain_name(value: &Value) -> Option<String> {
    let text = value.as_str()?.trim().to_lowercase();
    let usable = !text.is_empty()
        && !text
            .chars()
            .any(|c| c == '@' || c.is_whitespace() || c.is_control());
    usable.then_some(text)
}

impl Identity {
    /// Reads `identity`. A missing or `null` section or key is unset; any
    /// other value of the wrong type is an error naming the key, never the
    /// value.
    pub fn from_config(extra: &BTreeMap<String, Value>) -> Result<Self> {
        let identity = match extra.get("identity") {
            None | Some(Value::Null) => return Ok(Self::default()),
            Some(Value::Object(identity)) => identity,
            Some(_) => {
                return Err(PurviewError::message(
                    "config.json: identity must be an object",
                ))
            }
        };
        let mut domain_aliases = BTreeMap::new();
        match identity.get("domain_aliases") {
            None | Some(Value::Null) => {}
            Some(Value::Object(aliases)) => {
                let refusal = || {
                    PurviewError::message(
                        "config.json: identity.domain_aliases must map domain names to domain \
                         names, such as \"fabrikam.example\": \"contoso.example\"",
                    )
                };
                for (from, to) in aliases {
                    let from = domain_name(&Value::String(from.clone())).ok_or_else(refusal)?;
                    let to = domain_name(to).ok_or_else(refusal)?;
                    if domain_aliases
                        .insert(from, to.clone())
                        .is_some_and(|earlier| earlier != to)
                    {
                        return Err(PurviewError::message(
                            "config.json: identity.domain_aliases names one domain twice, in \
                             different case, with different targets",
                        ));
                    }
                }
            }
            Some(_) => {
                return Err(PurviewError::message(
                    "config.json: identity.domain_aliases must be an object",
                ))
            }
        }
        // One step only, so that a chain cannot hide where a domain ends.
        if domain_aliases
            .iter()
            .any(|(from, to)| from != to && domain_aliases.get(to).is_some_and(|next| next != to))
        {
            return Err(PurviewError::message(
                "config.json: identity.domain_aliases maps a domain to one that is mapped again; \
                 map each domain to its final name",
            ));
        }
        let internal_domains = match identity.get("internal_domains") {
            None | Some(Value::Null) => BTreeSet::new(),
            Some(Value::Array(domains)) => domains
                .iter()
                .map(|domain| {
                    domain_name(domain).ok_or_else(|| {
                        PurviewError::message(
                            "config.json: identity.internal_domains must be a list of domain \
                             names, such as \"contoso.example\"",
                        )
                    })
                })
                .collect::<Result<Vec<String>>>()?
                .into_iter()
                .map(|domain| domain_aliases.get(&domain).cloned().unwrap_or(domain))
                .collect(),
            Some(_) => {
                return Err(PurviewError::message(
                    "config.json: identity.internal_domains must be a list of domain names, \
                     such as \"contoso.example\"",
                ))
            }
        };
        Ok(Self {
            internal_domains,
            domain_aliases,
        })
    }

    /// Whether `identity.internal_domains` names any domain, which
    /// `--merge-local-part` needs.
    pub fn has_internal_domains(&self) -> bool {
        !self.internal_domains.is_empty()
    }

    fn alias<'a>(&'a self, domain: &'a str) -> &'a str {
        self.domain_aliases
            .get(domain)
            .map(String::as_str)
            .unwrap_or(domain)
    }
}

/// `defaults.top` in `config.json`: `DEFAULT_TOP` when missing or `null`,
/// otherwise a whole number above zero.
pub fn top_setting(extra: &BTreeMap<String, Value>) -> Result<usize> {
    let defaults = match extra.get("defaults") {
        None | Some(Value::Null) => return Ok(DEFAULT_TOP),
        Some(Value::Object(defaults)) => defaults,
        Some(_) => {
            return Err(PurviewError::message(
                "config.json: defaults must be an object",
            ))
        }
    };
    match defaults.get("top") {
        None | Some(Value::Null) => Ok(DEFAULT_TOP),
        Some(value) => value
            .as_u64()
            .filter(|top| *top > 0)
            .and_then(|top| usize::try_from(top).ok())
            .ok_or_else(|| {
                PurviewError::message("config.json: defaults.top must be a whole number above zero")
            }),
    }
}

/// Who sent an item, normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Who {
    /// A person or mailbox. `key` groups senders; `raw` is the address as
    /// `items::sender_address` gives it, and `canonical` the same after
    /// `identity.domain_aliases`.
    Person {
        key: SenderKey,
        raw: String,
        canonical: String,
        domain: Option<String>,
    },
    /// A Teams thread id, which names a chat (Observed).
    Thread,
    /// A list of addresses (`items::is_address_list`; Observed).
    List,
    /// No `Sender`.
    Nobody,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum SenderKey {
    /// The address after `identity.domain_aliases`.
    Address(String),
    /// A local part in `identity.internal_domains`, under
    /// `--merge-local-part`.
    Internal(String),
}

fn who(sender: Option<&str>, identity: &Identity, merge_local_part: bool) -> Who {
    let Some(sender) = sender else {
        return Who::Nobody;
    };
    let raw = items::sender_address(sender);
    if raw.is_empty() {
        return Who::Nobody;
    }
    if items::is_thread_id(&raw) {
        return Who::Thread;
    }
    if items::is_address_list(&raw) {
        return Who::List;
    }
    // The domain as `items::sender_domain` takes it: after the last `@`,
    // and only when something follows.
    let Some((local, domain)) = raw
        .rsplit_once('@')
        .filter(|(_, domain)| !domain.is_empty())
    else {
        return Who::Person {
            key: SenderKey::Address(raw.clone()),
            canonical: raw.clone(),
            raw,
            domain: None,
        };
    };
    let domain = identity.alias(domain).to_owned();
    let canonical = format!("{local}@{domain}");
    let key =
        if merge_local_part && !local.is_empty() && identity.internal_domains.contains(&domain) {
            SenderKey::Internal(local.to_owned())
        } else {
            SenderKey::Address(canonical.clone())
        };
    Who::Person {
        key,
        canonical,
        raw,
        domain: Some(domain),
    }
}

/// Whether an `Item class` is a Teams message's.
fn is_teams_class(class: &str) -> bool {
    class
        .as_bytes()
        .get(..TEAMS_CLASS_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TEAMS_CLASS_PREFIX.as_bytes()))
}

/// One sender's items, by the raw address each came under.
#[derive(Debug, Default)]
struct SenderAgg {
    items: u64,
    /// Raw address to its canonical form and item count.
    addresses: HashMap<String, (String, u64)>,
}

/// The profile of a pass, built one unique item at a time.
#[derive(Debug)]
pub struct Profile {
    options: Options,
    items: u64,
    hash_keyed: u64,
    copies: u64,
    max_copies: u64,
    classes: HashMap<Option<String>, u64>,
    workloads: HashMap<Option<String>, u64>,
    senders: HashMap<SenderKey, SenderAgg>,
    thread_senders: u64,
    list_senders: u64,
    no_sender: u64,
    domains: HashMap<String, u64>,
    teams_items: u64,
    conversations: HashMap<String, u64>,
    unnamed_conversations: u64,
    buckets: BTreeMap<NaiveDate, u64>,
    undated: u64,
}

/// `(name, count)` pairs, most first, then by name; the first `top` when
/// given.
fn ranked<K: Ord>(counts: impl IntoIterator<Item = (K, u64)>, top: Option<usize>) -> Vec<(K, u64)> {
    let mut list: Vec<(K, u64)> = counts.into_iter().collect();
    list.sort_by(|(a_name, a), (b_name, b)| b.cmp(a).then_with(|| a_name.cmp(b_name)));
    if let Some(top) = top {
        list.truncate(top);
    }
    list
}

impl Profile {
    pub fn new(options: Options) -> Self {
        Self {
            options,
            items: 0,
            hash_keyed: 0,
            copies: 0,
            max_copies: 0,
            classes: HashMap::new(),
            workloads: HashMap::new(),
            senders: HashMap::new(),
            thread_senders: 0,
            list_senders: 0,
            no_sender: 0,
            domains: HashMap::new(),
            teams_items: 0,
            conversations: HashMap::new(),
            unnamed_conversations: 0,
            buckets: BTreeMap::new(),
            undated: 0,
        }
    }

    /// Counts one unique item.
    pub fn add(&mut self, agg: &UniqueAgg, identity: &Identity) {
        let item: &SlimItem = &agg.first;
        self.items += 1;
        if agg.kind == items::KeyKind::Hash {
            self.hash_keyed += 1;
        }
        self.copies = self.copies.saturating_add(agg.copies);
        self.max_copies = self.max_copies.max(agg.copies);
        *self.classes.entry(item.class.clone()).or_default() += 1;
        *self.workloads.entry(item.workload.clone()).or_default() += 1;
        match who(
            item.sender.as_deref(),
            identity,
            self.options.merge_local_part,
        ) {
            Who::Person {
                key,
                raw,
                canonical,
                domain,
            } => {
                let sender = self.senders.entry(key).or_default();
                sender.items += 1;
                sender.addresses.entry(raw).or_insert((canonical, 0)).1 += 1;
                if let Some(domain) = domain {
                    *self.domains.entry(domain).or_default() += 1;
                }
            }
            Who::Thread => self.thread_senders += 1,
            Who::List => self.list_senders += 1,
            Who::Nobody => self.no_sender += 1,
        }
        if item.class.as_deref().is_some_and(is_teams_class) {
            self.teams_items += 1;
            match &item.conversation_name {
                Some(name) => *self.conversations.entry(name.clone()).or_default() += 1,
                None => self.unnamed_conversations += 1,
            }
        }
        match item.date {
            Some(date) => {
                *self
                    .buckets
                    .entry(self.options.bucket.start(date.date_naive()))
                    .or_default() += 1
            }
            None => self.undated += 1,
        }
    }

    /// The senders, most items first, each shown as the canonical address
    /// most of its items came under (the first by name on a tie), with the
    /// number of addresses merged into it.
    fn top_senders(&self) -> Vec<(String, u64, usize)> {
        let mut list: Vec<(String, u64, usize)> = self
            .senders
            .values()
            .map(|sender| {
                let mut canonical: HashMap<&str, u64> = HashMap::new();
                for (form, count) in sender.addresses.values() {
                    *canonical.entry(form.as_str()).or_default() += count;
                }
                let shown = ranked(canonical, Some(1))
                    .pop()
                    .map(|(form, _)| form.to_owned())
                    .unwrap_or_default();
                (shown, sender.items, sender.addresses.len())
            })
            .collect();
        list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        list.truncate(self.options.top);
        list
    }

    fn mean_copies(&self) -> Option<f64> {
        (self.items > 0).then(|| self.copies as f64 / self.items as f64)
    }

    /// The profile as JSON (`docs/SPEC.md` section 3.5, `parse profile`).
    pub fn to_value(&self) -> Value {
        let top = Some(self.options.top);
        json!({
            "items": self.items,
            "hashKeyed": self.hash_keyed,
            "copies": {
                "rows": self.copies,
                "mean": self.mean_copies(),
                "max": self.max_copies,
            },
            "classes": ranked(self.classes.clone(), None)
                .into_iter()
                .map(|(class, items)| json!({"class": class, "items": items}))
                .collect::<Vec<_>>(),
            "workloads": ranked(self.workloads.clone(), None)
                .into_iter()
                .map(|(workload, items)| json!({"workload": workload, "items": items}))
                .collect::<Vec<_>>(),
            "senders": {
                "distinct": self.senders.len(),
                "teamsThread": self.thread_senders,
                "addressLists": self.list_senders,
                "none": self.no_sender,
                "top": self.top_senders()
                    .into_iter()
                    .map(|(sender, items, addresses)| json!({
                        "sender": sender,
                        "items": items,
                        "addresses": addresses,
                    }))
                    .collect::<Vec<_>>(),
            },
            "senderDomains": {
                "distinct": self.domains.len(),
                "top": ranked(self.domains.clone(), top)
                    .into_iter()
                    .map(|(domain, items)| json!({"senderDomain": domain, "items": items}))
                    .collect::<Vec<_>>(),
            },
            "teamsConversations": {
                "items": self.teams_items,
                "distinct": self.conversations.len(),
                "unnamed": self.unnamed_conversations,
                "top": ranked(self.conversations.clone(), top)
                    .into_iter()
                    .map(|(name, items)| json!({"conversationName": name, "items": items}))
                    .collect::<Vec<_>>(),
            },
            "histogram": {
                "bucket": self.options.bucket.as_str(),
                "undated": self.undated,
                "buckets": self.buckets
                    .iter()
                    .map(|(start, items)| json!({
                        "start": start.format("%Y-%m-%d").to_string(),
                        "items": items,
                    }))
                    .collect::<Vec<_>>(),
            },
            "options": {
                "top": self.options.top,
                "bucket": self.options.bucket.as_str(),
                "mergeLocalPart": self.options.merge_local_part,
            },
        })
    }

    /// The profile as `SECTION`, `NAME`, `COUNT` rows, with tenant text as
    /// it came: the caller makes it safe to show.
    pub fn rows(&self) -> Vec<[String; 3]> {
        let mut rows: Vec<[String; 3]> = Vec::new();
        let mut push = |section: &str, name: &str, count: String| {
            rows.push([section.to_owned(), name.to_owned(), count]);
        };
        let or_none = |name: &Option<String>| name.clone().unwrap_or_else(|| "(none)".into());
        push("items", "unique", self.items.to_string());
        push("items", "keyed by hash", self.hash_keyed.to_string());
        push("copies", "rows", self.copies.to_string());
        push(
            "copies",
            "mean",
            self.mean_copies()
                .map(|mean| format!("{mean:.2}"))
                .unwrap_or_else(|| "-".into()),
        );
        push("copies", "max", self.max_copies.to_string());
        for (class, items) in ranked(self.classes.clone(), None) {
            push("class", &or_none(&class), items.to_string());
        }
        for (workload, items) in ranked(self.workloads.clone(), None) {
            push("workload", &or_none(&workload), items.to_string());
        }
        for (sender, items, _) in self.top_senders() {
            push("sender", &sender, items.to_string());
        }
        if self.thread_senders > 0 {
            push("sender", "(Teams thread)", self.thread_senders.to_string());
        }
        if self.list_senders > 0 {
            push("sender", "(address list)", self.list_senders.to_string());
        }
        if self.no_sender > 0 {
            push("sender", "(none)", self.no_sender.to_string());
        }
        for (domain, items) in ranked(self.domains.clone(), Some(self.options.top)) {
            push("domain", &domain, items.to_string());
        }
        for (name, items) in ranked(self.conversations.clone(), Some(self.options.top)) {
            push("conversation", &name, items.to_string());
        }
        if self.unnamed_conversations > 0 {
            push(
                "conversation",
                "(unnamed)",
                self.unnamed_conversations.to_string(),
            );
        }
        let bucket = self.options.bucket.as_str();
        for (start, items) in &self.buckets {
            push(
                bucket,
                &start.format("%Y-%m-%d").to_string(),
                items.to_string(),
            );
        }
        if self.undated > 0 {
            push(bucket, "(undated)", self.undated.to_string());
        }
        rows
    }
}

/// What a profile pass read, for the summary.
#[derive(Debug)]
pub struct Read {
    pub profile: Profile,
    pub tally: Tally,
    /// Unique items, and those keyed by hash.
    pub unique: (usize, usize),
}

/// Reads the item report zip at `path` through `filters` and profiles its
/// unique items.
pub fn read(
    path: &Path,
    limits: ReportLimits,
    filters: &Filters,
    max_unique: usize,
    identity: &Identity,
    options: Options,
) -> Result<Read> {
    let mut dedup = Dedup::new(max_unique);
    let tally = items::read(path, limits, filters, |row| dedup.add(row))?;
    let unique = (dedup.len(), dedup.hash_keys());
    let mut profile = Profile::new(options);
    for (_, agg) in dedup.finish() {
        profile.add(&agg, identity);
    }
    Ok(Read {
        profile,
        tally,
        unique,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(value: Value) -> BTreeMap<String, Value> {
        serde_json::from_value(value).unwrap()
    }

    fn identity(value: Value) -> Identity {
        Identity::from_config(&config(json!({ "identity": value }))).unwrap()
    }

    fn date(text: &str) -> NaiveDate {
        NaiveDate::parse_from_str(text, "%Y-%m-%d").unwrap()
    }

    #[test]
    fn an_unset_identity_is_empty_and_a_wrong_type_is_refused() {
        assert_eq!(
            Identity::from_config(&config(json!({}))).unwrap(),
            Identity::default()
        );
        assert_eq!(identity(Value::Null), Identity::default());
        assert_eq!(
            identity(json!({"internal_domains": null, "domain_aliases": null})),
            Identity::default()
        );
        for bad in [
            json!("contoso.example"),
            json!({"internal_domains": [""]}),
            json!({"internal_domains": [" "]}),
            json!({"internal_domains": ["a b.example"]}),
            json!({"internal_domains": [3]}),
            json!({"domain_aliases": []}),
            json!({"domain_aliases": {"": "contoso.example"}}),
            json!({"domain_aliases": {"fabrikam.example": null}}),
        ] {
            assert!(
                Identity::from_config(&config(json!({ "identity": bad.clone() }))).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn aliases_are_lowercased_one_step_and_apply_to_internal_domains() {
        let identity = identity(json!({
            "internal_domains": ["OLD.contoso.example"],
            "domain_aliases": {"Old.Contoso.example": " CONTOSO.example ", "contoso.example": "contoso.example"},
        }));
        assert_eq!(identity.alias("old.contoso.example"), "contoso.example");
        assert_eq!(identity.alias("fabrikam.example"), "fabrikam.example");
        assert!(identity.internal_domains.contains("contoso.example"));
        assert!(!identity.internal_domains.contains("old.contoso.example"));
        // One domain in two cases is refused only when the targets differ.
        let error = Identity::from_config(&config(json!({"identity": {"domain_aliases": {
            "fabrikam.example": "contoso.example",
            "FABRIKAM.example": "eu.contoso.example",
        }}})))
        .unwrap_err()
        .to_string();
        assert!(error.contains("names one domain twice"), "{error}");
        assert!(!error.contains("eu.contoso"), "{error}");
        let chain = Identity::from_config(&config(json!({"identity": {"domain_aliases": {
            "a.example": "b.example",
            "b.example": "c.example",
        }}})));
        assert!(chain.is_err());
    }

    #[test]
    fn top_is_twenty_unless_set_to_a_whole_number_above_zero() {
        assert_eq!(top_setting(&config(json!({}))).unwrap(), 20);
        assert_eq!(
            top_setting(&config(json!({"defaults": {"top": null}}))).unwrap(),
            20
        );
        assert_eq!(
            top_setting(&config(json!({"defaults": {"top": 5}}))).unwrap(),
            5
        );
        for bad in [json!(0), json!(-1), json!(2.5), json!("5"), json!(true)] {
            assert!(
                top_setting(&config(json!({"defaults": {"top": bad.clone()}}))).is_err(),
                "{bad}"
            );
        }
        assert!(top_setting(&config(json!({"defaults": []}))).is_err());
    }

    #[test]
    fn buckets_start_on_the_day_the_iso_monday_or_the_first_of_the_month() {
        // 2026-07-12 is a Sunday, 2026-07-13 a Monday.
        assert_eq!(Bucket::Day.start(date("2026-07-12")), date("2026-07-12"));
        assert_eq!(Bucket::Week.start(date("2026-07-12")), date("2026-07-06"));
        assert_eq!(Bucket::Week.start(date("2026-07-13")), date("2026-07-13"));
        // A week across a year end starts in the earlier year.
        assert_eq!(Bucket::Week.start(date("2027-01-01")), date("2026-12-28"));
        assert_eq!(Bucket::Month.start(date("2026-07-31")), date("2026-07-01"));
        assert_eq!(Bucket::Week.start(NaiveDate::MIN), NaiveDate::MIN);
    }

    #[test]
    fn teams_messages_are_known_by_class_prefix_in_any_ascii_case() {
        assert!(is_teams_class("IPM.SkypeTeams.Message"));
        assert!(is_teams_class("ipm.skypeteams.systemmessage"));
        assert!(!is_teams_class("IPM.File.TeamsConversation"));
        assert!(!is_teams_class(
            "IPM.AppointmentSnapshot.SkypeTeams.Meeting"
        ));
        assert!(!is_teams_class("IPM.SkypeTeams"));
        // A multibyte character where the prefix would end is no panic.
        assert!(!is_teams_class("IPM.SkypeTeams\u{e9}x"));
    }

    #[test]
    fn senders_are_normalised_and_thread_ids_are_never_people() {
        let identity = identity(json!({
            "internal_domains": ["contoso.example", "fabrikam.example"],
            "domain_aliases": {"old.contoso.example": "contoso.example"},
        }));
        assert_eq!(who(Some("19:abc@thread.v2"), &identity, true), Who::Thread);
        assert_eq!(
            who(Some("Chat <19:abc@thread.v2>"), &identity, true),
            Who::Thread
        );
        assert_eq!(who(None, &identity, true), Who::Nobody);
        assert_eq!(
            who(Some("a@contoso.example; b@fabrik"), &identity, true),
            Who::List
        );
        assert_eq!(
            who(
                Some("Alex <alex@contoso.example>; Bea <bea@fabrikam.example>"),
                &identity,
                true
            ),
            Who::List
        );
        assert_eq!(who(Some("<>"), &identity, true), Who::Nobody);
        let Who::Person {
            key,
            raw,
            canonical,
            domain,
        } = who(Some("Alex <ALEX@Old.Contoso.example>"), &identity, false)
        else {
            panic!("a person");
        };
        assert_eq!(raw, "alex@old.contoso.example");
        assert_eq!(canonical, "alex@contoso.example");
        assert_eq!(key, SenderKey::Address("alex@contoso.example".into()));
        assert_eq!(domain.as_deref(), Some("contoso.example"));
        let key_of = |sender: &str, merge: bool| match who(Some(sender), &identity, merge) {
            Who::Person { key, .. } => key,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            key_of("alex@fabrikam.example", true),
            SenderKey::Internal("alex".into())
        );
        assert_eq!(
            key_of("alex@old.contoso.example", true),
            SenderKey::Internal("alex".into())
        );
        assert_eq!(
            key_of("alex@eu.fabrikam.example", true),
            SenderKey::Address("alex@eu.fabrikam.example".into())
        );
        assert_eq!(
            key_of("alex@fabrikam.example", false),
            SenderKey::Address("alex@fabrikam.example".into())
        );
        // A display name alone, or an address with nothing after `@`, has
        // no domain and is never merged.
        assert!(matches!(
            who(Some("Alex Example"), &identity, true),
            Who::Person {
                domain: None,
                key: SenderKey::Address(_),
                ..
            }
        ));
        assert!(matches!(
            who(Some("alex@"), &identity, true),
            Who::Person { domain: None, .. }
        ));
        assert_eq!(
            key_of("@contoso.example", true),
            SenderKey::Address("@contoso.example".into())
        );
    }
}
