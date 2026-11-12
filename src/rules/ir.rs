//! Versioned rule IR (`netmail.rules/1`). One JSON document describes the
//! desired rules of an account; compilers, the importer and the local
//! evaluator all consume these types, so their semantics cannot drift.
//!
//! Semantics (documented in README «Reglas»):
//! - Rules run in order; disabled rules are skipped.
//! - A rule matches when its conditions match (`all`/`any`; no
//!   conditions = every message) and none of its exceptions match.
//! - A condition with several values matches when any value matches.
//! - Within a rule, flag actions (`mark_read`, `flag`, `add_tag`) run
//!   first and accumulate into the message flag set (RFC 5232 internal
//!   variable): they apply to later deliveries of this and later rules
//!   and to the implicit keep. Delivery actions then run in listed order.
//!   `stop` always runs last.
//! - `move` files the message and cancels the implicit keep; `copy` files
//!   a copy and keeps it. Several moves produce several deliveries,
//!   exactly as in Sieve.
use serde::{Deserialize, Serialize};

pub const SCHEMA: u32 = 1;
pub const MAX_RULES: usize = 500;
pub const MAX_CONDITIONS: usize = 50;
pub const MAX_VALUES: usize = 100;
pub const MAX_VALUE_BYTES: usize = 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub schema: u32,
    pub rules: Vec<Rule>,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub revision: u64,
    #[serde(rename = "match", default)]
    pub match_mode: MatchMode,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub exceptions: Vec<Condition>,
    pub actions: Vec<RuleAction>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    #[default]
    All,
    Any,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    From,
    Sender,
    To,
    Cc,
    ToOrCc,
    Subject,
    Header,
    ListId,
    Size,
    HasAttachment,
    AttachmentName,
    BodyText,
}

impl Field {
    pub fn is_address(self) -> bool {
        matches!(
            self,
            Field::From | Field::Sender | Field::To | Field::Cc | Field::ToOrCc
        )
    }
    pub fn is_text(self) -> bool {
        matches!(
            self,
            Field::Subject
                | Field::Header
                | Field::ListId
                | Field::AttachmentName
                | Field::BodyText
        ) || self.is_address()
    }
    /// Header names consulted by Sieve/snapshots for header-backed fields.
    pub fn header_names(self, header: Option<&str>) -> Vec<String> {
        match self {
            Field::From => vec!["from".into()],
            Field::Sender => vec!["sender".into()],
            Field::To => vec!["to".into()],
            Field::Cc => vec!["cc".into()],
            Field::ToOrCc => vec!["to".into(), "cc".into()],
            Field::Subject => vec!["subject".into()],
            Field::ListId => vec!["list-id".into()],
            Field::Header => header.map(|h| vec![h.to_string()]).unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Is,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    Exists,
    Over,
    Under,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AddressPart {
    #[default]
    All,
    Localpart,
    Domain,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Comparator {
    /// RFC 5228 default `i;ascii-casemap`.
    #[default]
    AsciiCasemap,
    /// `i;octet`, exact.
    Octet,
    /// Client-only: Unicode lower-case after removing accents (NFD).
    UnicodeFold,
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: Field,
    pub op: Operator,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub address_part: AddressPart,
    #[serde(default, skip_serializing_if = "is_default")]
    pub comparator: Comparator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub negate: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleAction {
    Move {
        mailbox: String,
    },
    Copy {
        mailbox: String,
    },
    MarkRead,
    Flag,
    AddTag {
        keyword: String,
    },
    Redirect {
        address: String,
        #[serde(default, skip_serializing_if = "is_false")]
        keep_copy: bool,
    },
    Stop,
    Notify,
    Sound {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sound: Option<String>,
    },
}

impl RuleAction {
    pub fn flag(&self) -> Option<&str> {
        match self {
            RuleAction::MarkRead => Some("\\Seen"),
            RuleAction::Flag => Some("\\Flagged"),
            RuleAction::AddTag { keyword } => Some(keyword),
            _ => None,
        }
    }
}

impl Rule {
    /// Actions in canonical execution order: flags, other actions in the
    /// listed order, `stop` last. Duplicated flags are kept once.
    pub fn canonical_actions(&self) -> Vec<&RuleAction> {
        let mut flags: Vec<&RuleAction> = Vec::new();
        for action in self.actions.iter().filter(|a| a.flag().is_some()) {
            if !flags.iter().any(|f| f.flag() == action.flag()) {
                flags.push(action);
            }
        }
        let others = self
            .actions
            .iter()
            .filter(|a| a.flag().is_none() && **a != RuleAction::Stop);
        let stop = self.actions.iter().find(|a| **a == RuleAction::Stop);
        flags.into_iter().chain(others).chain(stop).collect()
    }
}

pub fn parse_rule_set(text: &str) -> Result<RuleSet, String> {
    let set: RuleSet = serde_json::from_str(text).map_err(|e| format!("InvalidRules: {e}"))?;
    validate(&set)?;
    Ok(set)
}

fn text_ok(value: &str, max: usize, what: &str) -> Result<(), String> {
    if value.len() > max || value.chars().any(|c| c == '\0' || c == '\r' || c == '\n') {
        return Err(format!(
            "InvalidRules: {what} exceeds {max} bytes or contains NUL/CR/LF"
        ));
    }
    Ok(())
}

/// RFC 5322 field name: printable US-ASCII except colon.
pub fn header_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| (33..=126).contains(&b) && b != b':')
}

/// IMAP keyword atom (RFC 3501 flag-keyword), never a system flag.
pub fn keyword_ok(keyword: &str) -> bool {
    !keyword.is_empty()
        && keyword.len() <= 128
        && keyword
            .bytes()
            .all(|b| (33..=126).contains(&b) && !b"(){ %*\"\\]".contains(&b))
}

fn address_ok(address: &str) -> bool {
    let Some((local, domain)) = address.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && address.len() <= 320
        && !address
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | '"'))
}

fn condition_ok(c: &Condition, at: &str) -> Result<(), String> {
    let fail = |m: &str| Err(format!("InvalidRules: {at}: {m}"));
    match c.field {
        Field::Size => {
            if !matches!(c.op, Operator::Over | Operator::Under) || c.size.is_none() {
                return fail("size requires over/under and size");
            }
        }
        Field::HasAttachment => {
            if c.op != Operator::Exists {
                return fail("has_attachment only admits exists");
            }
        }
        _ => {
            if matches!(c.op, Operator::Over | Operator::Under) {
                return fail("over/under only apply to size");
            }
            if c.op == Operator::Exists
                && !matches!(c.field, Field::Header | Field::ListId | Field::Subject)
            {
                return fail("exists only applies to headers");
            }
        }
    }
    let needs_values = c.field.is_text() && c.op != Operator::Exists;
    if needs_values != !c.values.is_empty() || c.values.len() > MAX_VALUES {
        return fail("text operators need 1..=100 values; other operators none");
    }
    for v in &c.values {
        text_ok(v, MAX_VALUE_BYTES, "value")?;
        if c.op != Operator::Contains && v.is_empty() && c.op != Operator::Is {
            return fail("empty pattern");
        }
    }
    if (c.field == Field::Header) != c.header.is_some() {
        return fail("header name is required only for field header");
    }
    if let Some(h) = &c.header {
        if !header_name_ok(h) {
            return fail("invalid header name");
        }
    }
    if c.field != Field::Size && c.size.is_some() {
        return fail("size only applies to field size");
    }
    if !c.field.is_address() && c.address_part != AddressPart::All {
        return fail("address_part only applies to address fields");
    }
    if !c.field.is_text() && c.comparator != Comparator::AsciiCasemap {
        return fail("comparator only applies to text fields");
    }
    Ok(())
}

pub fn validate(set: &RuleSet) -> Result<(), String> {
    if set.schema != SCHEMA {
        return Err(format!("InvalidRules: schema must be {SCHEMA}"));
    }
    if set.rules.len() > MAX_RULES {
        return Err(format!("InvalidRules: more than {MAX_RULES} rules"));
    }
    let mut ids = std::collections::HashSet::new();
    for (i, rule) in set.rules.iter().enumerate() {
        let at = format!("rules[{i}]");
        if rule.id.is_empty()
            || rule.id.len() > 64
            || !rule
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(format!(
                "InvalidRules: {at}.id must be 1..=64 of [A-Za-z0-9._-]"
            ));
        }
        if !ids.insert(rule.id.as_str()) {
            return Err(format!("InvalidRules: duplicate rule id {}", rule.id));
        }
        text_ok(&rule.name, 200, "name")?;
        if rule.name.chars().any(char::is_control) {
            return Err(format!(
                "InvalidRules: {at}.name contains control characters"
            ));
        }
        if rule.conditions.len() > MAX_CONDITIONS || rule.exceptions.len() > MAX_CONDITIONS {
            return Err(format!("InvalidRules: {at} has too many conditions"));
        }
        for (j, c) in rule.conditions.iter().enumerate() {
            condition_ok(c, &format!("{at}.conditions[{j}]"))?;
        }
        for (j, c) in rule.exceptions.iter().enumerate() {
            condition_ok(c, &format!("{at}.exceptions[{j}]"))?;
        }
        if rule.actions.is_empty() || rule.actions.len() > 20 {
            return Err(format!("InvalidRules: {at} needs 1..=20 actions"));
        }
        for action in &rule.actions {
            match action {
                RuleAction::Move { mailbox } | RuleAction::Copy { mailbox } => {
                    if mailbox.is_empty() {
                        return Err(format!("InvalidRules: {at}: empty mailbox"));
                    }
                    text_ok(mailbox, 1024, "mailbox")?;
                }
                RuleAction::AddTag { keyword } if !keyword_ok(keyword) => {
                    return Err(format!("InvalidRules: {at}: invalid IMAP keyword"));
                }
                RuleAction::Redirect { address, .. } if !address_ok(address) => {
                    return Err(format!("InvalidRules: {at}: invalid redirect address"));
                }
                RuleAction::Sound { sound: Some(s) } => text_ok(s, 256, "sound")?,
                _ => {}
            }
        }
        if rule
            .actions
            .iter()
            .filter(|a| **a == RuleAction::Stop)
            .count()
            > 1
        {
            return Err(format!("InvalidRules: {at}: duplicate stop"));
        }
    }
    Ok(())
}
