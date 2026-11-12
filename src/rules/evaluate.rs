//! Local evaluation of the IR against normalised message snapshots.
//! String comparison uses the reference `match_value` and the same key
//! derivation as the Sieve compiler, so an `exact` rule behaves the same
//! locally and on the server for the same decoded values.
use super::compile::keys_for;
use super::ir::{
    AddressPart, Comparator, Condition, Field, MatchMode, Operator, Rule, RuleAction, RuleSet,
};
use mailrs_sieve_core::{match_value, scope_to_part, Comparator as SieveComparator, MatchType};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

pub const MAX_MESSAGES: usize = 1000;
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Decoded, normalised message data prepared by the client (MimeKit,
/// Graph or Gmail metadata). `None` means "not available yet", which is
/// never treated as an empty value.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub id: String,
    /// Decoded header values by field name (case-insensitive).
    #[serde(default)]
    pub headers: Option<BTreeMap<String, Vec<String>>>,
    /// True when `headers` lists every header of the message.
    #[serde(default)]
    pub headers_complete: bool,
    #[serde(default)]
    pub from: Option<Vec<String>>,
    #[serde(default)]
    pub sender: Option<Vec<String>>,
    #[serde(default)]
    pub to: Option<Vec<String>>,
    #[serde(default)]
    pub cc: Option<Vec<String>>,
    /// RFC 5322 size in bytes.
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub has_attachment: Option<bool>,
    #[serde(default)]
    pub attachment_names: Option<Vec<String>>,
    #[serde(default)]
    pub body_text: Option<String>,
    #[serde(default)]
    pub body_truncated: bool,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Tri {
    True,
    False,
    Unknown,
}

impl Tri {
    fn from(b: bool) -> Self {
        if b {
            Tri::True
        } else {
            Tri::False
        }
    }
    fn not(self) -> Self {
        match self {
            Tri::True => Tri::False,
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
        }
    }
}

fn fold(text: &str) -> String {
    text.nfd()
        .filter(|c| !is_combining_mark(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

fn compare(c: &Condition, haystack: &str, key: &str) -> bool {
    let mt = match c.op {
        Operator::Is => MatchType::Is,
        Operator::Contains => MatchType::Contains,
        _ => MatchType::Matches,
    };
    match c.comparator {
        Comparator::AsciiCasemap => match_value(mt, SieveComparator::AsciiCasemap, haystack, key),
        Comparator::Octet => match_value(mt, SieveComparator::Octet, haystack, key),
        Comparator::UnicodeFold => {
            match_value(mt, SieveComparator::Octet, &fold(haystack), &fold(key))
        }
    }
}

struct View<'a> {
    message: &'a Snapshot,
    headers: BTreeMap<String, &'a Vec<String>>,
}

impl<'a> View<'a> {
    fn new(message: &'a Snapshot) -> Self {
        let headers = message
            .headers
            .iter()
            .flatten()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        View { message, headers }
    }

    /// Values of the named headers; `None` when availability is unknown.
    fn header(&self, names: &[String]) -> Option<Vec<String>> {
        let mut out = Vec::new();
        for name in names {
            match self.headers.get(&name.to_ascii_lowercase()) {
                Some(values) => out.extend(values.iter().cloned()),
                None if self.message.headers_complete => {}
                None => return None,
            }
        }
        Some(out)
    }

    fn addresses(&self, field: Field) -> Option<Vec<String>> {
        let m = self.message;
        match field {
            Field::From => m.from.clone(),
            Field::Sender => m.sender.clone(),
            Field::To => m.to.clone(),
            Field::Cc => m.cc.clone(),
            Field::ToOrCc => Some([m.to.clone()?, m.cc.clone()?].concat()),
            _ => None,
        }
    }

    fn candidates(&self, c: &Condition) -> Result<Vec<String>, &'static str> {
        if c.field.is_address() {
            let part = match c.address_part {
                AddressPart::All => mailrs_sieve_core::AddressPart::All,
                AddressPart::Localpart => mailrs_sieve_core::AddressPart::LocalPart,
                AddressPart::Domain => mailrs_sieve_core::AddressPart::Domain,
            };
            let list = self.addresses(c.field).ok_or("addresses")?;
            return Ok(list.iter().filter_map(|a| scope_to_part(a, part)).collect());
        }
        match c.field {
            Field::AttachmentName => self
                .message
                .attachment_names
                .clone()
                .ok_or("attachment_names"),
            Field::BodyText => self
                .message
                .body_text
                .clone()
                .map(|b| vec![b])
                .ok_or("body_text"),
            field => self
                .header(&field.header_names(c.header.as_deref()))
                .ok_or("headers"),
        }
    }

    fn condition(&self, c: &Condition, missing: &mut Vec<&'static str>) -> Tri {
        let result = match (c.field, c.op) {
            (Field::Size, op) => match self.message.size {
                Some(size) => Tri::from(if op == Operator::Over {
                    size > c.size.unwrap_or_default()
                } else {
                    size < c.size.unwrap_or_default()
                }),
                None => {
                    missing.push("size");
                    Tri::Unknown
                }
            },
            (Field::HasAttachment, _) => match self.message.has_attachment {
                Some(v) => Tri::from(v),
                None => {
                    missing.push("has_attachment");
                    Tri::Unknown
                }
            },
            (field, Operator::Exists) => {
                match self.header(&field.header_names(c.header.as_deref())) {
                    Some(values) => Tri::from(!values.is_empty()),
                    None => {
                        missing.push("headers");
                        Tri::Unknown
                    }
                }
            }
            _ => match self.candidates(c) {
                Ok(candidates) => {
                    let (_, keys) = keys_for(c);
                    let hit = candidates
                        .iter()
                        .any(|h| keys.iter().any(|k| compare(c, h, k)));
                    if !hit && c.field == Field::BodyText && self.message.body_truncated {
                        missing.push("body_text");
                        Tri::Unknown
                    } else {
                        Tri::from(hit)
                    }
                }
                Err(field) => {
                    missing.push(field);
                    Tri::Unknown
                }
            },
        };
        if c.negate {
            result.not()
        } else {
            result
        }
    }

    fn group(
        &self,
        mode: MatchMode,
        conditions: &[Condition],
        missing: &mut Vec<&'static str>,
    ) -> (Tri, Vec<Value>) {
        let results: Vec<Tri> = conditions
            .iter()
            .map(|c| self.condition(c, missing))
            .collect();
        let detail = results
            .iter()
            .map(|r| match r {
                Tri::True => json!(true),
                Tri::False => json!(false),
                Tri::Unknown => Value::Null,
            })
            .collect();
        let (decisive, absorbing) = match mode {
            MatchMode::All => (Tri::False, Tri::True),
            MatchMode::Any => (Tri::True, Tri::False),
        };
        let total = if results.is_empty() {
            Tri::True
        } else if results.contains(&decisive) {
            decisive
        } else if results.contains(&Tri::Unknown) {
            Tri::Unknown
        } else {
            absorbing
        };
        (total, detail)
    }

    fn rule(&self, rule: &Rule, missing: &mut Vec<&'static str>) -> (Tri, Value) {
        let (main, conditions) = self.group(rule.match_mode, &rule.conditions, missing);
        let (exception, exceptions) = if rule.exceptions.is_empty() {
            (Tri::False, Vec::new())
        } else {
            self.group(MatchMode::Any, &rule.exceptions, missing)
        };
        let total = match (main, exception) {
            (Tri::False, _) | (_, Tri::True) => Tri::False,
            (Tri::True, Tri::False) => Tri::True,
            _ => Tri::Unknown,
        };
        (
            total,
            json!({"rule_id": rule.id, "conditions": conditions, "exceptions": exceptions}),
        )
    }
}

fn evaluate_one(rules: &RuleSet, message: &Snapshot) -> Value {
    let view = View::new(message);
    let mut flags: Vec<String> = Vec::new();
    let mut actions = Vec::new();
    let mut effects = Vec::new();
    let mut matched = Vec::new();
    let mut explicit = false;
    let mut stopped_by = Value::Null;
    for rule in rules.rules.iter().filter(|r| r.enabled) {
        let mut missing = Vec::new();
        let (result, explanation) = view.rule(rule, &mut missing);
        match result {
            Tri::False => continue,
            Tri::Unknown => {
                missing.sort_unstable();
                missing.dedup();
                // Precedence cannot be decided: nothing may be applied.
                return json!({"id": message.id, "status": "deferred", "deferred_rule": rule.id,
                    "missing": missing, "matched": matched, "actions": [], "effects": []});
            }
            Tri::True => {}
        }
        matched.push(explanation);
        for action in rule.canonical_actions() {
            if let Some(flag) = action.flag() {
                if !flags.iter().any(|f| f == flag) {
                    flags.push(flag.to_string());
                }
                continue;
            }
            match action {
                RuleAction::Move { mailbox } => {
                    explicit = true;
                    actions.push(json!({"type": "fileinto", "mailbox": mailbox, "flags": flags, "copy": false, "rule_id": rule.id}));
                }
                RuleAction::Copy { mailbox } => {
                    actions.push(json!({"type": "fileinto", "mailbox": mailbox, "flags": flags, "copy": true, "rule_id": rule.id}));
                }
                RuleAction::Redirect { address, keep_copy } => {
                    explicit |= !keep_copy;
                    actions.push(json!({"type": "redirect", "recipient": address, "copy": keep_copy, "rule_id": rule.id}));
                }
                RuleAction::Notify => effects.push(json!({"type": "notify", "rule_id": rule.id})),
                RuleAction::Sound { sound } => {
                    effects.push(json!({"type": "sound", "sound": sound, "rule_id": rule.id}))
                }
                RuleAction::Stop => stopped_by = json!(rule.id),
                _ => {}
            }
        }
        if !stopped_by.is_null() {
            break;
        }
    }
    if !explicit {
        actions.push(json!({"type": "keep", "flags": flags}));
    }
    json!({"id": message.id, "status": "evaluated", "matched": matched, "actions": actions,
        "effects": effects, "stopped_by": stopped_by})
}

pub fn evaluate(rules: &RuleSet, messages_json: &str) -> Result<Value, String> {
    let messages: Vec<Snapshot> =
        serde_json::from_str(messages_json).map_err(|e| format!("InvalidRequest: {e}"))?;
    if messages.len() > MAX_MESSAGES {
        return Err(format!("InputLimit: more than {MAX_MESSAGES} messages"));
    }
    if messages.iter().any(|m| {
        m.body_text
            .as_ref()
            .is_some_and(|b| b.len() > MAX_BODY_BYTES)
    }) {
        return Err("InputLimit: body_text exceeds 1 MiB; truncate and set body_truncated".into());
    }
    Ok(json!({
        "success": true, "schema_version": 1,
        "results": messages.iter().map(|m| evaluate_one(rules, m)).collect::<Vec<_>>(),
    }))
}
