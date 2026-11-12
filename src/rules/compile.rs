//! IR → Sieve. The region is generated from typed values with a single
//! quoting/escaping implementation; callers never concatenate Sieve text.
use super::ir::{
    AddressPart, Comparator, Condition, Field, MatchMode, Operator, Rule, RuleAction, RuleSet,
};
use mailrs_sieve_core::escape_glob;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const REGION_BEGIN: &str = "# NetMail rules begin v1";
pub const REGION_END: &str = "# NetMail rules end";
pub const RULE_MARKER: &str = "# netmail-rule ";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub rules: RuleSet,
    /// Extensions announced by the ManageSieve server (SIEVE capability).
    pub server_capabilities: Vec<String>,
}

pub fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

fn string_list(values: &[String]) -> String {
    if values.len() == 1 {
        quote(&values[0])
    } else {
        format!(
            "[{}]",
            values
                .iter()
                .map(|v| quote(v))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// Match-type tag and key list for a text operator.
pub fn keys_for(c: &Condition) -> (&'static str, Vec<String>) {
    match c.op {
        Operator::Is => (":is", c.values.clone()),
        Operator::Contains => (":contains", c.values.clone()),
        Operator::Matches => (":matches", c.values.clone()),
        Operator::StartsWith => (
            ":matches",
            c.values
                .iter()
                .map(|v| format!("{}*", escape_glob(v)))
                .collect(),
        ),
        Operator::EndsWith => (
            ":matches",
            c.values
                .iter()
                .map(|v| format!("*{}", escape_glob(v)))
                .collect(),
        ),
        Operator::Exists | Operator::Over | Operator::Under => ("", Vec::new()),
    }
}

/// Why a condition or action cannot be expressed exactly in Sieve.
#[derive(Default)]
pub struct Support {
    pub requires: BTreeSet<&'static str>,
    pub unsupported: Vec<String>,
    pub provider_defined: Vec<String>,
}

fn condition_support(c: &Condition, caps: &BTreeSet<String>, s: &mut Support) {
    match c.field {
        Field::HasAttachment | Field::AttachmentName => s
            .unsupported
            .push(format!("field_not_in_sieve:{:?}", c.field).to_lowercase()),
        Field::BodyText if caps.contains("body") => {
            s.requires.insert("body");
            s.provider_defined
                .push("body_semantics_server_defined".into());
        }
        Field::BodyText => s.unsupported.push("missing_capability:body".into()),
        _ => {}
    }
    if c.comparator == Comparator::UnicodeFold {
        s.unsupported
            .push("client_only_comparator:unicode_fold".into());
    }
}

pub fn emit_condition(c: &Condition) -> String {
    let comparator = if c.comparator == Comparator::Octet {
        ":comparator \"i;octet\" "
    } else {
        ""
    };
    let test = match (c.field, c.op) {
        (Field::Size, Operator::Over) => format!("size :over {}", c.size.unwrap_or_default()),
        (Field::Size, _) => format!("size :under {}", c.size.unwrap_or_default()),
        (_, Operator::Exists) => format!(
            "exists {}",
            string_list(&c.field.header_names(c.header.as_deref()))
        ),
        (Field::BodyText, _) => {
            let (mt, keys) = keys_for(c);
            format!("body :text {comparator}{mt} {}", string_list(&keys))
        }
        (field, _) if field.is_address() => {
            let part = match c.address_part {
                AddressPart::All => "",
                AddressPart::Localpart => ":localpart ",
                AddressPart::Domain => ":domain ",
            };
            let (mt, keys) = keys_for(c);
            format!(
                "address {comparator}{part}{mt} {} {}",
                string_list(&field.header_names(None)),
                string_list(&keys)
            )
        }
        (field, _) => {
            let (mt, keys) = keys_for(c);
            format!(
                "header {comparator}{mt} {} {}",
                string_list(&field.header_names(c.header.as_deref())),
                string_list(&keys)
            )
        }
    };
    if c.negate {
        format!("not {test}")
    } else {
        test
    }
}

fn group(mode: &str, tests: Vec<String>) -> String {
    if tests.len() == 1 {
        tests.into_iter().next().unwrap_or_default()
    } else {
        format!("{mode}({})", tests.join(", "))
    }
}

pub fn emit_test(rule: &Rule) -> String {
    let conditions: Vec<_> = rule.conditions.iter().map(emit_condition).collect();
    let main = if conditions.is_empty() {
        "true".to_string()
    } else {
        group(
            match rule.match_mode {
                MatchMode::All => "allof",
                MatchMode::Any => "anyof",
            },
            conditions,
        )
    };
    let test = if rule.exceptions.is_empty() {
        main
    } else {
        let exceptions = group(
            "anyof",
            rule.exceptions.iter().map(emit_condition).collect(),
        );
        if main == "true" {
            format!("not {exceptions}")
        } else {
            format!("allof({main}, not {exceptions})")
        }
    };
    if rule.enabled {
        test
    } else {
        format!("allof(false, {test})")
    }
}

fn action_support(a: &RuleAction, caps: &BTreeSet<String>, s: &mut Support) {
    let need = |cap: &'static str, s: &mut Support| {
        if caps.contains(cap) {
            s.requires.insert(cap);
        } else {
            s.unsupported.push(format!("missing_capability:{cap}"));
        }
    };
    match a {
        RuleAction::Move { .. } => need("fileinto", s),
        RuleAction::Copy { .. } => {
            need("fileinto", s);
            need("copy", s);
        }
        RuleAction::MarkRead | RuleAction::Flag | RuleAction::AddTag { .. } => {
            need("imap4flags", s)
        }
        RuleAction::Redirect { keep_copy, .. } => {
            if *keep_copy {
                need("copy", s)
            }
        }
        RuleAction::Stop => {}
        RuleAction::Notify | RuleAction::Sound { .. } => s.unsupported.push("local_effect".into()),
    }
}

pub fn emit_actions(rule: &Rule) -> Vec<String> {
    let actions = rule.canonical_actions();
    let flags: Vec<String> = actions
        .iter()
        .filter_map(|a| a.flag().map(str::to_string))
        .collect();
    let mut out = Vec::new();
    if !flags.is_empty() {
        out.push(format!("addflag {};", string_list(&flags)));
    }
    for a in actions {
        match a {
            RuleAction::Move { mailbox } => out.push(format!("fileinto {};", quote(mailbox))),
            RuleAction::Copy { mailbox } => out.push(format!("fileinto :copy {};", quote(mailbox))),
            RuleAction::Redirect { address, keep_copy } => out.push(format!(
                "redirect {}{};",
                if *keep_copy { ":copy " } else { "" },
                quote(address)
            )),
            RuleAction::Stop => out.push("stop;".into()),
            _ => {}
        }
    }
    out
}

pub fn rule_support(rule: &Rule, caps: &BTreeSet<String>) -> Support {
    let mut s = Support::default();
    for c in rule.conditions.iter().chain(&rule.exceptions) {
        condition_support(c, caps, &mut s);
    }
    for a in &rule.actions {
        action_support(a, caps, &mut s);
    }
    s
}

/// Local evaluator coverage, independent of any server.
pub fn local_support(rule: &Rule) -> Vec<String> {
    rule.actions
        .iter()
        .filter_map(|a| match a {
            RuleAction::Redirect { .. } => Some("redirect_not_local".to_string()),
            _ => None,
        })
        .collect()
}

pub fn metadata(rule: &Rule) -> String {
    json!({"id": rule.id, "name": rule.name, "revision": rule.revision}).to_string()
}

pub fn emit_rule(rule: &Rule) -> String {
    let mut text = format!(
        "{RULE_MARKER}{}\r\nif {} {{\r\n",
        metadata(rule),
        emit_test(rule)
    );
    for line in emit_actions(rule) {
        text.push_str("    ");
        text.push_str(&line);
        text.push_str("\r\n");
    }
    text.push_str("}\r\n");
    text
}

pub fn compile(request: Request) -> Result<Value, String> {
    super::ir::validate(&request.rules)?;
    let caps: BTreeSet<String> = request
        .server_capabilities
        .iter()
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let mut region = format!("{REGION_BEGIN}\r\n");
    let mut requires = BTreeSet::new();
    let mut results = Vec::new();
    for rule in &request.rules.rules {
        let support = rule_support(rule, &caps);
        let local = local_support(rule);
        let status = if !support.unsupported.is_empty() {
            "unsupported"
        } else if !support.provider_defined.is_empty() {
            "provider_defined"
        } else {
            "exact"
        };
        let mut range = Value::Null;
        if status != "unsupported" {
            requires.extend(support.requires.iter().copied());
            let start = region.len();
            region.push_str(&emit_rule(rule));
            range = json!({"start": start, "end": region.len()});
        }
        results.push(json!({
            "id": rule.id, "enabled": rule.enabled, "sieve": status,
            "reasons": support.unsupported, "provider_defined": support.provider_defined,
            "local": if local.is_empty() { "supported" } else { "unsupported" },
            "local_reasons": local, "range": range,
        }));
    }
    region.push_str(REGION_END);
    region.push_str("\r\n");
    // The generated region must be valid Sieve on its own (plus require).
    let declaration = if requires.is_empty() {
        String::new()
    } else {
        format!(
            "require {};\r\n",
            string_list(&requires.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        )
    };
    crate::source::parse(&format!("{declaration}{region}"))
        .map_err(|e| format!("InternalError: generated region does not parse: {e}"))?;
    Ok(json!({
        "success": true, "schema_version": 1, "offset_unit": "utf8_bytes",
        "require": requires, "region": region, "rules": results,
    }))
}
