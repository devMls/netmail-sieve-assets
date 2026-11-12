//! Sieve → IR. Conversion is permissive about the shapes it recognises;
//! `reversible` is decided by regenerating the rule and comparing the
//! normalised reference AST with the original command, never by trusting
//! a comment. Unrecognised commands are reported as preserved blocks.
use super::compile::{emit_actions, emit_test, REGION_BEGIN, REGION_END, RULE_MARKER};
use super::ir::{
    header_name_ok, keyword_ok, AddressPart, Comparator, Condition, Field, MatchMode, Operator,
    Rule, RuleAction,
};
use crate::source::{self, Document, Node};
use mailrs_sieve_core::{Argument, Command, Test};
use serde_json::{json, Value};

type Converted<T> = Result<T, String>;

/// Byte range of the NetMail region, including both marker lines.
/// Markers must be comments between top-level commands.
pub fn region_bounds(script: &str, doc: &Document) -> Result<Option<(usize, usize)>, String> {
    let mut begins = Vec::new();
    let mut ends = Vec::new();
    let mut offset = 0;
    for line in script.split_inclusive('\n') {
        let text = line.trim_end_matches(['\r', '\n']).trim();
        if text == REGION_BEGIN {
            begins.push(offset);
        } else if text == REGION_END {
            ends.push(offset + line.len());
        }
        offset += line.len();
    }
    let inside = |p: usize| doc.nodes.iter().any(|n| n.start <= p && p < n.end);
    begins.retain(|p| !inside(*p));
    ends.retain(|p| !inside(p - 1));
    match (begins.as_slice(), ends.as_slice()) {
        ([], []) => Ok(None),
        ([b], [e]) if b < e => Ok(Some((*b, *e))),
        _ => Err(
            "UnsafeToManage: NetMail rules region markers are missing, repeated or out of order"
                .into(),
        ),
    }
}

fn strings(arg: &Argument) -> Option<Vec<String>> {
    match arg {
        Argument::String(s) => Some(vec![s.clone()]),
        Argument::StringList(v) if !v.is_empty() => Some(v.clone()),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Glob {
    Literal(char),
    Star,
    One,
}

fn glob_tokens(pattern: &str) -> Vec<Glob> {
    let mut out = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        out.push(match c {
            '*' => Glob::Star,
            '?' => Glob::One,
            '\\' => Glob::Literal(chars.next().unwrap_or('\\')),
            other => Glob::Literal(other),
        });
    }
    out
}

fn literal(tokens: &[Glob]) -> Option<String> {
    tokens
        .iter()
        .map(|t| match t {
            Glob::Literal(c) => Some(*c),
            Glob::Star | Glob::One => None,
        })
        .collect()
}

/// `abc*` → StartsWith("abc"), `*abc` → EndsWith("abc"), otherwise raw.
fn classify(patterns: &[String]) -> (Operator, Vec<String>) {
    let star_at = |p: &str, end: bool| -> Option<String> {
        let tokens = glob_tokens(p);
        let (edge, rest) = if end {
            tokens.split_last()?
        } else {
            tokens.split_first()?
        };
        if *edge != Glob::Star || rest.is_empty() {
            return None;
        }
        literal(rest)
    };
    if let Some(v) = patterns
        .iter()
        .map(|p| star_at(p, true))
        .collect::<Option<Vec<_>>>()
    {
        return (Operator::StartsWith, v);
    }
    if let Some(v) = patterns
        .iter()
        .map(|p| star_at(p, false))
        .collect::<Option<Vec<_>>>()
    {
        return (Operator::EndsWith, v);
    }
    (Operator::Matches, patterns.to_vec())
}

struct Tags {
    match_tag: Option<String>,
    comparator: Comparator,
    part: AddressPart,
    rest: Vec<Argument>,
}

fn tags(t: &Test, address: bool, extra: &[&str]) -> Converted<Tags> {
    let mut args = t.args.clone();
    let mut out = Tags {
        match_tag: None,
        comparator: Comparator::AsciiCasemap,
        part: AddressPart::All,
        rest: Vec::new(),
    };
    for tag in &t.tags {
        match tag.as_str() {
            "is" | "contains" | "matches" if out.match_tag.is_none() => {
                out.match_tag = Some(tag.clone())
            }
            "comparator" => {
                if args.is_empty() {
                    return Err("comparator without name".into());
                }
                out.comparator = match args.remove(0) {
                    Argument::String(n) if n.eq_ignore_ascii_case("i;octet") => Comparator::Octet,
                    Argument::String(n) if n.eq_ignore_ascii_case("i;ascii-casemap") => {
                        Comparator::AsciiCasemap
                    }
                    _ => return Err("unsupported comparator".into()),
                }
            }
            "all" if address => out.part = AddressPart::All,
            "localpart" if address => out.part = AddressPart::Localpart,
            "domain" if address => out.part = AddressPart::Domain,
            other if extra.contains(&other) => {}
            other => return Err(format!("unsupported tag :{other}")),
        }
    }
    out.rest = args;
    Ok(out)
}

fn text_condition(
    field: Field,
    header: Option<String>,
    t: &Tags,
    keys: &Argument,
) -> Converted<Condition> {
    let keys = strings(keys).ok_or("expected key list")?;
    let (op, values) = match t.match_tag.as_deref().unwrap_or("is") {
        "is" => (Operator::Is, keys),
        "contains" => (Operator::Contains, keys),
        _ => classify(&keys),
    };
    Ok(Condition {
        field,
        op,
        values,
        header,
        address_part: t.part,
        comparator: t.comparator,
        size: None,
        negate: false,
    })
}

fn header_field(names: &[String]) -> Converted<(Field, Option<String>)> {
    match names {
        [n] if n == "subject" => Ok((Field::Subject, None)),
        [n] if n == "list-id" => Ok((Field::ListId, None)),
        [n] if header_name_ok(n) => Ok((Field::Header, Some(n.clone()))),
        _ => Err("header test over several or invalid names".into()),
    }
}

fn condition(t: &Test) -> Converted<Condition> {
    match t.name.as_str() {
        "not" => {
            let mut c = condition(t.children.first().ok_or("empty not")?)?;
            if c.negate {
                return Err("double negation".into());
            }
            c.negate = true;
            Ok(c)
        }
        "header" => {
            let o = tags(t, false, &[])?;
            let [names, keys] = o.rest.as_slice() else {
                return Err("header expects names and keys".into());
            };
            let (field, header) = header_field(&strings(names).ok_or("names")?)?;
            text_condition(field, header, &o, keys)
        }
        "address" => {
            let o = tags(t, true, &[])?;
            let [names, keys] = o.rest.as_slice() else {
                return Err("address expects names and keys".into());
            };
            let names = strings(names).ok_or("names")?;
            let field = match names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                ["from"] => Field::From,
                ["sender"] => Field::Sender,
                ["to"] => Field::To,
                ["cc"] => Field::Cc,
                ["to", "cc"] => Field::ToOrCc,
                _ => return Err("address header not representable".into()),
            };
            text_condition(field, None, &o, keys)
        }
        "body" => {
            let o = tags(t, false, &["text"])?;
            if !t.tags.iter().any(|x| x == "text") {
                return Err("only body :text is representable".into());
            }
            let [keys] = o.rest.as_slice() else {
                return Err("body expects keys".into());
            };
            text_condition(Field::BodyText, None, &o, keys)
        }
        "exists" if t.tags.is_empty() => {
            let [names] = t.args.as_slice() else {
                return Err("exists expects names".into());
            };
            let (field, header) = header_field(&strings(names).ok_or("names")?)?;
            Ok(Condition {
                field,
                op: Operator::Exists,
                values: Vec::new(),
                header,
                address_part: AddressPart::All,
                comparator: Comparator::AsciiCasemap,
                size: None,
                negate: false,
            })
        }
        "size" => {
            let op = match t.tags.as_slice() {
                [o] if o == "over" => Operator::Over,
                [o] if o == "under" => Operator::Under,
                _ => return Err("size expects :over or :under".into()),
            };
            let [Argument::Number(n)] = t.args.as_slice() else {
                return Err("size expects a number".into());
            };
            Ok(Condition {
                field: Field::Size,
                op,
                values: Vec::new(),
                header: None,
                address_part: AddressPart::All,
                comparator: Comparator::AsciiCasemap,
                size: Some(*n),
                negate: false,
            })
        }
        other => Err(format!("test {other} is not representable")),
    }
}

fn simple_list(tests: &[Test]) -> Converted<Vec<Condition>> {
    tests.iter().map(condition).collect()
}

fn is_group(t: &Test) -> bool {
    matches!(t.name.as_str(), "allof" | "anyof")
}

type RuleTest = (bool, MatchMode, Vec<Condition>, Vec<Condition>);

fn rule_test(t: &Test) -> Converted<RuleTest> {
    if t.name == "allof"
        && t.children.len() == 2
        && t.children[0].name == "false"
        && t.children[0].args.is_empty()
        && t.children[0].tags.is_empty()
    {
        let (_, mode, c, e) = rule_test(&t.children[1])?;
        return Ok((false, mode, c, e));
    }
    let main = |t: &Test| -> Converted<(MatchMode, Vec<Condition>)> {
        match t.name.as_str() {
            "true" => Ok((MatchMode::All, Vec::new())),
            "allof" => Ok((MatchMode::All, simple_list(&t.children)?)),
            "anyof" => Ok((MatchMode::Any, simple_list(&t.children)?)),
            _ => Ok((MatchMode::All, vec![condition(t)?])),
        }
    };
    let exceptions = |t: &Test| -> Converted<Vec<Condition>> {
        if t.name == "anyof" {
            simple_list(&t.children)
        } else {
            Ok(vec![condition(t)?])
        }
    };
    if t.name == "allof" && t.children.len() == 2 && t.children[1].name == "not" {
        let negated = &t.children[1].children[0];
        if is_group(&t.children[0]) || negated.name == "anyof" {
            let (mode, conditions) = main(&t.children[0])?;
            return Ok((true, mode, conditions, exceptions(negated)?));
        }
    }
    if t.name == "not" && t.children[0].name == "anyof" {
        return Ok((
            true,
            MatchMode::All,
            Vec::new(),
            exceptions(&t.children[0])?,
        ));
    }
    let (mode, conditions) = main(t)?;
    Ok((true, mode, conditions, Vec::new()))
}

fn flag_action(flag: &str) -> Converted<RuleAction> {
    if flag.eq_ignore_ascii_case("\\Seen") {
        Ok(RuleAction::MarkRead)
    } else if flag.eq_ignore_ascii_case("\\Flagged") {
        Ok(RuleAction::Flag)
    } else if keyword_ok(flag) {
        Ok(RuleAction::AddTag {
            keyword: flag.to_string(),
        })
    } else {
        Err(format!("flag {flag} is not representable"))
    }
}

fn actions(block: &[Command]) -> Converted<Vec<RuleAction>> {
    let mut out = Vec::new();
    for c in block {
        let copy = c
            .args
            .iter()
            .any(|a| matches!(a, Argument::Tag(t) if t == "copy"));
        let positional: Vec<&Argument> = c
            .args
            .iter()
            .filter(|a| !matches!(a, Argument::Tag(_)))
            .collect();
        let tags_ok = c
            .args
            .iter()
            .all(|a| !matches!(a, Argument::Tag(t) if t != "copy"));
        match (c.name.as_str(), positional.as_slice()) {
            ("addflag", [flags]) if tags_ok && !copy => {
                for flag in strings(flags).ok_or("addflag expects flags")? {
                    out.push(flag_action(&flag)?);
                }
            }
            ("fileinto", [Argument::String(mailbox)]) if tags_ok => out.push(if copy {
                RuleAction::Copy {
                    mailbox: mailbox.clone(),
                }
            } else {
                RuleAction::Move {
                    mailbox: mailbox.clone(),
                }
            }),
            ("redirect", [Argument::String(address)]) if tags_ok => {
                out.push(RuleAction::Redirect {
                    address: address.clone(),
                    keep_copy: copy,
                })
            }
            ("stop", []) if c.args.is_empty() => out.push(RuleAction::Stop),
            (name, _) => return Err(format!("action {name} is not representable")),
        }
        if !c.block.is_empty() {
            return Err("nested block inside rule actions".into());
        }
    }
    if out.is_empty() {
        return Err("rule without actions".into());
    }
    Ok(out)
}

fn normalise_args(args: &[Argument]) -> Vec<Argument> {
    args.iter()
        .map(|a| match a {
            Argument::StringList(v) if v.len() == 1 => Argument::String(v[0].clone()),
            Argument::Test(t) => Argument::Test(normalise_test(t)),
            Argument::TestList(v) => Argument::TestList(v.iter().map(normalise_test).collect()),
            other => other.clone(),
        })
        .collect()
}

fn normalise_test(t: &Test) -> Test {
    Test {
        name: t.name.clone(),
        tags: t.tags.clone(),
        args: normalise_args(&t.args),
        children: t.children.iter().map(normalise_test).collect(),
    }
}

fn normalise(c: &Command) -> Command {
    Command {
        name: c.name.clone(),
        args: normalise_args(&c.args),
        block: c.block.iter().map(normalise).collect(),
    }
}

/// True when regenerating `rule` reproduces the original command.
pub fn reversible(rule: &Rule, original: &Command) -> bool {
    let mut text = format!("if {} {{\r\n", emit_test(rule));
    for line in emit_actions(rule) {
        text.push_str(&line);
        text.push_str("\r\n");
    }
    text.push('}');
    source::parse(&text)
        .ok()
        .and_then(|doc| doc.commands.into_iter().next())
        .is_some_and(|generated| normalise(&generated) == normalise(original))
}

struct Meta {
    id: String,
    name: String,
    revision: u64,
    origin: &'static str,
}

fn meta(between: &str) -> Meta {
    let mut found = Meta {
        id: String::new(),
        name: String::new(),
        revision: 0,
        origin: "unknown",
    };
    for line in between.lines().map(str::trim) {
        if let Some(json) = line.strip_prefix(RULE_MARKER.trim_end()) {
            if let Ok(v) = serde_json::from_str::<Value>(json.trim()) {
                found = Meta {
                    id: v["id"].as_str().unwrap_or_default().into(),
                    name: v["name"].as_str().unwrap_or_default().into(),
                    revision: v["revision"].as_u64().unwrap_or_default(),
                    origin: "netmail",
                };
            }
        } else if let Some(rest) = line.strip_prefix("# rule:[") {
            if let Some(name) = rest.strip_suffix(']') {
                found = Meta {
                    id: String::new(),
                    name: name.into(),
                    revision: 0,
                    origin: "roundcube",
                };
            }
        }
    }
    found
}

fn convert(command: &Command, between: &str) -> Converted<(Rule, &'static str)> {
    let [Argument::Test(test)] = command.args.as_slice() else {
        return Err("if without a single test".into());
    };
    let (enabled, match_mode, conditions, exceptions) = rule_test(test)?;
    let m = meta(between);
    let rule = Rule {
        id: m.id,
        name: m.name,
        enabled,
        revision: m.revision,
        match_mode,
        conditions,
        exceptions,
        actions: actions(&command.block)?,
    };
    Ok((rule, m.origin))
}

pub fn import(script: &str) -> Result<Value, String> {
    let doc = source::parse(script)?;
    let region = region_bounds(script, &doc)?;
    let in_region = |n: &Node| region.is_some_and(|(b, e)| b <= n.start && n.end <= e);
    let mut rules = Vec::new();
    let mut external = Vec::new();
    let mut previous_end = 0;
    let commands: Vec<_> = doc.commands.iter().zip(&doc.nodes).collect();
    let mut i = 0;
    while i < commands.len() {
        let (command, node) = commands[i];
        let between = &script[previous_end..node.start];
        // An if/elsif/else chain is one preserved unit.
        let mut chain_end = i;
        while commands
            .get(chain_end + 1)
            .is_some_and(|(c, _)| matches!(c.name.as_str(), "elsif" | "else"))
        {
            chain_end += 1;
        }
        let end = commands[chain_end].1.end;
        let source_text = &script[node.start..end];
        if command.name == "require" {
            // Declarations are reported through `capabilities`.
        } else if command.name == "if" && chain_end == i {
            match convert(command, between) {
                Ok((rule, origin)) => {
                    let reversible = reversible(&rule, command);
                    rules.push(
                        json!({"rule": rule, "origin": origin, "managed": in_region(node),
                        "reversible": reversible, "start": node.start, "end": end,
                        "source": source_text}),
                    );
                }
                Err(reason) => external.push(json!({"start": node.start, "end": end,
                    "managed": in_region(node), "kind": "unconvertible_rule", "reason": reason,
                    "source": source_text})),
            }
        } else {
            external.push(
                json!({"start": node.start, "end": end, "managed": in_region(node),
                "kind": if chain_end > i { "conditional_chain" } else { "command" },
                "reason": format!("{} is outside the rule model", command.name),
                "source": source_text}),
            );
        }
        previous_end = end;
        i = chain_end + 1;
    }
    Ok(json!({
        "success": true, "schema_version": 1, "offset_unit": "utf8_bytes",
        "capabilities": crate::analysis::capabilities(&doc),
        "region": region.map(|(start, end)| json!({"start": start, "end": end})),
        "rules": rules, "external": external,
    }))
}
