//! RFC 5228 §5 test-evaluation engine — extracted from `eval/mod.rs`
//! so the command-dispatch loop stays under the file-size limit.
//!
//! Public entry: `eval_test(test, ctx)`. The two arg-shaping
//! helpers (`pair_lists`, `arg_strings_or_list`) live here because
//! they're only used by tests, not by command dispatch.

use crate::address::{address_part_from_tags, extract_addresses, scope_to_part};
use crate::ast::{Argument, Envelope, MatchType, Test};
use crate::compare::{Comparator, match_value};

use super::EvalError;
use super::context::MessageContext;

pub(super) fn eval_test(
    t: &Test,
    ctx: &MessageContext<'_>,
    flags: &[String],
    envelope: &Envelope,
) -> Result<bool, EvalError> {
    match t.name.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        "not" => Ok(!eval_test(&t.children[0], ctx, flags, envelope)?),
        "allof" => {
            for c in &t.children {
                if !eval_test(c, ctx, flags, envelope)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        "anyof" => {
            for c in &t.children {
                if eval_test(c, ctx, flags, envelope)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        "exists" => {
            options(t, &[])?;
            let names = arg_strings_or_list(&t.args);
            Ok(names.iter().all(|n| !ctx.header_values(n).is_empty()))
        }
        "size" => eval_size(t, ctx),
        "header" => eval_header(t, ctx),
        "address" => eval_address(t, ctx),
        "hasflag" => eval_hasflag(t, flags),
        "envelope" => eval_envelope_test(t, envelope),
        other => Err(EvalError::UnknownTest(other.to_string())),
    }
}

const MATCH_TAGS: &[&str] = &["is", "contains", "matches"];
const ADDRESS_TAGS: &[&str] = &["all", "localpart", "domain", "user", "detail"];

/// NetMail patch `netmail-rules-1`: tagged arguments are validated instead
/// of silently ignored. `:comparator` consumes the first string argument
/// (RFC 5228 §2.6.2: tagged arguments precede positional arguments);
/// unknown tags such as `:regex`, `:count` or `:value` and unsupported
/// comparators are errors, never a fallback to `:is`/`i;ascii-casemap`.
struct Options<'t> {
    match_type: MatchType,
    comparator: Comparator,
    tags: &'t [String],
    args: &'t [Argument],
}

fn options<'t>(t: &'t Test, allowed: &[&str]) -> Result<Options<'t>, EvalError> {
    let mut args = t.args.as_slice();
    let mut comparator = None;
    let mut match_type = None;
    let mut part = None;
    for tag in &t.tags {
        let tag = tag.as_str();
        if !allowed.contains(&tag) {
            return Err(EvalError::UnsupportedTag {
                context: t.name.clone(),
                tag: tag.to_string(),
            });
        }
        let duplicate = if tag == "comparator" {
            let Some((Argument::String(name), rest)) = args.split_first() else {
                return Err(EvalError::BadArg {
                    cmd: t.name.clone(),
                    detail: ":comparator expects a comparator name".into(),
                });
            };
            args = rest;
            let resolved = Comparator::from_name(name)
                .ok_or_else(|| EvalError::UnsupportedComparator(name.clone()))?;
            comparator.replace(resolved).is_some()
        } else if MATCH_TAGS.contains(&tag) {
            match_type.replace(tag).is_some()
        } else if ADDRESS_TAGS.contains(&tag) {
            part.replace(tag).is_some()
        } else {
            false
        };
        if duplicate {
            return Err(EvalError::BadArg {
                cmd: t.name.clone(),
                detail: format!("conflicting or duplicate tag :{tag}"),
            });
        }
    }
    Ok(Options {
        match_type: MatchType::from_tags(&t.tags),
        comparator: comparator.unwrap_or_default(),
        tags: &t.tags,
        args,
    })
}

fn string_options(t: &Test, address: bool) -> Result<Options<'_>, EvalError> {
    let mut allowed: Vec<&str> = MATCH_TAGS.to_vec();
    allowed.push("comparator");
    if address {
        allowed.extend_from_slice(ADDRESS_TAGS);
    }
    options(t, &allowed)
}

/// RFC 5228 §5.4 `envelope` test. Inspects the caller-supplied
/// `from` / `to` / `auth` envelope state with the requested
/// match-type + address-part semantics.
fn eval_envelope_test(t: &Test, envelope: &Envelope) -> Result<bool, EvalError> {
    let o = string_options(t, true)?;
    let part = address_part_from_tags(o.tags);
    let (parts, values) = pair_lists(o.args);
    for part_name in &parts {
        let candidates = envelope_field(envelope, part_name);
        for addr in candidates {
            let Some(scoped) = scope_to_part(&addr, part) else {
                continue; // undefined :detail (no `+`) → skip
            };
            for needle in &values {
                if match_value(o.match_type, o.comparator, &scoped, needle) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Resolve `from` / `to` / `auth` (RFC 5228 §5.4, case-insensitive
/// part name) into the candidate address strings for matching.
fn envelope_field(envelope: &Envelope, name: &str) -> Vec<String> {
    match name.to_ascii_lowercase().as_str() {
        "from" => envelope.from.clone().into_iter().collect(),
        "to" => envelope.to.clone(),
        "auth" => envelope.auth.clone().into_iter().collect(),
        _ => Vec::new(),
    }
}

/// RFC 5232 §5.4 `hasflag` — true iff any flag in the test arg
/// list matches any flag in the implicit flags variable, using
/// the requested match-type (defaults to `:is`, case-insensitive).
fn eval_hasflag(t: &Test, flags: &[String]) -> Result<bool, EvalError> {
    let o = string_options(t, false)?;
    let needles = match o.args.first() {
        Some(Argument::String(s)) => vec![s.clone()],
        Some(Argument::StringList(v)) => v.clone(),
        _ => return Ok(false),
    };
    for needle in &needles {
        for held in flags {
            if match_value(o.match_type, o.comparator, held, needle) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn eval_size(t: &Test, ctx: &MessageContext<'_>) -> Result<bool, EvalError> {
    options(t, &["over", "under"])?;
    let over = t.tags.iter().any(|s| s == "over");
    let under = t.tags.iter().any(|s| s == "under");
    let n = match t.args.first() {
        Some(Argument::Number(n)) if over != under && t.args.len() == 1 => *n,
        _ => {
            return Err(EvalError::BadArg {
                cmd: "size".into(),
                detail: "expects exactly one of :over/:under and a numeric size".into(),
            });
        }
    };
    let size = ctx.body_size();
    Ok(if under { size < n } else { size > n })
}

fn eval_header(t: &Test, ctx: &MessageContext<'_>) -> Result<bool, EvalError> {
    let o = string_options(t, false)?;
    let (names, values) = pair_lists(o.args);
    for name in &names {
        // RFC 5228 §2.7.2: compare decoded header values.
        for hv in ctx.decoded_header_values(name) {
            for needle in &values {
                if match_value(o.match_type, o.comparator, &hv, needle) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

fn eval_address(t: &Test, ctx: &MessageContext<'_>) -> Result<bool, EvalError> {
    let o = string_options(t, true)?;
    let part = address_part_from_tags(o.tags);
    let (names, values) = pair_lists(o.args);
    for name in &names {
        for hv in ctx.header_values(name) {
            for addr in extract_addresses(&hv) {
                let Some(scoped) = scope_to_part(&addr, part) else {
                    continue; // undefined :detail (no `+`) → skip
                };
                for needle in &values {
                    if match_value(o.match_type, o.comparator, &scoped, needle) {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

/// Collect every `String` / `StringList` arg into a flat vector
/// (skip tags, numbers, nested tests). Used by `exists`.
fn arg_strings_or_list(args: &[Argument]) -> Vec<String> {
    let mut out = Vec::new();
    for a in args {
        match a {
            Argument::String(s) => out.push(s.clone()),
            Argument::StringList(v) => out.extend(v.iter().cloned()),
            _ => {}
        }
    }
    out
}

/// Split a header/address test's args into `(names, values)`: the
/// first non-tag arg (string-or-list) is the header names, the
/// second is the values to match against.
fn pair_lists(args: &[Argument]) -> (Vec<String>, Vec<String>) {
    let mut names = Vec::new();
    let mut values = Vec::new();
    let mut idx = 0usize;
    for a in args {
        let collected = match a {
            Argument::String(s) => vec![s.clone()],
            Argument::StringList(v) => v.clone(),
            _ => continue,
        };
        if idx == 0 {
            names = collected;
        } else if idx == 1 {
            values = collected;
        }
        idx += 1;
    }
    (names, values)
}
