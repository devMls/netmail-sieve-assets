//! Replace, insert or remove the NetMail rules region in an existing
//! script, with the same verifiable edit plan used for absences.
use super::compile::{REGION_BEGIN, REGION_END};
use super::import::region_bounds;
use crate::edit::{add_requires, patch, Edit};
use crate::{analysis, source};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Region produced by `rules_compile_sieve_json`; empty removes it.
    #[serde(default)]
    pub region: String,
    /// `require` list returned with the region.
    #[serde(default)]
    pub require: Vec<String>,
    /// Exact current region text (`null` when the script has none).
    pub expected_region: Option<String>,
    #[serde(default)]
    pub allow_append_after_control_flow: bool,
}

fn check_region(region: &str) -> Result<(), String> {
    if region.is_empty() {
        return Ok(());
    }
    let mut lines = region.lines().map(str::trim);
    if lines.next() != Some(REGION_BEGIN)
        || region.lines().map(str::trim).rfind(|l| !l.is_empty()) != Some(REGION_END)
        || !region.ends_with('\n')
    {
        return Err("InvalidRequest: region must start and end with the NetMail markers".into());
    }
    let doc = source::parse(region)?;
    if region_bounds(region, &doc)? != Some((0, region.len())) {
        return Err("InvalidRequest: region contains nested markers".into());
    }
    if doc.commands.iter().any(|c| c.name == "require") {
        return Err("InvalidRequest: require belongs to the script header".into());
    }
    Ok(())
}

pub fn apply(script: &str, request: Request) -> Result<Value, String> {
    check_region(&request.region)?;
    let doc = source::parse(script)?;
    let bounds = region_bounds(script, &doc)?;
    let mut warnings = Vec::new();
    let mut edits = Vec::new();
    match (bounds, request.expected_region.as_deref()) {
        (Some((start, end)), Some(expected)) if &script[start..end] == expected => {
            edits.push(Edit {
                start,
                end,
                expected: expected.into(),
                replacement: request.region.clone(),
            });
        }
        (None, None | Some("")) if request.region.is_empty() => {}
        (None, None | Some("")) => {
            if analysis::contains_command(&doc.commands, &["stop", "discard", "reject", "redirect"])
            {
                if !request.allow_append_after_control_flow {
                    return Err("UnsafeToManage: existing delivery control flow requires an explicit append decision".into());
                }
                warnings.push("Rules appended after existing stop/discard/reject/redirect may not run for every message");
            }
            let prefix = if script.is_empty() || script.ends_with('\n') {
                ""
            } else {
                "\r\n"
            };
            edits.push(Edit {
                start: script.len(),
                end: script.len(),
                expected: String::new(),
                replacement: format!("{prefix}{}", request.region),
            });
        }
        _ => return Err("Conflict: NetMail rules region changed".into()),
    }
    if !request.region.is_empty() {
        let caps: BTreeSet<String> = request
            .require
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect();
        add_requires(script, &doc, &caps, &mut edits, bounds);
    }
    patch(script, edits, warnings)
}
