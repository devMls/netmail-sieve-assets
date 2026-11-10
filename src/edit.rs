use crate::{analysis, source};
use mailrs_sieve_core::Command;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;

#[derive(Debug, Serialize)]
pub struct Edit {
    pub start: usize,
    pub end: usize,
    pub expected: String,
    pub replacement: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation: String,
    pub target_index: Option<usize>,
    pub expected_source: Option<String>,
    #[serde(default)]
    pub snippet: String,
    #[serde(default = "command_scope")]
    pub scope: String,
    #[serde(default)]
    pub allow_append_after_control_flow: bool,
}

fn command_scope() -> String {
    "command".into()
}

fn patch(source: &str, mut edits: Vec<Edit>, warnings: Vec<&str>) -> Result<Value, String> {
    edits.sort_by_key(|e| (e.start, e.end));
    let mut end = 0;
    for e in &edits {
        if e.start < end
            || e.start > e.end
            || !source.is_char_boundary(e.start)
            || !source.is_char_boundary(e.end)
            || source.get(e.start..e.end) != Some(e.expected.as_str())
        {
            return Err("Conflict: overlapping, invalid or stale source edit".into());
        }
        end = e.end;
    }
    let mut script = source.to_string();
    for e in edits.iter().rev() {
        script.replace_range(e.start..e.end, &e.replacement);
    }
    source::parse(&script)?;
    Ok(
        json!({"success":true,"schema_version":2,"changed":script != source,
        "script":script,"offset_unit":"utf8_bytes","edits":edits,"warnings":warnings}),
    )
}

fn prepare(snippet: &str) -> Result<(String, BTreeSet<String>), String> {
    let doc = source::parse(snippet)?;
    let found = analysis::vacations(&doc);
    let executable: Vec<_> = doc
        .commands
        .iter()
        .filter(|c| c.name != "require")
        .collect();
    if found.is_empty() {
        if executable.is_empty()
            || (executable.len() == 1
                && executable[0].name == "keep"
                && executable[0].args.is_empty()
                && executable[0].block.is_empty())
        {
            return Ok((String::new(), BTreeSet::new()));
        }
        return Err(
            "UnsafeToManage: snippet must contain only one vacation or a disabled template".into(),
        );
    }
    if found.len() != 1 || executable.len() != 1 {
        return Err("AmbiguousVacation: snippet must contain exactly one isolated vacation".into());
    }
    analysis::settings_schedule(&found[0])?;
    analysis::parameters(found[0].command)?;
    // Slice the AST's single executable node. No line stripping: require and
    // vacation may share a line, comments and text: literals contain fake code.
    let node = doc
        .commands
        .iter()
        .zip(&doc.nodes)
        .find(|(c, _)| c.name != "require")
        .unwrap()
        .1;
    let mut caps = analysis::capabilities(&doc);
    caps.insert("vacation".into());
    if !found[0].contexts.is_empty() {
        let schedule = analysis::settings_schedule(&found[0])?;
        if schedule.start.is_some() || schedule.end.is_some() {
            caps.insert("date".into());
            caps.insert("relational".into());
        }
    }
    if found[0]
        .command
        .args
        .iter()
        .any(|a| matches!(a,mailrs_sieve_core::Argument::Tag(t) if t == "seconds"))
    {
        caps.insert("vacation-seconds".into());
    }
    Ok((snippet[node.start..node.end].to_string(), caps))
}

fn unknown_external_flow(commands: &[Command]) -> bool {
    // Imported includes and variable-bearing scripts need a higher-level
    // ownership/import decision. A comment is never proof of ownership.
    analysis::contains_command(commands, &["include", "return", "foreverypart"])
}

pub fn edit(original: &str, request: Request) -> Result<Value, String> {
    let doc = source::parse(original)?;
    if unknown_external_flow(&doc.commands) {
        return Err("UnsafeToManage: external includes or unsupported control flow".into());
    }
    let found = analysis::vacations(&doc);
    let (body, caps) = prepare(&request.snippet)?;
    let mut warnings = Vec::new();
    let mut edits = Vec::new();
    match request.operation.as_str() {
        "append" => {
            if request.target_index.is_some()
                || request.expected_source.is_some()
                || !found.is_empty()
                || body.is_empty()
            {
                return Err(
                    "AmbiguousVacation: append requires no existing vacation and one new vacation"
                        .into(),
                );
            }
            if analysis::contains_command(&doc.commands, &["stop", "discard", "reject", "redirect"])
            {
                if !request.allow_append_after_control_flow {
                    return Err("UnsafeToManage: delivery control flow requires an explicit append decision".into());
                }
                warnings.push("Vacation reachability and suppression must be verified against server delivery policy");
            }
            let prefix = if original.is_empty() || original.ends_with('\n') {
                ""
            } else {
                "\r\n"
            };
            edits.push(Edit {
                start: original.len(),
                end: original.len(),
                expected: String::new(),
                replacement: format!("{prefix}{body}\r\n"),
            });
        }
        "replace" | "remove" => {
            let index = request
                .target_index
                .ok_or("AmbiguousVacation: target_index is required")?;
            let target = found
                .get(index)
                .ok_or("Conflict: vacation target no longer exists")?;
            let expected = request
                .expected_source
                .as_deref()
                .ok_or("Conflict: expected_source is required")?;
            if original.get(target.node.start..target.node.end) != Some(expected) {
                return Err("Conflict: vacation source changed".into());
            }
            if (request.operation == "remove" && !request.snippet.is_empty())
                || (request.operation == "replace" && body.is_empty())
            {
                return Err(
                    "InvalidRequest: remove requires an empty snippet; replace requires a vacation"
                        .into(),
                );
            }
            let node = match request.scope.as_str() {
                "command" => target.node,
                "settings" => {
                    analysis::settings_schedule(target)?;
                    target.contexts.first().map_or(target.node, |p| p.node)
                }
                _ => return Err("InvalidRequest: scope must be command or settings".into()),
            };
            edits.push(Edit {
                start: node.start,
                end: node.end,
                expected: original[node.start..node.end].into(),
                replacement: if request.operation == "remove" {
                    String::new()
                } else {
                    body
                },
            });
        }
        _ => return Err("InvalidRequest: operation must be append, replace or remove".into()),
    }
    let existing = analysis::capabilities(&doc);
    let missing: Vec<_> = caps.difference(&existing).collect();
    if !missing.is_empty() {
        let position = doc
            .commands
            .iter()
            .zip(&doc.nodes)
            .find(|(c, _)| c.name != "require")
            .map_or(original.len(), |(_, n)| n.start);
        let quoted: Vec<_> = missing
            .iter()
            .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        let prefix = if position > 0 && !original[..position].ends_with(char::is_whitespace) {
            "\r\n"
        } else {
            ""
        };
        let declaration = format!("{prefix}require [{}];\r\n", quoted.join(", "));
        if let Some(insertion) = edits
            .iter_mut()
            .find(|e| e.start == position && e.end == position)
        {
            insertion.replacement.insert_str(0, &declaration);
        } else {
            edits.push(Edit {
                start: position,
                end: position,
                expected: String::new(),
                replacement: declaration,
            });
        }
    }
    patch(original, edits, warnings)
}

pub fn merge(original: &str, snippet: &str) -> Result<Value, String> {
    let doc = source::parse(original)?;
    let found = analysis::vacations(&doc);
    if found.len() > 1 {
        return Err(
            "AmbiguousVacation: use an explicit target from sieve_analyze_script_json".into(),
        );
    }
    let (body, _) = prepare(snippet)?;
    if found.is_empty() && body.is_empty() {
        return patch(original, Vec::new(), Vec::new());
    }
    let target = found.first();
    let scope = if target.is_some_and(|v| analysis::settings_schedule(v).is_ok()) {
        "settings"
    } else {
        "command"
    };
    edit(
        original,
        Request {
            operation: if target.is_none() {
                "append"
            } else if body.is_empty() {
                "remove"
            } else {
                "replace"
            }
            .into(),
            target_index: target.map(|_| 0),
            expected_source: target.map(|v| original[v.node.start..v.node.end].into()),
            snippet: if body.is_empty() {
                String::new()
            } else {
                snippet.into()
            },
            scope: scope.into(),
            allow_append_after_control_flow: false,
        },
    )
}
