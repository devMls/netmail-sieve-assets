use crate::source::{Document, Node};
use mailrs_sieve_core::{parse_vacation_args, validate, Argument, Command, Test, VacationPeriod};
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashSet};

pub fn argument(arg: &Argument) -> Value {
    match arg {
        Argument::Tag(v) => json!({"kind":"tag", "value":v}),
        Argument::Number(v) => json!({"kind":"number", "value":v}),
        Argument::String(v) => json!({"kind":"string", "value":v}),
        Argument::StringList(v) => json!({"kind":"string_list", "value":v}),
        Argument::Test(v) => json!({"kind":"test", "value":test(v)}),
        Argument::TestList(v) => {
            json!({"kind":"test_list", "value":v.iter().map(test).collect::<Vec<_>>()})
        }
    }
}

pub fn test(t: &Test) -> Value {
    json!({"name":t.name, "tags":t.tags,
        "args":t.args.iter().map(argument).collect::<Vec<_>>(),
        "children":t.children.iter().map(test).collect::<Vec<_>>()})
}

pub fn command(c: &Command, n: &Node) -> Value {
    json!({"name":c.name, "start":n.start, "end":n.end,
        "args":c.args.iter().map(argument).collect::<Vec<_>>(),
        "block":c.block.iter().zip(&n.children).map(|(c,n)| command(c,n)).collect::<Vec<_>>()})
}

pub fn capabilities(doc: &Document) -> BTreeSet<String> {
    doc.commands
        .iter()
        .filter(|c| c.name == "require")
        .flat_map(|c| {
            c.args.iter().flat_map(|a| match a {
                Argument::String(s) => vec![s.clone()],
                Argument::StringList(v) => v.clone(),
                _ => Vec::new(),
            })
        })
        .collect()
}

pub fn parameters(c: &Command) -> Result<Value, String> {
    // Reuse the reference RFC 5230/6131 argument parser. Reject duplicates
    // before it runs, since this release of the reference accepts them.
    let mut tags = HashSet::new();
    for arg in &c.args {
        if let Argument::Tag(tag) = arg {
            if !tags.insert(tag) {
                return Err(format!("UnsafeToManage: duplicate vacation tag :{tag}"));
            }
        }
    }
    let v = parse_vacation_args(&c.args).map_err(|e| format!("UnsafeToManage: {e}"))?;
    let (days, seconds) = match v.period {
        Some(VacationPeriod::Days(0) | VacationPeriod::Seconds(0)) => {
            return Err("UnsafeToManage: vacation interval must be positive".into())
        }
        Some(VacationPeriod::Days(n)) => (Some(n), None),
        Some(VacationPeriod::Seconds(n)) => (None, Some(n)),
        None => (None, None),
    };
    Ok(
        json!({"days":days,"seconds":seconds,"subject":v.subject,"from":v.from,
        "handle":v.handle,"addresses":v.addresses,"mime":v.mime,"reason":v.reason}),
    )
}

#[derive(Clone)]
pub struct Context<'a> {
    pub command: &'a Command,
    pub node: &'a Node,
    pub has_alternatives: bool,
}

pub struct Vacation<'a> {
    pub command: &'a Command,
    pub node: &'a Node,
    pub contexts: Vec<Context<'a>>,
}

pub fn vacations(doc: &Document) -> Vec<Vacation<'_>> {
    fn walk<'a>(
        commands: &'a [Command],
        nodes: &'a [Node],
        parents: &[Context<'a>],
        out: &mut Vec<Vacation<'a>>,
    ) {
        for (i, (c, n)) in commands.iter().zip(nodes).enumerate() {
            if c.name == "vacation" {
                out.push(Vacation {
                    command: c,
                    node: n,
                    contexts: parents.to_vec(),
                });
            }
            let mut context = parents.to_vec();
            context.push(Context {
                command: c,
                node: n,
                has_alternatives: commands
                    .get(i + 1)
                    .is_some_and(|c| matches!(c.name.as_str(), "elsif" | "else")),
            });
            walk(&c.block, &n.children, &context, out);
        }
    }
    let mut out = Vec::new();
    walk(&doc.commands, &doc.nodes, &[], &mut out);
    out
}

#[derive(Default)]
pub struct Schedule {
    pub disabled: bool,
    pub start: Option<String>,
    pub end: Option<String>,
}

fn schedule_test(t: &Test, schedule: &mut Schedule) -> Result<(), String> {
    let unsupported = || {
        "UnsafeToManage: vacation has conditions not representable by absence settings".to_string()
    };
    match t.name.as_str() {
        "true" if t.args.is_empty() && t.tags.is_empty() && t.children.is_empty() => Ok(()),
        "false" if t.args.is_empty() && t.tags.is_empty() && t.children.is_empty() => {
            schedule.disabled = true;
            Ok(())
        }
        "allof" if t.args.is_empty() && t.tags.is_empty() && !t.children.is_empty() => {
            for child in &t.children {
                schedule_test(child, schedule)?;
            }
            Ok(())
        }
        "currentdate" if t.children.is_empty() && t.tags.len() == 2 && t.args.len() == 4 => {
            let values: Vec<_> = t
                .args
                .iter()
                .map(|a| match a {
                    Argument::String(v) => Ok(v.as_str()),
                    _ => Err(unsupported()),
                })
                .collect::<Result<_, _>>()?;
            let mut zone = None;
            let mut comparison = None;
            for (tag, value) in t.tags.iter().zip(&values) {
                match tag.as_str() {
                    "zone" if zone.is_none() => zone = Some(*value),
                    "value" if comparison.is_none() => comparison = Some(*value),
                    _ => return Err(unsupported()),
                }
            }
            // Only the UTC ge/lt form generated by NetMail is converted into
            // settings. Other date tests remain visible as a typed AST.
            if zone != Some("+0000") || values[2] != "iso8601" || !values[3].ends_with('Z') {
                return Err(unsupported());
            }
            match comparison {
                Some("ge") if schedule.start.is_none() => schedule.start = Some(values[3].into()),
                Some("lt") if schedule.end.is_none() => schedule.end = Some(values[3].into()),
                _ => return Err(unsupported()),
            }
            Ok(())
        }
        _ => Err(unsupported()),
    }
}

pub fn settings_schedule(v: &Vacation<'_>) -> Result<Schedule, String> {
    let mut schedule = Schedule::default();
    for parent in &v.contexts {
        if parent.command.name != "if" || parent.command.block.len() != 1 || parent.has_alternatives
        {
            return Err("UnsafeToManage: mixed block or conditional branch requires explicit target editing".into());
        }
        match parent.command.args.as_slice() {
            [Argument::Test(t)] => schedule_test(t, &mut schedule)?,
            _ => return Err("UnsafeToManage: unsupported vacation guard".into()),
        }
    }
    Ok(schedule)
}

pub fn contains_command(commands: &[Command], names: &[&str]) -> bool {
    commands
        .iter()
        .any(|c| names.contains(&c.name.as_str()) || contains_command(&c.block, names))
}

pub fn analyze(source: &str, doc: &Document) -> Value {
    let local_error = validate(&doc.commands).err().map(|e| e.to_string());
    let inventory: Vec<_> = vacations(doc)
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let params = parameters(v.command);
            let can_read = params.is_ok()
                && settings_schedule(v).is_ok()
                && !contains_command(&doc.commands, &["include", "return", "foreverypart"])
                && !(capabilities(doc).contains("variables")
                    && params.as_ref().is_ok_and(|p| p.to_string().contains("${")));
            json!({"index":i,"start":v.node.start,"end":v.node.end,
            "source":&source[v.node.start..v.node.end],
            "parameters":params.as_ref().ok(), "parameter_error":params.err(),
            "can_read_as_settings":can_read,
            "contexts":v.contexts.iter().map(|p| json!({
                "name":p.command.name,"start":p.node.start,"end":p.node.end,
                "args":p.command.args.iter().map(argument).collect::<Vec<_>>(),
                "has_alternatives":p.has_alternatives})).collect::<Vec<_>>()})
        })
        .collect();
    json!({"success":true,"schema_version":2,"offset_unit":"utf8_bytes",
        "capabilities":capabilities(doc),"commands":doc.commands.iter().zip(&doc.nodes)
            .map(|(c,n)| command(c,n)).collect::<Vec<_>>(),"vacations":inventory,
        "has_external_includes":contains_command(&doc.commands,&["include"]),
        "has_delivery_control_flow":contains_command(&doc.commands,&["stop","discard","reject","redirect"]),
        "local_capability_validation":{"valid":local_error.is_none(),"error":local_error}})
}
