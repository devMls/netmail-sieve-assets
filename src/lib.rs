//! NetMail Sieve Support Library (C-ABI Dynamic Library)
//! 
//! Exposes a high-performance, memory-safe C Foreign Function Interface (FFI)
//! wrapping the RFC 5228 Sieve email filtering engine and RFC 5230 Vacation extension.
//! Designed for zero-overhead consumption in .NET 8/9 via `[LibraryImport]`.

use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::slice;

use mailrs_sieve_core::{eval_script, parse_script, Action, Argument, Command, Test};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct AstCommandDto {
    pub name: String,
    pub args: Vec<String>,
    pub block: Vec<AstCommandDto>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AstParseResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commands: Option<Vec<AstCommandDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ValidationResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ActionDto {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EvalResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<ActionDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VacationExtractResponse {
    pub success: bool,
    pub has_vacation: bool,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub addresses: Vec<String>,
    pub mime: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MergeVacationResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn convert_command(cmd: &Command) -> AstCommandDto {
    AstCommandDto {
        name: cmd.name.clone(),
        args: cmd.args.iter().map(|a| format!("{:?}", a)).collect(),
        block: cmd.block.iter().map(convert_command).collect(),
    }
}

fn convert_action(action: &Action) -> ActionDto {
    match action {
        Action::FileInto { mailbox, flags } => ActionDto {
            action_type: "fileinto".to_string(),
            mailbox: Some(mailbox.clone()),
            flags: Some(flags.clone()),
            recipient: None,
            reason: None,
            details: None,
        },
        Action::Keep { flags } => ActionDto {
            action_type: "keep".to_string(),
            mailbox: None,
            flags: Some(flags.clone()),
            recipient: None,
            reason: None,
            details: None,
        },
        Action::Discard => ActionDto {
            action_type: "discard".to_string(),
            mailbox: None,
            flags: None,
            recipient: None,
            reason: None,
            details: None,
        },
        Action::Redirect(recipient) => ActionDto {
            action_type: "redirect".to_string(),
            mailbox: None,
            flags: None,
            recipient: Some(recipient.clone()),
            reason: None,
            details: None,
        },
        Action::Reject(reason) => ActionDto {
            action_type: "reject".to_string(),
            mailbox: None,
            flags: None,
            recipient: None,
            reason: Some(reason.clone()),
            details: None,
        },
        other => ActionDto {
            action_type: "other".to_string(),
            mailbox: None,
            flags: None,
            recipient: None,
            reason: None,
            details: Some(format!("{:?}", other)),
        },
    }
}

fn str_to_c_char(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

unsafe fn read_c_str<'a>(ptr: *const c_char) -> Result<&'a str, &'static str> {
    if ptr.is_null() {
        return Err("Null pointer passed");
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| "Invalid UTF-8 sequence in string")
}

fn extract_managed_header(script: &str) -> Option<String> {
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("# NetMail managed absence v1 ")
            || trimmed.starts_with("# NetMail managed absence v2 ")
        {
            return Some(trimmed.to_string());
        }
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            break;
        }
    }
    None
}

fn find_vacation_in_commands<'a>(
    commands: &'a [Command],
    parent_if: Option<&'a Command>,
) -> Option<(&'a Command, Option<&'a Command>)> {
    for cmd in commands {
        if cmd.name.eq_ignore_ascii_case("vacation") {
            return Some((cmd, parent_if));
        }
        if cmd.name.eq_ignore_ascii_case("if")
            || cmd.name.eq_ignore_ascii_case("elsif")
            || cmd.name.eq_ignore_ascii_case("else")
        {
            if let Some(found) = find_vacation_in_commands(&cmd.block, Some(cmd)) {
                return Some(found);
            }
        } else if !cmd.block.is_empty() {
            if let Some(found) = find_vacation_in_commands(&cmd.block, parent_if) {
                return Some(found);
            }
        }
    }
    None
}

fn extract_dates_from_test(test: &Test, start: &mut Option<String>, end: &mut Option<String>) {
    if test.name.eq_ignore_ascii_case("currentdate") {
        let mut comp: Option<String> = None;
        let mut date_val: Option<String> = None;
        for arg in &test.args {
            if let Argument::String(s) = arg {
                let lower = s.to_lowercase();
                if lower == "ge" || lower == "gt" || lower == "le" || lower == "lt" {
                    comp = Some(lower);
                } else if s.contains('T') || s.contains('-') || s.contains(':') {
                    date_val = Some(s.clone());
                }
            }
        }
        if let (Some(c), Some(d)) = (comp, date_val) {
            if c == "ge" || c == "gt" {
                *start = Some(d);
            } else if c == "le" || c == "lt" {
                *end = Some(d);
            }
        }
    }
    for child in &test.children {
        extract_dates_from_test(child, start, end);
    }
}

// =========================================================================
// C-ABI EXPORTED FUNCTIONS
// =========================================================================

/// Quick numeric validation:
/// Returns:
///   0 = Valid Sieve script (RFC 5228)
///   1 = Invalid pointer or invalid UTF-8
///   2 = Syntax / Parse error
#[no_mangle]
pub extern "C" fn sieve_validate(script: *const c_char) -> i32 {
    let result = catch_unwind(|| {
        let text = match unsafe { read_c_str(script) } {
            Ok(s) => s,
            Err(_) => return 1,
        };
        match parse_script(text) {
            Ok(_) => 0,
            Err(_) => 2,
        }
    });

    result.unwrap_or(2)
}

/// Validates Sieve script and returns detailed JSON:
/// `{"valid": true}` or `{"valid": false, "error": "description"}`
#[no_mangle]
pub extern "C" fn sieve_validate_detail_json(script: *const c_char) -> *mut c_char {
    let result = catch_unwind(|| {
        let text = match unsafe { read_c_str(script) } {
            Ok(s) => s,
            Err(e) => {
                let resp = ValidationResponse {
                    valid: false,
                    error: Some(e.to_string()),
                };
                return str_to_c_char(serde_json::to_string(&resp).unwrap_or_default());
            }
        };

        let resp = match parse_script(text) {
            Ok(_) => ValidationResponse {
                valid: true,
                error: None,
            },
            Err(err) => ValidationResponse {
                valid: false,
                error: Some(format!("{}", err)),
            },
        };

        str_to_c_char(serde_json::to_string(&resp).unwrap_or_default())
    });

    result.unwrap_or_else(|_| {
        let err_resp = ValidationResponse {
            valid: false,
            error: Some("Internal panic caught during Sieve validation".to_string()),
        };
        str_to_c_char(serde_json::to_string(&err_resp).unwrap_or_default())
    })
}

/// Parses full Sieve script into structured Abstract Syntax Tree (AST) JSON.
/// Returns a JSON string pointer allocated by Rust.
/// MUST be freed after use using `sieve_free_string`.
#[no_mangle]
pub extern "C" fn sieve_parse_ast_json(script: *const c_char) -> *mut c_char {
    let result = catch_unwind(|| {
        let text = match unsafe { read_c_str(script) } {
            Ok(s) => s,
            Err(e) => {
                let resp = AstParseResponse {
                    success: false,
                    commands: None,
                    error: Some(e.to_string()),
                };
                return str_to_c_char(serde_json::to_string(&resp).unwrap_or_default());
            }
        };

        let resp = match parse_script(text) {
            Ok(commands) => AstParseResponse {
                success: true,
                commands: Some(commands.iter().map(convert_command).collect()),
                error: None,
            },
            Err(err) => AstParseResponse {
                success: false,
                commands: None,
                error: Some(format!("{}", err)),
            },
        };

        str_to_c_char(serde_json::to_string(&resp).unwrap_or_default())
    });

    result.unwrap_or_else(|_| {
        let err_resp = AstParseResponse {
            success: false,
            commands: None,
            error: Some("Internal panic caught during Sieve AST parsing".to_string()),
        };
        str_to_c_char(serde_json::to_string(&err_resp).unwrap_or_default())
    })
}

/// Evaluates a Sieve script against a raw email message bytes buffer.
/// Returns JSON list of resulting delivery actions (fileinto, keep, discard, redirect, vacation).
/// MUST be freed after use using `sieve_free_string`.
#[no_mangle]
pub extern "C" fn sieve_eval_actions_json(
    script: *const c_char,
    message_ptr: *const u8,
    message_len: usize,
) -> *mut c_char {
    let result = catch_unwind(|| {
        let text = match unsafe { read_c_str(script) } {
            Ok(s) => s,
            Err(e) => {
                let resp = EvalResponse {
                    success: false,
                    actions: None,
                    error: Some(e.to_string()),
                };
                return str_to_c_char(serde_json::to_string(&resp).unwrap_or_default());
            }
        };

        if message_ptr.is_null() && message_len > 0 {
            let resp = EvalResponse {
                success: false,
                actions: None,
                error: Some("Null message pointer passed".to_string()),
            };
            return str_to_c_char(serde_json::to_string(&resp).unwrap_or_default());
        }

        let message_bytes = if message_len == 0 {
            &[]
        } else {
            unsafe { slice::from_raw_parts(message_ptr, message_len) }
        };

        let resp = match eval_script(text, message_bytes) {
            Ok(actions) => EvalResponse {
                success: true,
                actions: Some(actions.iter().map(convert_action).collect()),
                error: None,
            },
            Err(err) => EvalResponse {
                success: false,
                actions: None,
                error: Some(format!("{}", err)),
            },
        };

        str_to_c_char(serde_json::to_string(&resp).unwrap_or_default())
    });

    result.unwrap_or_else(|_| {
        let err_resp = EvalResponse {
            success: false,
            actions: None,
            error: Some("Internal panic caught during Sieve execution".to_string()),
        };
        str_to_c_char(serde_json::to_string(&err_resp).unwrap_or_default())
    })
}

/// Extracts RFC 5230 Vacation parameters and RFC 5228 date constraints from any Sieve script.
/// Traverses AST recursively so scripts with complex filter rules are handled without errors.
/// Returns JSON string pointer allocated by Rust.
/// MUST be freed after use using `sieve_free_string`.
#[no_mangle]
pub extern "C" fn sieve_extract_vacation_json(script: *const c_char) -> *mut c_char {
    let result = catch_unwind(|| {
        let text = match unsafe { read_c_str(script) } {
            Ok(s) => s,
            Err(e) => {
                let resp = VacationExtractResponse {
                    success: false,
                    has_vacation: false,
                    enabled: false,
                    days: None,
                    subject: None,
                    from: None,
                    handle: None,
                    addresses: Vec::new(),
                    mime: false,
                    reason: None,
                    start: None,
                    end: None,
                    managed_header: None,
                    error: Some(e.to_string()),
                };
                return str_to_c_char(serde_json::to_string(&resp).unwrap_or_default());
            }
        };

        let managed_header = extract_managed_header(text);

        let commands = match parse_script(text) {
            Ok(cmds) => cmds,
            Err(err) => {
                let resp = VacationExtractResponse {
                    success: false,
                    has_vacation: false,
                    enabled: false,
                    days: None,
                    subject: None,
                    from: None,
                    handle: None,
                    addresses: Vec::new(),
                    mime: false,
                    reason: None,
                    start: None,
                    end: None,
                    managed_header,
                    error: Some(format!("{}", err)),
                };
                return str_to_c_char(serde_json::to_string(&resp).unwrap_or_default());
            }
        };

        let (vac_cmd, parent_if) = match find_vacation_in_commands(&commands, None) {
            Some(pair) => pair,
            None => {
                let resp = VacationExtractResponse {
                    success: true,
                    has_vacation: false,
                    enabled: false,
                    days: None,
                    subject: None,
                    from: None,
                    handle: None,
                    addresses: Vec::new(),
                    mime: false,
                    reason: None,
                    start: None,
                    end: None,
                    managed_header,
                    error: None,
                };
                return str_to_c_char(serde_json::to_string(&resp).unwrap_or_default());
            }
        };

        let mut days: Option<u32> = None;
        let mut subject: Option<String> = None;
        let mut from: Option<String> = None;
        let mut handle: Option<String> = None;
        let mut addresses: Vec<String> = Vec::new();
        let mut mime = false;
        let mut reason: Option<String> = None;

        let mut i = 0;
        while i < vac_cmd.args.len() {
            match &vac_cmd.args[i] {
                Argument::Tag(tag) => {
                    let tag_name = tag.to_lowercase();
                    match tag_name.as_str() {
                        "days" => {
                            if i + 1 < vac_cmd.args.len() {
                                i += 1;
                                if let Argument::Number(n) = &vac_cmd.args[i] {
                                    days = Some(*n as u32);
                                }
                            }
                        }
                        "subject" => {
                            if i + 1 < vac_cmd.args.len() {
                                i += 1;
                                if let Argument::String(s) = &vac_cmd.args[i] {
                                    subject = Some(s.clone());
                                }
                            }
                        }
                        "from" => {
                            if i + 1 < vac_cmd.args.len() {
                                i += 1;
                                if let Argument::String(s) = &vac_cmd.args[i] {
                                    from = Some(s.clone());
                                }
                            }
                        }
                        "handle" => {
                            if i + 1 < vac_cmd.args.len() {
                                i += 1;
                                if let Argument::String(s) = &vac_cmd.args[i] {
                                    handle = Some(s.clone());
                                }
                            }
                        }
                        "addresses" => {
                            if i + 1 < vac_cmd.args.len() {
                                i += 1;
                                match &vac_cmd.args[i] {
                                    Argument::StringList(list) => {
                                        for addr in list {
                                            addresses.push(addr.clone());
                                        }
                                    }
                                    Argument::String(s) => {
                                        addresses.push(s.clone());
                                    }
                                    _ => {}
                                }
                            }
                        }
                        "mime" => {
                            mime = true;
                        }
                        _ => {}
                    }
                }
                Argument::String(s) => {
                    reason = Some(s.clone());
                }
                _ => {}
            }
            i += 1;
        }

        let mut enabled = true;
        let mut start: Option<String> = None;
        let mut end: Option<String> = None;

        if let Some(if_cmd) = parent_if {
            for arg in &if_cmd.args {
                if let Argument::Test(test) = arg {
                    if test.name.eq_ignore_ascii_case("false") {
                        enabled = false;
                    }
                    extract_dates_from_test(test, &mut start, &mut end);
                }
            }
        }

        let resp = VacationExtractResponse {
            success: true,
            has_vacation: true,
            enabled,
            days,
            subject,
            from,
            handle,
            addresses,
            mime,
            reason,
            start,
            end,
            managed_header,
            error: None,
        };

        str_to_c_char(serde_json::to_string(&resp).unwrap_or_default())
    });

    result.unwrap_or_else(|_| {
        let err_resp = VacationExtractResponse {
            success: false,
            has_vacation: false,
            enabled: false,
            days: None,
            subject: None,
            from: None,
            handle: None,
            addresses: Vec::new(),
            mime: false,
            reason: None,
            start: None,
            end: None,
            managed_header: None,
            error: Some("Internal panic caught during Sieve vacation extraction".to_string()),
        };
        str_to_c_char(serde_json::to_string(&err_resp).unwrap_or_default())
    })
}

/// Non-destructively merges a vacation rule snippet into an existing Sieve script.
/// Consolidates all `require` extensions, removes old vacation blocks, preserves existing filter rules,
/// and validates the resulting Sieve script against RFC 5228 syntax.
/// Returns JSON with `{"success": true, "script": "..."}` or `{"success": false, "error": "..."}`.
/// MUST be freed after use using `sieve_free_string`.
#[no_mangle]
pub extern "C" fn sieve_merge_vacation(
    original_script: *const c_char,
    vacation_snippet: *const c_char,
) -> *mut c_char {
    let result = catch_unwind(|| {
        let orig_text = match unsafe { read_c_str(original_script) } {
            Ok(s) => s.trim(),
            Err(_) => "",
        };

        let snip_text = match unsafe { read_c_str(vacation_snippet) } {
            Ok(s) => s.trim(),
            Err(_) => "",
        };

        let merged_result = merge_vacation_internal(orig_text, snip_text);

        let resp = match merged_result {
            Ok(script) => MergeVacationResponse {
                success: true,
                script: Some(script),
                error: None,
            },
            Err(e) => MergeVacationResponse {
                success: false,
                script: None,
                error: Some(e),
            },
        };

        str_to_c_char(serde_json::to_string(&resp).unwrap_or_default())
    });

    result.unwrap_or_else(|_| {
        let err_resp = MergeVacationResponse {
            success: false,
            script: None,
            error: Some("Internal panic caught during Sieve vacation merge".to_string()),
        };
        str_to_c_char(serde_json::to_string(&err_resp).unwrap_or_default())
    })
}

fn merge_vacation_internal(orig: &str, snip: &str) -> Result<String, String> {
    // 1. If original script is empty:
    if orig.is_empty() {
        if snip.is_empty() {
            return Ok(String::new());
        }
        parse_script(snip).map_err(|e| format!("Invalid vacation snippet syntax: {}", e))?;
        return Ok(snip.to_string());
    }

    // 2. Collect capabilities from original script
    let mut caps: HashSet<String> = HashSet::new();
    let orig_cmds = parse_script(orig)
        .map_err(|e| format!("Original script has syntax errors: {}", e))?;
    collect_capabilities(&orig_cmds, &mut caps);

    // 3. Process snippet if non-empty
    let mut snip_has_vacation = false;
    let mut snip_clean_body = String::new();
    let mut managed_header: Option<String> = extract_managed_header(snip);
    if managed_header.is_none() {
        managed_header = extract_managed_header(orig);
    }

    if !snip.is_empty() {
        let snip_cmds = parse_script(snip)
            .map_err(|e| format!("Vacation snippet has syntax errors: {}", e))?;
        collect_capabilities(&snip_cmds, &mut caps);

        if find_vacation_in_commands(&snip_cmds, None).is_some() {
            snip_has_vacation = true;
            caps.insert("vacation".to_string());
        }

        if snip.contains("currentdate") {
            caps.insert("date".to_string());
            caps.insert("relational".to_string());
        }

        // Strip require lines and managed header from snippet body
        for line in snip.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("# NetMail managed absence")
                || trimmed.starts_with("require ")
                || trimmed.starts_with("require[")
            {
                continue;
            }
            snip_clean_body.push_str(line);
            snip_clean_body.push('\n');
        }
        snip_clean_body = snip_clean_body.trim().to_string();
    }

    // 4. Split original script into top-level statements, removing old vacation block and old require
    let statements = split_sieve_statements(orig);
    let mut preserved_statements: Vec<String> = Vec::new();

    for stmt in statements {
        let trimmed = stmt.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Skip NetMail header and disabled comment
        if trimmed.starts_with("# NetMail managed absence")
            || trimmed.starts_with("# Automatic replies disabled.")
        {
            continue;
        }

        // Skip require statements (emitted in unified require header)
        if trimmed.starts_with("require ") || trimmed.starts_with("require[") {
            continue;
        }

        // Check if statement contains a vacation command
        if let Ok(cmds) = parse_script(trimmed) {
            if find_vacation_in_commands(&cmds, None).is_some() {
                // Old vacation block -> skip
                continue;
            }
            if cmds.len() == 1 && cmds[0].name.eq_ignore_ascii_case("keep") && trimmed == "keep;" {
                // Skip standalone keep if part of previous empty template
                continue;
            }
        }

        preserved_statements.push(trimmed.to_string());
    }

    // 5. Construct unified merged script
    let mut out = String::new();

    // A) Managed header if present
    if let Some(h) = managed_header {
        out.push_str(&h);
        out.push_str("\r\n");
    }

    // B) Unified require statement
    if !caps.is_empty() {
        let mut sorted_caps: Vec<String> = caps.into_iter().collect();
        sorted_caps.sort();
        out.push_str("require [");
        for (idx, cap) in sorted_caps.iter().enumerate() {
            if idx > 0 {
                out.push_str(", ");
            }
            out.push('"');
            out.push_str(cap);
            out.push('"');
        }
        out.push_str("];\r\n\r\n");
    }

    // C) Preserved existing rules
    for stmt in &preserved_statements {
        out.push_str(stmt);
        out.push_str("\r\n\r\n");
    }

    // D) New vacation block
    if snip_has_vacation && !snip_clean_body.is_empty() {
        out.push_str(&snip_clean_body);
        out.push_str("\r\n");
    } else if preserved_statements.is_empty() {
        out.push_str("# Automatic replies disabled.\r\nkeep;\r\n");
    }

    let final_script = out.trim().to_string();

    // 6. Validate the merged script
    if !final_script.is_empty() {
        parse_script(&final_script)
            .map_err(|e| format!("Merged script validation error: {}", e))?;
    }

    Ok(final_script)
}

fn collect_capabilities(commands: &[Command], caps: &mut HashSet<String>) {
    for cmd in commands {
        if cmd.name.eq_ignore_ascii_case("require") {
            for arg in &cmd.args {
                match arg {
                    Argument::String(s) => {
                        caps.insert(s.clone());
                    }
                    Argument::StringList(list) => {
                        for item in list {
                            caps.insert(item.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn split_sieve_statements(script: &str) -> Vec<String> {
    let mut statements: Vec<String> = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = script.chars().collect();
    let len = chars.len();
    let mut i = 0;
    let mut brace_depth: usize = 0;
    let mut in_quote = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;

    while i < len {
        let c = chars[i];

        if in_line_comment {
            current.push(c);
            if c == '\n' {
                in_line_comment = false;
                if brace_depth == 0 {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        statements.push(trimmed.to_string());
                        current.clear();
                    }
                }
            }
            i += 1;
            continue;
        }

        if in_block_comment {
            current.push(c);
            if c == '*' && i + 1 < len && chars[i + 1] == '/' {
                current.push('/');
                i += 2;
                in_block_comment = false;
                if brace_depth == 0 {
                    let trimmed = current.trim();
                    if !trimmed.is_empty() {
                        statements.push(trimmed.to_string());
                        current.clear();
                    }
                }
                continue;
            }
            i += 1;
            continue;
        }

        if in_quote {
            current.push(c);
            if c == '\\' && i + 1 < len {
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_quote = false;
            }
            i += 1;
            continue;
        }

        if c == '#' {
            in_line_comment = true;
            current.push(c);
            i += 1;
            continue;
        }

        if c == '/' && i + 1 < len && chars[i + 1] == '*' {
            in_block_comment = true;
            current.push('/');
            current.push('*');
            i += 2;
            continue;
        }

        if c == '"' {
            in_quote = true;
            current.push(c);
            i += 1;
            continue;
        }

        if c == 't' || c == 'T' {
            if i + 5 <= len {
                let slice: String = chars[i..i + 5].iter().collect();
                if slice.eq_ignore_ascii_case("text:") {
                    let mut k = i + 5;
                    while k < len && (chars[k] == ' ' || chars[k] == '\t' || chars[k] == '\r') {
                        k += 1;
                    }
                    if k < len && chars[k] == '\n' {
                        for ch in &chars[i..=k] {
                            current.push(*ch);
                        }
                        i = k + 1;
                        while i < len {
                            let line_start = i;
                            while i < len && chars[i] != '\n' {
                                i += 1;
                            }
                            let line_end = i;
                            if i < len && chars[i] == '\n' {
                                i += 1;
                            }
                            let line_chars = &chars[line_start..line_end];
                            for ch in line_chars {
                                current.push(*ch);
                            }
                            if line_end < len {
                                current.push('\n');
                            }
                            let line_str: String = line_chars.iter().collect();
                            if line_str.trim_end_matches('\r') == "." {
                                break;
                            }
                        }
                        continue;
                    }
                }
            }
        }

        if c == '{' {
            brace_depth += 1;
            current.push(c);
            i += 1;
            continue;
        }

        if c == '}' {
            if brace_depth > 0 {
                brace_depth -= 1;
            }
            current.push(c);
            i += 1;

            if brace_depth == 0 {
                let mut k = i;
                while k < len && (chars[k] == ' ' || chars[k] == '\t' || chars[k] == '\r' || chars[k] == '\n') {
                    k += 1;
                }
                if k + 5 <= len {
                    let next5: String = chars[k..k + 5].iter().collect();
                    if next5.eq_ignore_ascii_case("elsif") {
                        continue;
                    }
                }
                if k + 4 <= len {
                    let next4: String = chars[k..k + 4].iter().collect();
                    if next4.eq_ignore_ascii_case("else") {
                        continue;
                    }
                }
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    statements.push(trimmed.to_string());
                    current.clear();
                }
            }
            continue;
        }

        if c == ';' && brace_depth == 0 {
            current.push(c);
            let trimmed = current.trim();
            if !trimmed.is_empty() {
                statements.push(trimmed.to_string());
                current.clear();
            }
            i += 1;
            continue;
        }

        current.push(c);
        i += 1;
    }

    let trimmed = current.trim();
    if !trimmed.is_empty() {
        statements.push(trimmed.to_string());
    }

    statements
}

/// Safely frees any C-string allocated by this library across the FFI boundary.
#[no_mangle]
pub extern "C" fn sieve_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

// =========================================================================
// UNIT TESTS
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_vacation_full() {
        let script = r#"
# NetMail managed absence v2 eyJTZXR0aW5ncyI6e319
require ["fileinto", "vacation", "date", "relational"];

if header :contains "Subject" "spam" {
    fileinto "Junk";
}

if allof (currentdate :zone "+0000" :value "ge" "iso8601" "2026-07-01T00:00:00Z", currentdate :zone "+0000" :value "lt" "iso8601" "2026-07-15T00:00:00Z") {
    vacation :days 14 :subject "Vacaciones de verano" :addresses ["yo@empresa.com", "backup@empresa.com"] text:
Estoy fuera de la oficina hasta el 15 de julio.
.
;
}
"#;
        let c_script = CString::new(script).unwrap();
        let ptr = sieve_extract_vacation_json(c_script.as_ptr());
        assert!(!ptr.is_null());
        let json_str = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        let resp: VacationExtractResponse = serde_json::from_str(json_str).unwrap();
        sieve_free_string(ptr);

        assert!(resp.success);
        assert!(resp.has_vacation);
        assert!(resp.enabled);
        assert_eq!(resp.days, Some(14));
        assert_eq!(resp.subject.as_deref(), Some("Vacaciones de verano"));
        assert_eq!(resp.addresses, vec!["yo@empresa.com", "backup@empresa.com"]);
        assert_eq!(resp.start.as_deref(), Some("2026-07-01T00:00:00Z"));
        assert_eq!(resp.end.as_deref(), Some("2026-07-15T00:00:00Z"));
        assert!(resp.reason.unwrap().contains("fuera de la oficina"));
    }

    #[test]
    fn test_merge_vacation_preserves_rules() {
        let original = r#"
require ["fileinto", "copy"];

if header :contains "subject" "Factura" {
    fileinto "Facturas";
}
"#;
        let vacation_snip = r#"
# NetMail managed absence v2 ey...
require ["vacation", "date", "relational"];
if allof (currentdate :zone "+0000" :value "ge" "iso8601" "2026-08-01T00:00:00Z") {
    vacation :days 5 :subject "Ausente" "Vuelvo pronto";
}
"#;
        let c_orig = CString::new(original).unwrap();
        let c_snip = CString::new(vacation_snip).unwrap();
        let ptr = sieve_merge_vacation(c_orig.as_ptr(), c_snip.as_ptr());
        assert!(!ptr.is_null());
        let json_str = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        let resp: MergeVacationResponse = serde_json::from_str(json_str).unwrap();
        sieve_free_string(ptr);

        assert!(resp.success);
        let merged = resp.script.unwrap();
        assert!(merged.contains("require ["));
        assert!(merged.contains("\"fileinto\""));
        assert!(merged.contains("\"copy\""));
        assert!(merged.contains("\"vacation\""));
        assert!(merged.contains("\"date\""));
        assert!(merged.contains("\"relational\""));
        assert!(merged.contains("fileinto \"Facturas\""));
        assert!(merged.contains("vacation :days 5"));
        assert_eq!(sieve_validate(CString::new(merged).unwrap().as_ptr()), 0);
    }

    #[test]
    fn test_merge_vacation_remove_vacation_keeps_rules() {
        let original = r#"
# NetMail managed absence v2 eyOld...
require ["fileinto", "vacation"];

if header :contains "subject" "Spam" {
    fileinto "Junk";
}

vacation :days 3 :subject "Viejo" "Texto viejo";
"#;
        let c_orig = CString::new(original).unwrap();
        let c_snip = CString::new("").unwrap();
        let ptr = sieve_merge_vacation(c_orig.as_ptr(), c_snip.as_ptr());
        assert!(!ptr.is_null());
        let json_str = unsafe { CStr::from_ptr(ptr).to_str().unwrap() };
        let resp: MergeVacationResponse = serde_json::from_str(json_str).unwrap();
        sieve_free_string(ptr);

        assert!(resp.success);
        let merged = resp.script.unwrap();
        assert!(merged.contains("fileinto \"Junk\""));
        assert!(!merged.contains("Texto viejo"));
        assert_eq!(sieve_validate(CString::new(merged).unwrap().as_ptr()), 0);
    }
}
