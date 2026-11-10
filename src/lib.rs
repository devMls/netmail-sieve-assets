//! NetMail Sieve Support Library (C-ABI Dynamic Library)
//! 
//! Exposes a high-performance, memory-safe C Foreign Function Interface (FFI)
//! wrapping the RFC 5228 Sieve email filtering engine and RFC 5230 Vacation extension.
//! Designed for zero-overhead consumption in .NET 8/9 via `[LibraryImport]`.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::catch_unwind;
use std::slice;

use mailrs_sieve_core::{eval_script, parse_script, Action, Command};
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
        return Err("Null pointer passed as script");
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| "Invalid UTF-8 sequence in script string")
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

/// Safely frees any C-string allocated by this library across the FFI boundary.
#[no_mangle]
pub extern "C" fn sieve_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}
