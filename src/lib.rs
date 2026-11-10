//! C-ABI adapter over mailrs-sieve-core. Parsing, token decoding, vacation
//! parameters, capability validation and evaluation remain in the reference.
//! Every input pointer must be valid for its declared buffer/NUL-terminated
//! string. Every non-null JSON result must be freed once by sieve_free_string.
#![allow(clippy::not_unsafe_ptr_arg_deref)] // C callers obey the documented pointer contract.

mod analysis;
mod edit;
mod source;

use mailrs_sieve_core::{eval_script_with_envelope, Action, Envelope};
use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

const MAX_MESSAGE_BYTES: usize = 32 * 1024 * 1024;

unsafe fn read<'a>(pointer: *const c_char) -> Result<&'a str, String> {
    if pointer.is_null() {
        return Err("InvalidInput: null string pointer".into());
    }
    let value = CStr::from_ptr(pointer)
        .to_str()
        .map_err(|_| "InvalidInput: invalid UTF-8")?;
    if value.len() > source::MAX_SCRIPT_BYTES {
        return Err("InputLimit: string exceeds 256 KiB".into());
    }
    Ok(value)
}

fn error(message: String) -> Value {
    let code = message.split_once(':').map_or("Failed", |(code, _)| code);
    json!({"success":false,"error_code":code,"error":message})
}

fn export(f: impl FnOnce() -> Result<Value, String>) -> *mut c_char {
    let value = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => error(e),
        Err(_) => error("InternalError: Rust panic caught at the C ABI".into()),
    };
    CString::new(value.to_string()).map_or(std::ptr::null_mut(), CString::into_raw)
}

/// Runtime contract and reference versions. The ABI major must match the consumer.
#[no_mangle]
pub extern "C" fn sieve_runtime_info_json() -> *mut c_char {
    export(|| {
        Ok(json!({"success":true,"abi_version":2,"schema_version":2,
        "version":env!("CARGO_PKG_VERSION"),"reference":"mailrs-sieve-core 0.3.0",
        "reference_patch":"netmail-source-spans-1","arch":std::env::consts::ARCH,"os":std::env::consts::OS,
        "source_revision":option_env!("NETMAIL_SIEVE_SOURCE_REVISION"),
        "max_script_bytes":source::MAX_SCRIPT_BYTES,"max_message_bytes":MAX_MESSAGE_BYTES,
        "offset_unit":"utf8_bytes","validation":"syntax_only; remote validation is required",
        "features":["typed_ast","lossless_edit_plan","explicit_vacation_target","smtp_envelope","vacation_parameters"]}))
    })
}

/// Numeric syntax validation: 0 valid, 1 invalid input, 2 syntax/limit failure.
#[no_mangle]
pub extern "C" fn sieve_validate(script: *const c_char) -> i32 {
    catch_unwind(|| match unsafe { read(script) } {
        Ok(text) => {
            if source::parse(text).is_ok() {
                0
            } else {
                2
            }
        }
        Err(_) => 1,
    })
    .unwrap_or(2)
}

/// Syntax validation, separately reporting reference local-capability validation.
#[no_mangle]
pub extern "C" fn sieve_validate_detail_json(script: *const c_char) -> *mut c_char {
    export(|| {
        let result = unsafe { read(script) }.and_then(source::parse);
        Ok(match result {
            Ok(doc) => {
                let e = mailrs_sieve_core::validate(&doc.commands)
                    .err()
                    .map(|e| e.to_string());
                json!({"valid":true,"validation_scope":"syntax","local_capabilities_valid":e.is_none(),"local_capability_error":e})
            }
            Err(e) => json!({"valid":false,"error":e}),
        })
    })
}

/// Versioned typed AST, source byte ranges, all vacation targets and diagnostics.
#[no_mangle]
pub extern "C" fn sieve_analyze_script_json(script: *const c_char) -> *mut c_char {
    export(|| {
        let text = unsafe { read(script) }?;
        Ok(analysis::analyze(text, &source::parse(text)?))
    })
}

/// Backward-compatible AST export: legacy debug args remain; typed_args and
/// source ranges are additive. New consumers should use analyze_script_json.
#[no_mangle]
pub extern "C" fn sieve_parse_ast_json(script: *const c_char) -> *mut c_char {
    fn convert(c: &mailrs_sieve_core::Command, n: &source::Node) -> Value {
        json!({"name":c.name,"args":c.args.iter().map(|a|format!("{a:?}")).collect::<Vec<_>>(),
            "typed_args":c.args.iter().map(analysis::argument).collect::<Vec<_>>(),
            "start":n.start,"end":n.end,
            "block":c.block.iter().zip(&n.children).map(|(c,n)|convert(c,n)).collect::<Vec<_>>()})
    }
    export(|| {
        let doc = source::parse(unsafe { read(script) }?)?;
        Ok(
            json!({"success":true,"schema_version":2,"commands":doc.commands.iter().zip(&doc.nodes).map(|(c,n)|convert(c,n)).collect::<Vec<_>>()}),
        )
    })
}

/// Read one absence representable by the settings model. Ambiguous/guarded
/// external responders return UnsafeToManage, never a false global state.
#[no_mangle]
pub extern "C" fn sieve_extract_vacation_json(script: *const c_char) -> *mut c_char {
    export(|| {
        let text = unsafe { read(script) }?;
        let doc = source::parse(text)?;
        if analysis::contains_command(&doc.commands, &["include", "return", "foreverypart"]) {
            return Err(
                "UnsafeToManage: external control flow prevents complete absence observation"
                    .into(),
            );
        }
        let found = analysis::vacations(&doc);
        if found.is_empty() {
            return Ok(json!({"success":true,"has_vacation":false,"enabled":false,"mime":false}));
        }
        if found.len() != 1 {
            return Err(
                "AmbiguousVacation: multiple responders require explicit target selection".into(),
            );
        }
        let v = &found[0];
        let schedule = analysis::settings_schedule(v)?;
        let mut result = analysis::parameters(v.command)?;
        if analysis::capabilities(&doc).contains("variables") && result.to_string().contains("${") {
            return Err("UnsafeToManage: vacation parameters depend on Sieve variables".into());
        }
        let obj = result.as_object_mut().unwrap();
        obj.insert("success".into(), json!(true));
        obj.insert("has_vacation".into(), json!(true));
        obj.insert("enabled".into(), json!(!schedule.disabled));
        obj.insert("start".into(), json!(schedule.start));
        obj.insert("end".into(), json!(schedule.end));
        // Informational metadata only. Never used to authorize source replacement.
        obj.insert(
            "managed_header".into(),
            json!(text
                .lines()
                .take_while(|l| l.trim().is_empty() || l.trim().starts_with('#'))
                .find(|l| l.trim().starts_with("# NetMail managed absence "))
                .map(str::trim)),
        );
        Ok(result)
    })
}

/// Conservative compatibility merge; preserves surrounding source and guards.
/// Ambiguous targets and append behind delivery control flow are rejected.
#[no_mangle]
pub extern "C" fn sieve_merge_vacation(
    original: *const c_char,
    snippet: *const c_char,
) -> *mut c_char {
    export(|| edit::merge(unsafe { read(original) }?, unsafe { read(snippet) }?))
}

/// Explicit edit plan. Requests select an operation, target index, exact old
/// source and command/settings scope. No network or server mutation occurs.
#[no_mangle]
pub extern "C" fn sieve_edit_vacation_json(
    script: *const c_char,
    request: *const c_char,
) -> *mut c_char {
    export(|| {
        let request = serde_json::from_str::<edit::Request>(unsafe { read(request) }?)
            .map_err(|e| format!("InvalidRequest: {e}"))?;
        edit::edit(unsafe { read(script) }?, request)
    })
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeInput {
    from: Option<String>,
    #[serde(default)]
    to: Vec<String>,
    auth: Option<String>,
}

fn action(a: &Action) -> Value {
    match a {
        Action::Keep { flags } => json!({"type":"keep","flags":flags}),
        Action::FileInto { mailbox, flags } => {
            json!({"type":"fileinto","mailbox":mailbox,"flags":flags})
        }
        Action::Discard => json!({"type":"discard"}),
        Action::Redirect(to) => json!({"type":"redirect","recipient":to}),
        Action::Reject(reason) => json!({"type":"reject","reason":reason}),
        Action::Vacation(v) => {
            json!({"type":"vacation","reason":v.reason,"subject":v.subject,"from":v.from,
            "handle":v.handle,"addresses":v.addresses,"mime":v.mime,"period":match v.period {
                Some(mailrs_sieve_core::VacationPeriod::Days(n))=>json!({"unit":"days","value":n}),
                Some(mailrs_sieve_core::VacationPeriod::Seconds(n))=>json!({"unit":"seconds","value":n}),None=>Value::Null}})
        }
    }
}

fn evaluate(
    script: *const c_char,
    message: *const u8,
    len: usize,
    envelope: EnvelopeInput,
) -> Result<Value, String> {
    if len > MAX_MESSAGE_BYTES {
        return Err("InputLimit: message exceeds 32 MiB".into());
    }
    if message.is_null() && len != 0 {
        return Err("InvalidInput: null message pointer".into());
    }
    let text = unsafe { read(script) }?;
    source::parse(text)?;
    let bytes = if len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(message, len) }
    };
    let env = Envelope {
        from: envelope.from,
        to: envelope.to,
        auth: envelope.auth,
    };
    let actions = eval_script_with_envelope(text, bytes, &env)
        .map_err(|e| format!("EvaluationError: {e}"))?;
    Ok(json!({"success":true,"actions":actions.iter().map(action).collect::<Vec<_>>()}))
}

/// Reference evaluator with no SMTP envelope. Does not send mail or auto-replies.
#[no_mangle]
pub extern "C" fn sieve_eval_actions_json(
    script: *const c_char,
    message: *const u8,
    len: usize,
) -> *mut c_char {
    export(|| evaluate(script, message, len, EnvelopeInput::default()))
}

/// Reference evaluator with an explicit SMTP envelope, never inferred from headers.
#[no_mangle]
pub extern "C" fn sieve_eval_actions_with_envelope_json(
    script: *const c_char,
    message: *const u8,
    len: usize,
    envelope: *const c_char,
) -> *mut c_char {
    export(|| {
        let env = serde_json::from_str::<EnvelopeInput>(unsafe { read(envelope) }?)
            .map_err(|e| format!("InvalidRequest: {e}"))?;
        evaluate(script, message, len, env)
    })
}

/// Free one non-null result exactly once using the same loaded library.
#[no_mangle]
pub extern "C" fn sieve_free_string(pointer: *mut c_char) {
    if !pointer.is_null() {
        unsafe {
            drop(CString::from_raw(pointer));
        }
    }
}
