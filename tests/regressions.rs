use netmail_sieve::*;
use serde_json::{json, Value};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}
fn result(pointer: *mut c_char) -> Value {
    assert!(!pointer.is_null());
    let text = unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .unwrap()
        .to_owned();
    sieve_free_string(pointer);
    serde_json::from_str(&text).unwrap()
}
fn merge(original: &str, snippet: &str) -> Value {
    result(sieve_merge_vacation(
        c(original).as_ptr(),
        c(snippet).as_ptr(),
    ))
}
fn merged(original: &str, snippet: &str) -> String {
    let value = merge(original, snippet);
    assert_eq!(value["success"], true, "{value}");
    value["script"].as_str().unwrap().into()
}
fn extract(s: &str) -> Value {
    result(sieve_extract_vacation_json(c(s).as_ptr()))
}
fn analyze(s: &str) -> Value {
    result(sieve_analyze_script_json(c(s).as_ptr()))
}
fn evaluate(s: &str, msg: &[u8]) -> Value {
    result(sieve_eval_actions_json(
        c(s).as_ptr(),
        msg.as_ptr(),
        msg.len(),
    ))
}
fn delivery(s: &str, msg: &[u8]) -> Vec<Value> {
    let r = evaluate(s, msg);
    assert_eq!(r["success"], true, "{r}");
    r["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["type"] != "vacation")
        .cloned()
        .collect()
}
fn edited(s: &str, request: Value) -> Value {
    result(sieve_edit_vacation_json(
        c(s).as_ptr(),
        c(&request.to_string()).as_ptr(),
    ))
}

const OLD:&str="require [\"fileinto\", \"vacation\"];\nif header :contains \"Subject\" \"Factura\" { fileinto \"Facturas\"; vacation \"Old reply\"; } else { keep; }\n";
const NEW: &str =
    "require [\"vacation\"]; vacation :days 7 :subject \"New subject\" \"New reply\";";

#[test]
fn shared_block_preserves_filter_and_else_for_matching_and_nonmatching_messages() {
    let new = merged(OLD, NEW);
    assert!(new.contains("fileinto \"Facturas\";"));
    assert!(new.contains("} else { keep; }"));
    for msg in [
        b"Subject: Factura\r\n\r\n".as_slice(),
        b"Subject: Another\r\n\r\n",
    ] {
        assert_eq!(delivery(OLD, msg), delivery(&new, msg));
    }
    assert!(!evaluate(&new, b"Subject: Another\r\n\r\n")["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["type"] == "vacation"));
}

#[test]
fn shared_multiline_block_is_not_deleted() {
    let old = OLD
        .replace("{ fileinto", "{\r\n fileinto")
        .replace("; vacation", ";\r\n vacation");
    assert!(merged(&old, NEW).contains("fileinto \"Facturas\";"));
}

#[test]
fn removing_vacation_preserves_shared_guard_and_all_delivery_actions() {
    let new = merged(OLD, "");
    assert!(new.contains("if header :contains \"Subject\" \"Factura\""));
    assert!(!new.contains("Old reply"));
    for msg in [
        b"Subject: Factura\r\n\r\n".as_slice(),
        b"Subject: Another\r\n\r\n",
    ] {
        assert_eq!(delivery(OLD, msg), delivery(&new, msg));
    }
}

#[test]
fn inline_require_never_eats_the_new_vacation() {
    let new = merged("require \"fileinto\"; fileinto \"Facturas\";", NEW);
    assert!(new.contains("New reply"));
    assert_eq!(extract(&new)["days"], 7);
}

#[test]
fn fresh_script_has_required_extension_before_body() {
    let new = merged("", "vacation \"New reply\";");
    assert_eq!(evaluate(&new, b"Subject: Hi\r\n\r\n")["success"], true);
}

#[test]
fn require_only_script_can_accept_a_vacation() {
    assert!(merged("require \"fileinto\";", NEW).contains("New reply"));
}

#[test]
fn no_op_preserves_all_original_bytes_and_explicit_keep() {
    let source = "# hello\r\nrequire [\"fileinto\"];\r\nkeep; fileinto \"X\";\r\n";
    assert_eq!(merged(source, ""), source);
    assert_eq!(merge(source, "")["changed"], false);
}

#[test]
fn explicit_keep_survives_disabling() {
    let source = "require [\"vacation\",\"fileinto\"]; keep; fileinto \"X\"; vacation \"old\";";
    let new = merged(source, "");
    assert!(new.contains("keep; fileinto \"X\";"));
    assert_eq!(delivery(source, b"\r\n"), delivery(&new, b"\r\n"));
}

#[test]
fn original_trivia_escapes_and_unicode_are_byte_preserved() {
    let source="# Información 🚀\r\nrequire [\"vacation\"]; /* { vacation \"fake\"; } */\n\t vacation \"old\"; # tail\n";
    let expected = source.replace("vacation \"old\";", "vacation \"new\";");
    assert_eq!(merged(source, "vacation \"new\";"), expected);
}

#[test]
fn repeated_merge_is_idempotent() {
    let first = merged(OLD, NEW);
    assert_eq!(merge(&first, NEW)["changed"], false);
}

#[test]
fn all_branch_guards_are_preserved() {
    let source="require [\"vacation\",\"fileinto\"]; if false { keep; } /* between */ elsif header :is \"Subject\" \"Invoice\" { vacation \"old\"; fileinto \"X\"; } else { discard; }";
    let new = merged(source, NEW);
    assert!(new.contains("/* between */ elsif header"));
    assert!(new.contains("else { discard; }"));
    for msg in [
        b"Subject: Invoice\r\n\r\n".as_slice(),
        b"Subject: Else\r\n\r\n",
    ] {
        assert_eq!(delivery(source, msg), delivery(&new, msg));
    }
}

#[test]
fn multiple_responders_are_not_implicitly_overwritten() {
    let source = "require \"vacation\"; if true { vacation \"one\"; } else { vacation \"two\"; }";
    assert_eq!(merge(source, NEW)["error_code"], "AmbiguousVacation");
    assert_eq!(extract(source)["error_code"], "AmbiguousVacation");
    let r = edited(
        source,
        json!({"operation":"replace","target_index":1,"expected_source":"vacation \"two\";","snippet":NEW}),
    );
    assert_eq!(r["success"], true, "{r}");
    assert!(r["script"].as_str().unwrap().contains("vacation \"one\";"));
}

#[test]
fn stale_explicit_target_is_a_conflict_without_candidate() {
    let r = edited(
        OLD,
        json!({"operation":"replace","target_index":0,"expected_source":"vacation \"changed\";","snippet":NEW}),
    );
    assert_eq!(r["error_code"], "Conflict");
    assert!(r.get("script").is_none());
}

#[test]
fn settings_scope_refuses_to_drop_external_audience() {
    let r = edited(
        OLD,
        json!({"operation":"replace","target_index":0,"expected_source":"vacation \"Old reply\";","snippet":NEW,"scope":"settings"}),
    );
    assert_eq!(r["error_code"], "UnsafeToManage");
    assert_eq!(extract(OLD)["error_code"], "UnsafeToManage");
}

#[test]
fn schedules_are_replaced_instead_of_nested() {
    let source="require [\"vacation\",\"date\",\"relational\"]; if currentdate :zone \"+0000\" :value \"ge\" \"iso8601\" \"2026-07-01T00:00:00Z\" { vacation \"old\"; }";
    let new = merged(source, NEW);
    assert!(!new.contains("if currentdate"));
    assert_eq!(extract(&new)["enabled"], true);
}

#[test]
fn exact_netmail_schedule_is_read_using_reference_test_ast() {
    let source="require [\"vacation\",\"date\",\"relational\"]; if allof (currentdate :zone \"+0000\" :value \"ge\" \"iso8601\" \"2026-07-01T00:00:00Z\",currentdate :value \"lt\" :zone \"+0000\" \"iso8601\" \"2026-07-15T00:00:00Z\") { vacation :days 14 :addresses [\"a@b.test\",\"c@d.test\"] \"reply\"; }";
    let r = extract(source);
    assert_eq!(r["success"], true, "{r}");
    assert_eq!(r["start"], "2026-07-01T00:00:00Z");
    assert_eq!(r["end"], "2026-07-15T00:00:00Z");
    assert_eq!(r["addresses"], json!(["a@b.test", "c@d.test"]));
}

#[test]
fn date_disjunction_and_negation_are_not_flattened_to_schedule() {
    for guard in [
        "anyof(true,false)",
        "not false",
        "currentdate :zone \"+0100\" :value \"ge\" \"iso8601\" \"2026-07-01T00:00:00Z\"",
    ] {
        assert_eq!(
            extract(&format!(
                "require \"vacation\"; if {guard} {{ vacation \"old\"; }}"
            ))["error_code"],
            "UnsafeToManage"
        );
    }
}

#[test]
fn false_and_nested_false_are_observed_as_disabled() {
    assert_eq!(
        extract("require \"vacation\"; if false { if true { vacation \"old\"; } }")["enabled"],
        false
    );
}

#[test]
fn arbitrary_audience_is_reported_in_analysis_without_global_enabled_state() {
    let source="require \"vacation\"; if address :domain :is \"from\" \"partner.test\" { vacation \"old\"; }";
    assert_eq!(extract(source)["success"], false);
    let r = analyze(source);
    assert_eq!(r["vacations"][0]["can_read_as_settings"], false);
    assert_eq!(
        r["vacations"][0]["contexts"][0]["args"][0]["value"]["name"],
        "address"
    );
}

#[test]
fn append_behind_stop_or_discard_requires_explicit_decision() {
    for source in ["stop;", "discard;", "redirect \"a@b.test\";"] {
        assert_eq!(merge(source, NEW)["error_code"], "UnsafeToManage");
        let r = edited(
            source,
            json!({"operation":"append","snippet":NEW,"allow_append_after_control_flow":true}),
        );
        assert_eq!(r["success"], true, "{r}");
        assert!(!r["warnings"].as_array().unwrap().is_empty());
        assert!(r["script"].as_str().unwrap().contains(source));
    }
}

#[test]
fn external_includes_never_imply_absence_is_disabled() {
    let source = "require \"include\"; include :personal \"external\";";
    assert_eq!(extract(source)["error_code"], "UnsafeToManage");
    assert_eq!(merge(source, NEW)["error_code"], "UnsafeToManage");
}

#[test]
fn invalid_or_side_effectful_snippets_never_produce_candidates() {
    for snippet in [
        "vacation;",
        "vacation :foo \"x\";",
        "vacation :days 3 :days 5 \"x\";",
        "vacation \"new\"; discard;",
        "fileinto \"X\";",
        "if header :is \"Subject\" \"X\" { vacation \"new\"; }",
    ] {
        let r = merge(OLD, snippet);
        assert_eq!(r["success"], false, "{snippet}: {r}");
        assert!(r.get("script").is_none());
    }
}

#[test]
fn complete_input_and_control_structure_are_checked() {
    for source in [
        "keep; } discard;",
        "else { keep; }",
        "keep; require \"fileinto\";",
        "if true { require \"vacation\"; }",
    ] {
        assert_ne!(sieve_validate(c(source).as_ptr()), 0, "{source}");
    }
}

#[test]
fn multiline_reference_fix_preserves_unicode_periods_and_dot_stuffing() {
    let source="REQUIRE \"vacation\"; VACATION TEXT:  # comment\r\nEstoy fuera.\r\n..Punto ñ 🚀.\r\nrequire \"fake\"; }\r\n.\r\n;";
    let r = extract(source);
    assert_eq!(r["success"], true, "{r}");
    assert_eq!(
        r["reason"],
        "Estoy fuera.\r\n.Punto ñ 🚀.\r\nrequire \"fake\"; }\r\n"
    );
    assert_eq!(analyze(source)["vacations"].as_array().unwrap().len(), 1);
    assert!(merged(source, NEW).contains("New reply"));
}

#[test]
fn reference_seconds_and_mime_parameters_are_preserved_without_numeric_truncation() {
    let r=extract("require [\"vacation\",\"vacation-seconds\"]; vacation :seconds 5000000000 :mime :handle \"campaign\" :from \"a@b.test\" \"MIME-Version: 1.0\";");
    assert_eq!(r["seconds"], 5000000000u64);
    assert_eq!(r["mime"], true);
    assert_eq!(r["handle"], "campaign");
}

#[test]
fn typed_ast_and_offsets_are_real_utf8_bytes() {
    let source = "# ñ 🚀\nrequire \"vacation\"; vacation \"old\";";
    let r = analyze(source);
    let v = &r["vacations"][0];
    let start = v["start"].as_u64().unwrap() as usize;
    let end = v["end"].as_u64().unwrap() as usize;
    assert_eq!(&source[start..end], "vacation \"old\";");
    assert_eq!(r["commands"][1]["args"][0]["kind"], "string");
}

#[test]
fn edit_plan_reconstructs_candidate_and_preserves_untouched_bytes() {
    let r = merge(OLD, NEW);
    let mut reconstructed = OLD.to_owned();
    for e in r["edits"].as_array().unwrap().iter().rev() {
        let start = e["start"].as_u64().unwrap() as usize;
        let end = e["end"].as_u64().unwrap() as usize;
        assert_eq!(&OLD[start..end], e["expected"].as_str().unwrap());
        reconstructed.replace_range(start..end, e["replacement"].as_str().unwrap());
    }
    assert_eq!(reconstructed, r["script"]);
}

#[test]
fn syntax_acceptance_does_not_claim_local_extension_support() {
    let source="require [\"date\",\"relational\"]; if currentdate :value \"ge\" \"iso8601\" \"2026-11-01T00:00:00Z\" { keep; }";
    let r = result(sieve_validate_detail_json(c(source).as_ptr()));
    assert_eq!(r["valid"], true);
    assert_eq!(r["local_capabilities_valid"], false);
    assert_eq!(evaluate(source, b"\r\n")["success"], false);
}

#[test]
fn evaluator_preserves_structured_vacation_and_flags() {
    let r=evaluate("require [\"vacation\",\"imap4flags\"]; setflag \"\\\\Seen\"; vacation :days 3 :subject \"Away\" \"reply\";",b"Subject: Hi\r\n\r\n");
    assert_eq!(r["success"], true, "{r}");
    assert!(r["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["type"] == "vacation" && a["period"]["value"] == 3));
}

#[test]
fn evaluator_uses_reference_smtp_envelope_api() {
    let script=c("require \"envelope\"; if envelope :is \"to\" \"actual@b.test\" { discard; } else { keep; }");
    let msg = b"To: misleading@b.test\r\n\r\n";
    let env = c(r#"{"from":"sender@b.test","to":["actual@b.test"]}"#);
    let r = result(sieve_eval_actions_with_envelope_json(
        script.as_ptr(),
        msg.as_ptr(),
        msg.len(),
        env.as_ptr(),
    ));
    assert_eq!(r["actions"][0]["type"], "discard");
}

#[test]
fn null_and_invalid_utf8_never_mean_disable_the_responder() {
    assert_eq!(
        result(sieve_merge_vacation(std::ptr::null(), c(NEW).as_ptr()))["error_code"],
        "InvalidInput"
    );
    let invalid = [0xffu8, 0];
    assert_eq!(
        result(sieve_merge_vacation(
            c(OLD).as_ptr(),
            invalid.as_ptr().cast()
        ))["error_code"],
        "InvalidInput"
    );
    assert_eq!(
        result(sieve_eval_actions_json(
            c("keep;").as_ptr(),
            std::ptr::null(),
            5
        ))["success"],
        false
    );
    sieve_free_string(std::ptr::null_mut());
}

#[test]
fn limits_are_checked_before_recursive_parse_or_message_read() {
    let deep = format!("{}keep;{}", "if true {".repeat(65), "}".repeat(65));
    assert_eq!(analyze(&deep)["error_code"], "InputLimit");
    let huge = " ".repeat(256 * 1024 + 1);
    assert_eq!(analyze(&huge)["error_code"], "InputLimit");
    assert_eq!(
        result(sieve_eval_actions_json(
            c("keep;").as_ptr(),
            std::ptr::null(),
            32 * 1024 * 1024 + 1
        ))["error_code"],
        "InputLimit"
    );
}

#[test]
fn runtime_and_legacy_ast_contract_are_versioned() {
    let r = result(sieve_runtime_info_json());
    assert_eq!(r["abi_version"], 2);
    let r = result(sieve_parse_ast_json(c("keep;").as_ptr()));
    assert_eq!(r["commands"][0]["name"], "keep");
    assert!(r["commands"][0]["args"].is_array());
    assert!(r["commands"][0]["typed_args"].is_array());
}

#[test]
fn analysis_of_many_responders_keeps_contexts_bounded() {
    let source = format!(
        "require \"vacation\"; if true {{ {} }}",
        "vacation \"old\";".repeat(100)
    );
    let r = analyze(&source);
    assert_eq!(r["success"], true);
    assert_eq!(r["vacations"].as_array().unwrap().len(), 100);
    assert!(
        r.to_string().len() < 100_000,
        "ancestor blocks must not be duplicated for every target"
    );
}
