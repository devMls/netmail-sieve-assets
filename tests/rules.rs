//! Rule IR: compilation, import, region editing, local evaluation and
//! equivalence with the reference Sieve evaluator.
use mailrs_sieve_core::{decode_encoded_words, extract_addresses};
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
fn ok(value: Value) -> Value {
    assert_eq!(value["success"], true, "{value}");
    value
}
fn set(rules: Value) -> Value {
    json!({"schema": 1, "rules": rules})
}
const ALL_CAPS: &[&str] = &["fileinto", "imap4flags", "copy", "body"];
fn compile(rules: &Value, caps: &[&str]) -> Value {
    let request = json!({"rules": rules, "server_capabilities": caps});
    result(rules_compile_sieve_json(c(&request.to_string()).as_ptr()))
}
fn apply(script: &str, request: Value) -> Value {
    result(rules_apply_region_json(
        c(script).as_ptr(),
        c(&request.to_string()).as_ptr(),
    ))
}
fn import(script: &str) -> Value {
    result(rules_import_sieve_json(c(script).as_ptr()))
}
fn evaluate(rules: &Value, messages: &Value) -> Value {
    result(rules_evaluate_batch_json(
        c(&rules.to_string()).as_ptr(),
        c(&messages.to_string()).as_ptr(),
    ))
}
fn validate(rules: &Value) -> Value {
    result(rules_validate_json(c(&rules.to_string()).as_ptr()))
}
/// Full script: require + region, as SieveScriptManager would publish it.
fn script_for(rules: &Value, caps: &[&str]) -> String {
    let compiled = ok(compile(rules, caps));
    let applied = ok(apply(
        "",
        json!({"region": compiled["region"], "require": compiled["require"], "expected_region": null}),
    ));
    applied["script"].as_str().unwrap().to_string()
}

fn invoices() -> Value {
    set(json!([{
        "id": "r1", "name": "Facturas", "revision": 3,
        "conditions": [{"field": "subject", "op": "contains", "values": ["Factura", "Presupuesto"]}],
        "actions": [{"type": "move", "mailbox": "Facturas"}, {"type": "mark_read"}]
    }]))
}

#[test]
fn compiles_flags_before_delivery_with_metadata() {
    let compiled = ok(compile(&invoices(), ALL_CAPS));
    let region = compiled["region"].as_str().unwrap();
    assert!(region.starts_with("# NetMail rules begin v1\r\n# netmail-rule {\"id\":\"r1\""));
    assert!(region.contains(
        "if header :contains \"subject\" [\"Factura\", \"Presupuesto\"] {\r\n    addflag \"\\\\Seen\";\r\n    fileinto \"Facturas\";\r\n}"
    ), "{region}");
    assert_eq!(compiled["require"], json!(["fileinto", "imap4flags"]));
    assert_eq!(compiled["rules"][0]["sieve"], "exact");
    assert_eq!(compiled["rules"][0]["local"], "supported");
}

#[test]
fn starts_and_ends_with_escape_wildcards() {
    let rules = set(json!([{"id": "r", "name": "x",
        "conditions": [{"field": "from", "op": "ends_with", "address_part": "domain", "values": ["*vip.es"]},
                       {"field": "subject", "op": "starts_with", "values": ["[a\\b]?"], "comparator": "octet"}],
        "actions": [{"type": "flag"}]}]));
    let region = ok(compile(&rules, ALL_CAPS))["region"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        region.contains(r#"address :domain :matches "from" "*\\*vip.es""#),
        "{region}"
    );
    assert!(
        region.contains(r#"header :comparator "i;octet" :matches "subject" "[a\\\\b]\\?*""#),
        "{region}"
    );
}

#[test]
fn unsupported_parts_are_reported_not_approximated() {
    let rules = set(json!([
        {"id": "a", "name": "adj", "conditions": [{"field": "has_attachment", "op": "exists"}],
         "actions": [{"type": "move", "mailbox": "X"}]},
        {"id": "b", "name": "sound", "conditions": [], "actions": [{"type": "sound"}]},
        {"id": "c", "name": "copy", "conditions": [], "actions": [{"type": "copy", "mailbox": "X"}]},
        {"id": "d", "name": "fold", "conditions": [{"field": "subject", "op": "is", "values": ["á"], "comparator": "unicode_fold"}],
         "actions": [{"type": "flag"}]},
        {"id": "e", "name": "body", "conditions": [{"field": "body_text", "op": "contains", "values": ["x"]}],
         "actions": [{"type": "flag"}]},
        {"id": "f", "name": "fwd", "conditions": [], "actions": [{"type": "redirect", "address": "a@b.es"}]}
    ]));
    let compiled = ok(compile(&rules, &["fileinto", "imap4flags"]));
    let status: Vec<_> = compiled["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["sieve"].as_str().unwrap(), r["local"].as_str().unwrap()))
        .collect();
    assert_eq!(
        status,
        vec![
            ("unsupported", "supported"),
            ("unsupported", "supported"),
            ("unsupported", "supported"),
            ("unsupported", "supported"),
            ("unsupported", "supported"),
            ("exact", "unsupported")
        ]
    );
    assert_eq!(
        compiled["rules"][2]["reasons"],
        json!(["missing_capability:copy"])
    );
    let with_body = ok(compile(&rules, ALL_CAPS));
    assert_eq!(with_body["rules"][4]["sieve"], "provider_defined");
    assert_eq!(with_body["rules"][2]["sieve"], "exact");
}

#[test]
fn validation_rejects_unsafe_values() {
    for bad in [
        json!([{"id": "x", "name": "n", "actions": []}]),
        json!([{"id": "x y", "name": "n", "actions": [{"type": "stop"}]}]),
        json!([{"id": "x", "name": "n", "actions": [{"type": "stop"}]}, {"id": "x", "name": "m", "actions": [{"type": "stop"}]}]),
        json!([{"id": "x", "name": "n", "conditions": [{"field": "subject", "op": "is", "values": ["a\r\nb"]}], "actions": [{"type": "stop"}]}]),
        json!([{"id": "x", "name": "n", "conditions": [{"field": "header", "op": "is", "values": ["a"]}], "actions": [{"type": "stop"}]}]),
        json!([{"id": "x", "name": "n", "conditions": [{"field": "header", "header": "Bad:Name", "op": "is", "values": ["a"]}], "actions": [{"type": "stop"}]}]),
        json!([{"id": "x", "name": "n", "actions": [{"type": "add_tag", "keyword": "\\Seen"}]}]),
        json!([{"id": "x", "name": "n", "actions": [{"type": "move", "mailbox": "A", "extra": 1}]}]),
        json!([{"id": "x", "name": "n", "conditions": [{"field": "size", "op": "contains", "values": ["1"]}], "actions": [{"type": "stop"}]}]),
        json!([{"id": "x", "name": "n", "actions": [{"type": "redirect", "address": "no-at"}]}]),
    ] {
        assert_eq!(validate(&set(bad.clone()))["success"], false, "{bad}");
    }
    let v = ok(validate(&invoices()));
    assert!(v["canonical"]
        .as_str()
        .unwrap()
        .contains("\"enabled\":true"));
}

#[test]
fn own_region_round_trips_through_import() {
    let rules = set(json!([
        {"id": "r1", "name": "Facturas «2026»", "revision": 7, "match": "any",
         "conditions": [{"field": "subject", "op": "contains", "values": ["Factura"]},
                        {"field": "from", "op": "is", "address_part": "domain", "values": ["proveedor.es"]}],
         "exceptions": [{"field": "list_id", "op": "exists"}],
         "actions": [{"type": "mark_read"}, {"type": "add_tag", "keyword": "$label1"},
                     {"type": "move", "mailbox": "Facturas"}, {"type": "stop"}]},
        {"id": "r2", "name": "Grandes", "enabled": false,
         "conditions": [{"field": "size", "op": "over", "size": 1048576}],
         "actions": [{"type": "copy", "mailbox": "Grandes"}]},
        {"id": "r3", "name": "Sin prefijo", "conditions": [{"field": "to_or_cc", "op": "starts_with", "values": ["ventas"], "address_part": "localpart"}],
         "actions": [{"type": "redirect", "address": "copia@empresa.es", "keep_copy": true}]}
    ]));
    let script = script_for(&rules, ALL_CAPS);
    let imported = ok(import(&script));
    assert!(imported["region"].is_object());
    assert_eq!(imported["external"], json!([]));
    let found: Vec<Value> = imported["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            assert_eq!(r["origin"], "netmail");
            assert_eq!(r["managed"], true);
            assert_eq!(r["reversible"], true, "{r}");
            r["rule"].clone()
        })
        .collect();
    let canonical: Value =
        serde_json::from_str(ok(validate(&rules))["canonical"].as_str().unwrap()).unwrap();
    assert_eq!(json!(found), canonical["rules"]);
}

#[test]
fn region_edits_are_conditional_and_preserve_foreign_rules() {
    let foreign = "require [\"fileinto\"];\r\n# mi regla\r\nif header :is \"X-Spam\" \"yes\" { fileinto \"Junk\"; }\r\n";
    let compiled = ok(compile(&invoices(), ALL_CAPS));
    let first = ok(apply(
        foreign,
        json!({"region": compiled["region"], "require": compiled["require"], "expected_region": null}),
    ));
    let script = first["script"].as_str().unwrap();
    // As with absence edits, missing declarations precede the first command.
    assert!(
        script.starts_with(
            "require [\"fileinto\"];\r\n# mi regla\r\nrequire [\"imap4flags\"];\r\nif header"
        ),
        "{script}"
    );
    assert!(script.ends_with("# NetMail rules end\r\n"));
    // A stale expected region is a conflict; the exact one replaces it.
    let empty = ok(compile(&set(json!([])), ALL_CAPS));
    let stale = apply(
        script,
        json!({"region": empty["region"], "expected_region": "# NetMail rules begin v1\r\n# NetMail rules end\r\n"}),
    );
    assert_eq!(stale["error_code"], "Conflict");
    let replaced = ok(apply(
        script,
        json!({"region": empty["region"], "expected_region": compiled["region"]}),
    ));
    let replaced_script = replaced["script"].as_str().unwrap();
    assert!(
        replaced_script.contains("fileinto \"Junk\";") && !replaced_script.contains("Facturas")
    );
    // Removing the region leaves the foreign rule untouched.
    let removed = ok(apply(
        replaced_script,
        json!({"region": "", "expected_region": empty["region"]}),
    ));
    assert!(removed["script"]
        .as_str()
        .unwrap()
        .ends_with("fileinto \"Junk\"; }\r\n"));
    // Appending behind control flow needs an explicit decision.
    let stopping = "if true { stop; }\r\n";
    let refused = apply(
        stopping,
        json!({"region": compiled["region"], "require": compiled["require"], "expected_region": null}),
    );
    assert_eq!(refused["error_code"], "UnsafeToManage");
    let accepted = ok(apply(
        stopping,
        json!({"region": compiled["region"], "require": compiled["require"],
        "expected_region": null, "allow_append_after_control_flow": true}),
    ));
    assert_eq!(accepted["warnings"].as_array().unwrap().len(), 1);
}

#[test]
fn require_is_inserted_before_a_leading_region() {
    let compiled = ok(compile(&invoices(), ALL_CAPS));
    let script = compiled["region"].as_str().unwrap().to_string();
    let empty = ok(compile(
        &set(json!([{"id": "s", "name": "s", "actions": [{"type": "copy", "mailbox": "A"}]}])),
        ALL_CAPS,
    ));
    let applied = ok(apply(
        &script,
        json!({"region": empty["region"], "require": empty["require"], "expected_region": compiled["region"]}),
    ));
    let out = applied["script"].as_str().unwrap();
    assert!(
        out.starts_with("require [\"copy\", \"fileinto\"];\r\n# NetMail rules begin v1"),
        "{out}"
    );
}

#[test]
fn imports_roundcube_rules_and_preserves_the_rest() {
    let script = "require [\"fileinto\",\"imap4flags\"];\n# rule:[Boletines]\nif header :contains \"list-id\" \"\" {\n\tfileinto \"INBOX.Boletines\";\n\tstop;\n}\n# rule:[Jefe]\nif anyof (address :is \"from\" \"jefe@empresa.es\", header :contains \"subject\" \"urgente\")\n{\n\taddflag \"\\\\Flagged\";\n}\nif header :is \"X\" \"1\" { keep; } else { discard; }\nif header :regex \"subject\" \"a+\" { stop; }\n";
    let imported = ok(import(script));
    let rules = imported["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["origin"], "roundcube");
    assert_eq!(rules[0]["rule"]["name"], "Boletines");
    assert_eq!(rules[0]["reversible"], true);
    assert_eq!(rules[1]["rule"]["match"], "any");
    assert_eq!(rules[1]["rule"]["actions"], json!([{"type": "flag"}]));
    assert_eq!(rules[1]["reversible"], true);
    let external = imported["external"].as_array().unwrap();
    assert_eq!(external.len(), 2);
    assert_eq!(external[0]["kind"], "conditional_chain");
    assert_eq!(external[1]["kind"], "unconvertible_rule");
    assert!(imported["region"].is_null());
}

#[test]
fn exceptions_and_match_mode_round_trip_exactly() {
    // H8: a single exception used to come back as a negated condition, and
    // one `any` condition as `all`. Negated conditions must stay conditions.
    let subject = json!({"field": "subject", "op": "contains", "values": ["Factura"]});
    let spam = json!({"field": "from", "op": "ends_with", "address_part": "domain", "values": ["spam.test"]});
    let negated = json!({"field": "list_id", "op": "exists", "negate": true});
    let rules = set(json!([
        {"id": "one-exception", "name": "A", "conditions": [subject], "exceptions": [spam],
         "actions": [{"type": "flag"}]},
        {"id": "only-exception", "name": "B", "exceptions": [spam], "actions": [{"type": "flag"}]},
        {"id": "negated-condition", "name": "C", "conditions": [subject, negated],
         "actions": [{"type": "flag"}]},
        {"id": "any-single", "name": "D", "match": "any", "conditions": [subject],
         "exceptions": [negated], "actions": [{"type": "flag"}]},
        {"id": "disabled", "name": "E", "enabled": false, "match": "any", "conditions": [subject],
         "exceptions": [spam], "actions": [{"type": "flag"}]},
        {"id": "no-conditions", "name": "F", "match": "any", "actions": [{"type": "flag"}]}
    ]));
    let script = script_for(&rules, ALL_CAPS);
    assert!(
        script.contains("allof(header :contains \"subject\" \"Factura\", not anyof(address"),
        "{script}"
    );
    let imported = ok(import(&script));
    let back: Vec<Value> = imported["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            assert_eq!(r["reversible"], true, "{r}");
            r["rule"].clone()
        })
        .collect();
    let canonical: Value =
        serde_json::from_str(ok(validate(&rules))["canonical"].as_str().unwrap()).unwrap();
    assert_eq!(json!(back), canonical["rules"]);
    // An `any` rule without conditions is canonically `all`.
    assert_eq!(canonical["rules"][5]["match"], "all");
    // Scripts compiled by 0.3.0 still import with the same meaning.
    let old = "require \"imap4flags\";\r\nif allof(header :contains \"subject\" \"Factura\", not address :domain :matches \"from\" \"*spam.test\") { addflag \"\\\\Flagged\"; }\r\n";
    let rule = &ok(import(old))["rules"][0]["rule"];
    assert_eq!(rule["conditions"][1]["negate"], true);
    assert_eq!(rule["exceptions"], json!([]));
}

#[test]
fn non_canonical_forms_import_but_are_not_reversible() {
    let script = "require \"fileinto\";\r\nif header :is :comparator \"i;octet\" \"subject\" \"A\" { fileinto \"X\"; }\r\n";
    let imported = ok(import(script));
    assert_eq!(
        imported["rules"][0]["rule"]["conditions"][0]["comparator"],
        "octet"
    );
    assert_eq!(imported["rules"][0]["reversible"], false);
}

#[test]
fn broken_region_markers_are_refused() {
    let script = "# NetMail rules begin v1\r\nkeep;\r\n";
    assert_eq!(import(script)["error_code"], "UnsafeToManage");
    let inside_text =
        "require \"vacation\";\r\nvacation text:\r\n# NetMail rules begin v1\r\n.\r\n;\r\n";
    assert!(ok(import(inside_text))["region"].is_null());
}

#[test]
fn local_evaluation_defers_instead_of_guessing() {
    let rules = set(json!([
        {"id": "a", "name": "body", "conditions": [{"field": "body_text", "op": "contains", "values": ["pedido"]}],
         "actions": [{"type": "move", "mailbox": "Pedidos"}]},
        {"id": "b", "name": "list", "conditions": [{"field": "list_id", "op": "exists"}],
         "actions": [{"type": "sound", "sound": "ding"}]}
    ]));
    let messages = json!([
        {"id": "1", "headers": {"Subject": ["x"]}, "headers_complete": true},
        {"id": "2", "headers": {"Subject": ["x"]}, "headers_complete": true, "body_text": "nuevo PEDIDO 7"},
        {"id": "3", "headers": {"List-Id": ["<l.x>"]}, "body_text": "nada", "body_truncated": true},
        {"id": "4", "headers": {}, "body_text": "nada"}
    ]);
    let r = ok(evaluate(&rules, &messages));
    let results = r["results"].as_array().unwrap();
    assert_eq!(results[0]["status"], "deferred");
    assert_eq!(results[0]["missing"], json!(["body_text"]));
    assert_eq!(
        results[1]["actions"],
        json!([{"type": "fileinto", "mailbox": "Pedidos", "flags": [], "copy": false, "rule_id": "a"}])
    );
    assert_eq!(results[2]["status"], "deferred");
    assert_eq!(results[3]["status"], "deferred");
    assert_eq!(results[3]["missing"], json!(["headers"]));
}

#[test]
fn unicode_fold_is_local_only() {
    let rules = set(json!([{"id": "a", "name": "n",
        "conditions": [{"field": "subject", "op": "contains", "values": ["AREA"], "comparator": "unicode_fold"}],
        "actions": [{"type": "flag"}, {"type": "notify"}]}]));
    let messages = json!([{"id": "1", "headers": {"subject": ["Reunión del Área"]}}]);
    let r = ok(evaluate(&rules, &messages));
    assert_eq!(
        r["results"][0]["actions"],
        json!([{"type": "keep", "flags": ["\\Flagged"]}])
    );
    assert_eq!(
        r["results"][0]["effects"],
        json!([{"type": "notify", "rule_id": "a"}])
    );
}

#[test]
fn catalog_and_runtime_announce_rules() {
    let info = ok(result(sieve_runtime_info_json()));
    assert!(info["features"]
        .as_array()
        .unwrap()
        .contains(&json!("rules_ir_v1")));
    assert_eq!(info["abi_version"], 2);
    let catalog = ok(result(rules_catalog_json()));
    assert_eq!(catalog["fields"]["subject"]["sieve"]["level"], "exact");
    assert_eq!(
        catalog["actions"]["redirect"]["local"]["level"],
        "unsupported"
    );
}

// ---------------------------------------------------------------------------
// Equivalence: local plan == reference Sieve evaluation of the compiled
// script, for generated rule sets and messages.

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[(self.next() % items.len() as u64) as usize]
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

const WORDS: &[&str] = &[
    "Factura", "factura", "PEDIDO", "Año", "año", "a*b", "x?y", "re:", "Área", "ventas",
];
const ADDRS: &[&str] = &[
    "ana@empresa.es",
    "Ventas@Proveedor.ES",
    "jefe+tag@empresa.es",
    "x@y.com",
];
const HEADERS: &[&str] = &["subject", "list-id", "X-Code"];

fn random_condition(rng: &mut Rng) -> Value {
    let negate = rng.chance(20);
    let op = *rng.pick(&["is", "contains", "starts_with", "ends_with", "matches"]);
    let comparator = *rng.pick(&["ascii_casemap", "ascii_casemap", "octet"]);
    let values: Vec<String> = (0..1 + rng.next() % 2)
        .map(|_| {
            let w = rng.pick(WORDS).to_string();
            let first = w.chars().next().unwrap().to_string();
            match op {
                "matches" => format!("*{first}*"),
                "is" | "starts_with" | "ends_with" if rng.chance(30) => first,
                _ => w,
            }
        })
        .collect();
    match rng.next() % 6 {
        0 | 1 => {
            json!({"field": "subject", "op": op, "values": values, "comparator": comparator, "negate": negate})
        }
        2 => {
            let field = *rng.pick(&["from", "to", "cc", "to_or_cc"]);
            let part = *rng.pick(&["all", "localpart", "domain"]);
            let values: Vec<String> = values
                .iter()
                .map(|_| {
                    let a = rng.pick(ADDRS);
                    match part {
                        "localpart" => a.split('@').next().unwrap().into(),
                        "domain" => a.split('@').nth(1).unwrap().into(),
                        _ => a.to_string(),
                    }
                })
                .collect();
            json!({"field": field, "op": op, "values": values, "address_part": part, "comparator": comparator, "negate": negate})
        }
        3 => {
            json!({"field": "header", "header": rng.pick(HEADERS), "op": op, "values": values, "negate": negate})
        }
        4 => {
            json!({"field": *rng.pick(&["list_id", "header"]), "header": null, "op": "exists", "negate": negate})
        }
        _ => {
            json!({"field": "size", "op": *rng.pick(&["over", "under"]), "size": rng.next() % 400, "negate": negate})
        }
    }
}

fn random_rules(rng: &mut Rng) -> Value {
    let rules: Vec<Value> = (0..1 + rng.next() % 4).map(|i| {
        let conditions: Vec<Value> = (0..rng.next() % 3).map(|_| random_condition(rng)).map(|mut c| {
            if c["field"] == "header" && c["header"].is_null() { c["header"] = json!("X-Code"); }
            if c["header"].is_null() { c.as_object_mut().unwrap().remove("header"); }
            c
        }).collect();
        let exceptions: Vec<Value> = if rng.chance(25) { vec![random_condition(rng)] } else { vec![] }
            .into_iter().map(|mut c| {
                if c["field"] == "header" && c["header"].is_null() { c["header"] = json!("X-Code"); }
                if c["header"].is_null() { c.as_object_mut().unwrap().remove("header"); }
                c
            }).collect();
        let mut actions = vec![];
        for _ in 0..1 + rng.next() % 3 {
            actions.push(match rng.next() % 7 {
                0 => json!({"type": "move", "mailbox": rng.pick(&["Facturas", "Año 2026", "Ventas"])}),
                1 => json!({"type": "copy", "mailbox": "Archivo"}),
                2 => json!({"type": "mark_read"}),
                3 => json!({"type": "flag"}),
                4 => json!({"type": "add_tag", "keyword": "$label1"}),
                5 => json!({"type": "redirect", "address": "copia@empresa.es", "keep_copy": rng.chance(50)}),
                _ => json!({"type": "mark_read"}),
            });
        }
        if rng.chance(20) { actions.push(json!({"type": "stop"})); }
        json!({"id": format!("r{i}"), "name": format!("Regla {i}"), "enabled": !rng.chance(15),
            "match": *rng.pick(&["all", "any"]), "conditions": conditions,
            "exceptions": exceptions, "actions": actions})
    }).collect();
    set(json!(rules))
}

fn encode_subject(text: &str, rng: &mut Rng) -> String {
    if text.is_ascii() && !rng.chance(30) {
        return text.to_string();
    }
    let mut out = String::from("=?UTF-8?Q?");
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(b as char)
        } else {
            out.push_str(&format!("={b:02X}"))
        }
    }
    out + "?="
}

/// Raw message plus the snapshot a client would derive from it.
fn random_message(rng: &mut Rng, id: usize) -> (Vec<u8>, Value) {
    let subject = format!(
        "{} {} {}",
        rng.pick(WORDS),
        rng.pick(WORDS),
        rng.pick(&["", "Ñ", "x"])
    );
    let mut headers = vec![
        ("From".to_string(), format!("Nombre <{}>", rng.pick(ADDRS))),
        (
            "To".to_string(),
            format!("{}, {}", rng.pick(ADDRS), rng.pick(ADDRS)),
        ),
        ("Subject".to_string(), encode_subject(subject.trim(), rng)),
    ];
    if rng.chance(50) {
        headers.push(("Cc".into(), rng.pick(ADDRS).to_string()));
    }
    if rng.chance(40) {
        headers.push(("List-Id".into(), "<boletin.empresa.es>".into()));
    }
    if rng.chance(50) {
        headers.push(("X-Code".into(), rng.pick(WORDS).to_string()));
    }
    let mut raw = String::new();
    for (n, v) in &headers {
        raw.push_str(&format!("{n}: {v}\r\n"));
    }
    raw.push_str("\r\nCuerpo\r\n");
    let mut map = serde_json::Map::new();
    for (n, v) in &headers {
        map.entry(n.clone())
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .unwrap()
            .push(json!(decode_encoded_words(v)));
    }
    let addresses = |name: &str| -> Value {
        json!(headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| extract_addresses(v))
            .collect::<Vec<_>>())
    };
    let snapshot = json!({"id": id.to_string(), "headers": map, "headers_complete": true,
        "from": addresses("from"), "sender": addresses("sender"), "to": addresses("to"),
        "cc": addresses("cc"), "size": raw.len()});
    (raw.into_bytes(), snapshot)
}

fn sieve_actions(script: &str, message: &[u8]) -> Value {
    let r = result(sieve_eval_actions_json(
        c(script).as_ptr(),
        message.as_ptr(),
        message.len(),
    ));
    assert_eq!(r["success"], true, "{r}\n{script}");
    r["actions"].clone()
}

fn strip(actions: &Value) -> Value {
    json!(actions
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let mut a = a.clone();
            let o = a.as_object_mut().unwrap();
            o.remove("copy");
            o.remove("rule_id");
            a
        })
        .collect::<Vec<_>>())
}

#[test]
fn local_plan_equals_reference_sieve_evaluation() {
    let mut rng = Rng(0x5eed_2026_1112);
    let mut compared = 0;
    for _ in 0..300 {
        let rules = random_rules(&mut rng);
        let compiled = ok(compile(&rules, &["fileinto", "imap4flags", "copy"]));
        assert!(
            compiled["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["sieve"] == "exact"),
            "{compiled}"
        );
        let script = script_for(&rules, &["fileinto", "imap4flags", "copy"]);
        // Round trip: every generated rule is recognised, reversible and
        // comes back as exactly the same IR (H8: exceptions, match mode).
        let imported = ok(import(&script));
        assert!(
            imported["rules"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["reversible"] == true),
            "{imported}"
        );
        let canonical: Value =
            serde_json::from_str(ok(validate(&rules))["canonical"].as_str().unwrap()).unwrap();
        let back: Vec<Value> = imported["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["rule"].clone())
            .collect();
        assert_eq!(json!(back), canonical["rules"], "script={script}");
        let messages: Vec<(Vec<u8>, Value)> = (0..8).map(|i| random_message(&mut rng, i)).collect();
        let snapshots = json!(messages.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>());
        let local = ok(evaluate(&rules, &snapshots));
        for ((raw, _), plan) in messages.iter().zip(local["results"].as_array().unwrap()) {
            assert_eq!(plan["status"], "evaluated");
            assert_eq!(
                strip(&plan["actions"]),
                sieve_actions(&script, raw),
                "rules={rules}\nmessage={}\nscript={script}",
                String::from_utf8_lossy(raw)
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 2400);
}
