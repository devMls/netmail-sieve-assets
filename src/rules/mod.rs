//! NetMail rule IR (`netmail.rules/1`): catalogue, validation, Sieve
//! compilation/import/region editing and local evaluation. No I/O.
pub mod catalog;
pub mod compile;
pub mod evaluate;
pub mod import;
pub mod ir;
pub mod region;

use serde_json::{json, Value};

/// Validate a rule set and return its canonical JSON (defaults applied,
/// stable field order) plus per-rule local coverage.
pub fn validate(text: &str) -> Result<Value, String> {
    let set = ir::parse_rule_set(text)?;
    let canonical = serde_json::to_string(&set).map_err(|e| format!("InternalError: {e}"))?;
    let rules: Vec<Value> = set
        .rules
        .iter()
        .map(|r| {
            let local = compile::local_support(r);
            json!({"id": r.id,
                "local": if local.is_empty() { "supported" } else { "unsupported" },
                "local_reasons": local})
        })
        .collect();
    Ok(json!({"success": true, "schema_version": 1, "canonical": canonical, "rules": rules}))
}
