//! Field × operator × backend catalogue. The UI, the .NET compilers and the
//! tests read this table; support levels are deliberately conservative.
//! - `exact`: same decision as the IR semantics for the same message.
//! - `provider_defined`: published with the provider's documented
//!   semantics; requires explicit acceptance and has no local fallback.
//! - `client_only` / `unsupported`.
//!
//! Graph and Gmail entries describe the provider APIs; their compilers live
//! in .NET and must not upgrade a level without equivalence tests.
use serde_json::{json, Value};

fn text_ops() -> Value {
    json!(["is", "contains", "starts_with", "ends_with", "matches"])
}

pub fn catalog() -> Value {
    let address = |graph: Value, gmail: Value| {
        json!({"operators": text_ops(), "address_parts": ["all", "localpart", "domain"],
            "comparators": ["ascii_casemap", "octet", "unicode_fold"],
            "sieve": {"level": "exact", "test": "address", "client_only_comparators": ["unicode_fold"]},
            "graph": graph, "gmail": gmail, "local": {"level": "exact"}})
    };
    let gmail_search = |criterion: &str| {
        json!({"level": "provider_defined", "criterion": criterion,
            "note": "Gmail search semantics: word-based tokens, not substrings"})
    };
    json!({
        "success": true, "schema_version": 1, "ir_schema": super::ir::SCHEMA,
        "levels": ["exact", "provider_defined", "client_only", "unsupported"],
        "limits": {"rules": super::ir::MAX_RULES, "conditions": super::ir::MAX_CONDITIONS,
            "values": super::ir::MAX_VALUES, "value_bytes": super::ir::MAX_VALUE_BYTES,
            "messages_per_batch": super::evaluate::MAX_MESSAGES,
            "body_text_bytes": super::evaluate::MAX_BODY_BYTES},
        "fields": {
            "from": address(
                json!({"level": "provider_defined", "predicates": ["fromAddresses", "senderContains"],
                    "operators": ["is", "contains"],
                    "note": "Exchange matching; is maps to fromAddresses, contains to senderContains"}),
                gmail_search("from")),
            "sender": address(json!({"level": "unsupported"}), json!({"level": "unsupported"})),
            "to": address(
                json!({"level": "provider_defined", "predicates": ["sentToAddresses"], "operators": ["is"]}),
                gmail_search("to")),
            "cc": address(json!({"level": "unsupported"}), gmail_search("to")),
            "to_or_cc": address(
                json!({"level": "provider_defined", "predicates": ["recipientContains"], "operators": ["contains"]}),
                gmail_search("to")),
            "subject": {"operators": text_ops(), "comparators": ["ascii_casemap", "octet", "unicode_fold"],
                "sieve": {"level": "exact", "test": "header"},
                "graph": {"level": "provider_defined", "predicates": ["subjectContains"], "operators": ["contains"]},
                "gmail": gmail_search("subject"), "local": {"level": "exact"}},
            "header": {"operators": ["is", "contains", "starts_with", "ends_with", "matches", "exists"],
                "comparators": ["ascii_casemap", "octet", "unicode_fold"], "requires": ["header"],
                "sieve": {"level": "exact", "test": "header"},
                "graph": {"level": "provider_defined", "predicates": ["headerContains"], "operators": ["contains"],
                    "note": "headerContains searches every header, not one named header"},
                "gmail": {"level": "unsupported"}, "local": {"level": "exact", "needs": "header fetch"}},
            "list_id": {"operators": ["is", "contains", "starts_with", "ends_with", "matches", "exists"],
                "comparators": ["ascii_casemap", "octet", "unicode_fold"],
                "sieve": {"level": "exact", "test": "header"},
                "graph": {"level": "unsupported"}, "gmail": gmail_search("query: list:"),
                "local": {"level": "exact", "needs": "List-Id header fetch"}},
            "size": {"operators": ["over", "under"], "unit": "bytes",
                "sieve": {"level": "exact", "test": "size"},
                "graph": {"level": "provider_defined", "predicates": ["withinSizeRange"], "note": "kilobytes"},
                "gmail": {"level": "provider_defined", "criterion": "size + sizeComparison"},
                "local": {"level": "exact", "needs": "RFC 5322 size"}},
            "has_attachment": {"operators": ["exists"],
                "sieve": {"level": "unsupported", "note": "needs the mime extension"},
                "graph": {"level": "provider_defined", "predicates": ["hasAttachments"]},
                "gmail": {"level": "provider_defined", "criterion": "hasAttachment"},
                "local": {"level": "exact", "needs": "MIME structure"}},
            "attachment_name": {"operators": text_ops(), "comparators": ["ascii_casemap", "octet", "unicode_fold"],
                "sieve": {"level": "unsupported"}, "graph": {"level": "unsupported"},
                "gmail": gmail_search("query: filename:"), "local": {"level": "exact", "needs": "MIME structure"}},
            "body_text": {"operators": text_ops(), "comparators": ["ascii_casemap", "octet", "unicode_fold"],
                "sieve": {"level": "provider_defined", "requires": ["body"], "note": "server-defined body transform"},
                "graph": {"level": "provider_defined", "predicates": ["bodyContains"], "operators": ["contains"]},
                "gmail": gmail_search("query"), "local": {"level": "exact", "needs": "decoded text body"}}
        },
        "actions": {
            "move": {"sieve": {"level": "exact", "requires": ["fileinto"]},
                "graph": {"level": "provider_defined", "action": "moveToFolder", "note": "folder id"},
                "gmail": {"level": "provider_defined", "action": "addLabelIds + removeLabelIds INBOX"},
                "local": {"level": "exact"}},
            "copy": {"sieve": {"level": "exact", "requires": ["fileinto", "copy"]},
                "graph": {"level": "provider_defined", "action": "copyToFolder"},
                "gmail": {"level": "provider_defined", "action": "addLabelIds"}, "local": {"level": "exact"}},
            "mark_read": {"sieve": {"level": "exact", "requires": ["imap4flags"]},
                "graph": {"level": "provider_defined", "action": "markAsRead"},
                "gmail": {"level": "provider_defined", "action": "removeLabelIds UNREAD"}, "local": {"level": "exact"}},
            "flag": {"sieve": {"level": "exact", "requires": ["imap4flags"]},
                "graph": {"level": "provider_defined", "action": "markImportance or flag"},
                "gmail": {"level": "provider_defined", "action": "addLabelIds STARRED"}, "local": {"level": "exact"}},
            "add_tag": {"sieve": {"level": "exact", "requires": ["imap4flags"], "note": "IMAP keyword"},
                "graph": {"level": "provider_defined", "action": "assignCategories"},
                "gmail": {"level": "provider_defined", "action": "addLabelIds", "note": "one user label per filter"},
                "local": {"level": "exact"}},
            "redirect": {"sieve": {"level": "exact", "requires_for_keep_copy": ["copy"]},
                "graph": {"level": "provider_defined", "action": "redirectTo / forwardTo"},
                "gmail": {"level": "provider_defined", "action": "forward", "note": "verified forwarding address only"},
                "local": {"level": "unsupported", "note": "automatic forwarding is not executed locally"}},
            "stop": {"sieve": {"level": "exact"}, "graph": {"level": "provider_defined", "action": "stopProcessingRules"},
                "gmail": {"level": "unsupported"}, "local": {"level": "exact"}},
            "notify": {"sieve": {"level": "client_only"}, "graph": {"level": "client_only"},
                "gmail": {"level": "client_only"}, "local": {"level": "exact"}},
            "sound": {"sieve": {"level": "client_only"}, "graph": {"level": "client_only"},
                "gmail": {"level": "client_only"}, "local": {"level": "exact"}}
        },
        "semantics": {
            "values": "a condition matches when any of its values matches",
            "match": "all/any over conditions; no conditions matches every message",
            "exceptions": "a matching exception prevents the rule",
            "flags": "mark_read/flag/add_tag run first and accumulate for later deliveries and the implicit keep (RFC 5232)",
            "move": "files the message and cancels the implicit keep; later rules still run unless stop",
            "copy": "files a copy and keeps the implicit keep (RFC 3894)",
            "deferred": "missing snapshot data never counts as false; precedence that depends on it defers the message",
            "ascii_casemap": "RFC 5228 default; only ASCII letters are case-folded",
            "matches": "* any sequence, ? one UTF-8 character, \\ escapes"
        }
    })
}
