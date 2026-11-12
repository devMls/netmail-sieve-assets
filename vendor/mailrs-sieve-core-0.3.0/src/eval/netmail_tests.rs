//! Regressions for NetMail patch `netmail-rules-1`.

use super::*;

const MSG: &[u8] = b"From: =?UTF-8?Q?P=C3=A9rez=2C_Juan?= <juan@example.com>\r\n\
To: ana@dest.es\r\n\
Subject: =?UTF-8?Q?Factura_n=C2=BA_42?=\r\n\
X-Code: ABC\r\n\
\r\n\
body\r\n";

fn run(script: &str) -> Result<Vec<Action>, EvalError> {
    eval_script(script, MSG)
}

fn into(mailbox: &str) -> Action {
    Action::FileInto {
        mailbox: mailbox.into(),
        flags: vec![],
    }
}

#[test]
fn octet_comparator_is_case_sensitive_and_keeps_header_names() {
    let script = r#"require "fileinto";
        if header :comparator "i;octet" :is "X-Code" "abc" { fileinto "Lower"; }
        if header :comparator "i;octet" :is "X-Code" "ABC" { fileinto "Upper"; }"#;
    assert_eq!(run(script).unwrap(), vec![into("Upper")]);
}

#[test]
fn unsupported_comparator_is_an_error() {
    let err = run(r#"if header :comparator "i;ascii-numeric" :is "X-Code" "1" { discard; }"#)
        .unwrap_err();
    assert!(matches!(err, EvalError::UnsupportedComparator(ref c) if c == "i;ascii-numeric"));
}

#[test]
fn unknown_match_tags_are_errors_not_is() {
    for script in [
        r#"if header :regex "Subject" "x" { discard; }"#,
        r#"if header :count "ge" "Subject" "1" { discard; }"#,
        r#"if size :over :under 1 { discard; }"#,
        r#"if exists :is "Subject" { discard; }"#,
    ] {
        assert!(run(script).is_err(), "{script}");
    }
}

#[test]
fn header_values_are_rfc2047_decoded() {
    let script =
        r#"require "fileinto"; if header :contains "Subject" "Factura nº" { fileinto "F"; }"#;
    assert_eq!(run(script).unwrap(), vec![into("F")]);
}

#[test]
fn address_test_ignores_encoded_display_name_separators() {
    let script =
        r#"require "fileinto"; if address :is "from" "juan@example.com" { fileinto "J"; }"#;
    assert_eq!(run(script).unwrap(), vec![into("J")]);
}

#[test]
fn matches_escapes_and_utf8_question_mark() {
    let script = r#"require "fileinto";
        if header :matches "Subject" "Factura n? 42" { fileinto "Q"; }
        if header :matches "Subject" "Factura\\*" { fileinto "Star"; }"#;
    assert_eq!(run(script).unwrap(), vec![into("Q")]);
}

#[test]
fn copy_keeps_the_implicit_keep() {
    let script = r#"require ["fileinto", "copy"]; fileinto :copy "Archive";"#;
    assert_eq!(
        run(script).unwrap(),
        vec![into("Archive"), Action::Keep { flags: vec![] }]
    );
    let script = r#"require ["copy"]; redirect :copy "x@example.com";"#;
    assert_eq!(
        run(script).unwrap(),
        vec![
            Action::Redirect("x@example.com".into()),
            Action::Keep { flags: vec![] }
        ]
    );
}

#[test]
fn copy_requires_capability_and_unknown_command_tags_fail() {
    assert!(run(r#"require "fileinto"; fileinto :copy "A";"#).is_err());
    assert!(run(r#"require "fileinto"; fileinto :create "A";"#).is_err());
    assert!(run(r#"require "fileinto"; fileinto :flags "\\Seen" :flags "x" "A";"#).is_err());
}

#[test]
fn flags_accumulate_across_rules_and_tagged_flags_override() {
    let script = r#"require ["fileinto", "imap4flags"];
        if true { addflag "\\Seen"; }
        if true { fileinto "A"; fileinto :flags "\\Flagged" "B"; }"#;
    assert_eq!(
        run(script).unwrap(),
        vec![
            Action::FileInto {
                mailbox: "A".into(),
                flags: vec!["\\Seen".into()]
            },
            Action::FileInto {
                mailbox: "B".into(),
                flags: vec!["\\Flagged".into()]
            },
        ]
    );
}
