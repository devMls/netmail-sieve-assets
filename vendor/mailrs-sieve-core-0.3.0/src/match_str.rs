//! RFC 5228 §2.7 string comparison + §2.7.1 wildcard `:matches`
//! engine. Extracted from `eval.rs` so the evaluator stays under
//! the file-size limit.
//!
//! All comparisons use the RFC 5228 default `i;ascii-casemap`
//! comparator — ASCII case-insensitive. The earlier implementation
//! allocated two `String`s per call (lowercasing both sides); the
//! v4 ckpt 25 rewrite keeps everything zero-alloc by going through
//! case-insensitive byte ops (`slice::eq_ignore_ascii_case`) plus
//! memchr2-anchored substring search.

#[cfg(test)]
use crate::ast::MatchType;

/// Match-type comparison with the RFC 5228 default `i;ascii-casemap`
/// comparator. NetMail patch: `:matches` delegates to
/// [`crate::compare::match_value`] (UTF-8 `?`, `\` escapes).
#[cfg(test)]
pub(crate) fn match_string(mt: MatchType, haystack: &str, needle: &str) -> bool {
    crate::compare::match_value(mt, crate::compare::Comparator::AsciiCasemap, haystack, needle)
}

/// Case-insensitive substring search. Uses `memchr2` on the
/// lowercase + uppercase variant of the needle's first byte to
/// jump from candidate to candidate without re-scanning every
/// position.
pub(crate) fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    find_first_ci(haystack, needle).is_some()
}

/// Test helper kept for the reference unit tests below.
#[cfg(test)]
fn glob_match(haystack: &str, pattern: &str) -> bool {
    match_string(MatchType::Matches, haystack, pattern)
}

/// Case-insensitive byte search for `needle` (no `?` wildcard) in
/// `haystack`.
fn find_first_ci(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    let first_lo = needle[0].to_ascii_lowercase();
    let first_up = needle[0].to_ascii_uppercase();
    let mut start = 0;
    while start + needle.len() <= haystack.len() {
        let rel = memchr::memchr2(first_lo, first_up, &haystack[start..])?;
        let pos = start + rel;
        if pos + needle.len() > haystack.len() {
            return None;
        }
        if haystack[pos..pos + needle.len()].eq_ignore_ascii_case(needle) {
            return Some(pos);
        }
        start = pos + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_case_insensitive() {
        assert!(match_string(MatchType::Is, "Hello", "HELLO"));
        assert!(!match_string(MatchType::Is, "Hello", "World"));
    }

    #[test]
    fn contains_substring() {
        assert!(match_string(
            MatchType::Contains,
            "spam offer here",
            "OFFER"
        ));
        assert!(!match_string(
            MatchType::Contains,
            "spam offer",
            "newsletter"
        ));
    }

    #[test]
    fn contains_empty_needle() {
        assert!(match_string(MatchType::Contains, "anything", ""));
    }

    #[test]
    fn glob_star_anywhere() {
        assert!(glob_match("hello world", "hello*"));
        assert!(glob_match("hello world", "*world"));
        assert!(glob_match("hello world", "*lo wor*"));
        assert!(!glob_match("hello", "world*"));
    }

    #[test]
    fn glob_question_one_char() {
        assert!(glob_match("cat", "c?t"));
        assert!(!glob_match("cat", "c??t"));
        assert!(glob_match("cat", "ca?"));
        assert!(!glob_match("ca", "ca?"));
    }

    #[test]
    fn glob_star_empty_sequence() {
        assert!(glob_match("abc", "*abc"));
        assert!(glob_match("abc", "abc*"));
        assert!(glob_match("", "*"));
        assert!(glob_match("anything", "*"));
    }

    #[test]
    fn glob_case_insensitive() {
        assert!(glob_match("Hello World", "*WORLD"));
        assert!(glob_match("foo.bar@example.com", "*@EXAMPLE.com"));
    }

    #[test]
    fn glob_multi_star() {
        assert!(glob_match("hello kind world", "hello*kind*world"));
        assert!(!glob_match("hello world", "hello*kind*world"));
        assert!(glob_match("aXbYc", "a*b*c"));
        // Collapsed `**` is identical to `*`.
        assert!(glob_match("abcdef", "a**f"));
    }

    #[test]
    fn glob_question_inside_star_chunk() {
        assert!(glob_match("abcXdef", "*c?d*"));
        assert!(!glob_match("abcdef", "*c?d?g"));
    }

    #[test]
    fn glob_anchored_both_sides_with_mid_star() {
        assert!(glob_match("foobar", "foo*bar"));
        assert!(!glob_match("foobar", "baz*bar"));
    }
}
