//! NetMail patch `netmail-rules-1`: RFC 4790 comparators and the RFC 5228
//! §2.7.1 `:matches` engine shared by the evaluator and by callers that
//! must reproduce Sieve string semantics outside a script.
//!
//! `i;ascii-casemap` (the RFC 5228 default) folds only ASCII letters;
//! `i;octet` compares exactly. In `:matches`, `*` matches any sequence,
//! `?` matches exactly one UTF-8 character and `\` escapes the next
//! character so that `\*`, `\?` and `\\` are literals.

use crate::ast::MatchType;

/// A comparator this implementation evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Comparator {
    /// `i;ascii-casemap` — ASCII case-insensitive (RFC 4790 §9.2).
    #[default]
    AsciiCasemap,
    /// `i;octet` — exact comparison (RFC 4790 §9.3).
    Octet,
}

impl Comparator {
    /// Resolve a `:comparator` name. Unknown names return `None` so the
    /// caller can reject the script instead of using another comparator.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "i;ascii-casemap" => Some(Self::AsciiCasemap),
            "i;octet" => Some(Self::Octet),
            _ => None,
        }
    }

    /// The registered comparator name.
    pub fn name(self) -> &'static str {
        match self {
            Self::AsciiCasemap => "i;ascii-casemap",
            Self::Octet => "i;octet",
        }
    }

    fn char_eq(self, a: char, b: char) -> bool {
        match self {
            Self::AsciiCasemap => a.eq_ignore_ascii_case(&b),
            Self::Octet => a == b,
        }
    }
}

/// Compare `haystack` against one key with the given match type and
/// comparator, exactly as the `header`/`address`/`envelope` tests do.
pub fn match_value(mt: MatchType, comparator: Comparator, haystack: &str, needle: &str) -> bool {
    match (mt, comparator) {
        (MatchType::Is, Comparator::AsciiCasemap) => haystack.eq_ignore_ascii_case(needle),
        (MatchType::Is, Comparator::Octet) => haystack == needle,
        (MatchType::Contains, Comparator::AsciiCasemap) => {
            crate::match_str::contains_ci(haystack.as_bytes(), needle.as_bytes())
        }
        (MatchType::Contains, Comparator::Octet) => haystack.contains(needle),
        (MatchType::Matches, c) => glob(haystack, needle, c),
    }
}

/// Escape a literal so that it matches only itself inside a `:matches`
/// pattern (before Sieve string quoting).
pub fn escape_glob(literal: &str) -> String {
    let mut out = String::with_capacity(literal.len());
    for c in literal.chars() {
        if matches!(c, '*' | '?' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[derive(Clone, Copy)]
enum Pattern {
    Literal(char),
    One,
    Any,
}

fn compile(pattern: &str) -> Vec<Pattern> {
    let mut out = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        out.push(match c {
            '*' => Pattern::Any,
            '?' => Pattern::One,
            // A trailing backslash has nothing to escape and is a literal.
            '\\' => Pattern::Literal(chars.next().unwrap_or('\\')),
            other => Pattern::Literal(other),
        });
    }
    out
}

/// Iterative wildcard matcher with single-star backtracking: linear
/// memory and O(n·m) worst case, bounded by the script/message limits.
fn glob(haystack: &str, pattern: &str, comparator: Comparator) -> bool {
    let text: Vec<char> = haystack.chars().collect();
    let pattern = compile(pattern);
    let (mut t, mut p) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(Pattern::Any) => {
                star = Some((p, t));
                p += 1;
                continue;
            }
            Some(Pattern::One) => {
                t += 1;
                p += 1;
                continue;
            }
            Some(Pattern::Literal(c)) if comparator.char_eq(*c, text[t]) => {
                t += 1;
                p += 1;
                continue;
            }
            _ => {}
        }
        match star {
            Some((star_p, star_t)) => {
                p = star_p + 1;
                t = star_t + 1;
                star = Some((star_p, star_t + 1));
            }
            None => return false,
        }
    }
    pattern[p..].iter().all(|x| matches!(x, Pattern::Any))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(h: &str, p: &str) -> bool {
        match_value(MatchType::Matches, Comparator::AsciiCasemap, h, p)
    }

    #[test]
    fn question_mark_is_one_utf8_character() {
        assert!(m("año", "a?o"));
        assert!(!m("año", "a??o"));
        assert!(m("🚀x", "?x"));
    }

    #[test]
    fn escapes_are_literals() {
        assert!(m("*urgente*", "\\*urgente\\*"));
        assert!(!m("xurgentex", "\\*urgente\\*"));
        assert!(m("a?b", "a\\?b"));
        assert!(!m("axb", "a\\?b"));
        assert!(m("c:\\temp", "c:\\\\*"));
    }

    #[test]
    fn escape_glob_round_trips() {
        for literal in ["a*b", "x?y", "back\\slash", "plain", "ñ*?"] {
            assert!(m(literal, &escape_glob(literal)));
            assert!(m(
                &format!("{literal}tail"),
                &format!("{}*", escape_glob(literal))
            ));
        }
    }

    #[test]
    fn backtracking_stars() {
        assert!(m("abcabcabd", "*abd"));
        assert!(m("hello kind world", "hello*kind*world"));
        assert!(!m("hello world", "hello*kind*world"));
        assert!(m("", "*"));
        assert!(!m("", "?"));
    }

    #[test]
    fn octet_is_case_sensitive() {
        assert!(!match_value(MatchType::Is, Comparator::Octet, "ABC", "abc"));
        assert!(!match_value(
            MatchType::Contains,
            Comparator::Octet,
            "xABCx",
            "abc"
        ));
        assert!(!match_value(
            MatchType::Matches,
            Comparator::Octet,
            "ABC",
            "a*"
        ));
        assert!(match_value(
            MatchType::Matches,
            Comparator::Octet,
            "ABC",
            "A*"
        ));
    }

    #[test]
    fn ascii_casemap_does_not_fold_non_ascii() {
        assert!(match_value(
            MatchType::Is,
            Comparator::AsciiCasemap,
            "FACTURA",
            "factura"
        ));
        assert!(!match_value(
            MatchType::Is,
            Comparator::AsciiCasemap,
            "ÁREA",
            "área"
        ));
    }

    #[test]
    fn comparator_names() {
        assert_eq!(Comparator::from_name("I;OCTET"), Some(Comparator::Octet));
        assert_eq!(Comparator::from_name("i;ascii-numeric"), None);
    }
}
