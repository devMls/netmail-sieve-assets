//! NetMail patch `netmail-rules-1`: RFC 2047 encoded-word decoding.
//!
//! RFC 5228 §2.7.2 requires header values to be decoded before string
//! comparison. Encoded words (`=?charset?B|Q?text?=`) are decoded with the
//! WHATWG encodings of `encoding_rs`; an RFC 2231 language suffix
//! (`charset*lang`) is ignored. Linear whitespace between two adjacent
//! encoded words is removed (RFC 2047 §6.2). A malformed word, an unknown
//! charset or invalid bytes leave the original text unchanged, never a
//! partially decoded value.

/// Decode every well-formed RFC 2047 encoded word in an unfolded header
/// value. Text outside encoded words is returned unchanged.
pub fn decode_encoded_words(value: &str) -> String {
    if !value.contains("=?") {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    let mut pending_space: Option<&str> = None;
    let mut previous_was_word = false;
    while !rest.is_empty() {
        if let Some((decoded, consumed)) = rest.strip_prefix("=?").and_then(|_| word(rest)) {
            if !previous_was_word && let Some(space) = pending_space.take() {
                out.push_str(space);
            }
            pending_space = None;
            out.push_str(&decoded);
            rest = &rest[consumed..];
            previous_was_word = true;
            continue;
        }
        let space_len = rest.len() - rest.trim_start_matches([' ', '\t']).len();
        if space_len > 0 {
            if let Some(space) = pending_space.take() {
                out.push_str(space);
            }
            pending_space = Some(&rest[..space_len]);
            rest = &rest[space_len..];
            continue;
        }
        if let Some(space) = pending_space.take() {
            out.push_str(space);
        }
        let c = rest.chars().next().unwrap_or_default();
        out.push(c);
        rest = &rest[c.len_utf8()..];
        previous_was_word = false;
    }
    if let Some(space) = pending_space {
        out.push_str(space);
    }
    out
}

/// Decode one encoded word at the start of `input`; returns the decoded
/// text and the number of bytes consumed.
fn word(input: &str) -> Option<(String, usize)> {
    let body = input.strip_prefix("=?")?;
    let (charset, after_charset) = body.split_once('?')?;
    let (encoding, after_encoding) = after_charset.split_once('?')?;
    let end = after_encoding.find("?=")?;
    let text = &after_encoding[..end];
    if charset.is_empty()
        || text.contains([' ', '\t', '\r', '\n'])
        || charset.contains([' ', '\t'])
        || encoding.len() != 1
    {
        return None;
    }
    let bytes = match encoding.as_bytes()[0].to_ascii_uppercase() {
        b'B' => base64(text)?,
        b'Q' => quoted(text)?,
        _ => return None,
    };
    let label = charset.split('*').next().unwrap_or(charset);
    let decoded = decode_charset(label, &bytes)?;
    let consumed = 2 + charset.len() + 1 + encoding.len() + 1 + end + 2;
    Some((decoded, consumed))
}

fn decode_charset(label: &str, bytes: &[u8]) -> Option<String> {
    let encoding = encoding_rs::Encoding::for_label(label.trim().as_bytes())?;
    let (text, had_errors) = encoding.decode_without_bom_handling(bytes);
    (!had_errors).then(|| text.into_owned())
}

fn quoted(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'_' => out.push(b' '),
            b'=' => {
                let hex = bytes.get(i + 1..i + 3)?;
                out.push((hex_value(hex[0])? << 4) | hex_value(hex[1])?);
                i += 2;
            }
            b'?' => return None,
            other => out.push(other),
        }
        i += 1;
    }
    Some(out)
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn base64(text: &str) -> Option<Vec<u8>> {
    let trimmed = text.trim_end_matches('=');
    if trimmed.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for c in trimmed.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::decode_encoded_words as d;

    #[test]
    fn plain_text_is_unchanged() {
        assert_eq!(d("Factura 42"), "Factura 42");
        assert_eq!(d("=? not a word"), "=? not a word");
    }

    #[test]
    fn quoted_printable_utf8() {
        assert_eq!(d("=?UTF-8?Q?Factura_n=C2=BA_42?="), "Factura nº 42");
    }

    #[test]
    fn base64_utf8_and_latin1() {
        assert_eq!(d("=?utf-8?B?w5FhbmR1?="), "Ñandu");
        assert_eq!(d("=?ISO-8859-1?Q?Jos=E9?= <j@x.es>"), "José <j@x.es>");
        assert_eq!(d("=?windows-1252?B?QWNjafNu?="), "Acción");
    }

    #[test]
    fn whitespace_between_adjacent_words_is_removed() {
        assert_eq!(d("=?UTF-8?Q?Hola?= =?UTF-8?Q?_mundo?="), "Hola mundo");
        assert_eq!(d("Re: =?UTF-8?Q?a?= b"), "Re: a b");
    }

    #[test]
    fn rfc2231_language_suffix() {
        assert_eq!(d("=?UTF-8*es?Q?a=C3=B1o?="), "año");
    }

    #[test]
    fn malformed_words_are_preserved() {
        assert_eq!(d("=?UTF-8?X?abc?="), "=?UTF-8?X?abc?=");
        assert_eq!(d("=?nope-charset?Q?abc?="), "=?nope-charset?Q?abc?=");
        assert_eq!(d("=?UTF-8?Q?bad=ZZ?="), "=?UTF-8?Q?bad=ZZ?=");
        assert_eq!(d("=?UTF-8?B?/w==?="), "=?UTF-8?B?/w==?=");
    }
}
