//! Dependency-free structural JSON field extractor (replaces the naive
//! `"key":"...` prefix scanners): honors string escapes, whitespace, and key
//! order, so colons or quotes inside values keep routing keys intact.

/// Decodes one JSON string literal at `bytes[i]`; returns value + end index.
fn decode_string(bytes: &[u8], mut i: usize) -> Option<(String, usize)> {
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    let mut out = String::new();
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                i += 1;
                let esc = bytes.get(i)?;
                match esc {
                    b'u' => {
                        if i + 4 >= bytes.len() {
                            return None;
                        }
                        let hex = std::str::from_utf8(&bytes[i + 1..i + 5]).ok()?;
                        let cp = u32::from_str_radix(hex, 16).ok()?;
                        out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        i += 4;
                    }
                    b'"' | b'\\' | b'/' => out.push(*esc as char),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{C}'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    _ => return None,
                }
                i += 1;
            }
            _ => {
                let s = std::str::from_utf8(&bytes[i..]).ok()?;
                let ch = s.chars().next()?;
                out.push(ch);
                i += ch.len_utf8();
            }
        }
    }
    None
}

/// Index just past the string at `i` (`None` if unterminated).
fn skip_string(bytes: &[u8], i: usize) -> Option<usize> {
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    let mut esc = false;
    for (k, &b) in bytes.iter().enumerate().skip(i + 1) {
        if esc {
            esc = false;
        } else if b == b'\\' {
            esc = true;
        } else if b == b'"' {
            return Some(k + 1);
        }
    }
    None
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while matches!(bytes.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// End index of the JSON value at `i`, respecting nesting and strings.
fn skip_value(bytes: &[u8], mut j: usize) -> Option<usize> {
    let mut depth = 0usize;
    while j < bytes.len() {
        match bytes[j] {
            b'"' => j = skip_string(bytes, j)?,
            b'{' | b'[' => {
                depth += 1;
                j += 1;
            }
            b'}' | b']' if depth == 0 => return Some(j),
            b',' if depth == 0 => return Some(j),
            b'}' | b']' => {
                depth -= 1;
                j += 1;
            }
            _ => j += 1,
        }
    }
    None
}

/// Byte range of the raw JSON value for top-level `key`, if present.
fn find_value_span(raw: &str, key: &str) -> Option<(usize, usize)> {
    let bytes = raw.as_bytes();
    let mut i = skip_ws(bytes, 0);
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    loop {
        i = skip_ws(bytes, i);
        if bytes.get(i) == Some(&b'}') {
            return None;
        }
        let (name, next) = decode_string(bytes, i)?;
        i = skip_ws(bytes, next);
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        i = skip_ws(bytes, i + 1);
        let val_start = i;
        let val_end = skip_value(bytes, i)?;
        if name == key {
            return Some((val_start, val_end));
        }
        i = val_end + usize::from(bytes[val_end] == b',');
    }
}

/// Decoded string value for top-level `key` (`None` if missing/non-string).
#[must_use]
pub fn json_string(raw: &str, key: &str) -> Option<String> {
    let (s, _) = find_value_span(raw, key)?;
    let bytes = raw.as_bytes();
    let i = skip_ws(bytes, s);
    if bytes.get(i) != Some(&b'"') {
        return None;
    }
    let (val, _) = decode_string(bytes, i)?;
    Some(val)
}

fn parse_raw_number(raw: &str, key: &str) -> Option<String> {
    let (s, e) = find_value_span(raw, key)?;
    let chunk = raw[s..e].trim();
    if chunk.is_empty()
        || !chunk
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'+')
    {
        return None;
    }
    if chunk.trim_matches(['-', '+']).is_empty() {
        return None;
    }
    Some(chunk.to_string())
}

/// Extracts an integer value for top-level `key`, tolerating whitespace.
#[must_use]
pub fn json_usize(raw: &str, key: &str) -> Option<usize> {
    parse_raw_number(raw, key)?.parse::<usize>().ok()
}

/// Extracts a `u64` value for top-level `key`, tolerating whitespace.
#[must_use]
pub fn json_u64(raw: &str, key: &str) -> Option<u64> {
    parse_raw_number(raw, key)?.parse::<u64>().ok()
}

/// Extracts a string array for top-level `key`, decoding escapes element-wise.
#[must_use]
pub fn json_string_array(raw: &str, key: &str) -> Vec<String> {
    let Some((s, _)) = find_value_span(raw, key) else {
        return Vec::new();
    };
    let bytes = raw.as_bytes();
    let mut i = skip_ws(bytes, s);
    if bytes.get(i) != Some(&b'[') {
        return Vec::new();
    }
    i += 1;
    let mut out = Vec::new();
    loop {
        i = skip_ws(bytes, i);
        match bytes.get(i) {
            None => return Vec::new(),
            Some(b']') => return out,
            Some(b',') => {
                i += 1;
                continue;
            }
            Some(b'"') => {
                let Some((val, next)) = decode_string(bytes, i) else {
                    return Vec::new();
                };
                out.push(val);
                i = next;
            }
            _ => return Vec::new(),
        }
        i = skip_ws(bytes, i);
        match bytes.get(i) {
            Some(b',') => i += 1,
            Some(b']') => return out,
            _ => return Vec::new(),
        }
    }
}

/// Top-level objects of the array `key`; string-aware (`}` in strings safe).
#[must_use]
pub fn json_objects(raw: &str, key: &str) -> Vec<String> {
    let Some((s, _)) = find_value_span(raw, key) else {
        return Vec::new();
    };
    let bytes = raw.as_bytes();
    let mut i = skip_ws(bytes, s);
    if bytes.get(i) != Some(&b'[') {
        return Vec::new();
    }
    i += 1;
    let mut out = Vec::new();
    loop {
        i = skip_ws(bytes, i);
        match bytes.get(i) {
            None => return Vec::new(),
            Some(b']') => return out,
            Some(b',') => {
                i += 1;
            }
            Some(b'{') => {
                let start = i;
                let mut depth = 0usize;
                let mut j = i;
                let mut closed = None;
                while j < bytes.len() {
                    match bytes[j] {
                        b'"' => j = skip_string(bytes, j).unwrap_or(bytes.len()),
                        b'{' => {
                            depth += 1;
                            j += 1;
                        }
                        b'}' => {
                            depth -= 1;
                            j += 1;
                            if depth == 0 {
                                closed = Some(j - 1);
                                break;
                            }
                        }
                        _ => j += 1,
                    }
                }
                let Some(end) = closed else {
                    return Vec::new();
                };
                out.push(raw[start..=end].to_string());
                i = end + 1;
            }
            _ => return Vec::new(),
        }
    }
}

/// Whether array `key` exists and holds at least one element (any type).
#[must_use]
pub fn json_array_nonempty(raw: &str, key: &str) -> bool {
    let Some((s, _)) = find_value_span(raw, key) else {
        return false;
    };
    let bytes = raw.as_bytes();
    let mut i = skip_ws(bytes, s);
    if bytes.get(i) != Some(&b'[') {
        return false;
    }
    i += 1;
    // Any non-`]` first element byte proves non-empty; strings (which may
    // contain `]`) are skipped structurally via `skip_string`.
    let mut j = skip_ws(bytes, i);
    if bytes.get(j) == Some(&b']') {
        return false;
    }
    while j < bytes.len() {
        match bytes[j] {
            b'"' => return skip_string(bytes, j).is_some(),
            b if b.is_ascii_whitespace() => j += 1,
            b']' => return false,
            _ => return true,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{json_array_nonempty, json_objects, json_string};

    #[test]
    fn core_extractors_are_structural() {
        assert_eq!(json_string(r#"{"v":"a\"b"}"#, "v").as_deref(), Some("a\"b"));
        assert_eq!(json_objects(r#"{"a":[{"k":"a}b"}]}"#, "a").len(), 1);
        assert!(json_array_nonempty(r#"{ "vm" : [ "a]b" ] }"#, "vm"));
        assert!(!json_array_nonempty(r#"{"vm":[]}"#, "vm"));
    }
}
