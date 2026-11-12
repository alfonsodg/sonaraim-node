//! HTTP request parsing, URL percent-decoding, Bearer token verification, and response helpers.

/// Formats a standardized JSON error payload.
#[must_use]
pub fn err_json(code: &str, message: &str) -> String {
    format!("{{\"error\":{{\"code\":\"{code}\",\"message\":\"{message}\"}}}}")
}

/// Decodes percent-encoded ASCII sequences (`%XX`, e.g. `%3A` -> `:`) in a URL path.
#[must_use]
pub fn percent_decode_path(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Validates `Authorization: Bearer <token>` header when an operator token is configured.
///
/// If `expected_token` is `None` or empty, returns `true`.
#[must_use]
pub fn verify_bearer_token(headers: &str, expected_token: Option<&str>) -> bool {
    let Some(expected) = expected_token.map(str::trim).filter(|s| !s.is_empty()) else {
        return true;
    };
    for line in headers.lines() {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                let v = val.trim();
                if let Some(tok) = v
                    .strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
                {
                    if tok.trim() == expected {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Parses an incoming raw HTTP/1.1 request buffer into `(method, decoded_path, headers, body)`.
#[must_use]
pub fn parse_http_request(raw: &str) -> (String, String, String, String) {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let raw_path = first.next().unwrap_or("");
    let path = percent_decode_path(raw_path);
    (method, path, head.to_string(), body.to_string())
}

/// Returns `true` if the HTTP `(method, path)` is a write route protected by `NODE_API_AUTH_TOKEN`.
#[must_use]
pub fn is_protected_write_route(method: &str, path: &str) -> bool {
    method == "POST"
        && (path == "/v1/identity"
            || path == "/v1/relay/envelopes"
            || path == "/v1/p2p/gossip"
            || path == "/v1/p2p/peers"
            || (path.starts_with("/v1/relay/mailboxes/") && path.ends_with("/ack")))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
