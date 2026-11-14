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

/// Compares two byte slices in constant time with respect to their contents.
///
/// Returns `false` if lengths differ; otherwise XOR-accumulates every byte
/// without short-circuiting so comparison time does not leak prefix matches.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Validates `Authorization: Bearer <token>` header against a configured operator token
/// using constant-time byte comparison.
///
/// Fails closed (`false`) if `expected_token` is `None` or empty.
#[must_use]
pub fn verify_bearer_token(headers: &str, expected_token: Option<&str>) -> bool {
    let Some(expected) = expected_token.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    for line in headers.lines() {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("authorization") {
                let v = val.trim();
                if let Some(tok) = v
                    .strip_prefix("Bearer ")
                    .or_else(|| v.strip_prefix("bearer "))
                {
                    if constant_time_eq(tok.trim().as_bytes(), expected.as_bytes()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Authorizes a protected write request against the configured Bearer token and dev opt-in policy.
///
/// Fails closed (`false`) when `expected_token` is `None` or empty unless
/// `allow_unauthenticated_dev` is explicitly `true`. When a token is configured,
/// Bearer verification is always enforced regardless of `allow_unauthenticated_dev`.
#[must_use]
pub fn authorize_write_request(
    headers: &str,
    expected_token: Option<&str>,
    allow_unauthenticated_dev: bool,
) -> bool {
    let has_token = expected_token.map(str::trim).is_some_and(|s| !s.is_empty());
    if !has_token {
        return allow_unauthenticated_dev;
    }
    verify_bearer_token(headers, expected_token)
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
            || path == "/v1/relay/signals"
            || path == "/v1/push/register"
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

#[cfg(test)]
mod tests {
    use super::{authorize_write_request, constant_time_eq, verify_bearer_token};

    #[test]
    fn constant_time_eq_checks_length_and_all_bytes() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
        assert!(!constant_time_eq(b"secret-token", b"secret-tokeN"));
        assert!(!constant_time_eq(b"secret", b"secret-token"));
        assert!(!constant_time_eq(b"secret-token", b"secret"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn verify_bearer_token_fails_closed_when_unset_or_empty() {
        assert!(!verify_bearer_token("Authorization: Bearer abc\r\n", None));
        assert!(!verify_bearer_token(
            "Authorization: Bearer abc\r\n",
            Some("")
        ));
        assert!(!verify_bearer_token(
            "Authorization: Bearer abc\r\n",
            Some("   ")
        ));
        assert!(verify_bearer_token(
            "Authorization: Bearer abc\r\n",
            Some("abc")
        ));
        assert!(!verify_bearer_token(
            "Authorization: Bearer abd\r\n",
            Some("abc")
        ));
    }

    #[test]
    fn authorize_write_request_requires_dev_opt_in_when_token_unset() {
        assert!(!authorize_write_request("", None, false));
        assert!(authorize_write_request("", None, true));
        assert!(!authorize_write_request("", Some("tok"), true));
        assert!(authorize_write_request(
            "Authorization: Bearer tok\r\n",
            Some("tok"),
            true
        ));
    }
}
