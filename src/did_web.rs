//! `did:web` document resolution over the network with TTL caching.
//!
//! `did:web:<domain>[:path...]` identities are verified by fetching
//! `https://<domain>/.well-known/did.json` over TLS (WebPKI roots) and
//! requiring the document's `"id"` to equal the DID exactly, plus a
//! non-empty `"verificationMethod"` array. Verified results are cached with a
//! TTL; DIDs whose documents cannot be fetched, parsed, or matched are never
//! reported as `verified_b2b`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// TTL for positive `did:web` verification cache entries (10 minutes).
pub const DID_WEB_CACHE_TTL_SECS: u64 = 600;

/// Cache entry for a resolved `did:web` document check.
#[derive(Debug, Clone)]
struct DidWebCacheEntry {
    verified: bool,
    cached_at_secs: u64,
}

fn cache() -> &'static Mutex<HashMap<String, DidWebCacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<String, DidWebCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Clears the `did:web` verification cache (intended for tests).
pub fn clear_did_web_cache() {
    if let Ok(mut guard) = cache().lock() {
        guard.clear();
    }
}

/// Converts `did:web:<host>[:path...]` into its `/.well-known/did.json` HTTPS URL.
///
/// Returns `None` when the DID is not a well-formed `did:web:` identifier.
#[must_use]
pub fn did_web_document_url(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:web:")?;
    if rest.is_empty() || rest.contains("..") || rest.contains(' ') {
        return None;
    }
    let mut parts = rest.split(':');
    let host = parts.next().filter(|h| !h.is_empty())?;
    if host.contains('/') || host.contains('@') || host.contains('%') {
        return None;
    }
    let mut url = format!("https://{host}");
    let path_parts: Vec<&str> = parts.collect();
    if !path_parts.is_empty() {
        if path_parts.iter().any(|p| p.is_empty()) {
            return None;
        }
        for part in &path_parts {
            if part.contains('/') || part.contains('@') || part.contains('%') {
                return None;
            }
            url.push('/');
            url.push_str(part);
        }
    }
    url.push_str("/.well-known/did.json");
    Some(url)
}

/// Fetches `url` over HTTPS with WebPKI roots, returning the response body.
///
/// Plain HTTP is never used: `did:web` resolution without TLS is a
/// downgrade vector, so `http://` URLs are rejected.
fn fetch_did_document_https(url: &str) -> Result<String, String> {
    crate::federation_client::execute_http_request("GET", url, "", None, 5000).and_then(
        |(status, body)| {
            if status == 200 {
                Ok(body)
            } else {
                Err(format!("did:web fetch failed with status {status}"))
            }
        },
    )
}

/// Checks whether `doc_json` is a valid `did:web` document for `did`.
///
/// Requires the document `"id"` to equal `did` exactly and a non-empty
/// `"verificationMethod"` array. Matching is case-sensitive.
#[must_use]
pub fn document_matches_did(did: &str, doc_json: &str) -> bool {
    if !did.starts_with("did:web:") {
        return false;
    }
    let normalized = doc_json.replace("\\\"", "\"");
    let Some(doc_id) = crate::storage::extract_json_str(&normalized, "id") else {
        return false;
    };
    if doc_id != did {
        return false;
    }
    let Some(vm_pos) = normalized.find("\"verificationMethod\"") else {
        return false;
    };
    let rest = &normalized[vm_pos..];
    let Some(open_bracket) = rest.find('[') else {
        return false;
    };
    let after_open = &rest[open_bracket + 1..];
    let Some(close_bracket) = after_open.find(']') else {
        return false;
    };
    !after_open[..close_bracket].trim().is_empty()
}

/// Resolves `did` over the network and reports whether it verifies.
///
/// Non-`did:web:` DIDs return `false` without network access. Results are
/// cached for [`DID_WEB_CACHE_TTL_SECS`]; only successful verifications with
/// a matching document are cached as verified, and any fetch/parse failure
/// yields `false`.
#[must_use]
pub fn verify_did_web_resolved(did: &str) -> bool {
    verify_did_web_resolved_with_fetch(did, fetch_did_document_https)
}

/// Test seam: resolves `did` using `fetch` instead of the network.
pub fn verify_did_web_resolved_with_fetch(
    did: &str,
    fetch: impl Fn(&str) -> Result<String, String>,
) -> bool {
    if !did.starts_with("did:web:") {
        return false;
    }
    let now = now_secs();
    if let Ok(guard) = cache().lock() {
        if let Some(entry) = guard.get(did) {
            if now.saturating_sub(entry.cached_at_secs) < DID_WEB_CACHE_TTL_SECS {
                return entry.verified;
            }
        }
    }
    let Some(url) = did_web_document_url(did) else {
        return false;
    };
    let verified = fetch(&url)
        .map(|doc| document_matches_did(did, &doc))
        .unwrap_or(false);
    if verified {
        if let Ok(mut guard) = cache().lock() {
            guard.insert(
                did.to_string(),
                DidWebCacheEntry {
                    verified: true,
                    cached_at_secs: now,
                },
            );
        }
    }
    // Negative results are intentionally not cached: a transient outage must
    // never pin a DID as unverified, and re-resolution is cheap.
    verified
}

/// Returns `true` when the cache currently holds a fresh verified entry for `did`.
#[cfg(test)]
pub fn is_cached_verified(did: &str) -> bool {
    cache().lock().is_ok_and(|guard| {
        guard.get(did).is_some_and(|e| {
            e.verified && now_secs().saturating_sub(e.cached_at_secs) < DID_WEB_CACHE_TTL_SECS
        })
    })
}

/// Fetches `url` with a deadline; shared helper for tests that need a live fetch.
#[allow(dead_code)]
pub fn fetch_with_deadline(url: &str, timeout: Duration) -> Result<String, String> {
    let ms = timeout.as_millis().min(u128::from(u64::MAX)) as u64;
    crate::federation_client::execute_http_request("GET", url, "", None, ms.max(50)).and_then(
        |(status, body)| {
            if status == 200 {
                Ok(body)
            } else {
                Err(format!("fetch failed with status {status}"))
            }
        },
    )
}
