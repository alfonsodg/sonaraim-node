//! Private Set Intersection (PSI) blind evaluation service and L2 Merkle anchor receipts.
//!
//! PSI tokens are derived with HMAC-SHA256 keyed by the node's configured
//! server secret (`NODE_PSI_SERVER_SECRET`, falling back to `NODE_ID` in dev).
//! Phone tokens are stored only as HMAC digests — never in plaintext.

use crate::crypto::{hmac_sha256_hex, sha256_hex};
use crate::storage::{extract_json_str, extract_json_str_array, extract_json_u64};

use std::collections::HashMap;

/// Receipt recording an optional periodic L2 anchor of the Key Transparency Merkle root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2AnchorReceipt {
    /// Merkle log size at anchor time.
    pub tree_size: usize,
    /// Hexadecimal Merkle root hash anchored on-chain.
    pub root_hash: String,
    /// Unix timestamp in seconds when the receipt was generated.
    pub anchored_at_epoch_secs: u64,
}

impl L2AnchorReceipt {
    /// Serializes the anchor receipt to JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        format!(
            "{{\"tree_size\":{},\"root_hash\":\"{}\",\"anchored_at_epoch_secs\":{}}}",
            self.tree_size, self.root_hash, self.anchored_at_epoch_secs
        )
    }
}

/// Evaluates a single blinded token with HMAC-SHA256 under `server_secret`.
#[must_use]
pub fn evaluate_psi_single(token: &str, server_secret: &[u8]) -> String {
    hmac_sha256_hex(server_secret, token.as_bytes())
}

/// Evaluates a batch of client-blinded contact tokens against a node secret key.
#[must_use]
pub fn evaluate_psi_batch(blinded_tokens: &[String], server_secret: &[u8]) -> Vec<String> {
    blinded_tokens
        .iter()
        .map(|tok| evaluate_psi_single(tok, server_secret))
        .collect()
}

/// Builds an [`L2AnchorReceipt`] for the latest Merkle tree head.
#[must_use]
pub fn build_l2_anchor_receipt(
    tree_size: usize,
    root_hash: &str,
    anchored_at_epoch_secs: u64,
) -> L2AnchorReceipt {
    L2AnchorReceipt {
        tree_size,
        root_hash: root_hash.to_string(),
        anchored_at_epoch_secs,
    }
}

/// Parameters for `POST /v1/media/presign`, resolved from config/env by the caller.
#[derive(Debug, Clone)]
pub struct PresignParams<'a> {
    /// S3/MinIO endpoint base URL (e.g. `https://s3.example.com`).
    pub endpoint_url: &'a str,
    /// S3 bucket for client-side encrypted media attachments.
    pub bucket: &'a str,
    /// SHA-256 of the ciphertext; becomes the S3 object key.
    pub sha256_ciphertext: &'a str,
    /// Declared upload size in bytes.
    pub content_length: u64,
    /// AWS region for the SigV4 signing scope.
    pub region: &'a str,
    /// S3 access key ID, when configured.
    pub access_key_id: Option<&'a str>,
    /// S3 secret access key, when configured.
    pub secret_access_key: Option<&'a str>,
    /// Unix epoch seconds used as the SigV4 request timestamp.
    pub request_epoch_secs: u64,
    /// Presigned URL lifetime in seconds (1..=604800).
    pub expires_secs: u64,
}

/// Handles `POST /v1/media/presign` JSON body and returns `(status, reason, json)`.
///
/// With S3 credentials configured, returns a real AWS Signature Version 4
/// presigned PUT URL. Without credentials it fails honestly with
/// `MISSING_S3_CREDENTIALS` instead of forging a signature.
#[must_use]
pub fn handle_presign_json(body: &str, params: &PresignParams<'_>) -> (u16, &'static str, String) {
    let Some(hash) = extract_json_str(body, "sha256_ciphertext") else {
        return (
            400,
            "Bad Request",
            "{\"error\":{\"code\":\"INVALID_BODY\",\"message\":\"missing sha256_ciphertext\"}}"
                .to_string(),
        );
    };
    let len = extract_json_u64(body, "content_length").unwrap_or(params.content_length);
    let (Some(access_key), Some(secret_key)) = (params.access_key_id, params.secret_access_key)
    else {
        return (
            400,
            "Bad Request",
            "{\"error\":{\"code\":\"MISSING_S3_CREDENTIALS\",\"message\":\"S3 access key ID and secret access key are not configured\"}}".to_string(),
        );
    };
    let url = generate_sigv4_presigned_put_url(
        params.endpoint_url,
        params.bucket,
        &hash,
        len,
        params.region,
        access_key,
        secret_key,
        params.request_epoch_secs,
        params.expires_secs,
    );
    (
        200,
        "OK",
        format!(
            "{{\"presigned_url\":\"{url}\",\"object_key\":\"{hash}\",\"expires_in_secs\":{}}}",
            params.expires_secs
        ),
    )
}

/// Builds an AWS Signature Version 4 presigned PUT URL for `object_key`.
///
/// Signs per the SigV4 spec: canonical PUT request with the
/// `X-Amz-*` query parameters, `StringToSign`, and the `kDate/kRegion/
/// kService/aws4_request` key derivation chain over HMAC-SHA256.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn generate_sigv4_presigned_put_url(
    endpoint_url: &str,
    bucket: &str,
    object_key: &str,
    content_length: u64,
    region: &str,
    access_key_id: &str,
    secret_access_key: &str,
    request_epoch_secs: u64,
    expires_secs: u64,
) -> String {
    let base = endpoint_url.trim_end_matches('/');
    let (amz_date, date_stamp) = sigv4_timestamps(request_epoch_secs);
    let expires = expires_secs.clamp(1, 604_800);
    let credential_scope = format!("{date_stamp}/{region}/s3/aws4_request");
    let credential = format!("{access_key_id}/{credential_scope}");
    let host = base
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let canonical_uri = format!("/{bucket}/{object_key}");
    let canonical_qs = format!(
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential={}&X-Amz-Date={amz_date}&X-Amz-Expires={expires}&X-Amz-SignedHeaders=host",
        url_encode(&credential)
    );
    let canonical_headers = format!("host:{host}\n");
    let payload_hash = "UNSIGNED-PAYLOAD";
    let canonical_request =
        format!("PUT\n{canonical_uri}\n{canonical_qs}\n{canonical_headers}\nhost\n{payload_hash}");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let signing_key = sigv4_signing_key(secret_access_key, &date_stamp, region);
    let signature = hmac_sha256_hex(&signing_key, string_to_sign.as_bytes());
    format!("{base}{canonical_uri}?{canonical_qs}&X-Amz-Signature={signature}&x-amz-content-length={content_length}")
}

/// Derives the SigV4 signing key for `date_stamp`/`region`/service `s3`.
fn sigv4_signing_key(secret: &str, date_stamp: &str, region: &str) -> Vec<u8> {
    let k_date = hmac_bytes(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_bytes(&k_date, region.as_bytes());
    let k_service = hmac_bytes(&k_region, b"s3");
    hmac_bytes(&k_service, b"aws4_request")
}

/// Raw-byte HMAC-SHA256 used by the SigV4 key derivation chain.
fn hmac_bytes(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let digest = crate::crypto::sha256_bytes(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Vec::with_capacity(64 + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_digest = crate::crypto::sha256_bytes(&inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_digest);
    crate::crypto::sha256_bytes(&outer).to_vec()
}

/// Formats SigV4 `X-Amz-Date` (`YYYYMMDD'T'HHMMSS'Z'`) and date stamp from epoch secs.
fn sigv4_timestamps(epoch_secs: u64) -> (String, String) {
    let (year, month, day) = civil_date_from_days((epoch_secs / 86_400) as i64 + 719_468);
    let secs_of_day = epoch_secs % 86_400;
    let (hour, minute, second) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    (
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    )
}

/// Converts days since the Unix epoch to a civil `(year, month, day)` date.
fn civil_date_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

/// Percent-encodes a SigV4 credential scope value (`/` must be escaped).
fn url_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Handles `POST /v1/contacts/psi` JSON body and returns `(status, reason, json)`.
///
/// Only HMAC-derived tokens match: the plaintext-token fallback was removed so
/// blind matching is actually blind.
#[must_use]
pub fn handle_psi_json(
    body: &str,
    secret: &[u8],
    phone_index: &HashMap<String, String>,
) -> (u16, &'static str, String) {
    let tokens = extract_json_str_array(body, "blinded_tokens");
    let mut quoted = Vec::new();
    let mut matches = Vec::new();
    for tok in &tokens {
        let eval = evaluate_psi_single(tok, secret);
        if let Some(did) = phone_index.get(&eval) {
            matches.push(format!(
                "{{\"blinded_token\":\"{tok}\",\"evaluated_token\":\"{eval}\",\"did\":\"{did}\"}}"
            ));
        }
        quoted.push(format!("\"{eval}\""));
    }
    (
        200,
        "OK",
        format!(
            "{{\"evaluated_tokens\":[{}],\"matches\":[{}]}}",
            quoted.join(","),
            matches.join(",")
        ),
    )
}
