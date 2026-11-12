//! Private Set Intersection (PSI) blind evaluation service and L2 Merkle anchor receipts.

use crate::storage::{
    extract_json_str, extract_json_str_array, extract_json_u64, generate_s3_presigned_url,
};

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

/// Evaluates a batch of client-blinded contact tokens against a node secret key.
#[must_use]
pub fn evaluate_psi_batch(blinded_tokens: &[String], server_secret: &[u8]) -> Vec<String> {
    blinded_tokens
        .iter()
        .map(|tok| {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for &b in server_secret.iter().chain(tok.as_bytes().iter()) {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            format!("{h:016x}")
        })
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

/// Handles `POST /v1/media/presign` JSON body and returns `(status, reason, json)`.
#[must_use]
pub fn handle_presign_json(body: &str) -> (u16, &'static str, String) {
    let Some(hash) = extract_json_str(body, "sha256_ciphertext") else {
        return (
            400,
            "Bad Request",
            "{\"error\":{\"code\":\"INVALID_BODY\",\"message\":\"missing sha256_ciphertext\"}}"
                .to_string(),
        );
    };
    let len = extract_json_u64(body, "content_length").unwrap_or(0);
    let ep = std::env::var("S3_ENDPOINT_URL").unwrap_or_default();
    let bkt = std::env::var("S3_BUCKET_MEDIA").unwrap_or_default();
    let url = generate_s3_presigned_url(&ep, &bkt, &hash, len);
    (200, "OK", format!("{{\"presigned_url\":\"{url}\"}}"))
}

/// Handles `POST /v1/contacts/psi` JSON body and returns `(status, reason, json)`.
#[must_use]
pub fn handle_psi_json(body: &str, secret: &[u8]) -> (u16, &'static str, String) {
    let tokens = extract_json_str_array(body, "blinded_tokens");
    let quoted: Vec<String> = evaluate_psi_batch(&tokens, secret)
        .into_iter()
        .map(|t| format!("\"{t}\""))
        .collect();
    (
        200,
        "OK",
        format!("{{\"evaluated_tokens\":[{}]}}", quoted.join(",")),
    )
}
