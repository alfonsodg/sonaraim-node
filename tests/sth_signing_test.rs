//! TDD regression tests for issue #21: signed STHs + did:web network resolution.
//!
//! - Forged STHs (wrong key, tampered payload) are rejected on ingest and
//!   never recorded; valid Ed25519 STHs (via the approved `ed25519-dalek`
//!   dependency) are accepted and equivocation still detected.
//! - `did:web` without a resolvable document is never `verified_b2b`; a
//!   matching fetched document verifies, with TTL caching.

use sonaraim_node::did_web::{
    clear_did_web_cache, did_web_document_url, document_matches_did,
    verify_did_web_resolved_with_fetch,
};
use sonaraim_node::p2p::SignedTreeHead;
use sonaraim_node::p2p::{sign_tree_head, verify_tree_head_signature, P2pError, P2pMeshNode};
use sonaraim_node::udp_gossip::{decode_tree_head_json, encode_tree_head_json, ingest_gossip_json};

fn signed(node: &str, size: usize, root: &str, seed: &[u8; 32]) -> SignedTreeHead {
    let (signer_pubkey_hex, signature_hex) = sign_tree_head(node, size, root, seed);
    SignedTreeHead {
        node_id: node.to_string(),
        tree_size: size,
        root_hash: root.to_string(),
        signer_pubkey_hex,
        signature_hex,
    }
}

#[test]
fn signed_sth_verifies_and_detects_equivocation() {
    let seed = [11u8; 32];
    let good = signed("node-a", 3, "aaaa", &seed);
    assert!(verify_tree_head_signature(&good).is_ok());

    let mut mesh = P2pMeshNode::new("node-b");
    assert!(mesh.accept_tree_head(good).is_ok());

    // Same size, different root, same key -> equivocation (signature valid).
    let conflict = signed("node-a", 3, "bbbb", &seed);
    assert!(matches!(
        mesh.accept_tree_head(conflict),
        Err(P2pError::EquivocationDetected { .. })
    ));
}

#[test]
fn forged_sth_rejected_and_never_recorded() {
    let seed = [11u8; 32];
    let good = signed("node-a", 7, "aaaa", &seed);
    let mut mesh = P2pMeshNode::new("node-b");
    assert!(mesh.accept_tree_head(good).is_ok());

    // Tampered root with the original signature -> invalid.
    let mut tampered = signed("node-a", 7, "aaaa", &seed);
    tampered.root_hash = "ffff".to_string();
    let err = mesh.accept_tree_head(tampered).unwrap_err();
    assert!(matches!(err, P2pError::InvalidSignature(_)));

    // Head signed by a different key over a conflicting root -> signature is
    // valid for that other key, so it surfaces as equivocation against the
    // already-accepted head (the attack the mesh must detect), not silent
    // acceptance.
    let other_seed = [22u8; 32];
    let forged = signed("node-a", 7, "bbbb", &other_seed);
    assert!(matches!(
        mesh.accept_tree_head(forged),
        Err(P2pError::EquivocationDetected { .. })
    ));

    // Unsigned legacy head -> invalid.
    let unsigned = SignedTreeHead {
        node_id: "node-a".to_string(),
        tree_size: 9,
        root_hash: "cccc".to_string(),
        signer_pubkey_hex: String::new(),
        signature_hex: String::new(),
    };
    assert!(matches!(
        mesh.accept_tree_head(unsigned),
        Err(P2pError::InvalidSignature(_))
    ));

    // The valid head for size 7 is still intact: re-accepting it is a no-op Ok.
    let again = signed("node-a", 7, "aaaa", &seed);
    assert!(mesh.accept_tree_head(again).is_ok());
}

#[test]
fn gossip_json_round_trip_preserves_signature_and_forged_rejected() {
    let seed = [33u8; 32];
    let sth = signed("node-x", 12, "deadbeef", &seed);
    let json = encode_tree_head_json(&sth);
    assert!(json.contains("\"signature_hex\""));
    let decoded = decode_tree_head_json(&json).expect("decode signed json");
    assert_eq!(decoded, sth);

    let mut mesh = P2pMeshNode::new("node-y");
    let (status, _, body) = ingest_gossip_json(&mut mesh, &json);
    assert_eq!(status, 200);
    assert!(body.contains("\"accepted\":true"));

    // Bit-flipped signature -> 400 INVALID_SIGNATURE.
    let mut bad_sig = sth.signature_hex.clone();
    let first = bad_sig.remove(0);
    bad_sig.insert(0, if first == '0' { '1' } else { '0' });
    let forged_json = format!(
        "{{\"node_id\":\"node-x\",\"tree_size\":12,\"root_hash\":\"deadbeef\",\"signer_pubkey_hex\":\"{}\",\"signature_hex\":\"{bad_sig}\"}}",
        sth.signer_pubkey_hex
    );
    let (status, _, body) = ingest_gossip_json(&mut mesh, &forged_json);
    assert_eq!(status, 400);
    assert!(body.contains("INVALID_SIGNATURE"));

    // Legacy unsigned JSON -> 400 INVALID_SIGNATURE, not 409/200.
    let (status, _, body) = ingest_gossip_json(
        &mut mesh,
        r#"{"node_id":"node-x","tree_size":13,"root_hash":"0011"}"#,
    );
    assert_eq!(status, 400);
    assert!(body.contains("INVALID_SIGNATURE"));
}

#[test]
fn did_web_document_url_mapping() {
    assert_eq!(
        did_web_document_url("did:web:example.com"),
        Some("https://example.com/.well-known/did.json".to_string())
    );
    assert_eq!(
        did_web_document_url("did:web:example.com:users:alice"),
        Some("https://example.com/users/alice/.well-known/did.json".to_string())
    );
    assert_eq!(did_web_document_url("did:sonaraim:abc"), None);
    assert_eq!(did_web_document_url("did:web:"), None);
    assert_eq!(did_web_document_url("did:web:exa mple.com"), None);
    assert_eq!(did_web_document_url("did:web:example.com::x"), None);
}

#[test]
fn did_web_without_resolvable_document_never_verified() {
    clear_did_web_cache();
    let err_fetch = |_: &str| -> Result<String, String> { Err("no network".to_string()) };
    assert!(!verify_did_web_resolved_with_fetch(
        "did:web:missing.example.com",
        err_fetch
    ));
    // Wrong-document and empty-verificationMethod docs do not verify either.
    let wrong = |_: &str| -> Result<String, String> {
        Ok(r#"{"id":"did:web:other.example.com","verificationMethod":[{"id":"x#1"}]}"#.to_string())
    };
    assert!(!verify_did_web_resolved_with_fetch(
        "did:web:missing.example.com",
        wrong
    ));
    let no_vm = |_: &str| -> Result<String, String> {
        Ok(r#"{"id":"did:web:missing.example.com","verificationMethod":[]}"#.to_string())
    };
    assert!(!verify_did_web_resolved_with_fetch(
        "did:web:missing.example.com",
        no_vm
    ));
    // Non-did:web DIDs never verify and never hit the network.
    let panic_fetch = |_: &str| -> Result<String, String> { panic!("must not fetch") };
    assert!(!verify_did_web_resolved_with_fetch(
        "did:sonaraim:abc",
        panic_fetch
    ));
}

#[test]
fn did_web_matching_document_verifies_and_caches() {
    clear_did_web_cache();
    let did = "did:web:cached.example.com";
    let doc = r#"{"id":"did:web:cached.example.com","verificationMethod":[{"id":"did:web:cached.example.com#k1"}]}"#;
    assert!(document_matches_did(did, doc));
    assert!(!document_matches_did(
        did,
        r#"{"id":"did:web:other","verificationMethod":[{"id":"x"}]}"#
    ));

    let ok_fetch = |_: &str| -> Result<String, String> { Ok(doc.to_string()) };
    assert!(verify_did_web_resolved_with_fetch(did, ok_fetch));

    // Cached: a now-failing fetch still reports verified within TTL.
    let dead_fetch = |_: &str| -> Result<String, String> { Err("down".to_string()) };
    assert!(verify_did_web_resolved_with_fetch(did, dead_fetch));
    clear_did_web_cache();
    assert!(!verify_did_web_resolved_with_fetch(did, dead_fetch));
}
