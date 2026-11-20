//! Live UDP datagram gossip transport (`UdpGossipNode`) and `did:web` document verifier.
//!
//! Exchanges [`SignedTreeHead`] JSON datagrams over [`std::net::UdpSocket`] and
//! validates `did:web` W3C DID documents (`/.well-known/did.json`) before granting
//! `verified_b2b` status.

use crate::p2p::{P2pMeshNode, SignedTreeHead};
use crate::storage::{extract_json_str, extract_json_usize};
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, UdpSocket};

/// Live non-blocking UDP socket wrapper for exchanging [`SignedTreeHead`] datagrams.
#[derive(Debug)]
pub struct UdpGossipNode {
    socket: UdpSocket,
}

impl UdpGossipNode {
    /// Binds a non-blocking [`UdpGossipNode`] to `bind_addr` (e.g., `"0.0.0.0:9031"` or `"127.0.0.1:0"`).
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if binding or configuring non-blocking mode fails.
    pub fn bind(bind_addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }

    /// Enables broadcast on the underlying socket (used by the gossip daemon).
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the socket option cannot be set.
    pub fn socket_set_broadcast(&self) -> io::Result<()> {
        self.socket.set_broadcast(true)
    }

    /// Returns the local [`SocketAddr`] to which this UDP node is bound.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if querying the socket address fails.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Serializes `sth` as JSON and sends it as a single UDP datagram to `target_addr`.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the datagram transmission fails.
    pub fn send_tree_head(&self, target_addr: &str, sth: &SignedTreeHead) -> io::Result<usize> {
        let payload = encode_tree_head_json(sth);
        self.socket.send_to(payload.as_bytes(), target_addr)
    }

    /// Attempts to receive and parse a [`SignedTreeHead`] datagram without blocking.
    ///
    /// Returns `Ok(None)` when no datagram is currently waiting on the socket.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] on socket failure or malformed datagram payload.
    pub fn recv_tree_head_nonblocking(&self) -> io::Result<Option<SignedTreeHead>> {
        let mut buf = [0u8; 2048];
        match self.socket.recv_from(&mut buf) {
            Ok((n, _src)) => {
                let raw = String::from_utf8_lossy(&buf[..n]);
                decode_tree_head_json(&raw).map(Some).ok_or_else(|| {
                    io::Error::new(ErrorKind::InvalidData, "malformed SignedTreeHead datagram")
                })
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Encodes a [`SignedTreeHead`] into a compact JSON string.
#[must_use]
pub fn encode_tree_head_json(sth: &SignedTreeHead) -> String {
    format!(
        "{{\"node_id\":\"{}\",\"tree_size\":{},\"root_hash\":\"{}\",\"signer_pubkey_hex\":\"{}\",\"signature_hex\":\"{}\"}}",
        sth.node_id, sth.tree_size, sth.root_hash, sth.signer_pubkey_hex, sth.signature_hex
    )
}

/// Decodes a [`SignedTreeHead`] from a JSON string.
///
/// Accepts both the signed encoding and the legacy unsigned encoding
/// (`node_id`/`tree_size`/`root_hash` only); unsigned heads decode with empty
/// key/signature fields and are rejected later by signature verification.
#[must_use]
pub fn decode_tree_head_json(raw: &str) -> Option<SignedTreeHead> {
    let node_id = extract_json_str(raw, "node_id")?;
    let tree_size = extract_json_usize(raw, "tree_size")?;
    let root_hash = extract_json_str(raw, "root_hash")?;
    Some(SignedTreeHead {
        node_id,
        tree_size,
        root_hash,
        signer_pubkey_hex: extract_json_str(raw, "signer_pubkey_hex").unwrap_or_default(),
        signature_hex: extract_json_str(raw, "signature_hex").unwrap_or_default(),
    })
}

/// Processes a raw JSON `POST /v1/p2p/gossip` body against `mesh`, returning `(status, reason, json)`.
///
/// Heads with missing or invalid Ed25519 signatures are rejected with
/// `400 INVALID_SIGNATURE` and never recorded.
pub fn ingest_gossip_json(mesh: &mut P2pMeshNode, body: &str) -> (u16, &'static str, String) {
    let Some(sth) = decode_tree_head_json(body) else {
        return (
            400,
            "Bad Request",
            "{\"error\":{\"code\":\"INVALID_BODY\",\"message\":\"malformed SignedTreeHead\"}}"
                .to_string(),
        );
    };
    match mesh.accept_tree_head(sth) {
        Ok(()) => (200, "OK", "{\"accepted\":true}".to_string()),
        Err(crate::p2p::P2pError::InvalidSignature(msg)) => (
            400,
            "Bad Request",
            format!("{{\"error\":{{\"code\":\"INVALID_SIGNATURE\",\"message\":\"{msg}\"}}}}"),
        ),
        Err(e) => (
            409,
            "Conflict",
            format!("{{\"error\":{{\"code\":\"EQUIVOCATION_DETECTED\",\"message\":\"{e}\"}}}}"),
        ),
    }
}

/// Validates a W3C `did:web` JSON document (`/.well-known/did.json`) against `did`.
///
/// Requires `did` to start with `"did:web:"`, the JSON document's `"id"` field to
/// match `did` exactly, and a non-empty `"verificationMethod"` array.
#[must_use]
pub fn verify_did_web_document(did: &str, doc_json: &str) -> bool {
    if !did.starts_with("did:web:") {
        return false;
    }
    let Some(doc_id) = extract_json_str(doc_json, "id") else {
        return false;
    };
    if doc_id != did {
        return false;
    }
    crate::json::json_array_nonempty(doc_json, "verificationMethod")
}
