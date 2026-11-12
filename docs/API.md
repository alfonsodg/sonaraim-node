# API Reference (`sonaraim-node`)

> Rust Library Interfaces and HTTP Health Endpoint Specification

## HTTP Endpoints

### `GET /health`

Returns the operational readiness, active ephemeral queue size, and Key Transparency Merkle log state of the node.

#### Response `200 OK`

```json
{
  "status": "ok",
  "node_id": "node-primary-01",
  "http_bind": "0.0.0.0:8040",
  "p2p_listen_addr": "/ip4/0.0.0.0/tcp/4001",
  "queued_envelopes": 3,
  "kt_log_entries": 12,
  "kt_tree_head": "a1b2c3d4e5f60718"
}
```

## Rust Crate Public API (`sonaraim_node`)

### `config::NodeConfig`

- `NodeConfig::from_env() -> Result<NodeConfig, ConfigError>`: Loads configuration from process environment variables.
- `NodeConfig::from_map(vars: &HashMap<String, String>) -> Result<NodeConfig, ConfigError>`: Loads configuration from a key-value map for deterministic testing.
- `NodeConfig::http_bind_address(&self) -> String`: Formats `<http_host>:<http_port>`.

### `relay::MailboxStore`

- `MailboxStore::new(ttl_seconds: u64) -> Self`: Initializes an ephemeral mailbox store with the configured TTL.
- `MailboxStore::enqueue(&mut self, envelope: SealedEnvelope) -> String`: Enqueues a sealed envelope and returns its deterministic blind push wake-up token.
- `MailboxStore::drain_active(&mut self, mailbox_id: &str, now_epoch_secs: u64) -> Vec<SealedEnvelope>`: Removes and returns all non-expired envelopes for `mailbox_id`.
- `MailboxStore::purge_expired(&mut self, now_epoch_secs: u64) -> usize`: Evicts all expired envelopes across all mailboxes and returns the number of removed items.
- `MailboxStore::total_queued(&self) -> usize`: Returns the current count of queued envelopes across all mailboxes.

### `merkle::KeyTransparencyLog`

- `KeyTransparencyLog::new() -> Self`: Creates an empty append-only Key Transparency Merkle log.
- `KeyTransparencyLog::append(&mut self, did: &str, key_commitment: &str, epoch_secs: u64) -> Result<(usize, String), MerkleError>`: Validates the DID (`did:sonaraim:*` or `did:web:*`), appends a new leaf entry, and returns `(leaf_index, tree_head_hash)`.
- `KeyTransparencyLog::tree_head(&self) -> String`: Computes the current Merkle root hash in hexadecimal format.
- `KeyTransparencyLog::generate_proof(&self, leaf_index: usize) -> Result<InclusionProof, MerkleError>`: Generates a cryptographic Merkle inclusion proof for the given leaf index.
- `KeyTransparencyLog::verify_proof(proof: &InclusionProof) -> bool`: Verifies that the inclusion proof reconstructs the expected Merkle `tree_head`.

### `health::HealthStatus`

- `HealthStatus::from_state(config: &NodeConfig, relay: &MailboxStore, kt_log: &KeyTransparencyLog) -> Self`: Captures a point-in-time health snapshot.
- `HealthStatus::to_json(&self) -> String`: Serializes the health snapshot into a deterministic JSON string.
