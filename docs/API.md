# API Reference (`sonaraim-node`)

> HTTP REST Endpoints and Rust Library Interfaces exposed by `sonaraim-node`.

## 1. Authentication & Security

Endpoints that modify state (write routes) require a Bearer token when `NODE_API_AUTH_TOKEN` is configured:

```http
Authorization: Bearer <NODE_API_AUTH_TOKEN>
```

Protected write routes:

- `POST /v1/relay/envelopes`
- `POST /v1/push/register`
- `POST /v1/relay/signals`
- `POST /v1/relay/mailboxes/{mailbox_id}/ack`
- `POST /v1/identity`
- `POST /v1/p2p/peers`
- `POST /v1/p2p/gossip`

All other endpoints (`GET /health`, `GET /metrics`, `GET /v1/relay/mailboxes/{id}`, `GET /v1/relay/signals/{id}`, `GET /v1/identity/{did}`, `POST /v1/contacts/psi`, `POST /v1/media/presign`, etc.) are public.

---

## 2. Health & Telemetry Endpoints

### `GET /health`

Returns operational health status, queue sizes, and Merkle tree state.

**Response (`200 OK`)**:

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

### `GET /metrics`

Exposes Prometheus counters and gauges (`text/plain; version=0.0.4`).

**Response Metrics Output (`200 OK`)**:

```text
# HELP sonaraim_node_kt_log_entries_total Total Key Transparency Merkle log entries
# TYPE sonaraim_node_kt_log_entries_total counter
sonaraim_node_kt_log_entries_total 12
# HELP sonaraim_node_relay_queued_total Total queued store-and-forward envelopes
# TYPE sonaraim_node_relay_queued_total gauge
sonaraim_node_relay_queued_total 3
```

---

## 3. Ephemeral Relay & Mailbox Endpoints

### `POST /v1/relay/envelopes`

Submits an encrypted Sealed Sender envelope into the recipient's ephemeral mailbox queue.

- **Auth**: Bearer token required.

**Request Payload**:

```json
{
  "envelope_id": "env_0193218a-7c40-7000-8000-1a2b3c4d5e6f",
  "recipient_mailbox_id": "mbx_user_alice_99",
  "payload_hex": "48656c6c6f20536f6e617261696d",
  "ephemeral_pub_key_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
  "ttl_seconds": 604800
}
```

**Response (`202 Accepted`)**:

```json
{
  "wake_up_token": "a1b2c3d4e5f60718...",
  "wake_up_queued": true
}
```

The response returns a blind wake-up token alongside `wake_up_queued` (`true` if a wake-up push notification was dispatched to the recipient's registered device push token).

### `GET /v1/relay/mailboxes/{mailbox_id}`

Fetches all non-expired envelopes queued for the specified mailbox.

**Response (`200 OK`)**:

```json
{
  "mailbox_id": "mbx_user_alice_99",
  "count": 1,
  "envelopes": [
    {
      "envelope_id": "env_0193218a-7c40-7000-8000-1a2b3c4d5e6f",
      "recipient_mailbox_id": "mbx_user_alice_99",
      "payload_hex": "48656c6c6f20536f6e617261696d",
      "created_at_epoch_secs": 1700000000,
      "ttl_seconds": 604800
    }
  ]
}
```

### `POST /v1/relay/mailboxes/{mailbox_id}/ack`

Acknowledges received envelope IDs, evicts them from the active queue, and triggers atomic WAL compaction.

- **Auth**: Bearer token required.

**Request Payload**:

```json
{
  "envelope_ids": ["env_0193218a-7c40-7000-8000-1a2b3c4d5e6f"]
}
```

**Response (`200 OK`)**:

```json
{
  "status": "acknowledged",
  "mailbox_id": "mbx_user_alice_99",
  "evicted_count": 1
}
```

### `POST /v1/push/register`

Registers a blind push notification token for an anonymous recipient mailbox. Device tokens are stored and verified as SHA-256 hashes (`token_hash`), ensuring zero plaintext token or sender metadata leakage at the relay layer.

- **Auth**: Bearer token required.

**Request Payload**:

```json
{
  "mailbox_id": "mbx_user_alice_99",
  "platform": "apns",
  "device_token": "98a7b6c5d4e3f210a1b2c3d4e5f6...",
  "endpoint_hint": "https://push.apple.com"
}
```

Supported `platform` values: `apns`, `fcm`, `webpush`.

**Response (`200 OK`)**:

```json
{
  "status": "ok",
  "registered": true,
  "mailbox_id": "mbx_user_alice_99",
  "platform": "apns",
  "token_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### `POST /v1/relay/signals`

Records an ephemeral conversational signal (typing indicator, delivery receipt, read receipt) for an active recipient mailbox. Signals are kept in-memory with automatic TTL expiration and are never committed to WAL storage.

- **Auth**: Bearer token required.

**Request Payload**:

```json
{
  "mailbox_id": "mbx_user_alice_99",
  "sender_did": "did:sonaraim:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
  "signal_type": "typing",
  "envelope_id": "env_0193218a-7c40-7000-8000-1a2b3c4d5e6f"
}
```

Supported `signal_type` values:

- `typing`: Sender is composing a message (default TTL 30 seconds).
- `delivered`: Message envelope was delivered to the recipient device (default TTL 300 seconds).
- `read`: Message envelope was opened and read by the recipient (default TTL 300 seconds).

**Response (`200 OK`)**:

```json
{
  "status": "ok",
  "recorded": true,
  "mailbox_id": "mbx_user_alice_99",
  "signal_type": "typing",
  "expires_at_epoch": 1700000030
}
```

### `GET /v1/relay/signals/{mailbox_id}`

Drains and returns all active non-expired ephemeral signals for the recipient's mailbox. Retrieved signals are atomically removed from memory upon retrieval.

- **Auth**: Public endpoint.

**Response (`200 OK`)**:

```json
{
  "mailbox_id": "mbx_user_alice_99",
  "signals": [
    {
      "mailbox_id": "mbx_user_alice_99",
      "sender_did": "did:sonaraim:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
      "signal_type": "typing",
      "envelope_id": null,
      "expires_at_epoch": 1700000030
    }
  ]
}
```

---

## 4. Key Transparency & Identity Endpoints

### `POST /v1/identity`

Registers or updates a public identity commitment in the Key Transparency Merkle log.

- **Auth**: Bearer token required.

**Request Payload**:

```json
{
  "did": "did:web:bank.example.com",
  "key_commitment": "ed25519:MCowBQYDK2VwAyEA...",
  "phone_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

**Response (`201 Created`)**:

```json
{
  "status": "committed",
  "did": "did:web:bank.example.com",
  "leaf_index": 12,
  "tree_head": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

### `GET /v1/identity/{did}`

Returns the verified DID identity entry, signing key commitment, and cryptographic Merkle inclusion proof. Supports percent-encoded DID paths (e.g., `did%3Aweb%3Abank.example.com`).

**Response (`200 OK`)**:

```json
{
  "did": "did:web:bank.example.com",
  "key_commitment": "ed25519:MCowBQYDK2VwAyEA...",
  "leaf_index": 12,
  "merkle_proof": {
    "tree_size": 13,
    "leaf_index": 12,
    "root_hash": "e3b0c442...",
    "inclusion_path": ["sha256:4a1b...", "sha256:9c8d..."]
  }
}
```

### `GET /v1/identity/by-phone/{token}`

Looks up a registered DID by blinded or hashed phone number token.

**Response (`200 OK`)**:

```json
{
  "status": "found",
  "did": "did:sonaraim:alice",
  "token": "e3b0c44298fc1c14..."
}
```

### `GET /v1/identity/anchors/latest`

Returns the latest L2 anchor checkpoint receipt for the Merkle tree head.

**Response (`200 OK`)**:

```json
{
  "status": "anchored",
  "tree_size": 13,
  "tree_head": "e3b0c442...",
  "epoch_secs": 1700000000,
  "anchor_proof": "l2:0xabcdef..."
}
```

---

## 5. P2P Federation & Gossip Endpoints

### `GET /v1/p2p/sync`

Returns local Merkle tree size, root hash, and known peer tree heads.

**Response (`200 OK`)**:

```json
{
  "node_id": "node-primary-01",
  "tree_size": 13,
  "tree_head": "e3b0c442...",
  "peers_count": 2,
  "peers": [
    { "peer_id": "node-peer-02", "tree_size": 13, "tree_head": "e3b0c442..." }
  ]
}
```

### `POST /v1/p2p/gossip`

Ingests a gossiped `SignedTreeHead` datagram from a peer node.

**Request Payload**:

```json
{
  "node_id": "node-peer-02",
  "tree_size": 13,
  "root_hash": "e3b0c442...",
  "signature_hex": "4a5b6c...",
  "timestamp_secs": 1700000000
}
```

**Response (`200 OK`)**:

```json
{
  "status": "ingested",
  "equivocation_detected": false
}
```

### `POST /v1/p2p/peers`

Registers or updates a peer's QUIC multiaddr and HTTP RPC endpoint.

- **Auth**: Bearer token required.

**Request Payload**:

```json
{
  "peer_id": "node-peer-02",
  "rpc_url": "http://node2.sonaraim.internal:8040",
  "multiaddr": "/ip4/10.0.0.2/udp/4001/quic-v1"
}
```

**Response (`200 OK`)**:

```json
{
  "status": "registered",
  "peer_id": "node-peer-02"
}
```

### `GET /v1/p2p/peers`

Lists all connected and registered P2P mesh peers.

---

## 6. Private Set Intersection & Media Endpoints

### `POST /v1/contacts/psi`

Performs blind contact discovery. Evaluates blinded phone tokens without learning the user's contacts.

**Request Payload**:

```json
{
  "blinded_tokens": [
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "4a5b6c7d8e9f..."
  ]
}
```

**Response (`200 OK`)**:

```json
{
  "matches": [
    {
      "token": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "did": "did:sonaraim:alice"
    }
  ]
}
```

### `POST /v1/media/presign`

Generates an S3/MinIO presigned PUT upload URL for client-side encrypted media attachments.

**Request Payload**:

```json
{
  "object_key": "attachments/0193218a-media-01.enc",
  "content_type": "application/octet-stream",
  "size_bytes": 1048576
}
```

**Response (`200 OK`)**:

```json
{
  "upload_url": "http://minio:9000/media-vault/attachments/0193218a-media-01.enc?X-Amz-Signature=...",
  "object_key": "attachments/0193218a-media-01.enc",
  "expires_in_secs": 900
}
```

---

## 7. Rust Crate Public Interfaces (`sonaraim_node`)

- **`config::NodeConfig`**: Environment variable loader and validator (`from_env`, `from_map`).
- **`relay::MailboxStore`**: Ephemeral envelope queue with TTL eviction (`enqueue`, `drain_active`, `purge_expired`).
- **`merkle::KeyTransparencyLog`**: Append-only cryptographic ledger (`append`, `tree_head`, `generate_proof`, `verify_proof`).
- **`health::HealthStatus`**: Health capture and Prometheus metric formatting (`format_prometheus_metrics`).
- **`udp_gossip::UdpGossipNode`**: Live non-blocking UDP socket wrapper for signed tree head gossip (`bind`, `send_sth`, `ingest_gossip_json`).
- **`s3_wal_maintenance`**: S3 uploader and atomic WAL compaction (`compact_wal_file`, `put_s3_object_http`).
- **`http_server`**: Std-only HTTP server runner (`run_server`, `start_test_server`).
