# System Architecture (`sonaraim-node`)

> Decentralized P2P Store-and-Forward Relay, Key Transparency Merkle Log, and UDP Gossip Subsystem.

## 1. Overview

`sonaraim-node` operates as a stateless-metadata, ephemeral store-and-forward relay node and Key Transparency log verifier within the SonarAIM sovereign messaging network. Relay nodes never possess sender or recipient private keys, inspecting only opaque mailbox routing hashes and cryptographic identity commitments.

---

## 2. Component Topology (ASCII)

```text
+-----------------------------------------------------------------------------------+
|                                   sonaraim-node                                   |
|                                                                                   |
|  +---------------------+      +---------------------+      +-------------------+  |
|  |     HTTP Server     |      |  KeyTransparencyLog |      |   MailboxStore    |  |
|  | (src/http_server.rs)|      |   (src/merkle.rs)   |      |  (src/relay.rs)   |  |
|  | - Auth Gate         |      | - did:web / sonaraim|      | - Sealed Envelopes|  |
|  | - REST Handlers     |      | - Inclusion Proofs  |      | - TTL Purging     |  |
|  | - Prometheus Metrics|      | - Tree Heads        |      | - Blind Wake Token|  |
|  +----------+----------+      +----------+----------+      +---------+---------+  |
|             |                            |                           |            |
|             +----------------------------+---------------------------+            |
|                                          |                                        |
|  +---------------------+      +----------+----------+      +-------------------+  |
|  |    UdpGossipNode    |      |     P2pMeshNode     |      | S3/WAL Maintenance|  |
|  | (src/udp_gossip.rs) |      |    (src/p2p.rs)     |      | (s3_wal_maint.rs) |  |
|  | - SignedTreeHeads   |      | - Peer QUIC Addrs   |      | - Compaction      |  |
|  | - Equivocation Det. |      | - Federation Sync   |      | - Presigned PUT   |  |
|  +---------------------+      +---------------------+      +-------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Subsystem Architecture

### 3.1 HTTP Server & Dispatch Subsystem (`src/http_server.rs`, `src/http_auth.rs`)

The HTTP server is built directly on Rust standard library primitives (`std::net::TcpListener`, `std::net::TcpStream`) for deterministic execution without external async runtime dependencies.

- **Request Parsing**: HTTP/1.1 request lines, headers, and bodies are parsed and dispatched to specialized route handlers.
- **Bearer Token Auth Gate (`src/http_auth.rs`)**: Write routes (`POST /v1/relay/envelopes`, `POST /v1/identity`, `POST /v1/p2p/peers`, etc.) enforce constant-time Bearer token verification when `NODE_API_AUTH_TOKEN` is configured.
- **Percent-Decoded DID Paths**: DID endpoints support percent-encoded colon delimiters (e.g., `did%3Aweb%3Abank.com` -> `did:web:bank.com`).

### 3.2 Ephemeral Store-and-Forward Relay (`src/relay.rs`, `src/http_relay.rs`)

When recipient devices are offline, incoming `SealedEnvelope` payloads are stored in memory and indexed by `mailbox_id`:

```text
Sender Node ---> [ POST /v1/relay/envelopes ] ---> MailboxStore
                                                         |
                           +-----------------------------+
                           |
                           v
               [ Derive Blind Wake Token ] ---> Apple APNs / Google FCM
                           |
Recipient Device <-- [ GET /v1/relay/mailboxes/{id} ] <--+
                           |
Recipient Device --> [ POST /v1/relay/mailboxes/{id}/ack ] ---> Evict & Compact WAL
```

- **TTL Expiration**: Envelopes are tagged with `created_at_epoch_secs` and `ttl_seconds`. Expired envelopes are evicted during `purge_expired` or fetch operations.
- **Blind Wake Tokens**: Wake tokens are deterministically derived from `(mailbox_id, envelope_id, timestamp)`, enabling push notifications without exposing sender identity or payload contents to push gateways.

### 3.3 Key Transparency Merkle Log (`src/merkle.rs`, `src/http_identity.rs`)

Maintains an append-only cryptographic ledger mapping DIDs to public key commitments:

```text
                      [ Root Hash (Tree Head) ]
                             /          \
                     [ Hash 0-1 ]     [ Hash 2-3 ]
                      /        \       /        \
                    Leaf 0   Leaf 1  Leaf 2   Leaf 3
```

- **Inclusion Proofs**: Generates logarithmic Merkle audit paths verifying that a DID commitment is present in the tree.
- **Verification**: Clients verify proofs against the gossiped `SignedTreeHead` before initiating encrypted sessions.

### 3.4 P2P Federation & Live UDP Gossip (`src/p2p.rs`, `src/udp_gossip.rs`)

Nodes federate over QUIC and UDP to synchronize Merkle tree heads:

- **`UdpGossipNode`**: Binds a non-blocking UDP socket (`NODE_P2P_PORT`) to exchange compact JSON `SignedTreeHead` datagrams.
- **Equivocation Detection**: If a peer advertises two conflicting tree heads for the same tree size, an equivocation alert is raised and the peer is flagged as untrusted.

### 3.5 Private Set Intersection Service (`src/psi_service.rs`)

Enables mobile users to discover contacts registered on Sonaraim:

- **Blinded Matching**: Clients submit blinded phone hashes. The server evaluates them against its registered phone index.
- **Zero Metadata Leak**: The node learns nothing about non-matching contacts or the client's contact graph.

### 3.6 S3 Maintenance & Atomic WAL Compaction (`src/s3_wal_maintenance.rs`, `src/storage.rs`)

- **Atomic WAL Compaction**: Evicted envelopes are filtered out and remaining active entries are written atomically to a temporary file before renaming, preventing file corruption.
- **S3 Presigning**: Generates signed PUT URLs for client-side encrypted attachments.
