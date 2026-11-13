# Sonaraim Node (`sonaraim-node`)

> Decentralized P2P relay node, ephemeral store-and-forward queue, Key Transparency Merkle log, and UDP gossip transport.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Crate: Rust 2021](https://img.shields.io/badge/Crate-Rust%202021-DEA584.svg?logo=rust&logoColor=white)](Cargo.toml)
[![Network: libp2p + QUIC](https://img.shields.io/badge/Network-libp2p%20%2B%20QUIC-blueviolet.svg)](src/p2p.rs)
[![Ledger: Key Transparency Merkle](https://img.shields.io/badge/Ledger-Key%20Transparency%20Merkle-brightgreen.svg)](src/merkle.rs)
[![Gossip: UDP Datagram Gossip](https://img.shields.io/badge/Gossip-UDP%20Datagram%20Gossip-yellow.svg)](src/udp_gossip.rs)

`sonaraim-node` is the core relay daemon of the Sonaraim sovereign communication network. It operates as a high-throughput, low-latency metadata-minimizing message router and distributed Key Transparency directory verifier.

---

## ⚡ Key Capabilities

- **Sealed Sender Relay (`src/relay.rs`, `src/http_relay.rs`)**: Routes encrypted envelopes exclusively by opaque `mailbox_id` tokens with TTL-bounded retention, protecting sender privacy from transport nodes.
- **Key Transparency Merkle Log (`src/merkle.rs`, `src/http_identity.rs`)**: Append-only cryptographic ledger tracking `did:sonaraim:` and `did:web:` public key commitments, providing verifiable inclusion proofs.
- **P2P Federation & Gossip (`src/p2p.rs`, `src/http_federation.rs`)**: Synchronizes peer states and gossips Merkle tree heads across federated nodes over QUIC and HTTP.
- **Live UDP Gossip Transport (`src/udp_gossip.rs`)**: Low-overhead UDP datagram exchange for `SignedTreeHead` packets with real-time equivocation and split-brain detection.
- **Private Set Intersection (`src/psi_service.rs`)**: Blind contact discovery allowing mobile clients to find registered contacts without exposing unhashed address books.
- **S3 Upload & WAL Compaction (`src/s3_wal_maintenance.rs`)**: Presigned media upload URL generation and atomic Write-Ahead Log compaction to disk.
- **Zero-Hardcode Configuration (`src/config.rs`)**: Strict environment variable loading (`NODE_ID`, `NODE_HTTP_HOST`, `NODE_HTTP_PORT`, `NODE_P2P_LISTEN_ADDR`, `NODE_ENVELOPE_TTL_SECONDS`).
- **Telemetry & Prometheus Metrics (`src/health.rs`)**: Native `GET /health` JSON status and `GET /metrics` Prometheus counters.

---

## 🏗️ Node Relay & Mesh Architecture

The following ASCII diagram illustrates the internal processing pipelines, storage subsystems, and P2P gossip flows:

```text
+-----------------------------------------------------------------------------------+
|                           SONARAIM NODE INTERNAL PIPELINE                         |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [Clients / B2B Bridges]                    [Federated Validator Peer Nodes]      |
|  - Inbound Sealed Envelopes                 - Merkle Tree Head Gossips (UDP)      |
|  - Anonymous Mailbox Drains                 - P2P Peer Sync & Proof Audits        |
|            |                                              |                       |
|            | HTTP / REST                                  | UDP Gossip / QUIC     |
|            v                                              v                       |
|  +-------------------------------------+    +----------------------------------+  |
|  |     HTTP REST & RELAY DISPATCHER    |    |        P2P GOSSIP TRANSPORT      |  |
|  | (http_relay.rs, http_identity.rs)   |    | (udp_gossip.rs, p2p.rs)          |  |
|  +------------------+------------------+    +-----------------+----------------+  |
|                     |                                         |                   |
|         +-----------+-----------+                             |                   |
|         |                       |                             |                   |
|         v                       v                             v                   |
|  +--------------+       +---------------+           +-------------------+         |
|  |   Ephemeral  |       |   Append-Only |           | Real-time Merkle  |         |
|  | Mailbox Store|       |   Merkle Log  |<----------| Equivocation &    |         |
|  |  (relay.rs)  |       |  (merkle.rs)  |  Commit   | Split-Brain Check |         |
|  +-------+------+       +-------+-------+           +-------------------+         |
|          |                      |                             |                   |
|          |                      v                             |                   |
|          |            +-------------------+                   |                   |
|          |            | DID Commitments   |                   |                   |
|          |            | & Inclusion Proofs|                   |                   |
|          |            +-------------------+                   |                   |
|          v                                                    v                   |
|  +-----------------------------------------------------------------------------+  |
|  |                        PERSISTENCE & COMPACTION LAYER                       |  |
|  |  - Write-Ahead Log (WAL) with replay recovery (storage.rs)                  |  |
|  |  - Redis RESP caching for hot mailboxes (redis_store.rs)                    |  |
|  |  - S3 Presigned Media & WAL Compactor (s3_wal_maintenance.rs)               |  |
|  |  - Private Set Intersection Blind Token Matcher (psi_service.rs)            |  |
|  +-----------------------------------------------------------------------------+  |
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

> [!NOTE]
> For complete topology mappings, Merkle tree sync sequence diagrams, and failover state machines, see [docs/DIAGRAMS.md](docs/DIAGRAMS.md).

---

## 📊 HTTP Endpoints Summary

| Method | Endpoint | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | Node operational health and Merkle tree state |
| `GET` | `/metrics` | Public | Prometheus scrape metrics |
| `POST` | `/v1/relay/envelopes` | Bearer | Submit sealed envelope for delivery |
| `GET` | `/v1/relay/mailboxes/{id}` | Public | Drain queued envelopes for an anonymous mailbox |
| `POST` | `/v1/relay/mailboxes/{id}/ack` | Bearer | Acknowledge receipt and evict envelopes |
| `GET` | `/v1/p2p/sync` | Public | Fetch Merkle tree state and connected peer heads |
| `POST` | `/v1/p2p/gossip` | Public | Ingest gossiped Signed Tree Head datagram |
| `POST` | `/v1/p2p/peers` | Bearer | Register or update peer node multiaddr |
| `GET` | `/v1/p2p/peers` | Public | List active P2P mesh peers |
| `POST` | `/v1/contacts/psi` | Public | Private Set Intersection blind contact matching |
| `POST` | `/v1/media/presign` | Public | S3/MinIO presigned media PUT upload URL |
| `POST` | `/v1/identity` | Bearer | Register or update DID identity commitment |
| `GET` | `/v1/identity/{did}` | Public | Resolve DID document and Merkle inclusion proof |
| `GET` | `/v1/identity/by-phone/{tok}` | Public | Lookup registered DID by hashed phone token |
| `GET` | `/v1/identity/anchors/latest` | Public | Retrieve latest L2 state-root anchor receipt |

---

## 🧩 Repository Layout

```text
sonaraim-node/
├── docs/
│   ├── ARCHITECTURE.md       # Subsystem design and ASCII topology
│   ├── API.md                # Complete HTTP REST and Rust crate API reference
│   ├── CONFIGURATION.md      # Environment variable specifications
│   ├── DIAGRAMS.md           # Mermaid sequence and state diagrams
│   └── STANDARDS.md          # Coding, testing, and linting rules
├── src/
│   ├── config.rs             # Zero-hardcode runtime configuration
│   ├── health.rs             # Health status and Prometheus metrics
│   ├── http_auth.rs          # Bearer token authentication gate
│   ├── http_federation.rs    # P2P peer registration and sync handlers
│   ├── http_identity.rs      # DID identity and Merkle proof handlers
│   ├── http_relay.rs         # Store-and-forward envelope and ACK handlers
│   ├── http_server.rs        # Std-only HTTP/1.1 REST server
│   ├── lib.rs                # Crate root and public exports
│   ├── main.rs               # Node daemon binary entry point
│   ├── merkle.rs             # Append-only Key Transparency Merkle log
│   ├── p2p.rs                # P2P mesh routing and gossip state
│   ├── psi_service.rs        # Private Set Intersection service
│   ├── redis_store.rs        # Redis RESP client for ephemeral caching
│   ├── relay.rs              # Ephemeral mailbox queue store
│   ├── s3_wal_maintenance.rs # S3 uploader and atomic WAL compaction
│   ├── storage.rs            # WAL persistence and replay logic
│   └── udp_gossip.rs         # Live UDP datagram gossip transport
├── tests/
│   ├── milestone2_test.rs    # Phase 1 node and HTTP tests
│   ├── milestone6_test.rs    # UDP gossip, WAL recovery and metrics tests
│   ├── milestone10_node_test.rs # Compaction, PSI and federation tests
│   └── node_test.rs          # Core mailbox and Merkle unit tests
├── Cargo.toml                # Rust crate manifest (Apache-2.0)
├── CODE_OF_CONDUCT.md        # Contributor Covenant v2.1
├── CONTRIBUTING.md           # Development, TDD & git workflow guide
├── LICENSE                   # Apache License 2.0
└── SECURITY.md               # Vulnerability disclosure & zero-trust model
```

---

## 🚀 Quick Start

### Build & Test

```bash
# 1. Format check
cargo fmt --check

# 2. Static analysis
cargo clippy --all-targets -- -D warnings

# 3. Test execution
cargo test

# 4. Markdown linting
npx --yes markdownlint-cli2 "*.md" "docs/*.md"
```

---

## 🌐 Collaboration & Governance

- **[Contributing Guide](CONTRIBUTING.md)** — Branching model (`develop`), TDD mandate, and commit conventions.
- **[Code of Conduct](CODE_OF_CONDUCT.md)** — Community standards and enforcement guidelines.
- **[Security Policy](SECURITY.md)** — Vulnerability reporting, SLAs, and cryptographic threat model.
- **[API Reference](docs/API.md)** — Detailed HTTP REST and Rust API documentation.
- **[Configuration Guide](docs/CONFIGURATION.md)** — Environment variable specifications and validation rules.
- **[Architecture Specification](docs/ARCHITECTURE.md)** — Detailed subsystem architecture and ASCII layouts.
- **[System Diagrams](docs/DIAGRAMS.md)** — Mermaid sequence, topology, and state diagrams.

---

## 📜 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

Copyright 2026 Sonaraim Contributors.
