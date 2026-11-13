# Sonaraim Node (`sonaraim-node`)

> Decentralized P2P relay node, ephemeral store-and-forward queue, Key Transparency Merkle log, and UDP gossip transport.

`sonaraim-node` is the core relay daemon of the Sonaraim sovereign communication network. It operates as a high-throughput, low-latency metadata-minimizing message router and distributed Key Transparency directory verifier.

---

## Key Capabilities

- **Sealed Sender Relay (`src/relay.rs`, `src/http_relay.rs`)**: Routes encrypted envelopes exclusively by opaque `mailbox_id` tokens with TTL-bounded retention, protecting sender privacy from transport nodes.
- **Key Transparency Merkle Log (`src/merkle.rs`, `src/http_identity.rs`)**: Append-only cryptographic ledger tracking `did:sonaraim:` and `did:web:` public key commitments, providing verifiable inclusion proofs.
- **P2P Federation & Gossip (`src/p2p.rs`, `src/http_federation.rs`)**: Synchronizes peer states and gossips Merkle tree heads across federated nodes over QUIC and HTTP.
- **Live UDP Gossip Transport (`src/udp_gossip.rs`)**: Low-overhead UDP datagram exchange for `SignedTreeHead` packets with real-time equivocation and split-brain detection.
- **Private Set Intersection (`src/psi_service.rs`)**: Blind contact discovery allowing mobile clients to find registered contacts without exposing unhashed address books.
- **S3 Upload & WAL Compaction (`src/s3_wal_maintenance.rs`)**: Presigned media upload URL generation and atomic Write-Ahead Log compaction to disk.
- **Zero-Hardcode Configuration (`src/config.rs`)**: Strict environment variable loading (`NODE_ID`, `NODE_HTTP_HOST`, `NODE_HTTP_PORT`, `NODE_P2P_LISTEN_ADDR`, `NODE_ENVELOPE_TTL_SECONDS`).
- **Telemetry & Prometheus Metrics (`src/health.rs`)**: Native `GET /health` JSON status and `GET /metrics` Prometheus counters.

---

## HTTP Endpoints Summary

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

## Repository Layout

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

## Quick Start

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

## Collaboration & Governance

- **[Contributing Guide](CONTRIBUTING.md)** — Branching model (`develop`), TDD mandate, and commit conventions.
- **[Code of Conduct](CODE_OF_CONDUCT.md)** — Community standards and enforcement guidelines.
- **[Security Policy](SECURITY.md)** — Vulnerability reporting, SLAs, and cryptographic threat model.
- **[API Reference](docs/API.md)** — Detailed HTTP REST and Rust API documentation.
- **[Configuration Guide](docs/CONFIGURATION.md)** — Environment variable specifications and validation rules.
- **[Architecture Specification](docs/ARCHITECTURE.md)** — Detailed subsystem architecture and ASCII layouts.
- **[System Diagrams](docs/DIAGRAMS.md)** — Mermaid sequence, topology, and state diagrams.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

Copyright 2026 Sonaraim Contributors.
