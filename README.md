# SonarAIM Node (`sonaraim-node`)

> Decentralized P2P Relay, Ephemeral Store-and-Forward Mailbox, and Key Transparency Merkle Log

`sonaraim-node` is the core decentralized infrastructure daemon for the SonarAIM messaging ecosystem. Built in safe Rust, it provides metadata-blind store-and-forward delivery for offline peers, verifiable Key Transparency Merkle logs for `did:sonaraim` and `did:web` identities, and blind push wake-up token routing without storing plaintext metadata.

## Core Capabilities

- **Zero-Hardcode Configuration (`config`)**: Loads all runtime parameters strictly from environment variables (`NODE_ID`, `NODE_HTTP_HOST`, `NODE_HTTP_PORT`, `NODE_P2P_LISTEN_ADDR`, `NODE_ENVELOPE_TTL_SECONDS`) with explicit validation and error reporting.
- **Metadata-Blind Ephemeral Relay (`relay`)**: Stores opaque `SealedEnvelope` payloads indexed only by recipient mailbox hash, enforces strict time-to-live (TTL) eviction, and derives deterministic blind push wake-up tokens.
- **Key Transparency Merkle Log (`merkle`)**: Append-only cryptographic log tracking `did:sonaraim` and `did:web` identity key bindings, computing deterministic tree heads and verifiable inclusion proofs.
- **Standardized Health Telemetry (`health`)**: Exposes structured JSON readiness and liveness status for `/health` probes.

## Repository Layout

```text
sonaraim-node/
├── configs/                # Node configuration templates
├── deploy/                 # Deployment manifests and compose definitions
├── docs/                   # Architecture, API, configuration, and standards docs
├── reference/              # Local specification references (gitignored)
├── samples/                # Sample environment variable templates
├── src/                    # Rust library and binary entrypoint
│   ├── config.rs           # Environment variable configuration loader
│   ├── health.rs           # /health telemetry serializer
│   ├── lib.rs              # Crate module exports
│   ├── main.rs             # Node daemon CLI entrypoint
│   ├── merkle.rs           # Key Transparency log and inclusion proofs
│   └── relay.rs            # Ephemeral store-and-forward mailbox queue
└── tests/                  # Integration and unit test suites
    └── node_test.rs        # End-to-end verification tests
```

## Quick Start

### 1. Configure Environment Variables

Copy the sample environment file and populate all required values:

```bash
cp samples/.env.example .env
set -a && source .env && set +a
```

### 2. Run Verification Suite

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test
```

### 3. Run the Node

```bash
cargo run --bin sonaraim-node
```

## Documentation Index

- [Development Standards](docs/STANDARDS.md)
- [System Architecture](docs/ARCHITECTURE.md)
- [Architecture Diagrams](docs/DIAGRAMS.md)
- [API Reference](docs/API.md)
- [Configuration Guide](docs/CONFIGURATION.md)

## License

Licensed under the Apache License, Version 2.0.
