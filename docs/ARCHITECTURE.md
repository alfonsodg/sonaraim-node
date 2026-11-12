# System Architecture (`sonaraim-node`)

> Decentralized P2P Store-and-Forward Relay and Key Transparency Subsystem Design

## Overview

`sonaraim-node` operates as a stateless-metadata, ephemeral store-and-forward relay node and Key Transparency log verifier within the SonarAIM network. Nodes never possess sender or recipient private keys and only inspect opaque mailbox routing hashes and cryptographic identity commitments.

## Component Topology (ASCII)

```text
+-----------------------------------------------------------------------+
|                             sonaraim-node                             |
|                                                                       |
|  +-----------------------+       +---------------------------------+  |
|  |   NodeConfig Loader   |       |      HealthStatus Reporter      |  |
|  |     (src/config.rs)   |       |         (src/health.rs)         |  |
|  +-----------+-----------+       +----------------+----------------+  |
|              |                                    ^                   |
|              v                                    |                   |
|  +-----------------------+       +----------------+----------------+  |
|  |     MailboxStore      |       |       KeyTransparencyLog        |  |
|  |     (src/relay.rs)    |       |         (src/merkle.rs)         |  |
|  |  - SealedEnvelopes    |       |  - did:sonaraim / did:web       |  |
|  |  - TTL Eviction       |       |  - Deterministic Tree Head      |  |
|  |  - Blind Wake Tokens  |       |  - Merkle Inclusion Proofs      |  |
|  +-----------------------+       +---------------------------------+  |
+-----------------------------------------------------------------------+
```

## Subsystem Responsibilities

### 1. Configuration Subsystem (`src/config.rs`)

Reads all runtime settings from the process environment (`NODE_ID`, `NODE_HTTP_HOST`, `NODE_HTTP_PORT`, `NODE_P2P_LISTEN_ADDR`, `NODE_ENVELOPE_TTL_SECONDS`). Rejects empty strings, invalid port numbers, or zero TTLs before any subsystem starts.

### 2. Ephemeral Store-and-Forward Relay (`src/relay.rs`)

When a recipient peer is offline, sender nodes enqueue `SealedEnvelope` items into `MailboxStore` keyed by an opaque `recipient_mailbox_id`.

```text
Sender Peer ---> [ enqueue(SealedEnvelope) ] ---> MailboxStore
                                                       |
                     +---------------------------------+
                     |
                     +---> Derive Blind Wake Token (no sender/content metadata)
                     |
Recipient Peer <-- [ drain_active(mailbox_id, now) ] <-+
```

- **TTL Enforcement**: Envelopes older than `NODE_ENVELOPE_TTL_SECONDS` are purged automatically during `purge_expired` or `drain_active`.
- **Blind Push Wake-Up Tokens**: Derives a deterministic wake token from `(recipient_mailbox_id, envelope_id, created_at_epoch_secs)` so mobile push gateways can wake devices without learning who sent the message.

### 3. Key Transparency Merkle Log (`src/merkle.rs`)

Provides an append-only ledger mapping Decentralized Identifiers (`did:sonaraim:*` and `did:web:*`) to public key commitments.

```text
                   [ Root Hash (Tree Head) ]
                         /           \
                 [ Hash(0,1) ]   [ Hash(2,3) ]
                    /     \         /     \
                  L0      L1      L2      L3
```

- Validates that every appended DID uses the `did:sonaraim:` or `did:web:` scheme.
- Computes pairwise Merkle parent hashes up to a deterministic root hash.
- Generates and verifies `InclusionProof` structures so any client can audit key history without trusting the relay node.

### 4. Health Telemetry (`src/health.rs`)

Aggregates node identity, active mailbox envelope counts, and current Key Transparency log size into a JSON payload served on `/health`.
