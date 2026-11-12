# Architecture Diagrams (`sonaraim-node`)

> Mermaid Component, Sequence, and State Visualizations

## Node Module Topology

```mermaid
flowchart TD
    Env["Environment Variables"] --> Config["NodeConfig::from_env()"]
    Config --> Relay["MailboxStore (Ephemeral Relay)"]
    Config --> KT["KeyTransparencyLog (Merkle Tree)"]
    Relay --> Health["HealthStatus::to_json()"]
    KT --> Health
```

## Ephemeral Store-and-Forward Sequence

```mermaid
sequenceDiagram
    participant S as Sender Peer
    participant N as sonaraim-node (MailboxStore)
    participant P as Blind Push Gateway
    participant R as Recipient Peer

    S->>N: enqueue(SealedEnvelope)
    N->>N: Verify TTL and store under mailbox_id
    N->>P: Emit blind wake_token (no sender identity)
    R->>N: drain_active(mailbox_id, current_epoch_secs)
    N->>N: Purge expired envelopes
    N-->>R: Return active SealedEnvelope list
```

## Key Transparency Inclusion Proof Flow

```mermaid
sequenceDiagram
    participant C as Client / Auditor
    participant K as KeyTransparencyLog

    C->>K: append(did:sonaraim / did:web, public_key_commitment, epoch)
    K->>K: Compute leaf hash and update Merkle Tree Head
    K-->>C: Return leaf_index and tree_head
    C->>K: generate_inclusion_proof(leaf_index)
    K-->>C: InclusionProof (sibling hashes + directions)
    C->>C: verify_inclusion_proof(proof, leaf_hash, tree_head)
```
