# System Diagrams (`sonaraim-node`)

> Mermaid sequence, topology, and state diagrams for `sonaraim-node`.

---

## 1. Store-and-Forward Envelope Relay Flow

```mermaid
sequenceDiagram
    autonumber
    participant Sender as Client / B2B Gateway
    participant Node as sonaraim-node (Relay)
    participant Push as Mobile Push Gateway (APNs/FCM)
    participant Recipient as Recipient Device

    Sender->>Node: POST /v1/relay/envelopes (Bearer Auth)
    Node->>Node: Validate mailbox_id, TTL, and 32B X25519 key
    Node->>Node: Persist to active queue and WAL
    Node->>Push: Dispatch Blind Wake Token (zero payload)
    Push->>Recipient: Background wake signal
    Recipient->>Node: GET /v1/relay/mailboxes/{mailbox_id}
    Node-->>Recipient: Return queued envelopes
    Recipient->>Node: POST /v1/relay/mailboxes/{mailbox_id}/ack (envelope_ids)
    Node->>Node: Evict envelopes & trigger compact_wal_file()
    Node-->>Recipient: 200 OK (acknowledged)
```

---

## 2. Key Transparency Merkle Append & Proof Verification

```mermaid
sequenceDiagram
    autonumber
    participant Client as User / Merchant Client
    participant Node as sonaraim-node
    participant Log as KeyTransparencyLog

    Client->>Node: POST /v1/identity (did, key_commitment)
    Node->>Log: append(did, key_commitment, epoch_secs)
    Log-->>Node: (leaf_index, tree_head_hash)
    Node-->>Client: 201 Created (leaf_index, tree_head)

    Note over Client,Node: Later, a third-party queries the identity

    Client->>Node: GET /v1/identity/{did}
    Node->>Log: generate_proof(leaf_index)
    Log-->>Node: InclusionProof(root_hash, audit_path)
    Node-->>Client: 200 OK (did, key_commitment, merkle_proof)
    Client->>Client: verify_proof(merkle_proof) against gossiped SignedTreeHead
```

---

## 3. Live UDP Gossip & Equivocation Detection

```mermaid
sequenceDiagram
    autonumber
    participant NodeA as sonaraim-node (Alpha)
    participant UDP as UdpGossipNode Socket
    participant NodeB as sonaraim-node (Beta)

    NodeA->>UDP: send_sth(SignedTreeHead(tree_size=10, root=H1))
    UDP->>NodeB: UDP Datagram -> POST /v1/p2p/gossip
    NodeB->>NodeB: ingest_gossip_json(SignedTreeHead)
    NodeB->>NodeB: Check observed_heads(tree_size=10)
    alt Same Root Hash H1
        NodeB-->>UDP: 200 OK (ingested, equivocation_detected=false)
    else Conflicting Root Hash H2
        NodeB-->>UDP: 409 Conflict (EQUIVOCATION_DETECTED)
        NodeB->>NodeB: Flag NodeA peer as compromised
    end
```

---

## 4. Private Set Intersection (PSI) Matching Flow

```mermaid
sequenceDiagram
    autonumber
    participant App as sonaraim-app Mobile Client
    participant Node as sonaraim-node (PSI Service)

    App->>App: Normalize address book phone numbers (E.164)
    App->>App: Blind phone hashes with client secret
    App->>Node: POST /v1/contacts/psi (blinded_tokens)
    Node->>Node: Match blinded tokens against phone_index
    Node-->>App: 200 OK (matched tokens and registered DIDs)
    App->>App: Unblind matches and update local contact list
```

---

## 5. Atomic WAL Compaction Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Relay as MailboxStore
    participant Maint as s3_wal_maintenance
    participant Disk as Local Storage

    Relay->>Maint: compact_wal_file(wal_path, active_entries)
    Maint->>Disk: Create temp file wal_path.tmp.<pid>
    loop For each active entry
        Maint->>Disk: Serialize JSON line with trailing newline
    end
    Maint->>Disk: fsync() temp file
    Maint->>Disk: atomic rename(wal_path.tmp, wal_path)
    Maint-->>Relay: Ok(written_count)
```
