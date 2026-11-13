# Security Policy (`sonaraim-node`)

## 1. Supported Versions

Security updates and patches are actively provided for the following releases:

| Version | Supported | Security Policy |
| :--- | :--- | :--- |
| `develop` | :white_check_mark: Yes | Bleeding edge; security fixes land here first |
| `0.1.x` | :white_check_mark: Yes | Current minor release series |
| `< 0.1.0` | :x: No | Unsupported pre-release builds |

---

## 2. Reporting a Vulnerability

The Sonaraim engineering team treats all security issues with top priority. We request that all security reports be handled through coordinated responsible disclosure.

### Reporting Procedure

- **Email**: Send vulnerability reports directly to [security@sonaraim.org](mailto:security@sonaraim.org).
- **PGP Encryption**: For proof-of-concept exploits, please encrypt your message with the Sonaraim Security PGP Key (`https://sonaraim.org/security.asc`).
- **Required Details**:
  - Clear summary of the issue and affected route or subsystem.
  - Steps to reproduce or a minimal proof-of-concept test.
  - Impact assessment on message confidentiality, node availability, or identity integrity.

### Response SLAs

- **Initial Acknowledgment**: Within **24 hours**.
- **Triage & Classification**: Within **48 hours**.
- **Remediation & Patch Target**: Critical severity issues are patched within **7 days**; high severity issues within **14 days**.
- **Coordinated Disclosure**: We request a **90-day embargo** from initial notification before public release.

---

## 3. Threat Model & Zero-Trust Scope

`sonaraim-node` operates under a zero-trust model where the relay node itself is an untrusted intermediary.

### 3.1 Zero Plaintext Access & Sealed Sender Routing

- **Metadata Minimization**: Relays route messages using opaque `mailbox_id` tokens. Nodes never inspect envelope contents, MLS group ratchets, or sender identities.
- **Payload Encryption**: All message bodies are sealed via HPKE (RFC 9180) and MLS 1.0 (RFC 9420). Nodes possess neither private unsealing keys nor group ratchet secrets.
- **Ephemeral Storage**: Undelivered envelopes are retained in memory/WAL only until delivered or TTL expiration (`NODE_ENVELOPE_TTL_SECONDS`), then permanently evicted.

### 3.2 Key Transparency & Equivocation Defense

- **Append-Only Merkle Log**: Public identity key commitments (`did:web` and `did:sonaraim`) are recorded in an append-only cryptographic tree log.
- **Gossip & Fork Detection**: Nodes exchange `SignedTreeHead` datagrams over UDP (`/v1/p2p/gossip`) to detect equivocation (split-brain attacks where a compromised node presents different tree heads to different clients).
- **Inclusion Proofs**: Clients verify `KeyTransparencyLog` inclusion proofs before establishing new MLS sessions.

### 3.3 Private Set Intersection (PSI) Privacy

- **Blind Matching**: Contact discovery via `POST /v1/contacts/psi` uses blinded token evaluations. The server evaluates tokens against registered phone hashes without learning non-matching contact phone numbers or social graphs.

### 3.4 Storage & Media Security

- **Encrypted Media Presigning**: S3/MinIO upload URLs generated via `POST /v1/media/presign` accept only client-side encrypted blobs. Decryption keys are shared out-of-band inside end-to-end encrypted MLS messages.
- **Atomic WAL Compaction**: Write-Ahead Logs are compacted atomically to prevent envelope resurrects or data corruption across restarts.

---

## 4. Out-of-Scope Vulnerabilities

- Physical host or hypervisor compromise of node hardware.
- Volumetric network denial of service (DDoS) mitigated by edge reverse proxies (Nginx/Cloudflare).
- Vulnerabilities arising from running modified binaries with disabled security flags.
