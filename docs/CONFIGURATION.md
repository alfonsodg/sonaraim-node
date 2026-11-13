# Configuration Guide (`sonaraim-node`)

> Environment Variable Specification and Zero-Hardcode Configuration Reference.

`sonaraim-node` enforces a strict zero-hardcode policy. No default hostnames, ports, timeouts, or credentials exist in the compiled binary. All parameters must be explicitly configured via process environment variables.

---

## 1. Core Runtime Variables

| Variable | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `NODE_ID` | `String` | Yes | Unique logical identifier for this relay node instance. | `node-primary-01` |
| `NODE_HTTP_HOST` | `String` | Yes | Bind address for the HTTP server (`/health`, `/metrics`, API). | `0.0.0.0` |
| `NODE_HTTP_PORT` | `u16` | Yes | TCP port for the HTTP server (`1..=65535`). | `8040` |
| `NODE_P2P_LISTEN_ADDR` | `String` | Yes | `libp2p` multiaddr for QUIC/WebTransport connections (must start with `/`). | `/ip4/0.0.0.0/udp/4001/quic-v1` |
| `NODE_ENVELOPE_TTL_SECONDS` | `u64` | Yes | Maximum retention time in seconds for queued envelopes (`> 0`). | `604800` |

---

## 2. Authentication & Security Variables

| Variable | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `NODE_API_AUTH_TOKEN` | `String` | No | Secret Bearer token protecting write endpoints (`POST /v1/relay/envelopes`, `POST /v1/identity`, `POST /v1/p2p/peers`, etc.). | `secret-bearer-token-1234` |
| `NODE_SIGNING_KEY_PATH` | `String` | No | Path to the node's Ed25519 private key for signing tree heads and deriving the WAL path (`<key>.wal`). | `/var/lib/sonaraim/node-signing.key` |

---

## 3. Storage, Cache & Media Variables

| Variable | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `REDIS_URL` | `String` | No | Redis connection URL for ephemeral queue caching and RESP operations. | `redis://:secret@redis:6379/0` |
| `S3_ENDPOINT_URL` | `String` | No | Endpoint URL for S3/MinIO presigned media uploads and object storage. | `http://minio:9000` |
| `S3_BUCKET_MEDIA` | `String` | No | S3 bucket name for client-side encrypted media attachments. | `sonaraim-media` |
| `S3_BUCKET_VAULT` | `String` | No | S3 bucket name for Passkey Zero-Knowledge vaults. | `sonaraim-vault` |
| `S3_ACCESS_KEY_ID` | `String` | No | S3 access key ID for presigning and storage operations. | `minioadmin` |
| `S3_SECRET_ACCESS_KEY` | `String` | No | S3 secret access key for presigning and storage operations. | `miniopassword` |

---

## 4. Gossip & Federation Variables

| Variable | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `NODE_P2P_PORT` | `u16` | No | UDP port exposed for peer-to-peer gossip datagrams. | `9031` |
| `NODE_BOOTSTRAP_PEERS` | `String` | No | Comma-separated list of bootstrap peer multiaddrs for initial mesh discovery. | `/ip4/10.0.0.2/udp/4001/quic-v1,/ip4/10.0.0.3/udp/4001/quic-v1` |

---

## 5. L2 Anchoring Variables (Optional)

| Variable | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `NODE_L2_ANCHOR_ENABLED` | `bool` | No | Whether periodic Merkle tree root anchoring to an L2 RPC is enabled (`true`/`false`). | `false` |
| `NODE_L2_RPC_URL` | `String` | Cond. | L2 JSON-RPC endpoint (required if `NODE_L2_ANCHOR_ENABLED=true`). | `https://rpc.arbitrum.example.com` |

---

## 6. Validation Behavior

When `NodeConfig::from_env()` or `NodeConfig::from_map()` executes:

1. Any missing or empty core variable triggers `ConfigError::MissingVariable(name)`.
2. A non-numeric or zero `NODE_HTTP_PORT` triggers `ConfigError::InvalidValue`.
3. A non-numeric or zero `NODE_ENVELOPE_TTL_SECONDS` triggers `ConfigError::InvalidValue`.
4. A `NODE_P2P_LISTEN_ADDR` that does not start with `/` triggers `ConfigError::InvalidValue`.
