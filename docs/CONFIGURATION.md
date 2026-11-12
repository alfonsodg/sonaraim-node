# Configuration Guide (`sonaraim-node`)

> Environment Variable Specification and Validation Rules

`sonaraim-node` enforces a strict zero-hardcode policy. No default hostnames, ports, or TTL constants exist in the binary. Every required environment variable must be explicitly provided before startup.

## Environment Variables

| Variable | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `NODE_ID` | `String` | Yes | Unique logical identifier for this relay node instance. | `node-primary-01` |
| `NODE_HTTP_HOST` | `String` | Yes | Bind address for the HTTP `/health` and diagnostics endpoint. | `0.0.0.0` |
| `NODE_HTTP_PORT` | `u16` | Yes | TCP port for the HTTP `/health` endpoint (`1..=65535`). | `8040` |
| `NODE_P2P_LISTEN_ADDR` | `String` | Yes | libp2p multiaddr where the node listens for P2P connections. | `/ip4/0.0.0.0/tcp/4001` |
| `NODE_ENVELOPE_TTL_SECONDS` | `u64` | Yes | Maximum lifetime in seconds for queued `SealedEnvelope` items (`> 0`). | `604800` |

## Validation Behavior

When `NodeConfig::from_env()` executes:

1. Any missing or whitespace-only variable triggers `ConfigError::MissingVariable(name)`.
2. A non-numeric or zero `NODE_HTTP_PORT` triggers `ConfigError::InvalidValue { key, reason }`.
3. A non-numeric or zero `NODE_ENVELOPE_TTL_SECONDS` triggers `ConfigError::InvalidValue { key, reason }`.
4. A `NODE_P2P_LISTEN_ADDR` not starting with `/` triggers `ConfigError::InvalidValue { key, reason }`.

## Sample `.env` Setup

See `samples/.env.example` for a ready-to-copy template and `configs/node.example.toml` for the declarative configuration mapping.
