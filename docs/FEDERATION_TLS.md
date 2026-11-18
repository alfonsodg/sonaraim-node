# Federation TLS Termination (`sonaraim-node`)

> How nodes speak TLS to each other through Nginx ingress.

`sonaraim-node` serves plaintext HTTP on `NODE_HTTP_HOST:NODE_HTTP_PORT`.
TLS is terminated at Nginx in front of every node. Node-to-node replication
targets the peer's **public `https://` RPC URL**; the Rust federation client
(`src/federation_client.rs`) negotiates TLS with WebPKI roots and sends each
peer's configured Bearer token (`PeerRecord::auth_token`).

## Topology

```text
node-a (http :8040) ---> https://node-b.example.com ---> [nginx:443] ---> node-b (http 127.0.0.1:8040)
```

- Nginx holds the certificate and private key for the peer's public hostname.
- The node itself never sees TLS bytes; it keeps serving plaintext loopback HTTP.
- Redis and gossip UDP traffic stay inside the private network and are not
  part of the TLS story.

## Minimal Nginx server block (per node)

```nginx
upstream sonaraim_node { server 127.0.0.1:8040; }

server {
    listen 443 ssl;
    server_name node-b.example.com;

    ssl_certificate     /etc/nginx/tls/node-b.example.com/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/node-b.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://sonaraim_node;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }
}
```

## Registering a TLS peer

```http
POST /v1/p2p/peers
Authorization: Bearer <NODE_API_AUTH_TOKEN>

{
  "peer_id": "node-b",
  "rpc_url": "https://node-b.example.com",
  "multiaddr": "/ip4/10.0.0.2/udp/4001/quic-v1",
  "auth_token": "<node-b NODE_API_AUTH_TOKEN>"
}
```

- `rpc_url` may be `http://` (direct, private networks only) or `https://`
  (through the peer's Nginx ingress).
- `auth_token` is the peer's `NODE_API_AUTH_TOKEN`; every replication call to
  that peer carries `Authorization: Bearer <auth_token>`. Without it, an
  auth-enabled peer answers `401` and the replication is logged as failed.
- `https://` URLs without an explicit port default to `443`.

## Operational notes

- Rotate peer tokens by reissuing `NODE_API_AUTH_TOKEN` on the peer and
  updating `auth_token` with a fresh `POST /v1/p2p/peers`.
- Certificate renewal is an Nginx concern (e.g. certbot); the node needs no
  restart when certificates rotate.
- Replication I/O failures (TCP, TLS, HTTP) are logged as structured JSON
  errors; gossip equivocation conflicts are returned to the caller as `409`.
