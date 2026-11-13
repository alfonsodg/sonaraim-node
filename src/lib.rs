//! Core library for `sonaraim-node`.
//!
//! Exports the zero-hardcode configuration loader, ephemeral P2P store-and-forward
//! mailbox relay, Key Transparency Merkle tree log, P2P mesh gossip, live UDP gossip
//! and `did:web` verifier, durable snapshot and WAL storage, Redis RESP client,
//! PSI blind service, HTTP auth/routing helpers, HTTP REST server, and health status serializer.

pub mod config;
pub mod health;
pub mod http_auth;
pub mod http_federation;
pub mod http_identity;
pub mod http_relay;
pub mod http_server;
pub mod merkle;
pub mod p2p;
pub mod psi_service;
pub mod push_signals;
pub mod redis_store;
pub mod relay;
pub mod s3_wal_maintenance;
pub mod storage;
pub mod udp_gossip;

pub use s3_wal_maintenance::{compact_wal_file, put_s3_object_http};
