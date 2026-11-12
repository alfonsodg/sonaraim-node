//! Core library for `sonaraim-node`.
//!
//! Exports the zero-hardcode configuration loader, ephemeral P2P store-and-forward
//! mailbox relay, Key Transparency Merkle tree log, and health status serializer.

pub mod config;
pub mod health;
pub mod merkle;
pub mod relay;
