//! std-threaded HTTP federation client with per-peer Bearer auth and TLS.
//!
//! Extracted from the P2P route handlers so replication can be tested and
//! reused independently. Plain `http://` peer URLs use direct TCP;
//! `https://` peer URLs are negotiated with rustls (WebPKI roots) so nodes
//! behind TLS-terminating Nginx ingress can federate.

use crate::p2p::PeerRecord;
use crate::storage::{extract_json_str, StorageError};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

/// Parsed peer endpoint: scheme-aware host, path, and TLS flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    /// `true` for `https://` URLs (TLS), `false` for `http://`.
    pub use_tls: bool,
    /// Server name for TLS verification (host without port).
    pub server_name: String,
    /// `host:port` used for the TCP connection.
    pub host_port: String,
    /// HTTP path including the leading `/`.
    pub path: String,
}

/// Splits an `http(s)://host[:port][/path]` URL into a [`PeerEndpoint`].
///
/// # Errors
///
/// Returns [`StorageError`] when the scheme is not `http`/`https` or no host
/// is present.
pub fn split_url(url: &str) -> Result<PeerEndpoint, StorageError> {
    let (use_tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(StorageError::Io(
            "peer url must start with http:// or https://".to_string(),
        ));
    };
    let (hp, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}")));
    if hp.is_empty() {
        return Err(StorageError::Io("peer url has empty host".to_string()));
    }
    let host_port = if hp.contains(':') {
        hp.to_string()
    } else if use_tls {
        format!("{hp}:443")
    } else {
        format!("{hp}:80")
    };
    let server_name = host_port
        .rsplit_once(':')
        .map_or(host_port.clone(), |(h, _)| h.to_string());
    Ok(PeerEndpoint {
        use_tls,
        server_name,
        host_port,
        path,
    })
}

/// Builds the `Authorization: Bearer <token>` header line, if a token is set.
fn bearer_header_line(auth_token: Option<&str>) -> String {
    auth_token
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map_or_else(String::new, |t| format!("Authorization: Bearer {t}\r\n"))
}

/// Executes a synchronous HTTP request against `url` using TCP (or TLS for
/// `https://`), returning `(status_code, response_body)`.
///
/// # Errors
///
/// Returns a [`String`] describing DNS, TCP, TLS, or protocol failures.
pub fn execute_http_request(
    method: &str,
    url: &str,
    body: &str,
    auth_token: Option<&str>,
    timeout_ms: u64,
) -> Result<(u16, String), String> {
    let endpoint = split_url(url).map_err(|e| e.to_string())?;
    let dur = Duration::from_millis(timeout_ms.max(50));
    let mut addrs = endpoint
        .host_port
        .to_socket_addrs()
        .map_err(|e| e.to_string())?;
    let addr = addrs
        .next()
        .ok_or_else(|| "no address resolved".to_string())?;
    let stream = TcpStream::connect_timeout(&addr, dur).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {hp}\r\n{auth}Content-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        path = endpoint.path,
        hp = endpoint.host_port,
        auth = bearer_header_line(auth_token),
        len = body.len(),
    );
    if endpoint.use_tls {
        let mut tls = tls_client(&endpoint.server_name, stream).map_err(|e| e.to_string())?;
        tls.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        tls.flush().map_err(|e| e.to_string())?;
        let text = read_response_tls(&mut tls)?;
        Ok(split_http_response(&text))
    } else {
        let mut stream = stream;
        stream
            .write_all(req.as_bytes())
            .map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;
        let text = read_response_plain(&mut stream)?;
        Ok(split_http_response(&text))
    }
}

/// Establishes a rustls TLS 1.2+ session over an already-connected TCP stream.
fn tls_client(
    server_name: &str,
    stream: TcpStream,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, rustls::Error> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name: rustls::pki_types::ServerName<'static> = server_name
        .to_string()
        .try_into()
        .map_err(|_| rustls::Error::General("invalid DNS name".to_string()))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)?;
    Ok(rustls::StreamOwned::new(conn, stream))
}

/// Reads a full HTTP response from a TLS stream until close or error.
fn read_response_tls(
    tls: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
) -> Result<String, String> {
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    Ok(String::from_utf8_lossy(&resp).into_owned())
}

/// Reads a full HTTP response from a plaintext stream until close or error.
fn read_response_plain(stream: &mut TcpStream) -> Result<String, String> {
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&buf[..n]),
            Err(_) => break,
        }
    }
    Ok(String::from_utf8_lossy(&resp).into_owned())
}

/// Splits a raw HTTP response into `(status_code, body)` without panicking.
fn split_http_response(text: &str) -> (u16, String) {
    let (head, resp_body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

/// Replicates an envelope across all registered peer nodes without looping.
///
/// Each peer receives its own configured Bearer token (`PeerRecord::auth_token`).
pub fn replicate_envelope_to_peers(
    peers: &[PeerRecord],
    env_id: &str,
    mbx: &str,
    payload_hex: &str,
) {
    let body = format!(
        "{{\"envelope_id\":\"{env_id}\",\"recipient_mailbox_id\":\"{mbx}\",\"payload_hex\":\"{payload_hex}\",\"replicated\":true}}"
    );
    for peer in peers {
        if !peer.rpc_url.is_empty() {
            let url = format!("{}/v1/relay/envelopes", peer.rpc_url.trim_end_matches('/'));
            let token = peer.auth_token.as_deref();
            match execute_http_request("POST", &url, &body, token, 1000) {
                Ok(_) => {}
                Err(e) => eprintln!(
                    "{{\"level\":\"ERROR\",\"msg\":\"envelope replication failed\",\"peer\":\"{}\",\"error\":\"{e}\"}}",
                    peer.peer_id
                ),
            }
        }
    }
}

/// Replicates an identity binding and new `SignedTreeHead` to registered peers.
///
/// Gossip equivocation conflicts are returned as `Err` for the caller to surface.
pub fn replicate_identity_to_peers(
    peers: &[PeerRecord],
    did: &str,
    commit: &str,
    phone_token: Option<&str>,
    sth: &crate::p2p::SignedTreeHead,
) -> Result<(), String> {
    let gossip_body = crate::udp_gossip::encode_tree_head_json(sth);
    let p_field = phone_token.map_or_else(String::new, |t| format!(",\"phone_token\":\"{t}\""));
    let id_body = format!(
        "{{\"did\":\"{did}\",\"key_commitment\":\"{commit}\"{p_field},\"replicated\":true}}"
    );
    for peer in peers {
        if !peer.rpc_url.is_empty() {
            let base = peer.rpc_url.trim_end_matches('/');
            let token = peer.auth_token.as_deref();
            let g_url = format!("{base}/v1/p2p/gossip");
            match execute_http_request("POST", &g_url, &gossip_body, token, 1000) {
                Ok((409, resp)) => {
                    return Err(format!("equivocation on peer {}: {resp}", peer.peer_id));
                }
                Ok(_) => {}
                Err(e) => eprintln!(
                    "{{\"level\":\"ERROR\",\"msg\":\"gossip replication failed\",\"peer\":\"{}\",\"error\":\"{e}\"}}",
                    peer.peer_id
                ),
            }
            let id_url = format!("{base}/v1/identity");
            match execute_http_request("POST", &id_url, &id_body, token, 1000) {
                Ok(_) => {}
                Err(e) => eprintln!(
                    "{{\"level\":\"ERROR\",\"msg\":\"identity replication failed\",\"peer\":\"{}\",\"error\":\"{e}\"}}",
                    peer.peer_id
                ),
            }
        }
    }
    Ok(())
}

/// Extracts the Bearer token for `peer_id` from a `POST /v1/p2p/peers` body.
#[must_use]
pub fn extract_peer_auth_token(body: &str) -> Option<String> {
    extract_json_str(body, "auth_token")
}
