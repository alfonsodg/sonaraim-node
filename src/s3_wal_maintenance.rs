//! S3/MinIO HTTP PUT object uploader and atomic WAL file compaction.

use crate::storage::StorageError;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Atomically rewrites a Write-Ahead Log (WAL) file via a temporary file,
/// retaining only the provided active unacknowledged entries.
///
/// Returns the number of entries written.
pub fn compact_wal_file(
    path: &Path,
    active_entries: &[(String, String, String)],
) -> Result<usize, StorageError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| StorageError::Io(e.to_string()))?;
        }
    }
    let tmp_path = PathBuf::from(format!("{}.tmp", path.display()));
    let mut file = fs::File::create(&tmp_path).map_err(|e| StorageError::Io(e.to_string()))?;
    for (env_id, recipient, payload) in active_entries {
        let line = format!(
            "{{\"envelope_id\":\"{env_id}\",\"recipient_mailbox_id\":\"{recipient}\",\"payload_hex\":\"{payload}\"}}\n"
        );
        file.write_all(line.as_bytes())
            .map_err(|e| StorageError::Io(e.to_string()))?;
    }
    file.flush().map_err(|e| StorageError::Io(e.to_string()))?;
    file.sync_all()
        .map_err(|e| StorageError::Io(e.to_string()))?;
    drop(file);

    fs::rename(&tmp_path, path).map_err(|e| StorageError::Io(e.to_string()))?;
    Ok(active_entries.len())
}

/// Performs an HTTP PUT upload of `payload` object bytes against an S3 or MinIO endpoint.
///
/// Returns the HTTP status code (e.g. 200, 201) returned by the S3 server.
pub fn put_s3_object_http(
    endpoint_url: &str,
    bucket: &str,
    object_key: &str,
    payload: &[u8],
    timeout_ms: u64,
) -> Result<u16, StorageError> {
    let trimmed = endpoint_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    let host_port = match trimmed.split_once('/') {
        Some((hp, _)) => hp,
        None => trimmed,
    };
    let addr_str = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };

    let dur = Duration::from_millis(timeout_ms.max(50));
    let mut addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| StorageError::Io(e.to_string()))?;
    let addr = addrs
        .next()
        .ok_or_else(|| StorageError::Io("no address resolved".to_string()))?;

    let mut stream =
        TcpStream::connect_timeout(&addr, dur).map_err(|e| StorageError::Io(e.to_string()))?;
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let clean_key = object_key.trim_start_matches('/');
    let header = format!(
        "PUT /{bucket}/{clean_key} HTTP/1.1\r\nHost: {host_port}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|e| StorageError::Io(e.to_string()))?;
    stream
        .write_all(payload)
        .map_err(|e| StorageError::Io(e.to_string()))?;
    stream
        .flush()
        .map_err(|e| StorageError::Io(e.to_string()))?;

    let mut resp = [0u8; 2048];
    let n = stream
        .read(&mut resp)
        .map_err(|e| StorageError::Io(e.to_string()))?;
    let text = String::from_utf8_lossy(&resp[..n]);
    let first_line = text.lines().next().unwrap_or_default();
    let mut parts = first_line.split_whitespace();
    parts.next(); // skip HTTP version
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| StorageError::Io("invalid HTTP response line".to_string()))
}
