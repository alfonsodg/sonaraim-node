//! TDD regression tests for `sonaraim-node` #20: durable envelope queue.
//!
//! - Enqueue -> restart (fresh in-memory state, same WAL dir) -> drain still
//!   returns the envelope (envelope WAL replay, no Redis).
//! - Redis-backed queue: enqueue via RPUSH, drain via LRANGE, ack via LREM.
//! - `RedisRespClient` parses the `/db` path of `REDIS_URL` and issues
//!   `SELECT db` on connect.
//! - Redis errors surface in state (`redis_last_error`) instead of `let _`.

use sonaraim_node::config::NodeConfig;
use sonaraim_node::http_server::{start_test_server, NodeState};
use sonaraim_node::merkle::KeyTransparencyLog;
use sonaraim_node::redis_store::RedisRespClient;
use sonaraim_node::relay::MailboxStore;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

fn dev_config() -> NodeConfig {
    let mut vars = HashMap::new();
    vars.insert("NODE_ID".to_string(), "node-durable-20".to_string());
    vars.insert("NODE_HTTP_HOST".to_string(), "127.0.0.1".to_string());
    vars.insert("NODE_HTTP_PORT".to_string(), "8040".to_string());
    vars.insert(
        "NODE_P2P_LISTEN_ADDR".to_string(),
        "/ip4/127.0.0.1/udp/0/quic-v1".to_string(),
    );
    vars.insert("NODE_ENVELOPE_TTL_SECONDS".to_string(), "3600".to_string());
    vars.insert("NODE_ALLOW_DEV_NOAUTH".to_string(), "true".to_string());
    NodeConfig::from_map(&vars).expect("valid dev config")
}

fn send_http(addr: &str, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).expect("connect to test http server");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(req.as_bytes()).expect("write request");
    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read response");
    let (head, resp_body) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, resp_body.to_string())
}

#[test]
fn issue20_enqueue_restart_drain_returns_envelope_without_redis() {
    let dir = std::env::temp_dir().join(format!("sonaraim-durable20-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let signing_key = dir.join("node-signing.key");
    let identity_wal =
        sonaraim_node::storage::wal_path_from_signing_key(&signing_key.to_string_lossy());

    let state = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    let (addr, _handle) = start_test_server(state).expect("start server");
    let (st, _) = send_http(
        &addr,
        "POST",
        "/v1/relay/envelopes",
        r#"{"envelope_id":"env-durable-20","recipient_mailbox_id":"mbx-durable-20","payload_hex":"beef01"}"#,
    );
    assert_eq!(st, 202);
    drop(_handle);

    // Fresh in-memory state, same WAL dir: the envelope must survive.
    let restarted = NodeState::with_wal_and_redis(
        dev_config(),
        MailboxStore::new(3600),
        KeyTransparencyLog::default(),
        Some(identity_wal.clone()),
        None,
    );
    let (r_addr, _r_handle) = start_test_server(restarted).expect("restart server");
    let (st, body) = send_http(&r_addr, "GET", "/v1/relay/mailboxes/mbx-durable-20", "");
    assert_eq!(st, 200);
    assert!(body.contains("env-durable-20"));
    assert!(body.contains("beef01"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Minimal in-memory mock Redis speaking just enough RESP2 for the queue ops.
fn spawn_mock_redis() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock redis");
    let addr = listener.local_addr().expect("local addr").to_string();
    let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let log_clone = Arc::clone(&log);
    // Queue contents: key -> list of JSON envelope records.
    let store: Arc<Mutex<std::collections::HashMap<String, Vec<String>>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let store_clone = Arc::clone(&store);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten().take(50) {
            handle_mock_conn(stream, &log_clone, &store_clone);
        }
    });
    (addr, log)
}

fn read_resp_command(stream: &mut TcpStream) -> Vec<String> {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read array header");
    let count: usize = line
        .trim()
        .strip_prefix('*')
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut args = Vec::new();
    for _ in 0..count {
        let mut h = String::new();
        reader.read_line(&mut h).expect("read bulk header");
        let len: usize = h
            .trim()
            .strip_prefix('$')
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut buf = vec![0u8; len + 2];
        use std::io::Read;
        reader.read_exact(&mut buf).expect("read bulk");
        args.push(String::from_utf8_lossy(&buf[..len]).to_string());
    }
    args
}

fn handle_mock_conn(
    mut stream: TcpStream,
    log: &Arc<Mutex<Vec<String>>>,
    store: &Arc<Mutex<std::collections::HashMap<String, Vec<String>>>>,
) {
    loop {
        let args = read_resp_command(&mut stream);
        if args.is_empty() {
            break;
        }
        let cmd = args[0].to_ascii_uppercase();
        log.lock().expect("log").push(cmd.clone());
        match cmd.as_str() {
            "AUTH" => {
                let _ = stream.write_all(b"+OK\r\n");
            }
            "SELECT" => {
                let _ = stream.write_all(b"+OK\r\n");
            }
            "RPUSH" => {
                let mut st = store.lock().expect("store");
                let list = st.entry(args[1].clone()).or_default();
                list.push(args[2].clone());
                let reply = format!(":{}\r\n", list.len());
                let _ = stream.write_all(reply.as_bytes());
            }
            "LRANGE" => {
                let st = store.lock().expect("store");
                let list: &[String] = st.get(&args[1]).map_or(&[], Vec::as_slice);
                let mut reply = format!("*{}\r\n", list.len());
                for item in list {
                    reply.push_str(&format!("${}\r\n{item}\r\n", item.len()));
                }
                let _ = stream.write_all(reply.as_bytes());
            }
            "LREM" => {
                let mut st = store.lock().expect("store");
                let mut removed = 0u64;
                // LREM key count value -> value is args[3] when count is present.
                let needle = args
                    .get(3)
                    .or_else(|| args.get(2))
                    .cloned()
                    .unwrap_or_default();
                if let Some(list) = st.get_mut(&args[1]) {
                    let before = list.len();
                    list.retain(|v| v != &needle);
                    removed = (before - list.len()) as u64;
                }
                let _ = stream.write_all(format!(":{removed}\r\n").as_bytes());
            }
            "DEL" => {
                let _ = stream.write_all(b":1\r\n");
            }
            _ => {
                let _ = stream.write_all(b"+OK\r\n");
            }
        }
    }
}

#[test]
fn issue20_redis_queue_round_trip_rpush_lrange_lrem() {
    let (addr, _log) = spawn_mock_redis();
    let client = RedisRespClient::from_url(&format!("redis://{addr}/3")).expect("parse url");
    let record = "{\"envelope_id\":\"env-r-1\",\"x\":1}".to_string();
    assert_eq!(client.rpush("sonaraim:q:mbx", &record).expect("rpush"), 1);
    let items = client.lrange("sonaraim:q:mbx").expect("lrange");
    assert_eq!(items, vec![record.clone()]);
    assert_eq!(client.lrem("sonaraim:q:mbx", &record).expect("lrem"), 1);
    assert!(client.lrange("sonaraim:q:mbx").expect("lrange2").is_empty());
}

#[test]
fn issue20_redis_url_db_select_is_honored() {
    let (addr, log) = spawn_mock_redis();
    let client = RedisRespClient::from_url(&format!("redis://{addr}/5")).expect("parse url");
    client
        .rpush("sonaraim:q:k", "{\"a\":1}")
        .expect("rpush with db");
    // Give the mock thread a moment to record commands.
    for _ in 0..50 {
        if log.lock().expect("log").contains(&"RPUSH".to_string()) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let seen = log.lock().expect("log").clone();
    assert!(
        seen.contains(&"SELECT".to_string()),
        "expected SELECT after connect, got {seen:?}"
    );
    assert!(seen.contains(&"RPUSH".to_string()));
}
