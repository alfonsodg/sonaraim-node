//! Zero-dependency Redis RESP2 TCP client for `sonaraim-node` mailbox synchronization.
//!
//! Supports `REDIS_URL` parsing (`redis://[:password@]host:port[/db]`), `AUTH`,
//! `SET key val EX ttl`, `GET key`, and `DEL key`.

use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Errors returned by [`RedisRespClient`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisError {
    /// The `REDIS_URL` string could not be parsed.
    InvalidUrl(String),
    /// Network or protocol error while communicating with Redis.
    Io(String),
    /// Redis server returned an `-ERR` reply.
    ServerError(String),
}

impl fmt::Display for RedisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "invalid REDIS_URL: {msg}"),
            Self::Io(msg) => write!(f, "redis I/O error: {msg}"),
            Self::ServerError(msg) => write!(f, "redis server error: {msg}"),
        }
    }
}

impl std::error::Error for RedisError {}

/// Lightweight TCP client speaking Redis Serialization Protocol (RESP2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisRespClient {
    /// Host and port string (`host:port`).
    pub host_port: String,
    /// Optional password parsed from `REDIS_URL`.
    pub password: Option<String>,
    /// Logical database index parsed from the `/db` path of `REDIS_URL` (default 0).
    pub db: u8,
}

impl RedisRespClient {
    /// Parses a `REDIS_URL` (`redis://[:password@]host:port[/db]`) into a [`RedisRespClient`].
    ///
    /// The optional `/db` path selects the logical database via `SELECT` on connect.
    pub fn from_url(url: &str) -> Result<Self, RedisError> {
        let without_scheme = url
            .trim()
            .strip_prefix("redis://")
            .ok_or_else(|| RedisError::InvalidUrl("must start with redis://".to_string()))?;
        let (authority, db) = match without_scheme.split_once('/') {
            Some((auth, db_str)) if !db_str.trim().is_empty() => {
                let parsed = db_str.trim().parse::<u8>().map_err(|_| {
                    RedisError::InvalidUrl("db path must be an integer 0-255".to_string())
                })?;
                (auth, parsed)
            }
            _ => (
                without_scheme.split('/').next().unwrap_or(without_scheme),
                0,
            ),
        };
        if authority.is_empty() {
            return Err(RedisError::InvalidUrl("empty authority".to_string()));
        }
        let (password, host_port) = if let Some((userinfo, hp)) = authority.rsplit_once('@') {
            let pass = userinfo.strip_prefix(':').unwrap_or(userinfo);
            let pwd = (!pass.is_empty()).then(|| pass.to_string());
            (pwd, hp.to_string())
        } else {
            (None, authority.to_string())
        };
        if !host_port.contains(':') {
            return Err(RedisError::InvalidUrl("missing :port".to_string()));
        }
        Ok(Self {
            host_port,
            password,
            db,
        })
    }

    /// Executes `SET key value EX ttl_seconds` on the Redis server.
    pub fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), RedisError> {
        let mut reader = self.connect_and_auth()?;
        let ttl_str = ttl_seconds.to_string();
        send_resp_array(reader.get_mut(), &["SET", key, value, "EX", &ttl_str])?;
        let line = read_line(&mut reader)?;
        line.starts_with("+OK")
            .then_some(())
            .ok_or(RedisError::ServerError(line))
    }

    /// Executes `GET key` on the Redis server and returns `Ok(Some(val))` or `Ok(None)`.
    pub fn get(&self, key: &str) -> Result<Option<String>, RedisError> {
        let mut reader = self.connect_and_auth()?;
        send_resp_array(reader.get_mut(), &["GET", key])?;
        let header = read_line(&mut reader)?;
        if header.starts_with("$-1") {
            return Ok(None);
        }
        if let Some(len_str) = header.strip_prefix('$') {
            let len = len_str
                .trim()
                .parse::<usize>()
                .map_err(|_| RedisError::Io("invalid bulk length".to_string()))?;
            let mut buf = vec![0u8; len + 2];
            reader
                .read_exact(&mut buf)
                .map_err(|e| RedisError::Io(e.to_string()))?;
            return Ok(Some(String::from_utf8_lossy(&buf[..len]).to_string()));
        }
        Err(RedisError::ServerError(header))
    }

    /// Executes `RPUSH key value` and returns the list length after the push.
    pub fn rpush(&self, key: &str, value: &str) -> Result<u64, RedisError> {
        let mut reader = self.connect_and_auth()?;
        send_resp_array(reader.get_mut(), &["RPUSH", key, value])?;
        read_integer_reply(&mut reader)
    }

    /// Executes `LRANGE key 0 -1` and returns every list element in order.
    pub fn lrange(&self, key: &str) -> Result<Vec<String>, RedisError> {
        let mut reader = self.connect_and_auth()?;
        send_resp_array(reader.get_mut(), &["LRANGE", key, "0", "-1"])?;
        let header = read_line(&mut reader)?;
        if header.starts_with("*-1") || header.starts_with("*0") {
            return Ok(Vec::new());
        }
        let count: usize = header
            .strip_prefix('*')
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| RedisError::Io("invalid array reply".to_string()))?;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let bulk = read_line(&mut reader)?;
            let len: usize = bulk
                .strip_prefix('$')
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| RedisError::Io("invalid bulk length".to_string()))?;
            let mut buf = vec![0u8; len + 2];
            reader
                .read_exact(&mut buf)
                .map_err(|e| RedisError::Io(e.to_string()))?;
            out.push(String::from_utf8_lossy(&buf[..len]).to_string());
        }
        Ok(out)
    }

    /// Executes `LREM key 0 value` and returns the count of removed elements.
    pub fn lrem(&self, key: &str, value: &str) -> Result<u64, RedisError> {
        let mut reader = self.connect_and_auth()?;
        send_resp_array(reader.get_mut(), &["LREM", key, "0", value])?;
        read_integer_reply(&mut reader)
    }

    /// Executes `DEL key` on the Redis server and returns the count of removed keys.
    pub fn del(&self, key: &str) -> Result<u64, RedisError> {
        let mut reader = self.connect_and_auth()?;
        send_resp_array(reader.get_mut(), &["DEL", key])?;
        let line = read_line(&mut reader)?;
        line.strip_prefix(':')
            .ok_or_else(|| RedisError::ServerError(line.clone()))?
            .trim()
            .parse::<u64>()
            .map_err(|_| RedisError::Io("invalid integer reply".to_string()))
    }

    /// Returns the logical database index parsed from `REDIS_URL`.
    #[must_use]
    pub fn db(&self) -> u8 {
        self.db
    }

    fn connect_and_auth(&self) -> Result<BufReader<TcpStream>, RedisError> {
        let addr: SocketAddr = self
            .host_port
            .to_socket_addrs()
            .map_err(|e| RedisError::Io(e.to_string()))?
            .next()
            .ok_or_else(|| RedisError::Io("resolved no socket addresses".to_string()))?;
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .map_err(|e| RedisError::Io(e.to_string()))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let mut reader = BufReader::new(stream);
        if let Some(pass) = &self.password {
            send_resp_array(reader.get_mut(), &["AUTH", pass])?;
            let reply = read_line(&mut reader)?;
            if !reply.starts_with("+OK") {
                return Err(RedisError::ServerError(reply));
            }
        }
        if self.db != 0 {
            let db_str = self.db.to_string();
            send_resp_array(reader.get_mut(), &["SELECT", &db_str])?;
            let reply = read_line(&mut reader)?;
            if !reply.starts_with("+OK") {
                return Err(RedisError::ServerError(reply));
            }
        }
        Ok(reader)
    }
}

fn read_integer_reply(reader: &mut BufReader<TcpStream>) -> Result<u64, RedisError> {
    let line = read_line(reader)?;
    line.strip_prefix(':')
        .ok_or_else(|| RedisError::ServerError(line.clone()))?
        .trim()
        .parse::<u64>()
        .map_err(|_| RedisError::Io("invalid integer reply".to_string()))
}

fn send_resp_array(stream: &mut TcpStream, args: &[&str]) -> Result<(), RedisError> {
    let mut payload = format!("*{}\r\n", args.len());
    for arg in args {
        payload.push_str(&format!("${}\r\n{arg}\r\n", arg.len()));
    }
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| RedisError::Io(e.to_string()))
}

fn read_line(reader: &mut BufReader<TcpStream>) -> Result<String, RedisError> {
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|e| RedisError::Io(e.to_string()))?;
    if n == 0 {
        return Err(RedisError::Io("unexpected EOF from redis".to_string()));
    }
    Ok(line.trim_end_matches(&['\r', '\n'][..]).to_string())
}
