//! Human-Readable **`@handle` Payment Resolution** (`.well-known/xcr-pay.json` + Local Address Book).
//!
//! Allows users and merchants to pay memorable identifiers like `cashier@127.0.0.1:8080`,
//! `coffee@merchant.lan`, or saved `@mom` nicknames instead of manually copying 140-character
//! `xcrstealth1_<128-hex>` strings, while still deriving a fresh unlinkable one-time stealth
//! output for every single transaction.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use credit_crypto::StealthMetaAddress;

use crate::payment_uri::url_encode;

/// Local TSV address-book mapping `@alias` -> `xcrstealth1_...` Stealth Meta-Address URI.
#[derive(Clone, Debug, Default)]
pub struct LocalHandleBook {
    entries: BTreeMap<String, String>,
}

impl LocalHandleBook {
    pub fn load(path: &Path) -> Self {
        let mut entries = BTreeMap::new();
        if let Ok(raw) = fs::read_to_string(path) {
            for line in raw.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                if let Some((alias, uri)) = trimmed.split_once('\t')
                    && StealthMetaAddress::from_uri(uri.trim()).is_some()
                {
                    entries.insert(normalize_alias(alias), uri.trim().to_owned());
                }
            }
        }
        Self { entries }
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let mut buf = String::new();
        for (alias, uri) in &self.entries {
            buf.push_str(alias);
            buf.push('\t');
            buf.push_str(uri);
            buf.push('\n');
        }
        fs::write(path, buf)
    }

    pub fn upsert(&mut self, alias: &str, stealth_uri: &str) -> bool {
        if StealthMetaAddress::from_uri(stealth_uri.trim()).is_none() {
            return false;
        }
        self.entries
            .insert(normalize_alias(alias), stealth_uri.trim().to_owned());
        true
    }

    pub fn resolve(&self, alias: &str) -> Option<StealthMetaAddress> {
        let uri = self.entries.get(&normalize_alias(alias))?;
        StealthMetaAddress::from_uri(uri)
    }

    pub fn entries(&self) -> &BTreeMap<String, String> {
        &self.entries
    }
}

fn normalize_alias(s: &str) -> String {
    s.trim().trim_start_matches('@').to_ascii_lowercase()
}

/// Resolves a domain handle (`user@host[:port]` or `$host[:port]`) over HTTP/1.1 via
/// `GET /.well-known/xcr-pay.json?user=<user>`, cryptographically verifying that the returned
/// `stealth_uri` contains a valid canonical Curve25519 `spend_pub` point.
pub fn resolve_remote_handle(handle: &str, timeout: Duration) -> io::Result<StealthMetaAddress> {
    let trimmed = handle.trim();
    let (user, host_port) = if let Some(rest) = trimmed.strip_prefix('$') {
        ("default", rest)
    } else if let Some((u, hp)) = trimmed.trim_start_matches('@').split_once('@') {
        if u.is_empty() || hp.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid user@domain handle",
            ));
        }
        (u, hp)
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handle must be `user@domain[:port]` or `$domain[:port]`",
        ));
    };

    let addr_spec = if host_port.contains(':') {
        host_port.to_owned()
    } else {
        format!("{host_port}:80")
    };
    let host_header = host_port.split(':').next().unwrap_or(host_port);

    let sock_addr: SocketAddr = addr_spec
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "could not resolve handle host"))?;

    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let req = format!(
        "GET /.well-known/xcr-pay.json?user={} HTTP/1.1\r\nHost: {host_header}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
        url_encode(user)
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    while raw.len() < 16_384 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let (_, body) = text.split_once("\r\n\r\n").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "malformed HTTP handle response")
    })?;

    let uri = extract_json_string_field(body, "stealth_uri").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing `stealth_uri` in .well-known/xcr-pay.json",
        )
    })?;
    StealthMetaAddress::from_uri(&uri).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Curve25519 StealthMetaAddress in .well-known/xcr-pay.json",
        )
    })
}

/// Formats the `.well-known/xcr-pay.json` payload served by `credit-gateway` so any merchant
/// gateway automatically acts as a live resolvable `@handle` endpoint.
pub fn format_well_known_pay_json(
    handle_name: &str,
    stealth: &StealthMetaAddress,
    network: &str,
) -> String {
    format!(
        r#"{{"handle":"{}","network":"{}","stealth_uri":"{}"}}"#,
        escape_json(handle_name),
        escape_json(network),
        stealth.to_uri()
    )
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn extract_json_string_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let idx = json.find(&needle)?;
    let after_key = &json[idx + needle.len()..];
    let colon = after_key.find(':')?;
    let rest = after_key[colon + 1..].trim_start();
    let inner = rest.strip_prefix('"')?;
    let end = inner.find('"')?;
    Some(inner[..end].to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use credit_crypto::StealthKeypair;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn remote_well_known_handle_and_local_book_resolve_cleanly() {
        let kp = StealthKeypair::from_seed(&[0x33; 32]);
        let meta = kp.meta_address();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let json_body = format_well_known_pay_json("coffee", &meta, "xcr-testnet-beta-2027");
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut req = [0u8; 512];
                let _ = sock.read(&mut req);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json_body.len(),
                    json_body
                );
                let _ = sock.write_all(resp.as_bytes());
            }
        });

        let handle = format!("coffee@127.0.0.1:{port}");
        let resolved = resolve_remote_handle(&handle, Duration::from_secs(2)).unwrap();
        assert_eq!(resolved, meta);

        let mut book = LocalHandleBook::default();
        assert!(book.upsert("@CoffeeShop", &meta.to_uri()));
        assert_eq!(book.resolve("coffeeshop"), Some(meta));
    }
}
