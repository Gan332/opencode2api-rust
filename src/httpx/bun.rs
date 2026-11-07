//! Bun-compatible request layout and TLS hello.

use anyhow::{anyhow, Result};
use http::HeaderMap;
use std::collections::BTreeMap;
use std::sync::Arc;
use url::Url;

pub const V1_BUN_VERSION: &str = "1.3.14";

pub const BUN_COMMON_HEADERS: [&str; 28] = [
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Authorization",
    "Cache-Control",
    "Connection",
    "Content-Encoding",
    "Content-Language",
    "Content-Length",
    "Content-Type",
    "Cookie",
    "DNT",
    "Expect",
    "Host",
    "If-None-Match",
    "Keep-Alive",
    "Last-Event-Id",
    "Origin",
    "Pragma",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "Sec-Fetch-Mode",
    "TE",
    "Upgrade-Insecure-Requests",
    "User-Agent",
    "X-Requested-With",
];

/// Renders the request line and headers the way Bun's fetch writes them.
/// Returns the bytes and whether the transport added Accept-Encoding (and so
/// must decode the response).
pub fn bun_request_head(
    method: &str,
    url: &Url,
    headers: &HeaderMap,
    body_length: Option<usize>,
) -> Result<(Vec<u8>, bool)> {
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        let text = value.to_str().unwrap_or_default();
        if !valid_header_field(name.as_str(), text) {
            return Err(anyhow!("bun transport: invalid header field {name:?}"));
        }
        if matches!(
            lower.as_str(),
            "host" | "connection" | "content-length" | "transfer-encoding"
        ) {
            continue;
        }
        values
            .entry(lower)
            .and_modify(|existing| {
                existing.push_str(", ");
                existing.push_str(text);
            })
            .or_insert_with(|| text.to_string());
    }
    if values.get("accept").map(String::as_str) == Some("*/*") {
        values.remove("accept");
    }
    let has_user_agent = values.contains_key("user-agent");
    let has_accept = values.contains_key("accept");
    let has_encoding = values.contains_key("accept-encoding");

    let mut head = String::new();
    head.push_str(method);
    head.push(' ');
    head.push_str(&request_target(url));
    head.push_str(" HTTP/1.1\r\n");

    let mut wrote_length = false;
    for name in BUN_COMMON_HEADERS {
        let lower = name.to_ascii_lowercase();
        if lower == "content-length" && body_length.is_some() {
            head.push_str(&format!("{name}: {}\r\n", body_length.unwrap_or(0)));
            values.remove(&lower);
            wrote_length = true;
            continue;
        }
        if let Some(value) = values.remove(&lower) {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(&value);
            head.push_str("\r\n");
        }
    }
    for (name, value) in values {
        head.push_str(&name);
        head.push_str(": ");
        head.push_str(&value);
        head.push_str("\r\n");
    }
    head.push_str("Connection: keep-alive\r\n");
    if !has_user_agent {
        head.push_str(&format!("User-Agent: Bun/{V1_BUN_VERSION}\r\n"));
    }
    if !has_accept {
        head.push_str("Accept: */*\r\n");
    }
    let mut host = url.host_str().unwrap_or_default().to_string();
    if url.scheme() == "https" {
        host = host.strip_suffix(":443").unwrap_or(&host).to_string();
    } else {
        host = host.strip_suffix(":80").unwrap_or(&host).to_string();
    }
    if let Some(port) = url.port() {
        if !(url.scheme() == "https" && port == 443 || url.scheme() == "http" && port == 80) {
            host = format!("{host}:{port}");
        }
    }
    head.push_str(&format!("Host: {host}\r\n"));
    if !has_encoding {
        head.push_str("Accept-Encoding: gzip, deflate, br, zstd\r\n");
    }
    if body_length.is_some() && !wrote_length {
        head.push_str(&format!(
            "Content-Length: {}\r\n",
            body_length.unwrap_or(0)
        ));
    }
    head.push_str("\r\n");
    Ok((head.into_bytes(), !has_encoding))
}

fn request_target(url: &Url) -> String {
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    match url.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_string(),
    }
}

fn valid_header_field(name: &str, value: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    for byte in name.bytes() {
        if byte <= b' ' || byte >= 0x7f || b"\"(),/:;<=>?@[\\]{}".contains(&byte) {
            return false;
        }
    }
    for byte in value.bytes() {
        if (byte < b' ' && byte != b'\t') || byte == 0x7f {
            return false;
        }
    }
    true
}

pub fn bun_tls_config() -> Result<rustls::ClientConfig> {
    use rustls::crypto::ring;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut provider = ring::default_provider();
    provider
        .cipher_suites
        .sort_by_key(|suite| cipher_rank(suite.suite()));
    provider.kx_groups.sort_by_key(|group| kx_rank(group.name()));
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

fn cipher_rank(suite: rustls::CipherSuite) -> u8 {
    match format!("{suite:?}").as_str() {
        "TLS13_AES_128_GCM_SHA256" => 0,
        "TLS13_AES_256_GCM_SHA384" => 1,
        "TLS13_CHACHA20_POLY1305_SHA256" => 2,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => 3,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => 4,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => 5,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => 6,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => 7,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => 8,
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" => 9,
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA" => 10,
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA" => 11,
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" => 12,
        "TLS_RSA_WITH_AES_128_GCM_SHA256" => 13,
        "TLS_RSA_WITH_AES_256_GCM_SHA384" => 14,
        "TLS_RSA_WITH_AES_128_CBC_SHA" => 15,
        "TLS_RSA_WITH_AES_256_CBC_SHA" => 16,
        _ => 200,
    }
}

fn kx_rank(name: rustls::NamedGroup) -> u8 {
    match format!("{name:?}").as_str() {
        "X25519MLKEM768" => 0,
        "X25519" => 1,
        "secp256r1" => 2,
        "secp384r1" => 3,
        _ => 200,
    }
}
