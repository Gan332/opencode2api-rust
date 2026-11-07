//! Proxy entry parsing, proxy-file loading and display redaction.

use super::Config;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;
use url::Url;

/// Splits an optional rotating-pool marker from a configured proxy string.
pub fn parse_proxy_entry(raw: &str) -> (String, bool) {
    let mut trimmed = raw.trim().to_string();
    if trimmed.is_empty() || trimmed == "direct" {
        return (trimmed, false);
    }
    let mut pool = false;
    if trimmed.to_ascii_lowercase().starts_with("pool+") {
        trimmed = trimmed[5..].trim().to_string();
        pool = true;
    }
    match Url::parse(&trimmed) {
        Ok(mut url) if url.host_str().is_some() => {
            if url
                .fragment()
                .map(|value| value.trim().eq_ignore_ascii_case("pool"))
                .unwrap_or(false)
            {
                pool = true;
                url.set_fragment(None);
                trimmed = url.to_string();
            }
        }
        _ => {
            if let Some(index) = trimmed.rfind('#') {
                if trimmed[index + 1..].trim().eq_ignore_ascii_case("pool") {
                    pool = true;
                    trimmed = trimmed[..index].trim().to_string();
                }
            }
        }
    }
    (trimmed, pool)
}

pub fn redact_url(raw: &str) -> String {
    let (clean, pool) = parse_proxy_entry(raw);
    let source = if clean.is_empty() { raw } else { &clean };
    let Ok(mut url) = Url::parse(source) else {
        return "<invalid>".to_string();
    };
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("***");
        let _ = url.set_password(None);
    }
    if pool && url.fragment().is_none() {
        url.set_fragment(Some("pool"));
    }
    url.to_string()
}

pub fn resolve_proxy_files(config_path: &str, cfg: &mut Config) -> Result<()> {
    super::trim_list(&mut cfg.proxies);
    let mut effective = cfg.proxies.clone();
    if !cfg.proxyfile.is_empty() {
        let resolved = if Path::new(&cfg.proxyfile).is_absolute() {
            std::path::PathBuf::from(&cfg.proxyfile)
        } else {
            Path::new(config_path)
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&cfg.proxyfile)
        };
        let proxies = read_proxy_file(&resolved)
            .with_context(|| format!("load proxy file {}", resolved.display()))?;
        effective.extend(proxies);
    }
    effective = unique_proxy_entries(effective);
    if effective.is_empty() {
        effective.push("direct".to_string());
    }
    cfg.effective_proxies = effective;
    Ok(())
}

fn read_proxy_file(path: &Path) -> Result<Vec<String>> {
    let data = std::fs::read_to_string(path)?;
    let mut proxies = Vec::new();
    for line in data.lines() {
        let value = line.trim_start_matches('\u{feff}').trim();
        let value = strip_proxy_line_comment(value).trim();
        if !value.is_empty() {
            proxies.push(value.to_string());
        }
    }
    Ok(proxies)
}

fn strip_proxy_line_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for index in 0..bytes.len() {
        if index > 0 && bytes[index - 1] != b' ' && bytes[index - 1] != b'\t' {
            continue;
        }
        if bytes[index] == b'#'
            || bytes[index] == b';'
            || (bytes[index] == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/')
        {
            return &line[..index];
        }
    }
    line
}

fn unique_proxy_entries(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut pools = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let (key, pool) = parse_proxy_entry(&item);
        if key.is_empty() {
            continue;
        }
        if pool {
            if pools.insert(key) {
                out.push(item);
            }
        } else if seen.insert(key) {
            out.push(item);
        }
    }
    out
}
