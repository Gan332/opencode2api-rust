//! Secret redaction, masking and stable fingerprints.

use super::Config;
use sha2::{Digest, Sha256};
use std::sync::RwLock;
use url::Url;

pub fn mask_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 5 {
        return "••••".to_string();
    }
    format!("••••{}", chars[chars.len() - 5..].iter().collect::<String>())
}

pub fn fingerprint(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())[..16].to_string()
}

pub fn key_display_id(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 5 {
        return value.to_string();
    }
    chars[chars.len() - 5..].iter().collect()
}

#[derive(Debug, Default)]
pub struct Redactor {
    values: RwLock<Vec<String>>,
}

pub fn secret_redactor() -> Redactor {
    Redactor::default()
}

impl Redactor {
    pub fn replace(&self, cfg: &Config) {
        let mut values: Vec<String> = Vec::new();
        values.extend(cfg.server_keys.iter().cloned());
        values.extend(cfg.zen_keys.iter().cloned());
        values.extend(cfg.go_keys.iter().cloned());
        if !cfg.webui.password.is_empty() {
            values.push(cfg.webui.password.clone());
        }
        for value in [
            &cfg.upstream.zen,
            &cfg.upstream.go,
            &cfg.upstream.anonymous,
        ] {
            if let Ok(parsed) = Url::parse(value) {
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    values.push(value.clone());
                    if !parsed.username().is_empty() {
                        values.push(parsed.username().to_string());
                    }
                    if let Some(password) = parsed.password() {
                        values.push(password.to_string());
                    }
                }
            }
        }
        for value in cfg.runtime_proxies() {
            if value == "direct" {
                continue;
            }
            let (clean, _) = super::parse_proxy_entry(&value);
            values.push(value.clone());
            values.push(clean.clone());
            if let Ok(parsed) = Url::parse(&clean) {
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    if !parsed.username().is_empty() {
                        values.push(parsed.username().to_string());
                    }
                    if let Some(password) = parsed.password() {
                        values.push(password.to_string());
                    }
                }
            }
        }
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        *self.values.write().expect("redactor lock") = values;
    }

    pub fn redact(&self, value: &str) -> String {
        let values = self.values.read().expect("redactor lock");
        let mut out = value.to_string();
        for secret in values.iter() {
            if secret.len() >= 4 {
                out = out.replace(secret, "***");
            }
        }
        out
    }
}
