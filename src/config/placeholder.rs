use super::Config;

const PLACEHOLDER_KEYS: [&str; 2] = ["sk-your-zen-key", "change-this-local-key"];

pub fn is_placeholder_key(key: &str) -> bool {
    let trimmed = key.trim().to_ascii_lowercase();
    PLACEHOLDER_KEYS.iter().any(|value| *value == trimmed)
}

pub fn drop_placeholder_keys(mut cfg: Config) -> Config {
    cfg.zen_keys.retain(|key| !is_placeholder_key(key));
    cfg.go_keys.retain(|key| !is_placeholder_key(key));
    cfg
}
