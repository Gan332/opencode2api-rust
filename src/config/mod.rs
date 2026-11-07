//! Loads, validates, persists, and redacts service configuration.

mod json;
mod password;
mod persistence;
mod placeholder;
mod proxy;
mod rotation;
mod secrets;
mod server_keys;
mod tier;

pub use json::strip_json_comments;
pub use password::{hash_password, verify_password};
pub use persistence::save_atomic;
pub use placeholder::{drop_placeholder_keys, is_placeholder_key};
pub use proxy::{parse_proxy_entry, redact_url, resolve_proxy_files};
pub use rotation::{RotationConfig, RotationGroup, SOTA_MODELS, is_sota};
pub use secrets::{fingerprint, key_display_id, mask_value, Redactor, SecretRedactor};
pub use server_keys::ServerKeyMetadata;
pub use tier::Tier;

use crate::config::rotation::validate_rotation;
use crate::protocol::Protocol;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::str::FromStr;
use std::time::Duration;
use url::Url;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub rotation: RotationConfig,
    pub listen: String,
    pub server_keys: Vec<String>,
    pub server_key_metadata: BTreeMap<String, ServerKeyMetadata>,
    pub zen_keys: Vec<String>,
    pub go_keys: Vec<String>,
    pub anonymous: bool,
    pub warp: WarpConfig,
    pub proxies: Vec<String>,
    pub proxyfile: String,
    pub proxy_bindings: BTreeMap<String, String>,
    pub upstream: UpstreamConfig,
    pub retry: RetryConfig,
    pub models: ModelsConfig,
    pub performance: PerformanceConfig,
    pub logging: LoggingConfig,
    pub webui: WebUIConfig,
    pub prefer: Tier,
    pub reasoning: ReasoningConfig,
    #[serde(skip)]
    pub effective_proxies: Vec<String>,
}

impl Config {
    pub fn forced_effort(&self, model: &str) -> String {
        match self.reasoning.effort_by_model.get(model) {
            Some(effort) => effort.clone(),
            None => self.reasoning.effort.clone(),
        }
    }

    pub fn runtime_proxies(&self) -> Vec<String> {
        if !self.effective_proxies.is_empty() {
            return self.effective_proxies.clone();
        }
        if !self.proxies.is_empty() {
            return self.proxies.clone();
        }
        vec!["direct".to_string()]
    }

    pub fn password_for_save(&mut self) {
        self.effective_proxies.clear();
    }

    pub fn server_key_enabled(&self, key: &str) -> bool {
        !self
            .server_key_metadata
            .get(&fingerprint(key))
            .map(|item| item.disabled)
            .unwrap_or(false)
    }

    pub fn first_enabled_server_key(&self) -> String {
        self.server_keys
            .iter()
            .find(|key| self.server_key_enabled(key))
            .cloned()
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReasoningConfig {
    pub effort: String,
    pub effort_by_model: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WarpConfig {
    pub enabled: bool,
    pub pool_size: i64,
    pub stack: String,
    pub source_ipv6: String,
}

impl Default for WarpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pool_size: 2,
            stack: "ipv6".to_string(),
            source_ipv6: String::new(),
        }
    }
}

impl WarpConfig {
    pub fn normalize(&mut self) -> Result<()> {
        if self.pool_size == 0 {
            self.pool_size = 2;
        }
        if self.stack.trim().is_empty() {
            self.stack = "ipv6".to_string();
        }
        let stack = crate::warp::parse_stack(&self.stack)?;
        self.stack = stack.as_str().to_string();
        if !(1..=32).contains(&self.pool_size) {
            bail!("warp.pool_size must be between 1 and 32");
        }
        self.source_ipv6 = self.source_ipv6.trim().to_string();
        if !self.source_ipv6.is_empty() {
            let (addr, bits) = parse_ipv6_prefix(&self.source_ipv6)
                .with_context(|| format!("warp.source_ipv6: {:?} is not an IPv6 prefix", self.source_ipv6))?;
            if bits > 64 {
                bail!("warp.source_ipv6: {}/{} must be /64 or shorter", addr, bits);
            }
            if stack != crate::warp::Stack::Ipv6 {
                bail!("warp.source_ipv6 requires warp.stack to be \"ipv6\"; an IPv4 stack cannot present an IPv6 egress");
            }
            self.source_ipv6 = format!("{}/{}", masked_ipv6(addr, bits), bits);
        }
        Ok(())
    }
}

fn parse_ipv6_prefix(value: &str) -> Result<(Ipv6Addr, u8)> {
    if let Some((addr, bits)) = value.split_once('/') {
        let addr = Ipv6Addr::from_str(addr.trim()).map_err(|_| anyhow!("invalid address"))?;
        let bits: u8 = bits.trim().parse().map_err(|_| anyhow!("invalid prefix length"))?;
        if bits > 128 {
            bail!("invalid prefix length");
        }
        Ok((addr, bits))
    } else {
        let addr = Ipv6Addr::from_str(value.trim()).map_err(|_| anyhow!("invalid address"))?;
        Ok((addr, 128))
    }
}

fn masked_ipv6(addr: Ipv6Addr, bits: u8) -> Ipv6Addr {
    let raw = u128::from(addr);
    let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
    Ipv6Addr::from(raw & mask)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamConfig {
    pub zen: String,
    pub go: String,
    pub anonymous: String,
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            zen: "https://opencode.ai/zen".to_string(),
            go: "https://opencode.ai/zen/go".to_string(),
            anonymous: "https://opencode.ai/inference".to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetryConfig {
    pub max_attempts: i64,
    pub timeout_seconds: i64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            timeout_seconds: 300,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelsConfig {
    pub refresh_seconds: i64,
    pub protocols: BTreeMap<String, String>,
    pub free_only: bool,
    pub active_probes: bool,
    pub anonymous_backoff: Option<AnonymousBackoffConfig>,
}

impl ModelsConfig {
    fn with_defaults() -> Self {
        Self {
            refresh_seconds: 300,
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AnonymousBackoffConfig {
    pub threshold: i64,
    pub base_hours: i64,
    pub max_hours: i64,
}

impl AnonymousBackoffConfig {
    pub fn normalize(&mut self) -> Result<()> {
        if self.threshold == 0 {
            self.threshold = 6;
        }
        if self.base_hours == 0 {
            self.base_hours = 1;
        }
        if self.max_hours == 0 {
            self.max_hours = 24;
        }
        if self.threshold < 1 {
            bail!("models.anonymous_backoff.threshold must be at least 1");
        }
        if self.base_hours < 1 {
            bail!("models.anonymous_backoff.base_hours must be at least 1");
        }
        if self.max_hours < self.base_hours {
            bail!("models.anonymous_backoff.max_hours must not be smaller than base_hours");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: String,
    pub ring_size: i64,
    pub dump_request_bodies: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            ring_size: 2000,
            dump_request_bodies: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebUIConfig {
    pub enabled: bool,
    pub listen: String,
    pub username: String,
    pub password: String,
    pub password_hash: String,
    pub session_ttl_minutes: i64,
}

impl Default for WebUIConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "0.0.0.0:8081".to_string(),
            username: String::new(),
            password: String::new(),
            password_hash: String::new(),
            session_ttl_minutes: 720,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PerformanceConfig {
    pub max_idle_conns: i64,
    pub max_idle_conns_per_host: i64,
    pub max_conns_per_host: i64,
    pub idle_conn_timeout_seconds: i64,
    pub connect_timeout_seconds: i64,
    pub failure_cooldown_seconds: i64,
    pub attempt_timeout_seconds: i64,
    pub first_event_timeout_seconds: i64,
    pub max_anonymous_exits: i64,
    pub free_tier_block_seconds: i64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_idle_conns: 2048,
            max_idle_conns_per_host: 256,
            max_conns_per_host: 0,
            idle_conn_timeout_seconds: 120,
            connect_timeout_seconds: 5,
            failure_cooldown_seconds: 15,
            attempt_timeout_seconds: 0,
            first_event_timeout_seconds: 0,
            max_anonymous_exits: 0,
            free_tier_block_seconds: 0,
        }
    }
}

impl PerformanceConfig {
    pub fn attempt_timeout(&self, request_timeout: Duration) -> Duration {
        if self.attempt_timeout_seconds > 0 {
            let attempt = Duration::from_secs(self.attempt_timeout_seconds as u64);
            if !request_timeout.is_zero() && attempt > request_timeout {
                return request_timeout;
            }
            return attempt;
        }
        request_timeout
    }
}

fn default_config() -> Config {
    Config {
        rotation: RotationConfig::default(),
        listen: "127.0.0.1:8080".to_string(),
        server_keys: Vec::new(),
        server_key_metadata: BTreeMap::new(),
        zen_keys: Vec::new(),
        go_keys: Vec::new(),
        anonymous: false,
        warp: WarpConfig::default(),
        proxies: Vec::new(),
        proxyfile: String::new(),
        proxy_bindings: BTreeMap::new(),
        upstream: UpstreamConfig::default(),
        retry: RetryConfig::default(),
        models: ModelsConfig::with_defaults(),
        performance: PerformanceConfig::default(),
        logging: LoggingConfig::default(),
        webui: WebUIConfig::default(),
        prefer: Tier::Go,
        reasoning: ReasoningConfig::default(),
        effective_proxies: Vec::new(),
    }
}

/// Reads the config file, strips comments, decodes it over the built-in
/// defaults, and normalizes the result.
pub fn load(path: &str) -> Result<Config> {
    let data = std::fs::read(path).with_context(|| format!("read {path}"))?;
    let data = strip_json_comments(&data).with_context(|| format!("parse {path}"))?;
    let mut cfg: Config = serde_json::from_slice(&data).with_context(|| format!("parse {path}"))?;
    let defaults = default_config();
    merge_defaults(&mut cfg, &defaults);
    normalize(path, cfg)
}

/// A container-level `#[serde(default)]` uses each field type's `Default`,
/// which differs from the Go defaults for a few structs. Restore the Go
/// defaults for fields a partial config omitted.
fn merge_defaults(cfg: &mut Config, defaults: &Config) {
    if cfg.listen.is_empty() {
        cfg.listen = defaults.listen.clone();
    }
    if cfg.models.refresh_seconds == 0 {
        cfg.models.refresh_seconds = defaults.models.refresh_seconds;
    }
    if cfg.webui.listen.is_empty() {
        cfg.webui.listen = defaults.webui.listen.clone();
    }
    if cfg.webui.session_ttl_minutes == 0 {
        cfg.webui.session_ttl_minutes = defaults.webui.session_ttl_minutes;
    }
}

pub fn normalize(path: &str, mut cfg: Config) -> Result<Config> {
    cfg.rotation.defaults();
    validate_rotation(&cfg.rotation, &[])?;
    cfg.warp.normalize()?;
    trim_list(&mut cfg.server_keys);
    remap_server_key_metadata(&mut cfg);
    trim_list(&mut cfg.zen_keys);
    trim_list(&mut cfg.go_keys);
    cfg = drop_placeholder_keys(cfg);
    cfg.proxyfile = cfg.proxyfile.trim().to_string();
    resolve_proxy_files(path, &mut cfg)?;
    if cfg.prefer != Tier::Zen && cfg.prefer != Tier::Go {
        bail!("prefer must be \"zen\" or \"go\"");
    }
    if cfg.listen.is_empty() {
        bail!("listen must not be empty");
    }
    cfg.upstream.zen = cfg.upstream.zen.trim().to_string();
    cfg.upstream.go = cfg.upstream.go.trim().to_string();
    cfg.upstream.anonymous = cfg.upstream.anonymous.trim().to_string();
    if cfg.upstream.anonymous.is_empty() {
        cfg.upstream.anonymous = "https://opencode.ai/inference".to_string();
    }
    for (name, raw) in [
        ("upstream.zen", cfg.upstream.zen.as_str()),
        ("upstream.go", cfg.upstream.go.as_str()),
        ("upstream.anonymous", cfg.upstream.anonymous.as_str()),
    ] {
        let parsed = Url::parse(raw.trim()).ok();
        if parsed
            .as_ref()
            .map(|url| url.host_str().is_some() && matches!(url.scheme(), "http" | "https"))
            != Some(true)
        {
            bail!("{name} must be an http or https URL");
        }
    }
    if cfg.server_keys.is_empty() {
        bail!("server_keys must contain at least one local key");
    }
    if cfg.first_enabled_server_key().is_empty() {
        bail!("at least one server key must remain enabled");
    }
    if !cfg.anonymous && cfg.zen_keys.is_empty() && cfg.go_keys.is_empty() {
        bail!("zen_keys or go_keys must contain at least one upstream key unless anonymous is enabled");
    }
    if cfg.retry.max_attempts < 1 {
        bail!("retry.max_attempts must be at least 1");
    }
    if cfg.retry.timeout_seconds < 1 {
        bail!("retry.timeout_seconds must be at least 1");
    }
    if cfg.models.refresh_seconds < 1 {
        bail!("models.refresh_seconds must be at least 1");
    }
    let perf = &cfg.performance;
    if perf.max_idle_conns < 1
        || perf.max_idle_conns_per_host < 1
        || perf.max_conns_per_host < 0
        || perf.idle_conn_timeout_seconds < 1
        || perf.connect_timeout_seconds < 1
        || perf.failure_cooldown_seconds < 1
    {
        bail!("performance values must be positive (max_conns_per_host may be zero for unlimited)");
    }
    if perf.attempt_timeout_seconds < 0 {
        bail!("performance.attempt_timeout_seconds must not be negative (0 keeps the retry timeout)");
    }
    if perf.first_event_timeout_seconds < 0 || perf.first_event_timeout_seconds > 86400 {
        bail!("performance.first_event_timeout_seconds must be between 0 and 86400 (0 disables the first-event timeout)");
    }
    if perf.max_anonymous_exits < 0 {
        bail!("performance.max_anonymous_exits must not be negative (0 uses the built-in cap)");
    }
    if perf.free_tier_block_seconds < 0 {
        bail!("performance.free_tier_block_seconds must not be negative (0 uses the built-in cool-down)");
    }
    if !matches!(cfg.logging.level.as_str(), "debug" | "info" | "warn" | "error") {
        bail!("logging.level must be debug, info, warn, or error");
    }
    if cfg.logging.ring_size < 100 || cfg.logging.ring_size > 50000 {
        bail!("logging.ring_size must be between 100 and 50000");
    }
    if !cfg.webui.password.is_empty() && cfg.webui.password.chars().count() < 10 {
        bail!("webui.password must contain at least 10 characters");
    }
    if cfg.webui.enabled {
        cfg.webui.listen = cfg.webui.listen.trim().to_string();
        cfg.webui.username = cfg.webui.username.trim().to_string();
        if cfg.webui.listen.is_empty() {
            bail!("webui.listen must not be empty when webui is enabled");
        }
        if cfg.webui.username.is_empty() {
            bail!("webui.username must not be empty when webui is enabled");
        }
        if cfg.webui.password.is_empty() && cfg.webui.password_hash.is_empty() {
            bail!("webui.password is required for first-time setup");
        }
        if cfg.webui.session_ttl_minutes < 5 || cfg.webui.session_ttl_minutes > 10080 {
            bail!("webui.session_ttl_minutes must be between 5 and 10080");
        }
    }
    for raw in cfg.runtime_proxies() {
        if raw == "direct" {
            continue;
        }
        let (clean, _) = parse_proxy_entry(&raw);
        let parsed = Url::parse(&clean).ok();
        if parsed.as_ref().and_then(Url::host_str).is_none() {
            bail!("invalid proxy URL {:?}", redact_url(&raw));
        }
        let scheme = parsed.map(|url| url.scheme().to_ascii_lowercase());
        if !matches!(scheme.as_deref(), Some("http" | "https" | "socks5" | "socks5h")) {
            bail!("unsupported proxy scheme {:?}", scheme.unwrap_or_default());
        }
    }
    if let Some(backoff) = cfg.models.anonymous_backoff.as_mut() {
        backoff.normalize()?;
    }
    for (model, protocol) in &cfg.models.protocols {
        if model.is_empty() || Protocol::from_str(protocol).is_none() {
            bail!("models.protocols contains invalid mapping {:?}: {:?}", model, protocol);
        }
    }
    normalize_reasoning(&mut cfg)?;
    normalize_proxy_bindings(&mut cfg)?;
    Ok(cfg)
}

fn remap_server_key_metadata(cfg: &mut Config) {
    if cfg.server_key_metadata.is_empty() {
        return;
    }
    let keys = cfg.server_keys.clone();
    for key in keys {
        let full = fingerprint(&key);
        let old_id = full.chars().take(10).collect::<String>();
        if let Some(metadata) = cfg.server_key_metadata.get(&old_id).cloned() {
            cfg.server_key_metadata.entry(full).or_insert(metadata);
            cfg.server_key_metadata.remove(&old_id);
        }
    }
}

fn validate_effort(name: &str, value: &str) -> Result<()> {
    match value {
        "" | "auto" | "minimal" | "low" | "medium" | "high" | "xhigh" | "max" | "none" => Ok(()),
        _ => bail!("{name} must be one of auto, minimal, low, medium, high, xhigh, max, none, or empty to disable the override"),
    }
}

fn normalize_reasoning(cfg: &mut Config) -> Result<()> {
    cfg.reasoning.effort = cfg.reasoning.effort.trim().to_ascii_lowercase();
    validate_effort("reasoning.effort", &cfg.reasoning.effort)?;
    if cfg.reasoning.effort_by_model.is_empty() {
        cfg.reasoning.effort_by_model.clear();
        return Ok(());
    }
    let mut normalized = BTreeMap::new();
    for (model, effort) in &cfg.reasoning.effort_by_model {
        let key = model.trim();
        if key.is_empty() {
            bail!("reasoning.effort_by_model must not contain an empty model ID");
        }
        let level = effort.trim().to_ascii_lowercase();
        validate_effort(&format!("reasoning.effort_by_model[{key:?}]"), &level)?;
        normalized.insert(key.to_string(), level);
    }
    cfg.reasoning.effort_by_model = normalized;
    Ok(())
}

fn normalize_proxy_bindings(cfg: &mut Config) -> Result<()> {
    if cfg.proxy_bindings.is_empty() {
        return Ok(());
    }
    let mut key_map = BTreeMap::new();
    for key in cfg.zen_keys.iter().chain(cfg.go_keys.iter()) {
        let fp = fingerprint(key);
        key_map.insert(key.clone(), fp.clone());
        key_map.insert(fp, fp);
    }
    let mut known_proxies = BTreeMap::new();
    for raw in cfg.runtime_proxies() {
        let (clean, _) = parse_proxy_entry(&raw);
        known_proxies.insert(raw.clone(), raw.clone());
        known_proxies.insert(clean.clone(), raw.clone());
        if clean == "direct" {
            known_proxies.insert("direct".to_string(), "direct".to_string());
        }
    }
    let mut normalized = BTreeMap::new();
    for (key_ref, proxy_ref) in &cfg.proxy_bindings {
        let trimmed_key = key_ref.trim();
        let trimmed_proxy = proxy_ref.trim();
        let Some(fp) = key_map.get(trimmed_key) else {
            bail!("proxy_bindings contains reference to unknown key {:?}", mask_value(trimmed_key));
        };
        let Some(canonical_proxy) = known_proxies.get(trimmed_proxy) else {
            bail!("proxy_bindings references unknown proxy {:?}", redact_url(trimmed_proxy));
        };
        normalized.insert(fp.clone(), canonical_proxy.clone());
    }
    cfg.proxy_bindings = normalized;
    Ok(())
}

pub fn trim_list(items: &mut Vec<String>) {
    items.retain_mut(|item| {
        *item = item.trim().to_string();
        !item.is_empty()
    });
}

fn _unused(_: ()) {}
