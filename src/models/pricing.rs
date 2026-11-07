//! Per-model pricing metadata from the OpenCode catalog.

use crate::httpx::Transport;
use crate::jsonutil;
use anyhow::{anyhow, Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

pub const METADATA_REFRESH: Duration = Duration::from_secs(24 * 60 * 60);
pub const METADATA_RETRY: Duration = Duration::from_secs(60);
pub const METADATA_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Price {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_cost: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_cost: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_cost: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write_cost: Option<f64>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub context_window: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_input: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_output: i64,
    #[serde(default)]
    pub deprecated: bool,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnonymousDecision {
    pub allowed: bool,
    pub source: String,
    pub known: bool,
    #[serde(default)]
    pub deprecated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_cost: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_cost: Option<f64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MetadataSnapshot {
    pub ready: bool,
    pub models: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<OffsetDateTime>,
    pub stale: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub last_error: String,
    #[serde(skip)]
    pub cache_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_refresh: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModelMetadataCache {
    #[serde(default)]
    pub updated_at: Option<OffsetDateTime>,
    #[serde(default)]
    pub models: BTreeMap<String, Price>,
}

pub type ClientProvider = Arc<dyn Fn() -> Vec<Arc<Transport>> + Send + Sync>;

struct PricingState {
    models: HashMap<String, Price>,
    updated_at: Option<OffsetDateTime>,
    next_refresh: Option<OffsetDateTime>,
    last_error: String,
}

pub struct PricingRegistry {
    state: RwLock<PricingState>,
    cache_path: String,
    endpoint: String,
    provider: RwLock<Option<ClientProvider>>,
    direct: Arc<Transport>,
}

impl PricingRegistry {
    pub fn new(config_path: &str) -> Self {
        let cache_path = if config_path.is_empty() {
            String::new()
        } else {
            format!("{config_path}.models.dev.json")
        };
        let direct = Arc::new(
            Transport::new(crate::httpx::TransportOptions::default())
                .expect("default transport"),
        );
        let store = Self {
            state: RwLock::new(PricingState {
                models: HashMap::new(),
                updated_at: None,
                next_refresh: None,
                last_error: String::new(),
            }),
            cache_path,
            endpoint: crate::models::discovery::CAPABILITIES_URL.to_string(),
            provider: RwLock::new(None),
            direct,
        };
        if let Err(error) = store.load_cache() {
            if error.kind() != std::io::ErrorKind::NotFound {
                store.state.write().last_error = format!("load metadata cache: {error}");
            }
        }
        store
    }

    pub fn set_client_provider(&self, provider: ClientProvider) {
        *self.provider.write() = Some(provider);
    }

    fn clients(&self) -> Vec<Arc<Transport>> {
        if let Some(provider) = self.provider.read().clone() {
            let clients = provider();
            if !clients.is_empty() {
                return clients;
            }
        }
        vec![self.direct.clone()]
    }

    pub async fn refresh(&self) -> Result<()> {
        let mut last_error = None;
        for client in self.clients() {
            match self.fetch(&client).await {
                Ok(data) => {
                    let models = decode_metadata(&data)?;
                    let now = OffsetDateTime::now_utc();
                    let cache = ModelMetadataCache {
                        updated_at: Some(now),
                        models: models
                            .iter()
                            .map(|(id, price)| (id.clone(), price.clone()))
                            .collect(),
                    };
                    if !self.cache_path.is_empty() {
                        if let Err(error) = save_metadata_cache(&self.cache_path, &cache) {
                            return Err(self.record_error(error));
                        }
                    }
                    let mut state = self.state.write();
                    state.models = models;
                    state.updated_at = Some(now);
                    state.last_error.clear();
                    return Ok(());
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(self.record_error(last_error.unwrap_or_else(|| anyhow!("no HTTP client available for OpenCode metadata refresh"))))
    }

    async fn fetch(&self, client: &Transport) -> Result<Vec<u8>> {
        let request = crate::httpx::Request::get(
            self.endpoint
                .parse()
                .context("metadata endpoint is not a URL")?,
        )
        .header("Accept", "application/json")
        .header("User-Agent", &crate::httpx::v2_user_agent());
        let response = client.execute(request).await?;
        if !response.status.is_success() {
            return Err(anyhow!(
                "OpenCode metadata endpoint returned HTTP {}",
                response.status.as_u16()
            ));
        }
        Ok(response.body.collect().await?.to_vec())
    }

    fn record_error(&self, error: anyhow::Error) -> anyhow::Error {
        self.state.write().last_error = error.to_string();
        error
    }

    pub fn decide(&self, model: &str) -> AnonymousDecision {
        let state = self.state.read();
        let price = state.models.get(model).cloned();
        let ready = state.updated_at.is_some() && !state.models.is_empty();
        drop(state);
        let name_free = is_free_model(model);
        let fallback = |source: &str| AnonymousDecision {
            allowed: name_free,
            source: if name_free { "name_free".into() } else { source.into() },
            known: false,
            ..Default::default()
        };
        if !ready {
            return fallback("metadata_pending");
        }
        let Some(price) = price else {
            return fallback("metadata_model_missing");
        };
        let mut decision = AnonymousDecision {
            known: true,
            deprecated: price.deprecated,
            input_cost: price.input_cost,
            output_cost: price.output_cost,
            ..Default::default()
        };
        let metadata_free = !price.deprecated
            && price.input_cost == Some(0.0)
            && price.output_cost == Some(0.0);
        if name_free || metadata_free {
            decision.allowed = true;
            decision.source = match (name_free, metadata_free) {
                (true, true) => "name_and_metadata_free",
                (true, false) => "name_free",
                _ => "metadata_free",
            }
            .into();
            return decision;
        }
        if price.deprecated {
            decision.source = "metadata_deprecated".into();
            return decision;
        }
        if price.input_cost.is_none() || price.output_cost.is_none() {
            decision.known = false;
            decision.source = "metadata_cost_unknown".into();
            return decision;
        }
        decision.source = "metadata_paid".into();
        decision
    }

    pub fn price(&self, model: &str) -> Option<Price> {
        self.state.read().models.get(model).cloned()
    }

    pub fn snapshot(&self) -> MetadataSnapshot {
        let state = self.state.read();
        let mut snapshot = MetadataSnapshot {
            ready: state.updated_at.is_some() && !state.models.is_empty(),
            models: state.models.len(),
            updated_at: state.updated_at,
            stale: false,
            last_error: state.last_error.clone(),
            cache_path: self.cache_path.clone(),
            next_refresh: state.next_refresh,
        };
        if let Some(updated) = state.updated_at {
            snapshot.stale =
                OffsetDateTime::now_utc() - updated > time::Duration::seconds(METADATA_REFRESH.as_secs() as i64);
        }
        snapshot
    }

    fn set_next_refresh(&self, value: Option<OffsetDateTime>) {
        self.state.write().next_refresh = value;
    }

    pub async fn run(&self, shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut shutdown = shutdown;
        loop {
            if *shutdown.borrow() {
                return;
            }
            self.set_next_refresh(None);
            let delay = if self.refresh().await.is_ok() {
                METADATA_REFRESH
            } else {
                METADATA_RETRY
            };
            self.set_next_refresh(Some(OffsetDateTime::now_utc() + time::Duration::seconds(delay.as_secs() as i64)));
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown.changed() => {
                    self.set_next_refresh(None);
                    return;
                }
            }
        }
    }

    fn load_cache(&self) -> std::io::Result<()> {
        if self.cache_path.is_empty() {
            return Err(std::io::ErrorKind::NotFound.into());
        }
        let data = std::fs::read(&self.cache_path)?;
        let cache: ModelMetadataCache = serde_json::from_slice(&data)?;
        let Some(updated_at) = cache.updated_at else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "metadata cache is empty or missing updated_at",
            ));
        };
        if cache.models.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "metadata cache is empty or missing updated_at",
            ));
        }
        let mut state = self.state.write();
        state.models = cache.models.into_iter().collect();
        state.updated_at = Some(updated_at);
        Ok(())
    }
}

pub fn is_free_model(model: &str) -> bool {
    model.to_ascii_lowercase().contains("free")
}

pub fn decode_metadata(data: &[u8]) -> Result<HashMap<String, Price>> {
    let providers: HashMap<String, Value> = serde_json::from_slice(data)
        .context("decode OpenCode metadata")?;
    let mut keys: Vec<&String> = providers.keys().collect();
    keys.sort_by(|left, right| {
        let rank = metadata_provider_rank(left).cmp(&metadata_provider_rank(right));
        rank.then_with(|| left.cmp(right))
    });
    let mut result = HashMap::new();
    for key in keys {
        if metadata_provider_rank(key) > 1 {
            continue;
        }
        let Some(provider) = providers.get(key).and_then(Value::as_object) else {
            continue;
        };
        if metadata_provider_rank(key) == 1 {
            let identity = jsonutil::first_of(jsonutil::get_str(provider, "id"), jsonutil::get_str(provider, "name")).to_ascii_lowercase();
            if !identity.contains("opencode") {
                continue;
            }
        }
        let Some(models) = jsonutil::map_of(provider, "models") else {
            continue;
        };
        for (id, raw) in models {
            let Some(model) = raw.as_object() else {
                continue;
            };
            let model_id = jsonutil::first_of(jsonutil::get_str(model, "id"), id.clone());
            if result.contains_key(&model_id) {
                continue;
            }
            let cost = jsonutil::map_of(model, "cost");
            let limit = jsonutil::map_of(model, "limit");
            result.insert(
                model_id.clone(),
                Price {
                    id: model_id,
                    input_cost: number_at(cost, "input"),
                    output_cost: number_at(cost, "output"),
                    cache_read_cost: number_at(cost, "cache_read"),
                    cache_write_cost: number_at(cost, "cache_write"),
                    context_window: limit.map(|limit| jsonutil::get_int(limit, "context")).unwrap_or(0),
                    max_input: limit.map(|limit| jsonutil::get_int(limit, "input")).unwrap_or(0),
                    max_output: limit.map(|limit| jsonutil::get_int(limit, "output")).unwrap_or(0),
                    deprecated: metadata_deprecated(model),
                }
                .normalize(),
            );
        }
    }
    if result.is_empty() {
        return Err(anyhow!("OpenCode metadata contains no OpenCode models"));
    }
    Ok(result)
}

impl Price {
    fn normalize(mut self) -> Self {
        if self.context_window == 0 {
            self.context_window = 0;
        }
        self
    }
}

fn number_at(object: Option<&serde_json::Map<String, Value>>, key: &str) -> Option<f64> {
    object?.get(key)?.as_f64()
}

fn metadata_provider_rank(key: &str) -> u8 {
    let lower = key.to_ascii_lowercase();
    if matches!(lower.as_str(), "opencode" | "opencode-zen" | "opencode_zen") {
        return 0;
    }
    if lower.contains("opencode") {
        return 1;
    }
    2
}

fn metadata_deprecated(model: &serde_json::Map<String, Value>) -> bool {
    if jsonutil::get_bool(model, "deprecated") {
        return true;
    }
    let status = jsonutil::first_of(jsonutil::get_str(model, "status"), jsonutil::get_str(model, "lifecycle")).to_ascii_lowercase();
    if matches!(status.as_str(), "deprecated" | "retired" | "disabled") {
        return true;
    }
    model.get("deprecated_at").is_some_and(|value| !value.is_null())
        || model.get("retirement_date").is_some_and(|value| !value.is_null())
}

pub fn save_metadata_cache(path: &str, cache: &ModelMetadataCache) -> Result<()> {
    let data = serde_json::to_vec_pretty(cache)?;
    crate::config::persistence::save_bytes_atomic(path, &data)
        .map_err(|error| anyhow!("save metadata cache: {error}"))?;
    Ok(())
}
