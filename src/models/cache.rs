//! Disk cache for the model catalog.

use super::{Metadata, ModelCatalog};
use crate::config::Tier;
use crate::protocol::Protocol;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;

const SCHEMA_VERSION: i32 = 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CatalogCache {
    schema_version: i32,
    updated_at: Option<OffsetDateTime>,
    zen: Vec<String>,
    #[serde(rename = "go")]
    go_models: Vec<String>,
    native_protocols: HashMap<Tier, HashMap<String, Protocol>>,
    unsupported: HashMap<Tier, HashMap<String, bool>>,
    #[serde(default)]
    metadata: HashMap<Tier, HashMap<String, Metadata>>,
}

pub fn catalog_cache_path(config_path: &str) -> String {
    if config_path.is_empty() {
        String::new()
    } else {
        format!("{config_path}.models.catalog.json")
    }
}

impl ModelCatalog {
    pub fn load_cache(&self, path: &str) -> Result<()> {
        let cache = load_catalog_cache(path)?;
        let mut state = self.state.write();
        state.zen = cache.zen.into_iter().collect();
        state.go_models = cache.go_models.into_iter().collect();
        state.native_protocols = cache.native_protocols;
        state.unsupported = cache.unsupported;
        state.model_meta = cache.metadata;
        state.updated_at = cache.updated_at;
        state.cache_source = "disk".into();
        state.stale = true;
        if state.cache_path.is_empty() {
            state.cache_path = path.to_string();
        }
        Ok(())
    }

    pub fn save_cache(&self) -> Result<()> {
        let state = self.state.read();
        let path = state.cache_path.clone();
        if path.is_empty() {
            return Ok(());
        }
        let cache = CatalogCache {
            schema_version: SCHEMA_VERSION,
            updated_at: Some(state.updated_at.unwrap_or(OffsetDateTime::UNIX_EPOCH)),
            zen: sorted_keys(&state.zen),
            go_models: sorted_keys(&state.go_models),
            native_protocols: state.native_protocols.clone(),
            unsupported: state.unsupported.clone(),
            metadata: state.model_meta.clone(),
        };
        drop(state);
        save_catalog_cache(&path, &cache)
    }
}

fn sorted_keys(items: &HashSet<String>) -> Vec<String> {
    let mut result: Vec<String> = items.iter().cloned().collect();
    result.sort();
    result
}

fn load_catalog_cache(path: &str) -> Result<CatalogCache> {
    if path.is_empty() {
        return Err(std::io::ErrorKind::NotFound.into());
    }
    let data = std::fs::read(path)?;
    let mut cache: CatalogCache = serde_json::from_slice(&data)?;
    if cache.schema_version != SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported model catalog cache schema version {}",
            cache.schema_version
        ));
    }
    if cache.updated_at.is_none() {
        return Err(anyhow!("model catalog cache is missing updated_at"));
    }
    cache.zen = crate::models::discovery::normalize_ids(cache.zen);
    cache.go_models = crate::models::discovery::normalize_ids(cache.go_models);
    if cache.zen.is_empty() && cache.go_models.is_empty() {
        return Err(anyhow!("model catalog cache is empty"));
    }
    validate_capabilities(&cache.native_protocols, &cache.unsupported)?;
    Ok(cache)
}

fn validate_capabilities(
    native: &HashMap<Tier, HashMap<String, Protocol>>,
    unsupported: &HashMap<Tier, HashMap<String, bool>>,
) -> Result<()> {
    for (tier, protocols) in native {
        if *tier != Tier::Zen && *tier != Tier::Go {
            return Err(anyhow!(
                "model catalog cache contains unknown tier {:?}",
                tier.as_str()
            ));
        }
        for model in protocols.keys() {
            if model.is_empty() {
                return Err(anyhow!(
                    "model catalog cache contains invalid protocol for {model:?}"
                ));
            }
        }
    }
    for (tier, models) in unsupported {
        if *tier != Tier::Zen && *tier != Tier::Go {
            return Err(anyhow!(
                "model catalog cache contains unknown tier {:?}",
                tier.as_str()
            ));
        }
        for model in models.keys() {
            if model.trim().is_empty() {
                return Err(anyhow!(
                    "model catalog cache contains an empty unsupported model"
                ));
            }
        }
    }
    Ok(())
}

fn save_catalog_cache(path: &str, cache: &CatalogCache) -> Result<()> {
    let data = serde_json::to_vec_pretty(cache)?;
    crate::config::persistence::save_bytes_atomic(path, &data)
        .map_err(|error| anyhow!("save model catalog cache: {error}"))?;
    Ok(())
}
