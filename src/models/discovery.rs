//! Discovery of the upstream model catalog and its per-tier protocols.

use crate::config::Tier;
use crate::httpx::{self, Transport};
use crate::jsonutil;
use crate::protocol::Protocol;
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use url::Url;

pub const CAPABILITIES_URL: &str = "https://models.opencode.ai/api.json";
pub const ZEN_DOCS_URL: &str =
    "https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/web/src/content/docs/zen.mdx";
pub const GO_DOCS_URL: &str =
    "https://raw.githubusercontent.com/anomalyco/opencode/dev/packages/web/src/content/docs/go.mdx";
pub const V1_BASE: &str = "https://opencode.ai/zen";

pub fn is_v1_upstream(base_url: &str) -> bool {
    let trimmed = base_url.trim().trim_end_matches('/').to_ascii_lowercase();
    if trimmed == V1_BASE.trim_end_matches('/').to_ascii_lowercase() {
        return true;
    }
    trimmed.ends_with("/zen")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Capabilities {
    pub protocols: HashMap<Tier, HashMap<String, Protocol>>,
    pub unsupported: HashMap<Tier, HashMap<String, bool>>,
    pub metadata: HashMap<Tier, HashMap<String, Metadata>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Metadata {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub context_window: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_input: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_output: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub reasoning: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub tool_call: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub structured_output: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_modalities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_modalities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Cost {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_write: Option<f64>,
}

static DOC_ENDPOINT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\|[^|]+\|\s*`?([^|`\s]+)`?\s*\|\s*`[^`]+/v1/(chat/completions|responses|messages|systemone)`")
        .expect("valid protocol doc regex")
});

pub async fn fetch_capabilities(client: &Transport, endpoint: &str) -> Result<Capabilities> {
    let request = httpx::Request::get(endpoint.parse().context("capability endpoint")?)
        .header("Accept", "application/json")
        .header("User-Agent", &httpx::v2_user_agent());
    let response = client.execute(request).await?;
    if !response.status.is_success() {
        return Err(anyhow!(
            "OpenCode capability endpoint returned HTTP {}",
            response.status.as_u16()
        ));
    }
    let data = response.body.collect().await?;
    let providers: HashMap<String, Value> =
        serde_json::from_slice(&data).context("decode capability catalog")?;
    let mut result = Capabilities::default();
    result.protocols.insert(Tier::Zen, HashMap::new());
    result.protocols.insert(Tier::Go, HashMap::new());
    result.unsupported.insert(Tier::Zen, HashMap::new());
    result.unsupported.insert(Tier::Go, HashMap::new());
    result.metadata.insert(Tier::Zen, HashMap::new());
    result.metadata.insert(Tier::Go, HashMap::new());
    for (provider_id, provider) in providers {
        let api = provider.get("api").and_then(Value::as_str).unwrap_or_default();
        let Some(tier) = capability_tier(&provider_id, api) else {
            continue;
        };
        let npm = provider.get("npm").and_then(Value::as_str).unwrap_or_default();
        let Some(models) = provider.get("models").and_then(Value::as_object) else {
            continue;
        };
        for (fallback_id, model) in models {
            let Some(model) = model.as_object() else {
                continue;
            };
            let model_id = jsonutil::first_of(
                model.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
                fallback_id.clone(),
            );
            let model_npm = model
                .get("provider")
                .and_then(Value::as_object)
                .and_then(|provider| provider.get("npm"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .unwrap_or(npm);
            if let Some(protocol) = protocol_for_sdk(model_npm) {
                result
                    .protocols
                    .get_mut(&tier)
                    .unwrap()
                    .insert(model_id.clone(), protocol);
            } else {
                result
                    .unsupported
                    .get_mut(&tier)
                    .unwrap()
                    .insert(model_id.clone(), true);
            }
            result
                .metadata
                .get_mut(&tier)
                .unwrap()
                .insert(model_id, capability_metadata(model));
        }
    }
    for (tier, url) in [(Tier::Zen, ZEN_DOCS_URL), (Tier::Go, GO_DOCS_URL)] {
        let Ok(protocols) = fetch_protocol_docs(client, url).await else {
            continue;
        };
        for (model, protocol) in protocols {
            result
                .protocols
                .get_mut(&tier)
                .unwrap()
                .insert(model.clone(), protocol);
            result.unsupported.get_mut(&tier).unwrap().remove(&model);
        }
    }
    let empty = |tier: &Tier| {
        result.protocols[tier].is_empty() && result.unsupported[tier].is_empty()
    };
    if empty(&Tier::Zen) && empty(&Tier::Go) {
        return Err(anyhow!(
            "OpenCode capability endpoint returned no Zen or Go models"
        ));
    }
    Ok(result)
}

fn capability_metadata(model: &serde_json::Map<String, Value>) -> Metadata {
    let mut metadata = Metadata {
        reasoning: jsonutil::get_bool(model, "reasoning"),
        tool_call: jsonutil::get_bool(model, "tool_call"),
        structured_output: jsonutil::get_bool(model, "structured_output"),
        ..Default::default()
    };
    if let Some(modalities) = jsonutil::map_of(model, "modalities") {
        metadata.input_modalities = string_list(modalities, "input");
        metadata.output_modalities = string_list(modalities, "output");
    }
    if let Some(limit) = jsonutil::map_of(model, "limit") {
        metadata.context_window = jsonutil::get_int(limit, "context");
        metadata.max_input = jsonutil::get_int(limit, "input");
        metadata.max_output = jsonutil::get_int(limit, "output");
    }
    metadata
}

fn string_list(object: &serde_json::Map<String, Value>, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub async fn fetch_protocol_docs(client: &Transport, endpoint: &str) -> Result<HashMap<String, Protocol>> {
    let request = httpx::Request::get(endpoint.parse().context("documentation URL")?)
        .header("Accept", "text/plain, text/markdown, */*")
        .header("User-Agent", &httpx::v2_user_agent());
    let response = client.execute(request).await?;
    if !response.status.is_success() {
        return Err(anyhow!(
            "OpenCode endpoint documentation returned HTTP {}",
            response.status.as_u16()
        ));
    }
    let data = response.body.collect().await?;
    let text = String::from_utf8_lossy(&data);
    let mut result = HashMap::new();
    for line in text.lines() {
        let Some(captures) = DOC_ENDPOINT.captures(line) else {
            continue;
        };
        let model = captures.get(1).map(|m| m.as_str().trim()).unwrap_or_default();
        if model.is_empty() || model.contains([' ', '`', '|']) {
            continue;
        }
        let protocol = match captures.get(2).map(|m| m.as_str()).unwrap_or_default() {
            "chat/completions" => Protocol::Chat,
            "responses" => Protocol::Responses,
            "messages" => Protocol::Anthropic,
            "systemone" => Protocol::SystemOne,
            _ => continue,
        };
        result.insert(model.to_string(), protocol);
    }
    if result.is_empty() {
        return Err(anyhow!(
            "OpenCode endpoint documentation returned no protocol rows"
        ));
    }
    Ok(result)
}

fn capability_tier(provider_id: &str, api: &str) -> Option<Tier> {
    let value = format!("{} {}", provider_id, api).trim().to_ascii_lowercase();
    if value.contains("opencode-go") || value.contains("/go/") {
        return Some(Tier::Go);
    }
    if value.contains("opencode") || value.contains("/zen/") {
        return Some(Tier::Zen);
    }
    None
}

fn protocol_for_sdk(npm: &str) -> Option<Protocol> {
    let value = npm.trim().to_ascii_lowercase();
    if value.contains("anthropic") {
        return Some(Protocol::Anthropic);
    }
    if value == "@ai-sdk/openai" || value.ends_with("/openai") {
        return Some(Protocol::Responses);
    }
    if value.contains("openai-compatible") {
        return Some(Protocol::Chat);
    }
    None
}

pub async fn fetch_models(
    client: &Transport,
    base_url: &str,
    key: &str,
) -> (Vec<String>, u16, Result<()>) {
    let trimmed = base_url.trim().trim_end_matches('/');
    let Ok(mut url) = format!("{trimmed}/v1/models").parse::<Url>() else {
        return (Vec::new(), 0, Err(anyhow!("invalid models endpoint")));
    };
    url.set_query(None);
    let user_agent = if is_v1_upstream(trimmed) {
        httpx::v1_user_agent()
    } else {
        httpx::v2_user_agent()
    };
    let request = httpx::Request::get(url)
        .header("Authorization", &format!("Bearer {key}"))
        .header("User-Agent", &user_agent)
        .header("x-opencode-client", "cli");
    let response = match client.execute(request).await {
        Ok(response) => response,
        Err(error) => return (Vec::new(), 0, Err(error)),
    };
    let status = response.status.as_u16();
    if !response.status.is_success() {
        return (
            Vec::new(),
            status,
            Err(anyhow!("models endpoint returned HTTP {status}")),
        );
    }
    let data = match response.body.collect().await {
        Ok(data) => data,
        Err(error) => return (Vec::new(), status, Err(error)),
    };
    let payload: Value = match serde_json::from_slice(&data) {
        Ok(payload) => payload,
        Err(error) => return (Vec::new(), status, Err(error.into())),
    };
    let models: Vec<String> = payload
        .get("data")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("id").and_then(Value::as_str))
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if models.is_empty() {
        return (
            Vec::new(),
            status,
            Err(anyhow!("models endpoint returned no models")),
        );
    }
    (models, status, Ok(()))
}

pub fn normalize_ids(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result: Vec<String> = items
        .into_iter()
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .filter(|item| seen.insert(item.clone()))
        .collect();
    result.sort();
    result
}
