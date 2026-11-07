//! Model catalog: routing, protocol selection, metadata and availability.

pub mod availability;
pub mod cache;
pub mod discovery;
pub mod pricing;

use crate::config::Tier;
use crate::protocol::Protocol;
use anyhow::{anyhow, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;

pub use availability::{Availability, AvailabilityRegistry, EffortProbe};
pub use discovery::{Capabilities, Cost, Metadata};
pub use pricing::{AnonymousDecision, MetadataSnapshot, PricingRegistry};

#[derive(Clone, Debug)]
pub struct Route {
    pub id: String,
    pub tier: Tier,
    pub protocol: Protocol,
    pub protocols: HashMap<Tier, Protocol>,
    pub anonymous: bool,
    pub key_tiers: Vec<Tier>,
}

impl Route {
    pub fn protocol_for(&self, tier: Tier) -> Protocol {
        self.protocols.get(&tier).copied().unwrap_or(self.protocol)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RouteDiagnostic {
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_protocol: Option<Protocol>,
    pub native_protocol: Protocol,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub native_protocols: HashMap<Tier, Protocol>,
    pub protocol_source: String,
    pub available_zen: bool,
    pub available_go: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    pub anonymous: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub channel: String,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub attempts: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub key_tiers: Vec<Tier>,
    pub anonymous_eligibility: AnonymousDecision,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub route_error: String,
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CatalogSnapshot {
    pub zen: usize,
    pub go: usize,
    pub total: usize,
    pub exposed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cache_source: String,
    pub stale: bool,
}

pub(crate) struct CatalogState {
    pub(crate) zen: HashSet<String>,
    pub(crate) go_models: HashSet<String>,
    pub(crate) protocols: HashMap<String, Protocol>,
    pub(crate) native_protocols: HashMap<Tier, HashMap<String, Protocol>>,
    pub(crate) unsupported: HashMap<Tier, HashMap<String, bool>>,
    pub(crate) model_meta: HashMap<Tier, HashMap<String, Metadata>>,
    pub(crate) updated_at: Option<OffsetDateTime>,
    pub(crate) prefer: Tier,
    pub(crate) pricing: Option<Arc<PricingRegistry>>,
    pub(crate) availability: Option<Arc<AvailabilityRegistry>>,
    pub(crate) cache_path: String,
    pub(crate) cache_source: String,
    pub(crate) stale: bool,
    pub(crate) refresh_after: Duration,
    pub(crate) free_only: bool,
}

impl CatalogState {
    fn pending(&self) -> bool {
        self.zen.is_empty() && self.go_models.is_empty()
    }

    fn protocol_for(&self, model: &str, tier: Tier) -> Protocol {
        if let Some(protocol) = self.protocols.get(model) {
            return *protocol;
        }
        self.native_protocols
            .get(&tier)
            .and_then(|models| models.get(model))
            .copied()
            .unwrap_or(Protocol::Chat)
    }

    fn tier_supported(&self, model: &str, tier: Tier) -> bool {
        if self.protocols.contains_key(model) {
            return true;
        }
        if self
            .unsupported
            .get(&tier)
            .and_then(|models| models.get(model))
            .copied()
            .unwrap_or(false)
        {
            return false;
        }
        if self
            .native_protocols
            .get(&tier)
            .map(|models| models.contains_key(model))
            .unwrap_or(false)
        {
            return true;
        }
        self.pending()
    }

    fn anonymous_decision(&self, model: &str) -> AnonymousDecision {
        match &self.pricing {
            Some(pricing) => pricing.decide(model),
            None => AnonymousDecision {
                allowed: pricing::is_free_model(model),
                source: "name_fallback_metadata_pending".into(),
                ..Default::default()
            },
        }
    }

    fn free_only_error(&self, model: &str) -> Result<()> {
        if self.free_only && !self.anonymous_decision(model).allowed {
            return Err(anyhow!(
                "model {model:?} is not free and models.free_only is enabled"
            ));
        }
        Ok(())
    }

    fn key_tier_order(
        &self,
        model: &str,
        has_zen_keys: bool,
        has_go_keys: bool,
    ) -> Vec<Tier> {
        let catalog_pending = self.pending();
        let available = |tier: Tier| match tier {
            Tier::Zen => {
                has_zen_keys
                    && (catalog_pending || self.zen.contains(model))
                    && self.tier_supported(model, Tier::Zen)
            }
            Tier::Go => {
                has_go_keys
                    && (catalog_pending || self.go_models.contains(model))
                    && self.tier_supported(model, Tier::Go)
            }
        };
        let order = if self.prefer == Tier::Go {
            [Tier::Go, Tier::Zen]
        } else {
            [Tier::Zen, Tier::Go]
        };
        order.into_iter().filter(|tier| available(*tier)).collect()
    }

    fn protocols_for(
        &self,
        model: &str,
        key_tiers: &[Tier],
        include_zen: bool,
    ) -> HashMap<Tier, Protocol> {
        let mut protocols = HashMap::new();
        if include_zen {
            protocols.insert(Tier::Zen, self.protocol_for(model, Tier::Zen));
        }
        for tier in key_tiers {
            protocols.insert(*tier, self.protocol_for(model, *tier));
        }
        protocols
    }

    fn route(
        &self,
        model: &str,
        has_zen_keys: bool,
        has_go_keys: bool,
        has_anonymous: bool,
    ) -> Result<Route> {
        if let Some(availability) = &self.availability {
            if availability.disabled(model) {
                return Err(anyhow!(
                    "model {model:?} is disabled after a failed availability check; restore it in the WebUI or wait for the next probe"
                ));
            }
        }
        self.free_only_error(model)?;
        let key_tiers = self.key_tier_order(model, has_zen_keys, has_go_keys);
        let decision = self.anonymous_decision(model);
        if has_anonymous
            && decision.allowed
            && (self.protocols.contains_key(model)
                || !self
                    .unsupported
                    .get(&Tier::Zen)
                    .and_then(|models| models.get(model))
                    .copied()
                    .unwrap_or(false))
            && (self.pending() || self.zen.contains(model) || self.go_models.contains(model))
        {
            let protocols = self.protocols_for(model, &key_tiers, true);
            return Ok(Route {
                id: model.to_string(),
                tier: Tier::Zen,
                protocol: protocols[&Tier::Zen],
                protocols,
                anonymous: true,
                key_tiers,
            });
        }
        if let Some(first) = key_tiers.first() {
            let protocols = self.protocols_for(model, &key_tiers, false);
            return Ok(Route {
                id: model.to_string(),
                tier: *first,
                protocol: protocols[first],
                protocols,
                anonymous: false,
                key_tiers,
            });
        }
        Err(anyhow!(
            "model {model:?} is not available in the configured Zen or Go pools"
        ))
    }

    fn model_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .zen
            .iter()
            .chain(self.go_models.iter())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        ids.sort();
        ids
    }

    fn supported(&self, model: &str) -> bool {
        if self.pending() {
            return true;
        }
        (self.zen.contains(model) && self.tier_supported(model, Tier::Zen))
            || (self.go_models.contains(model) && self.tier_supported(model, Tier::Go))
    }

    fn snapshot(&self, ids: &[String]) -> CatalogSnapshot {
        let exposed = ids.iter().filter(|id| self.supported(id)).count();
        let mut stale = self.stale;
        if let Some(updated) = self.updated_at {
            if !self.refresh_after.is_zero() {
                let age = OffsetDateTime::now_utc() - updated;
                let threshold = (self.refresh_after * 2).max(Duration::from_secs(60));
                stale = stale || age > time::Duration::seconds(threshold.as_secs() as i64);
            }
        }
        CatalogSnapshot {
            zen: self.zen.len(),
            go: self.go_models.len(),
            total: ids.len(),
            exposed,
            updated_at: self.updated_at,
            cache_source: self.cache_source.clone(),
            stale,
        }
    }
}

pub struct ModelCatalog {
    state: RwLock<CatalogState>,
}

impl ModelCatalog {
    pub fn new(prefer: Tier, overrides: HashMap<String, String>) -> Self {
        let protocols = overrides
            .into_iter()
            .filter_map(|(model, protocol)| {
                Protocol::from_str(&protocol).map(|protocol| (model, protocol))
            })
            .collect();
        Self {
            state: RwLock::new(CatalogState {
                zen: HashSet::new(),
                go_models: HashSet::new(),
                protocols,
                native_protocols: tier_map(),
                unsupported: tier_map(),
                model_meta: tier_map(),
                updated_at: None,
                prefer,
                pricing: None,
                availability: None,
                cache_path: String::new(),
                cache_source: "none".into(),
                stale: false,
                refresh_after: Duration::ZERO,
                free_only: false,
            }),
        }
    }

    pub fn set_pricing_store(&self, store: Arc<PricingRegistry>) {
        self.state.write().pricing = Some(store);
    }

    pub fn set_availability_store(&self, store: Arc<AvailabilityRegistry>) {
        self.state.write().availability = Some(store);
    }

    pub fn metadata_snapshot(&self) -> MetadataSnapshot {
        let pricing = self.state.read().pricing.clone();
        pricing
            .map(|pricing| pricing.snapshot())
            .unwrap_or_default()
    }

    pub fn set_cache_path(&self, path: &str) {
        self.state.write().cache_path = path.to_string();
    }

    pub fn set_refresh_interval(&self, interval: Duration) {
        self.state.write().refresh_after = interval;
    }

    pub fn set_free_only(&self, enabled: bool) {
        self.state.write().free_only = enabled;
    }

    pub fn replace(&self, zen: Vec<String>, go_models: Vec<String>) {
        self.replace_with_capabilities(Some(zen), Some(go_models), None, None, None);
    }

    pub fn replace_with_capabilities(
        &self,
        zen: Option<Vec<String>>,
        go_models: Option<Vec<String>>,
        native: Option<HashMap<Tier, HashMap<String, Protocol>>>,
        unsupported: Option<HashMap<Tier, HashMap<String, bool>>>,
        metadata: Option<HashMap<Tier, HashMap<String, Metadata>>>,
    ) {
        let mut state = self.state.write();
        if let Some(zen) = zen {
            state.zen = zen.into_iter().collect();
        }
        if let Some(go_models) = go_models {
            state.go_models = go_models.into_iter().collect();
        }
        if let Some(native) = native {
            for tier in [Tier::Zen, Tier::Go] {
                if let Some(protocols) = native.get(&tier) {
                    state.native_protocols.insert(tier, protocols.clone());
                }
            }
        }
        if let Some(unsupported) = unsupported {
            for tier in [Tier::Zen, Tier::Go] {
                if let Some(models) = unsupported.get(&tier) {
                    state.unsupported.insert(tier, models.clone());
                }
            }
        }
        if let Some(metadata) = metadata {
            state.model_meta = metadata;
        }
        state.updated_at = Some(OffsetDateTime::now_utc());
        state.cache_source = "live".into();
        state.stale = false;
    }

    pub fn copy_state(&self, source: &ModelCatalog) {
        let source = source.state.read();
        let zen = source.zen.clone();
        let go_models = source.go_models.clone();
        let native = source.native_protocols.clone();
        let unsupported = source.unsupported.clone();
        let metadata = source.model_meta.clone();
        let updated_at = source.updated_at;
        let cache_source = source.cache_source.clone();
        let stale = source.stale;
        drop(source);
        let mut target = self.state.write();
        target.zen = zen;
        target.go_models = go_models;
        target.native_protocols = native;
        target.unsupported = unsupported;
        target.model_meta = metadata;
        target.updated_at = updated_at;
        target.cache_source = cache_source;
        target.stale = stale;
    }

    pub fn route(
        &self,
        model: &str,
        has_zen_keys: bool,
        has_go_keys: bool,
        has_anonymous: bool,
    ) -> Result<Route> {
        self.state
            .read()
            .route(model, has_zen_keys, has_go_keys, has_anonymous)
    }

    pub fn route_for_tier(
        &self,
        model: &str,
        tier: Tier,
        has_zen_keys: bool,
        has_go_keys: bool,
    ) -> Result<Route> {
        let has_keys = if tier == Tier::Go {
            has_go_keys
        } else {
            has_zen_keys
        };
        if !has_keys {
            return Err(anyhow!("no {} key is configured", tier.as_str()));
        }
        let state = self.state.read();
        if let Some(availability) = &state.availability {
            if availability.disabled(model) {
                return Err(anyhow!(
                    "model {model:?} is disabled after a failed availability check"
                ));
            }
        }
        state.free_only_error(model)?;
        let advertised = if tier == Tier::Go {
            state.go_models.contains(model)
        } else {
            state.zen.contains(model)
        };
        if !state.pending() && !advertised {
            return Err(anyhow!(
                "model {model:?} is not available in the selected {} key tier",
                tier.as_str()
            ));
        }
        if !state.tier_supported(model, tier) {
            return Err(anyhow!(
                "model {model:?} uses an upstream protocol that is not available on the selected {} key tier",
                tier.as_str()
            ));
        }
        let protocol = state.protocol_for(model, tier);
        Ok(Route {
            id: model.to_string(),
            tier,
            protocol,
            protocols: HashMap::from([(tier, protocol)]),
            anonymous: false,
            key_tiers: vec![tier],
        })
    }

    pub fn is_free_model(&self, model: &str) -> bool {
        self.state.read().anonymous_decision(model).allowed
    }

    pub fn diagnostic(
        &self,
        model: &str,
        requested: Option<Protocol>,
        has_zen_keys: bool,
        has_go_keys: bool,
        has_anonymous: bool,
    ) -> RouteDiagnostic {
        let (configured, explicit, zen, go_model, zen_known, go_known, prefer, native_protocols, eligibility) = {
            let state = self.state.read();
            (
                state.protocols.get(model).copied(),
                state.protocols.contains_key(model),
                state.zen.contains(model),
                state.go_models.contains(model),
                state
                    .native_protocols
                    .get(&Tier::Zen)
                    .map(|models| models.contains_key(model))
                    .unwrap_or(false),
                state
                    .native_protocols
                    .get(&Tier::Go)
                    .map(|models| models.contains_key(model))
                    .unwrap_or(false),
                state.prefer,
                HashMap::from([
                    (Tier::Zen, state.protocol_for(model, Tier::Zen)),
                    (Tier::Go, state.protocol_for(model, Tier::Go)),
                ]),
                state.anonymous_decision(model),
            )
        };
        let source = if !explicit {
            if zen_known || go_known {
                "upstream"
            } else {
                "default"
            }
        } else {
            "configured"
        };
        let protocol = configured.unwrap_or_else(|| {
            if prefer == Tier::Go {
                native_protocols[&Tier::Go]
            } else {
                native_protocols[&Tier::Zen]
            }
        });
        let mut diagnostic = RouteDiagnostic {
            model: model.to_string(),
            requested_protocol: requested,
            native_protocol: protocol,
            native_protocols,
            protocol_source: source.into(),
            available_zen: zen,
            available_go: go_model,
            anonymous_eligibility: eligibility,
            ..Default::default()
        };
        match self.route(model, has_zen_keys, has_go_keys, has_anonymous) {
            Ok(route) => {
                diagnostic.native_protocol = route.protocol;
                diagnostic.native_protocols = route.protocols;
                diagnostic.tier = Some(route.tier);
                diagnostic.anonymous = route.anonymous;
                diagnostic.key_tiers = route.key_tiers;
            }
            Err(error) => diagnostic.route_error = error.to_string(),
        }
        diagnostic
    }

    pub fn list(&self) -> Vec<String> {
        let state = self.state.read();
        let mut ids = state.model_ids();
        ids.retain(|model| state.supported(model));
        ids
    }

    pub fn snapshot(&self) -> CatalogSnapshot {
        let state = self.state.read();
        state.snapshot(&state.model_ids())
    }

    pub fn available_models(
        &self,
        has_zen_keys: bool,
        has_go_keys: bool,
        has_anonymous: bool,
    ) -> (Vec<Route>, CatalogSnapshot) {
        let state = self.state.read();
        let ids = state.model_ids();
        let mut routes = Vec::new();
        for model in &ids {
            if !state.supported(model) {
                continue;
            }
            if let Ok(route) = state.route(model, has_zen_keys, has_go_keys, has_anonymous) {
                routes.push(route);
            }
        }
        let mut snapshot = state.snapshot(&ids);
        snapshot.exposed = routes.len();
        (routes, snapshot)
    }

    pub fn supported(&self, model: &str) -> bool {
        self.state.read().supported(model)
    }

    pub fn known(&self, model: &str) -> bool {
        let state = self.state.read();
        if state.protocols.contains_key(model)
            || state.zen.contains(model)
            || state.go_models.contains(model)
        {
            return true;
        }
        if state
            .native_protocols
            .values()
            .any(|models| models.contains_key(model))
        {
            return true;
        }
        if state
            .unsupported
            .values()
            .any(|models| models.get(model).copied().unwrap_or(false))
        {
            return true;
        }
        state.model_meta.values().any(|models| {
            models
                .get(model)
                .map(|metadata| metadata.context_window > 0)
                .unwrap_or(false)
        })
    }

    pub fn metadata_for_tier(&self, model: &str, tier: Tier) -> Metadata {
        let (mut metadata, pricing) = {
            let state = self.state.read();
            (
                state
                    .model_meta
                    .get(&tier)
                    .and_then(|models| models.get(model))
                    .cloned()
                    .unwrap_or_default(),
                state.pricing.clone(),
            )
        };
        let Some(pricing) = pricing else {
            return metadata;
        };
        let Some(price) = pricing.price(model) else {
            return metadata;
        };
        if metadata.context_window == 0 {
            metadata.context_window = price.context_window;
        }
        if metadata.max_input == 0 {
            metadata.max_input = price.max_input;
        }
        if metadata.max_output == 0 {
            metadata.max_output = price.max_output;
        }
        if price.input_cost.is_some() || price.output_cost.is_some() {
            metadata.cost = Some(Cost {
                input: price.input_cost,
                output: price.output_cost,
                cache_read: price.cache_read_cost,
                cache_write: price.cache_write_cost,
            });
        }
        metadata
    }
}

fn tier_map<T>() -> HashMap<Tier, HashMap<String, T>> {
    HashMap::from([(Tier::Zen, HashMap::new()), (Tier::Go, HashMap::new())])
}
